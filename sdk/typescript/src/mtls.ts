// SPDX-License-Identifier: Apache-2.0
/**
 * The mTLS connect helper (ADR-MCPS-044 §client obligation).
 *
 * {@link McpReHttpTransport} takes its HTTP leg as an injected `poster` so that layer
 * stays transport-agnostic and testable. This module builds the leg a real deployment
 * needs: a **verifying** mutual-TLS connection to `mcp-re-proxy`.
 *
 * ```ts
 * const transport = connectMtlsHttp(config, { serverCa, clientCert, clientKey });
 * const client = new Client({ name: "app", version: "1.0.0" });
 * await client.connect(transport);
 * ```
 *
 * It mirrors the Rust client leg (`mcp_re_transport::remote::MtlsRemoteTransport`), and
 * the properties that matter are the same ones:
 *
 * - **only the configured CA authenticates the proxy.** Node's bundled roots are
 *   replaced, not extended, so a certificate from any other public or corporate root is
 *   refused.
 * - **the server's identity is proven, not assumed.** The certificate must be valid for
 *   `serverName` — what the address is dialled for, not merely where it answered.
 * - **a client certificate is presented**, for the proxy's own binding check.
 * - **one connection per exchange**, matching the proxy's framing.
 * - **every bound fails closed**: a connect/read that stalls past `timeoutMs`, or a
 *   response past `maxResponseBytes`, rejects rather than hanging or buffering without
 *   bound.
 *
 * There is no way to turn verification off. A helper with a `rejectUnauthorized: false`
 * knob is how mTLS deployments quietly become TLS-shaped plaintext, and the evidence
 * layer above it cannot detect that — a response signature verifies identically whether
 * or not the channel proved who produced it.
 *
 * The signed request is carried unchanged: MCP-RE's evidence lives in the headers and
 * body (RFC 9421 `Signature`/`Signature-Input`, RFC 9530 `Content-Digest`), so this must
 * transmit exactly what was signed and hand back exactly what arrived.
 */
import { request as httpsRequest } from "node:https";

import type { HttpHeader } from "../native/binding.js";
import { McpReSdkError } from "./custody.js";
import { McpReHttpTransport, type HttpReply, type McpReConfig, type Poster } from "./transport.js";

/**
 * Headers this transport owns because it owns the framing. A caller that could set one
 * could desynchronise the message boundary from what the peer parses — the classic
 * request-smuggling shape — so supplying one fails closed rather than being silently
 * dropped or duplicated. Same list the Rust client refuses.
 */
const TRANSPORT_OWNED_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding"]);

/** Default response ceiling, mirroring the proxy's own `max_body_bytes`. */
const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

/** Default connect/read/write bound in ms, mirroring the Rust client's `ClientLimits`. */
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * The channel failed: handshake refused, timed out, or an over-sized response.
 *
 * A LOCAL condition, never an MCP-RE verdict. A proxy that cannot authenticate itself is
 * a failed channel, not a failed signature, and it must not be reported as bad evidence —
 * nothing was signed, verified, or rejected here.
 */
export class MtlsTransportError extends McpReSdkError {
  constructor(detail: string) {
    super(detail);
    this.name = "MtlsTransportError";
  }
}

/** The material and bounds for one verifying mTLS client. */
export interface MtlsOptions {
  /**
   * PEM of the ONLY roots trusted to authenticate the proxy. Node's bundled root store is
   * not consulted in addition to it.
   */
  serverCa: string | Buffer | (string | Buffer)[];
  /** PEM of the client certificate chain presented to the proxy. */
  clientCert: string | Buffer;
  /** PEM of its private key. */
  clientKey: string | Buffer;
  /** Passphrase for an encrypted `clientKey`. */
  clientKeyPassphrase?: string;

  /**
   * The identity the proxy must PROVE, matched against its certificate, and sent as SNI
   * and in the `Host` header. Defaults to the host of the config's `targetUri`.
   */
  serverName?: string;
  /**
   * Where to dial, when that is not `serverName`'s own address — a load balancer, a
   * port-forward, a test listener. The identity proven is still `serverName`.
   */
  connectHost?: string;
  /** The port to dial. Defaults to the target URI's, or 443. */
  connectPort?: number;

  /**
   * Bound on connect and on socket inactivity, in ms. Defaults to 30s. `null` disables
   * it, which lets a stalled peer hold an exchange open indefinitely.
   */
  timeoutMs?: number | null;
  /** Response bytes buffered before failing closed. Defaults to 16 MiB. */
  maxResponseBytes?: number;
}

/** The name to prove, the port, and the host to dial. */
function endpoint(
  targetUri: string,
  options: MtlsOptions,
): { serverName: string; port: number; host: string; path: string } {
  let url: URL;
  try {
    url = new URL(targetUri);
  } catch {
    throw new McpReSdkError(`targetUri is not absolute: ${JSON.stringify(targetUri)}`);
  }
  if (url.protocol !== "https:") {
    // An http:// target would be signed and sent in the clear. The evidence would still
    // verify, which is exactly why this cannot be left to the deployment.
    throw new McpReSdkError(
      `connectMtlsHttp needs an https:// targetUri, got ${JSON.stringify(targetUri)}`,
    );
  }
  const serverName = options.serverName ?? url.hostname;
  if (!serverName) {
    throw new McpReSdkError(`targetUri has no host to authenticate: ${JSON.stringify(targetUri)}`);
  }
  const port = options.connectPort ?? (url.port ? Number(url.port) : 443);
  return {
    serverName,
    port,
    host: options.connectHost ?? serverName,
    // The signature covers the ABSOLUTE target URI; the request line carries the origin
    // form of it. Both sides derive the covered value from their own configuration, so
    // this conversion never feeds the signature base — it only routes the request.
    path: `${url.pathname || "/"}${url.search}`,
  };
}

/**
 * A {@link Poster} that sends each signed request over one verifying mTLS connection.
 *
 * The endpoint is resolved once, here, so a malformed target fails at construction rather
 * than on the first request. Use this directly to compose the connection with an existing
 * transport; {@link connectMtlsHttp} is the one-call form.
 */
export function mtlsPoster(config: McpReConfig, options: MtlsOptions): Poster {
  const { serverName, port, host, path } = endpoint(config.targetUri, options);
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1) {
    throw new McpReSdkError(
      `maxResponseBytes must be a positive integer, got ${JSON.stringify(options.maxResponseBytes)}`,
    );
  }
  const timeoutMs = options.timeoutMs === null ? undefined : (options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  return (method: string, _targetUri: string, headers: HttpHeader[], body: Buffer) =>
    new Promise<HttpReply>((resolve, reject) => {
      for (const { key } of headers) {
        if (TRANSPORT_OWNED_HEADERS.has(key.toLowerCase())) {
          reject(
            new MtlsTransportError(
              `${key.toLowerCase()} is set by the transport and must not be signed into a request`,
            ),
          );
          return;
        }
      }

      const req = httpsRequest({
        host,
        port,
        path,
        method,
        // `servername` is BOTH the SNI sent and the name the certificate is checked
        // against, and it is the configured identity — not `host`, which is only where
        // the connection goes.
        servername: serverName,
        ca: options.serverCa,
        cert: options.clientCert,
        key: options.clientKey,
        passphrase: options.clientKeyPassphrase,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        // One connection per exchange, as the proxy frames it. `agent: false` also keeps
        // this off the global pool, where a socket authenticated for another identity
        // could otherwise be reused.
        agent: false,
        setHost: false,
        headers: {
          // The identity proven, not the address dialled: a Host header naming the load
          // balancer would describe a different resource than the one authenticated.
          Host: serverName,
          "Content-Length": String(body.length),
          Connection: "close",
        },
        timeout: timeoutMs,
      });

      // Registered BEFORE anything can destroy the request. `destroy()` emits `error` on
      // the next tick, and a ClientRequest with no `error` listener throws that as an
      // unhandled exception — taking down the host process for what is, here, a refusal
      // this poster has already reported by rejecting.
      req.on("timeout", () => {
        req.destroy(new MtlsTransportError(`the exchange timed out after ${timeoutMs}ms`));
      });
      req.on("error", (e) => {
        // A handshake rejection — untrusted chain, wrong identity, expired certificate —
        // arrives here, as does a reset or a timeout. All are failed channels. Rejecting
        // an already-settled promise is a no-op, which is what makes it safe to also
        // reject at the throw sites below.
        reject(e instanceof MtlsTransportError ? e : new MtlsTransportError(`the connection failed: ${e.message}`));
      });

      // `setHeader` refuses a CR/LF in a value, so a header that would split the request
      // into two never reaches the socket.
      try {
        for (const { key, value } of headers) req.setHeader(key, value);
      } catch (e) {
        reject(new MtlsTransportError(`refusing to emit a malformed header: ${String(e)}`));
        req.destroy();
        return;
      }

      req.on("response", (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxResponseBytes) {
            // Stop reading rather than buffer a hostile length to find out how big it is.
            res.destroy();
            reject(new MtlsTransportError(`response exceeded maxResponseBytes (${maxResponseBytes})`));
            return;
          }
          chunks.push(chunk);
        });
        res.on("error", (e) =>
          reject(new MtlsTransportError(`the response could not be read: ${e.message}`)),
        );
        res.on("end", () => {
          // From `rawHeaders`, not `headers`: lowercased and in WIRE ORDER, keeping
          // repeats distinct. The signature base is built from what arrived, and
          // Node's parsed map folds duplicates into arrays.
          const parsed: HttpHeader[] = [];
          for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) {
            parsed.push({ key: res.rawHeaders[i].toLowerCase(), value: res.rawHeaders[i + 1] });
          }
          resolve({ status: res.statusCode ?? 0, headers: parsed, body: Buffer.concat(chunks) });
        });
      });

      req.end(body);
    });
}

/**
 * An {@link McpReHttpTransport} whose HTTP leg is a verifying mTLS connection.
 *
 * Returns the transport ready for `client.connect(...)`; this only supplies the
 * connection, so everything the adapter guarantees — signing, delegated verification,
 * correlation, continuation — is unchanged.
 */
export function connectMtlsHttp(config: McpReConfig, options: MtlsOptions): McpReHttpTransport {
  return new McpReHttpTransport(config, mtlsPoster(config, options));
}
