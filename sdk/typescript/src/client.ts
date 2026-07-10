/**
 * High-level entry point: build an MCP-RE-secured `Transport` for an MCP `Client`.
 *
 * The MCP TypeScript SDK idiom is `await new Client(...).connect(transport)`.
 * {@link connectMtlsHttp} builds the secured transport the app connects — every request
 * is signed and every response verified, with application code otherwise unchanged from
 * ordinary MCP. MCP-RE is HTTP-profile only: a stdio-only MCP server is fronted by an
 * EXTERNAL plain-MCP adapter (e.g. FastMCP) that speaks HTTP to `mcp-re-proxy`.
 */

import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { McpReConfig, TransportHooks } from "./transport.js";
import { McpReHttpTransport, type PostFn } from "./httpTransport.js";

/**
 * Build a transport whose every request is one MCP-RE-signed mTLS POST to the production
 * `mcp-re-proxy` (verified server-signed response).
 *
 * The proxy serves one HTTP/1.1 POST per mTLS connection (`Connection: close`), so each
 * `Client` request opens its own connection. `initialize` round-trips as a normal
 * signed request; client->server notifications are dropped (the transport has no
 * fire-and-forget channel and the minimal proxy never pushes).
 *
 * The client authenticates with `clientCert` / `clientKey` (the cert's URI SAN is the
 * MCP-RE signer DID) and verifies the proxy's server certificate against `serverCa` for
 * `serverName`.
 */
export function connectMtlsHttp(
  host: string,
  port: number,
  config: McpReConfig,
  tls: {
    serverCa: string | Buffer;
    clientCert: string | Buffer;
    clientKey: string | Buffer;
    serverName: string;
    timeoutMs?: number;
  },
  hooks?: TransportHooks,
): McpReHttpTransport {
  // `serverName` is interpolated into the raw HTTP `Host:` header — reject any control
  // character (CR/LF especially) up front so a caller-supplied name can't inject headers.
  if (/[\u0000-\u001f\u007f]/.test(tls.serverName)) {
    throw new Error("mcp-re: serverName must not contain control characters (CR/LF header injection)");
  }
  const timeoutMs = tls.timeoutMs ?? 15000;
  const post: PostFn = (body: Buffer) => oneMtlsPost(host, port, body, tls, timeoutMs);
  return new McpReHttpTransport(post, config, hooks);
}

/** One mTLS HTTP/1.1 POST; resolves `{ contentType, body }`. */
function oneMtlsPost(
  host: string,
  port: number,
  body: Buffer,
  tls: { serverCa: string | Buffer; clientCert: string | Buffer; clientKey: string | Buffer; serverName: string },
  timeoutMs: number,
): Promise<{ contentType: string; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const socket: TLSSocket = tlsConnect({
      host,
      port,
      ca: tls.serverCa,
      cert: tls.clientCert,
      key: tls.clientKey,
      servername: tls.serverName,
      timeout: timeoutMs,
    });
    const chunks: Buffer[] = [];
    let settled = false;
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };
    socket.on("secureConnect", () => {
      const head = Buffer.from(
        `POST / HTTP/1.1\r\nHost: ${tls.serverName}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
      );
      // write() (NOT end()): on a TLS socket, end() sends close_notify and tears down the
      // read side before the server's response arrives. Connection: close means the server
      // FINs after responding, which ends our read normally.
      socket.write(Buffer.concat([head, body]));
    });
    socket.on("data", (d: Buffer) => chunks.push(d));
    socket.on("timeout", () => fail(new Error("mcp-re.transport_error: mTLS POST timed out")));
    socket.on("error", fail);
    socket.on("end", () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks);
      const sep = raw.indexOf("\r\n\r\n");
      const headBytes = sep >= 0 ? raw.subarray(0, sep) : Buffer.alloc(0);
      const respBody = sep >= 0 ? raw.subarray(sep + 4) : raw;
      let contentType = "";
      for (const line of headBytes.toString("latin1").split("\r\n")) {
        const colon = line.indexOf(":");
        if (colon > 0 && line.slice(0, colon).trim().toLowerCase() === "content-type") {
          contentType = line.slice(colon + 1).trim();
          break;
        }
      }
      resolve({ contentType, body: respBody });
    });
  });
}
