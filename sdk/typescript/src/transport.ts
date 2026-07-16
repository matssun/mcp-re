// SPDX-License-Identifier: Apache-2.0
/**
 * The MCP-RE transport adapter (ADR-MCPS-044 §wrap-or-fork rule).
 *
 * `Client` speaks plain MCP; this adapter signs the outgoing bytes and verifies the
 * incoming bytes underneath it, so application code never calls `signRequest` /
 * `verifyResponse` itself.
 *
 *     application code
 *       -> Client (@modelcontextprotocol/sdk)  plain MCP; unaware of MCP-RE
 *       -> McpReHttpTransport                  signs outbound bytes / verifies inbound
 *       -> ../native/binding (napi-rs)         the audited mcp-re-client-core, in Rust
 *       -> mcp-re-proxy (HTTP profile)         one signed mTLS POST per request
 *
 * Why a transport and not a wrapper: the MCP SDK serializes JSON-RPC *inside* each
 * transport — `Client` hands the transport parsed objects, not bytes. The transport is
 * therefore the only seam with exact-byte control, which is what a byte-exact signature
 * requires.
 *
 * **Every failure is delivered, correlated to the request id, as a JSON-RPC error.** A
 * transport that dropped a failed exchange would leave `Client` awaiting a reply that
 * never comes; a hang is a worse failure mode than a raise, and an unverifiable response
 * must never reach the application as a result.
 *
 * MCP-RE is HTTP-profile only: one signed POST per request. The POST itself is injected as
 * a `poster` so this layer stays transport-agnostic and testable; `connectMtlsHttp` (the
 * mTLS construction helper) builds on top of it.
 */
import { randomBytes } from "node:crypto";

import type { JSONRPCMessage, RequestId } from "@modelcontextprotocol/sdk/types.js";
import { JSONRPCMessageSchema } from "@modelcontextprotocol/sdk/types.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

import { verifyResponse, type HttpHeader } from "../native/binding.js";
import {
  bindingsJson as serializeBindings,
  type AuthorizationBindingPolicy,
  type AuthorizationBindingProvider,
  type BindingRequestContext,
} from "./authorization.js";
import { ContinuationHandles, CorrelationStore } from "./correlation.js";
import { McpReError, McpReSdkError, type Signer, type SignerPolicy } from "./custody.js";

/**
 * The response-side body evidence block. Stripped before the result reaches the app:
 * MCP-RE's own evidence is not part of the MCP result.
 */
const RESPONSE_BLOCK_KEY = "se.syncom/mcp-re.http.response";

/**
 * JSON-RPC application error code for a delivered MCP-RE failure. The precise cause is
 * always the frozen `mcp-re.*` token in `.message`.
 */
const MCP_RE_ERROR_CODE = -32001;

/** What a {@link Poster} returns: the raw HTTP response, unparsed and unverified. */
export interface HttpReply {
  status: number;
  headers: HttpHeader[];
  body: Buffer;
}

/** Send one signed POST. */
export type Poster = (
  method: string,
  targetUri: string,
  headers: HttpHeader[],
  body: Buffer,
) => Promise<HttpReply>;

/** 128 bits from the OS CSPRNG: the freshness window rejects a repeat, so the only
 * requirement here is that a collision is not reachable in practice. */
const defaultNonce = (): string => randomBytes(16).toString("base64url");

const defaultClock = (): number => Math.floor(Date.now() / 1000);

/**
 * Everything the adapter needs to sign one request and verify one response.
 *
 * Freshness is generated here, not by the caller: a nonce that repeats inside the window
 * is a defect, not a policy knob.
 */
export interface McpReConfig {
  // --- signing ---
  signer: Signer;
  audienceId: string;
  targetUri: string;
  dpopToken: string;
  route?: string | null;
  policy?: SignerPolicy;

  // --- delegated verification (ADR-MCPRE-052): the trusted ROOT ISSUER anchor ---
  issuerKeyId: string;
  issuerPubkeyB64Url: string;
  issuerRole?: string;
  issuerTrustDomain: string;
  issuerSubject: string;
  verifierAudiences: readonly string[];
  expectedAudienceHash: string;
  acceptedEpochs: readonly string[];
  maxClockSkew?: number;
  revokedIdentifiers?: readonly string[];

  // --- authorization bindings (bind-not-interpret) ---
  authorization?: readonly AuthorizationBindingProvider[];
  authorizationPolicy?: AuthorizationBindingPolicy;

  // --- freshness ---
  requestTtl?: number;
  clock?: () => number;
  nonceFactory?: () => string;

  /**
   * Called with each client->server notification the adapter drops. MCP-RE's wire is one
   * signed POST per request: a notification has no reply, so it carries no evidence and
   * cannot be verified. Dropping is the honest behaviour, but it is surfaced here rather
   * than done silently.
   */
  onDroppedNotification?: (method: string) => void;

  /**
   * Called when a verified response is an ADR-MCPS-047 `InputRequiredResult`, with the
   * handles its answer leg must sign over. The open leg stays outstanding.
   */
  onInputRequired?: (handles: ContinuationHandles) => void;
}

/** Remove MCP-RE's response evidence block; the app sees plain MCP.
 *
 * Read only AFTER verification: the content-digest covered these bytes. */
function stripResponseEvidence(body: Buffer): unknown {
  const doc = JSON.parse(body.toString("utf8"));
  const meta = doc?._meta;
  if (meta && typeof meta === "object" && RESPONSE_BLOCK_KEY in meta) {
    delete meta[RESPONSE_BLOCK_KEY];
    if (Object.keys(meta).length === 0) delete doc._meta;
  }
  return doc;
}

/** A JSON-RPC error correlated to the request, so the awaiting call rejects. */
const errorMessage = (id: RequestId, wireCode: string): JSONRPCMessage => ({
  jsonrpc: "2.0",
  id,
  error: { code: MCP_RE_ERROR_CODE, message: wireCode },
});

/**
 * An MCP client transport that signs requests and verifies responses.
 *
 * ```ts
 * const transport = new McpReHttpTransport(config, poster);
 * const client = new Client({ name: "app", version: "1.0.0" });
 * await client.connect(transport);
 * await client.callTool({ name: "read_file", arguments: { path: "/etc/hosts" } });
 * ```
 *
 * The signer is checked against the route's policy in `start()`, so a custody violation
 * fails the connection rather than a request.
 */
export class McpReHttpTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  readonly #config: McpReConfig;
  readonly #poster: Poster;
  readonly #correlation = new CorrelationStore();
  #started = false;

  constructor(config: McpReConfig, poster: Poster) {
    this.#config = config;
    this.#poster = poster;
  }

  get #clock(): () => number {
    return this.#config.clock ?? defaultClock;
  }

  async start(): Promise<void> {
    if (this.#started) {
      // The MCP SDK's own transports treat a double start as a defect; a second start
      // would sign under a policy that was already accepted, hiding the first one.
      throw new McpReSdkError("McpReHttpTransport is already started");
    }
    this.#config.policy?.check(this.#config.signer);
    this.#config.authorizationPolicy?.check(this.#config.authorization ?? []);
    this.#started = true;
  }

  async send(message: JSONRPCMessage): Promise<void> {
    if (!("method" in message) || !("id" in message)) {
      // A notification (or a client-side response) has no reply, so it carries no
      // evidence and cannot be verified. MCP-RE is the client-initiated
      // request/response subset.
      const method = "method" in message ? message.method : "<unknown>";
      this.#config.onDroppedNotification?.(method);
      return;
    }

    const request = message;
    let reply: JSONRPCMessage;
    try {
      reply = await this.#exchange(request);
    } catch (e) {
      if (e instanceof McpReError) {
        reply = errorMessage(request.id, e.wireCode);
      } else if (e instanceof McpReSdkError) {
        // A local failure (e.g. the signing device). No wire code describes it.
        reply = errorMessage(request.id, `mcp-re-sdk: ${e.message}`);
      } else if (e instanceof Error) {
        // The core's own fail-closed errors arrive as plain Errors carrying the frozen
        // token; deliver it rather than letting the caller hang.
        reply = errorMessage(request.id, e.message);
      } else {
        throw e;
      }
    }
    this.onmessage?.(reply);
  }

  async close(): Promise<void> {
    this.#started = false;
    this.onclose?.();
  }

  /**
   * Sign one request, POST it, verify the reply, and correlate it back.
   *
   * Returns the plain-MCP message to hand the client — a result on success, or a
   * JSON-RPC error carrying the frozen wire code on any failure.
   */
  async #exchange(
    request: JSONRPCMessage & { method: string; id: RequestId },
  ): Promise<JSONRPCMessage> {
    const config = this.#config;
    const now = this.#clock;
    const created = now();
    const expires = created + (config.requestTtl ?? 300);
    const params = "params" in request && request.params !== undefined ? request.params : {};

    const signed = config.signer.signRequest({
      idJson: JSON.stringify(request.id),
      method: request.method,
      paramsJson: JSON.stringify(params),
      targetUri: config.targetUri,
      audienceId: config.audienceId,
      route: config.route ?? null,
      dpopToken: config.dpopToken,
      nonce: (config.nonceFactory ?? defaultNonce)(),
      created,
      expires,
      bindingsJson: this.#bindingsJson(request.method),
    });

    const correlationId = this.#correlation.record(signed, {
      requestId: String(request.id),
      // The nonce rode into the signature; the handle is the evidence digest.
      nonce: "",
      audienceId: config.audienceId,
      expectedSignerId: config.issuerKeyId,
      created,
      expires,
      route: config.route ?? null,
    });

    const httpReply = await this.#poster(signed.method, signed.targetUri, signed.headers, signed.body);

    const verified = verifyResponse(
      httpReply.status,
      httpReply.headers,
      httpReply.body,
      signed.method,
      signed.targetUri,
      signed.headers,
      signed.body,
      signed.evidenceDigestAlg,
      signed.evidenceDigestValue,
      config.issuerKeyId,
      config.issuerPubkeyB64Url,
      config.issuerRole ?? "server",
      config.issuerTrustDomain,
      config.issuerSubject,
      [...config.verifierAudiences],
      config.expectedAudienceHash,
      [...config.acceptedEpochs],
      config.maxClockSkew ?? 60,
      [...(config.revokedIdentifiers ?? [])],
      now(),
    );

    // A verified rejection receipt is genuine evidence, but it is NOT an acceptance: it
    // must reach the app as an error, never as a result.
    if (verified.outcome !== "success") {
      this.#correlation.take(correlationId, now());
      return errorMessage(request.id, verified.wireCode ?? "mcp-re.response_sig_invalid");
    }

    if (verified.requestState !== undefined && verified.requestState !== null) {
      // ADR-MCPS-047: an elicitation does not end the exchange, so the open leg stays
      // outstanding (associate, do not consume) until its answer leg terminates it.
      const handles = this.#correlation.recordInputRequired(correlationId, {
        responseDigestAlg: verified.respEvidenceDigestAlg,
        responseDigestValue: verified.respEvidenceDigestValue,
        requestState: verified.requestState,
        now: now(),
      });
      config.onInputRequired?.(handles);
    } else {
      this.#correlation.take(correlationId, now());
    }

    return JSONRPCMessageSchema.parse(stripResponseEvidence(httpReply.body));
  }

  #bindingsJson(method: string): string | null {
    const providers = this.#config.authorization ?? [];
    if (providers.length === 0) return null;
    const context: BindingRequestContext = {
      audienceId: this.#config.audienceId,
      targetUri: this.#config.targetUri,
      method,
      route: this.#config.route ?? null,
    };
    return serializeBindings(providers, context);
  }
}
