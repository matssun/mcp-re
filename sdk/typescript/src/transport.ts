// SPDX-License-Identifier: Apache-2.0
/**
 * The MCP-RE transport adapter (ADR-MCPS-044 §wrap-or-fork rule).
 *
 * `Client` speaks plain MCP; this adapter signs the outgoing bytes and verifies the
 * incoming bytes underneath it, so application code never calls `signRequest` /
 * `verifyResponse` itself.
 *
 *     application code
 *       -> Client (@modelcontextprotocol/client)  plain MCP; unaware of MCP-RE
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
 * **One-way notifications are carried, not dropped.** A notification is its own signed
 * POST, and the acknowledgement it earns — a signed bodyless 202 bound to that exact
 * transmission — is verified before the adapter treats it as delivered. See
 * {@link NotificationNotAcknowledged} for what happens when it is not.
 *
 * **A multi-round-trip call is driven to a terminal result.** An ADR-MCPS-047 elicitation
 * pauses a call rather than finishing it, so the adapter signs the answer leg over the
 * verified handles of the leg before it and continues until the server returns a terminal
 * result — that result, and only that, is what the caller's await resolves to. Supply
 * {@link McpReConfig.answerInputRequired} to answer; without it an elicitation fails
 * closed ({@link ContinuationNotAnswered}) rather than reaching the application as if the
 * call had completed.
 *
 * MCP-RE is HTTP-profile only: one signed POST per request. The POST itself is injected as
 * a `poster` so this layer stays transport-agnostic and testable. {@link connectMtlsHttp}
 * builds the mTLS leg on top of it, mirroring the Rust client's
 * `mcp_re_transport::remote::MtlsRemoteTransport`.
 */
import { createHash, randomBytes } from "node:crypto";

import type { JSONRPCMessage, RequestId, Transport } from "@modelcontextprotocol/client";
import { JSONRPCMessageSchema } from "@modelcontextprotocol/core";

import {
  verifyAccepted202,
  verifyResponse,
  type HttpHeader,
} from "../native/binding.js";
import {
  bindingsJson as serializeBindings,
  type AuthorizationBindingPolicy,
  type AuthorizationBindingProvider,
  type BindingRequestContext,
} from "./authorization.js";
import { ContinuationHandles, CorrelationStore, type PendingRequest } from "./correlation.js";
import { McpReError, McpReSdkError, type Signer, type SignerPolicy } from "./custody.js";

/**
 * JSON-RPC application error code for a delivered MCP-RE failure. The precise cause is
 * always the frozen `mcp-re.*` token in `.message`.
 *
 * This envelope is synthesized locally by the transport, never received from the peer, so
 * MCP 2026-07-28 requires that it cannot be mistaken for a peer error: it sits outside
 * JSON-RPC's reserved band, and it differs from the proxy's own rejection code (-31000) so
 * a caller can tell "my transport refused this" from "the peer rejected this".
 */
const MCP_RE_ERROR_CODE = -31001;

/**
 * Widest delegation clock skew a caller may configure, in seconds.
 *
 * Mirrors the RFC 9421 verifier's own ceiling (`VerifierPolicy::MAX_CLOCK_SKEW_BOUND`)
 * so one deployment does not run two different notions of "close enough" — beyond this
 * the credential's nbf/exp window stops bounding anything.
 */
const MAX_CLOCK_SKEW_BOUND = 300;

/**
 * The client tried to send a client->server RESPONSE, which has no MCP-RE carrier.
 *
 * A server-initiated request (sampling, elicitation over the same session) would be
 * answered by a JSON-RPC response travelling client->server. MCP-RE profiles two client
 * message shapes — a request that earns a signed reply, and a notification that earns a
 * signed bodyless 202 — and a response is neither.
 *
 * Failing closed here is the narrow choice on purpose. The alternative the notification
 * path makes available is worse: a response has no `method`, so carrying it as a
 * notification would mean signing a fabricated message and reporting the acknowledgement
 * of THAT as if the response had been delivered.
 */
export class ClientResponseUnsupported extends McpReSdkError {
  constructor(detail: string) {
    super(detail);
    this.name = "ClientResponseUnsupported";
  }
}

/**
 * A notification was transmitted and its acknowledgement did not verify.
 *
 * The message left this process. What could not be established is that the enforcement
 * boundary authenticated and accepted it: the 202 was absent, unsigned, signed by an
 * untrusted key, or bound to a different transmission.
 *
 * It is thrown from `send()`, so the caller that emitted the notification is the one
 * that learns it was not acknowledged — there is no reply for a JSON-RPC error to ride
 * back on, and treating an unverifiable acknowledgement as delivery is the
 * take-it-on-faith posture this protocol exists to remove. `wireCode` carries the frozen
 * reason when the failure has one.
 */
export class NotificationNotAcknowledged extends McpReSdkError {
  readonly method: string;
  readonly wireCode: string;

  constructor(method: string, wireCode: string) {
    super(
      `'${method}' was sent but its acknowledgement did not verify (${wireCode}); ` +
        `it must not be treated as delivered`,
    );
    this.name = "NotificationNotAcknowledged";
    this.method = method;
    this.wireCode = wireCode;
  }
}

/**
 * The transport's lifecycle state (#421).
 *
 * Explicit because the alternative is a boolean that cannot express "closing": work must
 * be refused the instant close begins, not once it finishes.
 */
export enum TransportState {
  New = "NEW",
  Open = "OPEN",
  Closing = "CLOSING",
  Closed = "CLOSED",
}

/**
 * The transport is not open for work: it has not started, or it is closing/closed.
 *
 * Also what queued and in-flight local requests fail with when `close()` aborts them.
 *
 * **This says nothing about the server.** Cancelling a local `poster` call does not mean
 * the request never arrived or that already-dispatched remote work has stopped — only
 * that this client will not process an answer to it.
 */
export class ConnectionClosed extends McpReSdkError {
  constructor(detail: string) {
    super(detail);
    this.name = "ConnectionClosed";
  }
}

/**
 * A verified elicitation could not be answered, so the call did not complete.
 *
 * An ADR-MCPS-047 `InputRequiredResult` is a PAUSE, not an outcome. When no answer leg can
 * be driven — no {@link McpReConfig.answerInputRequired}, a handler that declined, or a
 * server that elicited past {@link McpReConfig.maxContinuationRounds} — the exchange ends
 * here.
 *
 * It ends as an ERROR, never as a result. Handing the pause up as the reply to
 * `callTool` would present a call that is still waiting for input as one that finished,
 * which is the misrepresentation the continuation profile's protected non-terminal
 * classification exists to make detectable (§5.2, §9.3).
 */
export class ContinuationNotAnswered extends McpReSdkError {
  constructor(detail: string) {
    super(detail);
    this.name = "ContinuationNotAnswered";
  }
}

/**
 * A verified reply body is not a JSON-RPC RESPONSE, so it is not an answer at all.
 *
 * A signature proves the server said these bytes. It does not prove the bytes are a reply
 * to anything, and `JSONRPCMessageSchema` is a UNION: a body carrying both a legal
 * `result` and a top-level `method` validates as a `JSONRPCRequest`, and `Protocol`
 * dispatches it as a server-initiated request — `sampling/createMessage`,
 * `elicitation/create`, `roots/list` — running the application's handlers on
 * peer-chosen params over a channel MCP-RE profiles no carrier for, and one `send()`
 * explicitly refuses in the other direction. The awaiting `callTool` never resolves
 * either, because its id was consumed as an inbound request id.
 *
 * The Rust ambassador refuses the same body and so does the Python twin; this is the
 * behaviour the byte-parity fixtures cannot see.
 */
export class VerifiedReplyNotAResponse extends McpReSdkError {
  constructor(detail: string) {
    super(detail);
    this.name = "VerifiedReplyNotAResponse";
  }
}

/**
 * The structured facts a verified rejection receipt carried, for `error.data`.
 *
 * `requestBound` is the core's verdict on whether the receipt is tied to THIS
 * transmission (RSP-7). The rest is the ADR-MCPRE-058 §10 execution / retry contract the
 * server derived from its exchange machine and signed into the body: without it a
 * post-dispatch refusal is indistinguishable from an ordinary outage, and the caller's
 * retry re-executes a tool call that already ran.
 *
 * Only members the receipt actually carried are emitted. An absent `executionStatus`
 * means the server stated nothing, and inventing `not_executed` for it would collapse
 * "unknown whether it ran" into "it did not run" at the one place that decides. The
 * Python twin emits the same keys — this is behaviour, so byte fixtures do not cover it.
 */
function rejectionData(verified: {
  bound: boolean;
  executionStatus?: string | null;
  retrySafety?: string | null;
  continuationStatus?: string | null;
  retentionStatus?: string | null;
}): Record<string, unknown> {
  const data: Record<string, unknown> = { requestBound: verified.bound };
  const members: [string, string | null | undefined][] = [
    ["executionStatus", verified.executionStatus],
    ["retrySafety", verified.retrySafety],
    ["continuationStatus", verified.continuationStatus],
    ["retentionStatus", verified.retentionStatus],
  ];
  for (const [key, value] of members) {
    if (value !== undefined && value !== null) data[key] = value;
  }
  return data;
}

/**
 * A verified ADR-MCPS-047 elicitation, and everything answering it needs.
 *
 * Everything here was read from the VERIFIED response — the signature, content digest and
 * request binding all checked out before this was built.
 */
export interface InputRequired {
  /** The two evidence handles + opaque state the answer leg signs over. */
  handles: ContinuationHandles;
  /** The MCP method being continued, unchanged across the chain. */
  method: string;
  /** The params of the leg that earned this elicitation. */
  params: Record<string, unknown>;
  /**
   * The verified `InputRequiredResult` — `requestState` plus whatever the server used to
   * describe what it wants (`elicitation` / `inputRequests`). Passed through
   * uninterpreted: what to ask, and how, is the application's decision.
   */
  result: Record<string, unknown>;
  /** Which continuation round this is, counting from 1. */
  round: number;
}

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

/**
 * Minimum characters in an anti-replay nonce. 128 bits base64url-encodes to 22, which
 * is what {@link defaultNonce} produces — so this floor never constrains the default
 * path. It constrains an OVERRIDE: `nonceFactory` is caller-supplied and was accepted
 * unchecked, so a factory returning a counter, a timestamp, or a truncated value
 * silently weakened replay protection for every request while every signature still
 * verified.
 */
const MIN_NONCE_CHARS = 22;

/**
 * Draw a nonce and refuse a sub-floor one, at SIGN time.
 *
 * Fails closed rather than signing: a request signed under a guessable nonce is
 * accepted by the verifier, which is precisely what the replay window cannot save you
 * from. Enforced only where a nonce is EMITTED, so the accepted wire language is
 * unchanged — no cross-implementation coordination, no fixture regeneration.
 */
/**
 * The frozen `mcp-re.*` token in a thrown core error's message, or `null`.
 *
 * The napi binding formats every core failure as `"mcp-re: mcp-re.<token>"`. What the
 * taxonomy pins — and what a caller branches on without parsing prose (REQ-14/POL-6) —
 * is the TOKEN, so the binding's prefix is stripped before the code is delivered. Both
 * spellings are accepted, since the prefix is a binding detail. The Python twin's
 * `_peer_wire_code` does the same, so one wire event has one spelling in both SDKs.
 *
 * `null` for anything that is not a token, so a local condition — a reset connection, a
 * TLS error, a timeout thrown by the caller's `poster` — is delivered under the
 * `mcp-re-sdk:` prefix instead of occupying the field that otherwise only ever holds
 * something the peer said.
 */
const peerWireCode = (message: string): string | null => {
  const token = message.startsWith("mcp-re: ") ? message.slice("mcp-re: ".length) : message;
  return /^mcp-re\.[a-z0-9_]+$/.test(token) ? token : null;
};

const checkedNonce = (factory: () => string): string => {
  const nonce = factory();
  if (typeof nonce !== "string" || nonce.length < MIN_NONCE_CHARS) {
    const got = typeof nonce === "string" ? `${nonce.length} characters` : typeof nonce;
    // `McpReSdkError`, matching the Python twin: a local misconfiguration is not a
    // protocol verdict, so it must not be an `McpReError` carrying an invented
    // `wireCode` — and it must not be an untyped `Error` either, or a caller cannot
    // catch it the same way in both SDKs.
    throw new McpReSdkError(
      `mcp-re-sdk: nonceFactory returned ${got}; a nonce must be at least ${MIN_NONCE_CHARS} (128 bits base64url)`,
    );
  }
  return nonce;
};

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
   * How many signed exchanges may be in flight at once. Defaults to 8.
   *
   * MCP is not lock-step — a client may have several requests outstanding, and each
   * MCP-RE exchange is an independent signed POST with its own nonce and its own
   * correlation entry, so nothing about the protocol requires serializing them.
   *
   * It is bounded rather than unlimited because each in-flight exchange holds a
   * connection in the caller's `poster` and a signing operation (a KMS round trip under
   * non-exporting custody); an unbounded fan-out would let a burst of calls exhaust
   * either. Raise it for a client that genuinely wants more parallelism.
   */
  maxConcurrentExchanges?: number;

  /**
   * Called with `(method, serverKeyid)` for each client->server notification whose signed
   * 202 verified. Observability only — the acceptance claim has already been checked by
   * the time this runs, and declining to observe it changes nothing.
   *
   * What a verified acknowledgement means is exactly: the enforcement boundary
   * authenticated and accepted the message. NOT that the action completed — a verified
   * ack for `notifications/cancelled` does not mean anything was cancelled.
   */
  onNotificationAcknowledged?: (method: string, serverKeyid: string) => void;

  /**
   * Called when a verified response is an ADR-MCPS-047 `InputRequiredResult`, with the
   * handles its answer leg must sign over. Observability only: it fires once per
   * continuation round and decides nothing. Answering is
   * {@link answerInputRequired}'s job.
   */
  onInputRequired?: (handles: ContinuationHandles) => void;

  /**
   * Answers an elicitation, so the adapter can drive the ADR-MCPS-047 answer leg itself.
   * Resolve with the `inputResponses` to continue with, or `null`/`undefined` to decline.
   *
   * With a handler installed, a multi-round-trip tool is an ordinary `callTool` from the
   * application's side: the adapter signs the answer leg over the verified handles, posts
   * it, verifies the reply, and repeats until a terminal result — which is what the
   * caller's await resolves to. Without one, an elicitation cannot be continued and the
   * exchange fails closed with {@link ContinuationNotAnswered}, because a pause delivered
   * as a result would read as a finished call.
   */
  answerInputRequired?: (
    prompt: InputRequired,
  ) => Promise<Record<string, unknown> | null | undefined> | Record<string, unknown> | null | undefined;

  /**
   * How many times one call may be elicited before the adapter gives up. Defaults to 4.
   *
   * A continuation chain is driven by whatever the server asks for, so it is the server
   * that decides how long it runs. Without a ceiling a hostile or looping peer could keep
   * one `callTool` in an elicitation cycle indefinitely, re-prompting a user each round.
   * Four is well past any interactive tool's genuine need; raise it for a workflow that
   * really does have more steps.
   */
  maxContinuationRounds?: number;
}

/**
 * The verified reply as plain MCP: evidence block removed, id the client's own.
 *
 * Read only AFTER verification: the content-digest covered these bytes.
 *
 * MCP-RE's own evidence is not part of the MCP result, and the rebuild below drops it
 * with every other top-level member the server sent. The id is restored because an ADR-MCPS-047 answer leg is an independent request with its own id
 * (SEP-2322 §retry), while the client issued exactly one call and is awaiting the id it
 * chose. Relabelling is the adapter's job at that seam — every hop was verified here, so
 * the terminal result it hands up is a complete record (§9.3), not a spliced one.
 *
 * The envelope is REBUILT from the one member the server sent, not edited in place.
 * Editing left every other top-level key in the document, and `JSONRPCMessageSchema` is a
 * union that accepts a request — so a body carrying both a legal `result` and a `method`
 * validated as a `JSONRPCRequest` and was dispatched by `Client` as a SERVER-INITIATED
 * request. See {@link VerifiedReplyNotAResponse}.
 */
function plainMcpReply(body: Buffer, requestId: RequestId): unknown {
  const response = plainResponseObject(JSON.parse(body.toString("utf8")));
  response.id = requestId;
  return response;
}

/**
 * The verified reply as a JSON-RPC RESPONSE, or throw.
 *
 * The one shape `Client` is awaiting is a response object carrying exactly one of
 * `result` / `error`. Every other shape is refused here rather than handed to the union
 * schema, which would pick whichever arm matched. Mirrors the Rust ambassador's
 * `plain_response_from_verified` and the Python twin's `_plain_response_object`.
 */
function plainResponseObject(doc: unknown): Record<string, unknown> {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw new VerifiedReplyNotAResponse(
      `a verified reply must be a JSON-RPC response object, got ${Array.isArray(doc) ? "array" : typeof doc}`,
    );
  }
  const object = doc as Record<string, unknown>;
  if ("method" in object) {
    // A JSON-RPC response has no `method`. Its presence is what makes the union schema
    // pick the REQUEST arm, so this is not a stray field — it is the whole confusion.
    // Refused rather than dropped: rebuilding would silently accept a reply the peer
    // deliberately shaped as something else.
    throw new VerifiedReplyNotAResponse(
      "a verified reply carries a top-level `method`; a JSON-RPC response has none",
    );
  }
  const hasResult = "result" in object;
  const hasError = "error" in object;
  if (hasResult && hasError) {
    throw new VerifiedReplyNotAResponse("a verified reply carries both a result and an error");
  }
  if (!hasResult && !hasError) {
    throw new VerifiedReplyNotAResponse("a verified reply carries neither a result nor an error");
  }
  const member = hasResult ? "result" : "error";
  return { jsonrpc: "2.0", id: object.id, [member]: object[member] };
}

/** The `result` object of a verified reply, for an answer-leg handler to read. */
function verifiedResult(body: Buffer): Record<string, unknown> {
  const result = JSON.parse(body.toString("utf8"))?.result;
  return result && typeof result === "object" && !Array.isArray(result) ? result : {};
}

/**
 * The JSON-RPC id for an answer leg.
 *
 * SEP-2322 makes the retry an INDEPENDENT request with a new id, so the chain must not
 * re-use the one the client issued. Derived from it rather than drawn at random, so a
 * capture or log shows which call the leg belongs to.
 */
const answerLegId = (requestId: RequestId, round: number): string => `${requestId}/mrt-${round}`;

/**
 * `sha-256:<b64url>` over the exact authorization-binding bytes that were signed.
 *
 * ADR-MCPS-044 enumerates this among the fields a conforming client keeps per outstanding
 * request. It is retained for audit only and never re-interpreted (bind-not-interpret): it
 * records WHICH authorization artefacts this request was bound to, so an audit trail can
 * be reconciled against the signed bytes without the transport ever parsing them. `null`
 * when the request carried no bindings.
 */
function authzBindingDigest(bindingsJson: string | null): string | null {
  if (bindingsJson === null) return null;
  return `sha-256:${createHash("sha256").update(bindingsJson, "utf8").digest("base64url")}`;
}

/**
 * A JSON-RPC error correlated to the request, so the awaiting call rejects.
 *
 * `data` carries structured facts about the verdict that are not part of the frozen
 * token — the token itself stays exactly what the peer said.
 */
const errorMessage = (id: RequestId, wireCode: string, data?: unknown): JSONRPCMessage => ({
  jsonrpc: "2.0",
  id,
  error: {
    code: MCP_RE_ERROR_CODE,
    message: wireCode,
    ...(data === undefined ? {} : { data }),
  },
});

/**
 * Bounds how many exchanges run at once.
 *
 * `send()` is called once per outgoing request and each call awaits its own reply, so
 * without a bound a burst of concurrent requests would fan out into unbounded in-flight
 * POSTs and signing operations.
 */
class Semaphore {
  #free: number;
  readonly #waiting: (() => void)[] = [];

  constructor(slots: number) {
    this.#free = slots;
  }

  async acquire(): Promise<void> {
    if (this.#free > 0) {
      this.#free -= 1;
      return;
    }
    await new Promise<void>((resolve) => this.#waiting.push(resolve));
  }

  release(): void {
    // Hand the slot straight to the next waiter rather than returning it to the pool —
    // incrementing here would let a later arrival overtake the queue.
    const next = this.#waiting.shift();
    if (next) next();
    else this.#free += 1;
  }
}

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
  readonly #slots: Semaphore;
  #state: TransportState = TransportState.New;
  /** Aborts in-flight exchanges when close() begins. */
  #abort = new AbortController();

  constructor(config: McpReConfig, poster: Poster) {
    // Validated where the value first enters SDK-owned code — `McpReConfig` is a plain
    // interface, so this constructor is the earliest point this SDK controls. A bound of
    // 0 is not a degenerate case that merely throttles: every sender waits for a slot
    // that can never be released, so the session deadlocks in silence.
    const bound = config.maxConcurrentExchanges ?? 8;
    if (!Number.isInteger(bound) || bound < 1) {
      throw new McpReSdkError(
        `maxConcurrentExchanges must be a positive integer, got ${JSON.stringify(
          config.maxConcurrentExchanges,
        )}`,
      );
    }
    // Zero rounds is a meaningful setting — it refuses continuation outright — so only a
    // negative or non-integer bound is rejected here.
    const rounds = config.maxContinuationRounds ?? 4;
    if (!Number.isInteger(rounds) || rounds < 0) {
      throw new McpReSdkError(
        `maxContinuationRounds must be a non-negative integer, got ${JSON.stringify(
          config.maxContinuationRounds,
        )}`,
      );
    }
    // The delegation credential's nbf/exp window is only as strong as the skew allowed
    // around it: `now + skew < nbf` and `now - skew > exp` are how it is applied, so a
    // large value accepts a credential arbitrarily far outside its validity window and
    // a negative one distorts the comparison rather than tightening it. Nothing
    // downstream bounds it — DelegationPolicy stores it verbatim — so it is checked
    // here, against the same ceiling the RFC 9421 verifier uses for its own skew.
    const skew = config.maxClockSkew ?? 60;
    if (!Number.isInteger(skew) || skew < 0 || skew > MAX_CLOCK_SKEW_BOUND) {
      throw new McpReSdkError(
        `maxClockSkew must be an integer in 0..=${MAX_CLOCK_SKEW_BOUND} seconds, got ${JSON.stringify(
          config.maxClockSkew,
        )}`,
      );
    }
    // The delegated-verification anchor. TypeScript's type system makes these fields
    // required but cannot make them non-empty, and an empty value cannot match anything
    // it is compared against: empty `acceptedEpochs` fails every response as a stale
    // trust epoch, empty `verifierAudiences` as an audience mismatch, an empty issuer key
    // as an invalid key. The client is therefore not *unsafe* with them blank — it is
    // unusable — but it does not discover that until the first response comes back
    // looking like a server fault.
    const missing = (
      [
        ["issuerKeyId", config.issuerKeyId],
        ["issuerPubkeyB64Url", config.issuerPubkeyB64Url],
        ["issuerTrustDomain", config.issuerTrustDomain],
        ["issuerSubject", config.issuerSubject],
        ["expectedAudienceHash", config.expectedAudienceHash],
        ["verifierAudiences", config.verifierAudiences?.length ? "set" : ""],
        ["acceptedEpochs", config.acceptedEpochs?.length ? "set" : ""],
      ] as const
    )
      .filter(([, value]) => !value)
      .map(([name]) => name);
    if (missing.length > 0) {
      throw new McpReSdkError(
        `the delegated-verification trust anchor is incomplete: ${missing
          .slice()
          .sort()
          .join(", ")} must be set. Every response is verified against these, so an ` +
          `empty value rejects every response the server sends rather than relaxing the check.`,
      );
    }
    // The revocation denylist, checked for SHAPE because this is the one config field
    // whose wrong value fails OPEN. `readonly string[]` is erased at runtime, and
    // `[..."kid-1"]` spreads a bare string into one entry per character: the denylist is
    // non-empty, reports as configured, and matches no delegated kid, issuer kid or
    // credential `jti` that can exist. The operator believes a compromised key is
    // revoked while the client accepts it for its whole TTL and epoch window. The
    // sibling anchor fields degrade the same way but fail CLOSED, which is why this one
    // is checked for shape and not merely for emptiness.
    const revoked: unknown = config.revokedIdentifiers;
    if (revoked !== undefined && revoked !== null) {
      if (!Array.isArray(revoked)) {
        throw new McpReSdkError(
          `revokedIdentifiers must be an array of identifier strings, not ${
            typeof revoked === "string" ? "a bare string" : typeof revoked
          }: a string spreads one character per entry, matching no identifier and ` +
            `disabling revocation while reporting a denylist as configured`,
        );
      }
      for (const id of revoked) {
        if (typeof id !== "string" || id.length === 0) {
          throw new McpReSdkError(
            `revokedIdentifiers entries must be non-empty strings, got ${JSON.stringify(id)}; ` +
              `an entry that cannot match an identifier silently revokes nothing`,
          );
        }
      }
    }
    this.#config = config;
    this.#poster = poster;
    this.#slots = new Semaphore(bound);
  }

  get #clock(): () => number {
    return this.#config.clock ?? defaultClock;
  }

  /** The lifecycle state (#421). */
  get state(): TransportState {
    return this.#state;
  }

  /** Outstanding correlation entries. Observable so "close clears it" is testable. */
  get pendingCorrelations(): number {
    return this.#correlation.size;
  }

  /**
   * The outstanding requests, in issue order — the ADR-MCPS-044 in-flight correlation
   * state this transport holds, including each request's authorization-binding digest.
   *
   * Read-only: the entries are what the store already recorded, and consuming one is the
   * response path's business.
   */
  pendingRequests(): PendingRequest[] {
    return this.#correlation.pending();
  }

  async start(): Promise<void> {
    if (this.#state !== TransportState.New) {
      // The MCP SDK's own transports treat a double start as a defect; a second start
      // would sign under a policy that was already accepted, hiding the first one.
      throw new McpReSdkError(
        `McpReHttpTransport cannot start from state ${this.#state}; a transport is ` +
          `single-use and start() is not a reset`,
      );
    }
    this.#config.policy?.check(this.#config.signer);
    this.#config.authorizationPolicy?.check(this.#config.authorization ?? []);
    this.#state = TransportState.Open;
  }

  async send(message: JSONRPCMessage): Promise<void> {
    // Refused the instant close begins, not once it finishes: a signed request must never
    // leave a transport the caller has already torn down (#421).
    if (this.#state !== TransportState.Open) {
      throw new ConnectionClosed(
        `McpReHttpTransport is ${this.#state}, not OPEN; it accepts no work`,
      );
    }
    if (!("method" in message)) {
      // A client->server RESPONSE or error. It has no `method`, so the notification path
      // below could only carry it by signing a fabricated message; refuse it instead of
      // inventing one.
      throw new ClientResponseUnsupported(
        "a client->server response has no MCP-RE carrier; the profile covers a signed " +
          "request and a signed notification, and a response is neither",
      );
    }
    if (!("id" in message)) {
      // A one-way notification: its own signed POST, answered by a signed bodyless 202
      // rather than a JSON-RPC reply. It runs under the same concurrency bound as an
      // exchange because it costs the same resources — a connection and a signing
      // operation. A failure throws from here rather than becoming a delivered message:
      // there is no request id to correlate one to, and this caller is the only party
      // that can learn the message was not acknowledged.
      const params = "params" in message ? message.params : undefined;
      await this.#slots.acquire();
      let releaseAbortListener: () => void = () => {};
      try {
        // Re-checked AFTER the queue wait, and raced against close(), for the same
        // reason a request is (#421): a notification that waited for a slot must not
        // reach the server after the caller tore the transport down, and an aborted one
        // must fail rather than wait out a poster nobody is listening for.
        if (this.#abort.signal.aborted) throw this.#abort.signal.reason;
        const aborted = this.#aborted();
        releaseAbortListener = aborted.release;
        await Promise.race([this.#notify(message.method, params), aborted.promise]);
      } finally {
        this.#slots.release();
        releaseAbortListener();
      }
      return;
    }

    const request = message;
    let reply: JSONRPCMessage;
    await this.#slots.acquire();
    // Registered per request and removed in the finally below. An AbortSignal outlives
    // every request raced against it, so a listener left behind is retained — with its
    // captured promise — until the transport itself is collected; a long session would
    // accumulate one per request it ever sent.
    let releaseAbortListener: () => void = () => {};
    try {
      // Re-check AFTER the queue wait. The state check above happened before this
      // request waited for a slot, and close() can land during that wait. Without this
      // the exchange below would still sign and POST — `Promise.race` starts both
      // arms, so racing `#aborted()` only decides which result the caller sees, not
      // whether the request reaches the server. A queued request is not
      // already-dispatched work, so emitting it after close() would hand the server
      // a valid, fresh, correctly-signed request the caller believes it cancelled.
      if (this.#abort.signal.aborted) throw this.#abort.signal.reason;
      // Race the exchange against close(): an aborted exchange fails its request with
      // ConnectionClosed rather than waiting out a poster the caller no longer wants.
      const aborted = this.#aborted();
      releaseAbortListener = aborted.release;
      reply = await Promise.race([this.#exchange(request), aborted.promise]);
    } catch (e) {
      if (e instanceof ConnectionClosed) {
        // Not a wire outcome: the local transport went away. The upstream Client already
        // rejects its pending requests from onclose, so this must not be laundered into a
        // JSON-RPC error that claims the peer said something. The finally below releases
        // the slot — releasing here too would inflate the pool.
        throw e;
      }
      if (e instanceof McpReError) {
        reply = errorMessage(request.id, e.wireCode);
      } else if (e instanceof McpReSdkError) {
        // A local failure (e.g. the signing device). No wire code describes it.
        reply = errorMessage(request.id, `mcp-re-sdk: ${e.message}`);
      } else if (e instanceof Error) {
        // Two unrelated things arrive here as plain Errors: the core's own fail-closed
        // errors, which carry a frozen `mcp-re.*` token, and whatever the caller's
        // `poster` throws while doing real I/O — a reset connection, a TLS error, a
        // timeout. Delivering both verbatim would put "socket hang up" in the same field
        // that otherwise only ever holds something the peer said, so only a message that
        // IS a frozen token is passed through as one. Everything else is delivered under
        // the prefix that means "local condition", named, exactly as Python does it.
        reply = errorMessage(request.id, peerWireCode(e.message) ?? `mcp-re-sdk: ${e.name}: ${e.message}`);
      } else {
        throw e;
      }
    } finally {
      // In a finally because the non-Error branch above re-throws: leaking a slot there
      // would shrink the pool permanently, and enough of them would deadlock the session.
      this.#slots.release();
      releaseAbortListener();
    }
    // No message callback after the close callback: delivering to an application that
    // believes it has disconnected is worse than dropping (#421).
    if (this.#state === TransportState.Open) this.onmessage?.(reply);
  }

  /**
   * A promise that rejects with ConnectionClosed as soon as close() begins, paired with
   * the `release` that unregisters it.
   *
   * The caller MUST call `release` once the race it feeds has settled. `{ once: true }`
   * only removes the listener when it actually fires, which is the rare case: the common
   * one is an exchange that completes normally, leaving the listener registered on a
   * signal that lives as long as the transport.
   */
  #aborted(): { promise: Promise<never>; release: () => void } {
    const signal = this.#abort.signal;
    let release = () => {};
    const promise = new Promise<never>((_resolve, reject) => {
      if (signal.aborted) return reject(signal.reason);
      const onAbort = () => reject(signal.reason);
      signal.addEventListener("abort", onAbort, { once: true });
      release = () => signal.removeEventListener("abort", onAbort);
    });
    // An already-aborted signal rejects synchronously above and registers nothing, so the
    // no-op release is correct there. Attach a catch so a promise that loses the race
    // cannot surface as an unhandled rejection when it is abandoned.
    promise.catch(() => {});
    return { promise, release: () => release() };
  }

  /**
   * Close the transport: abortive, idempotent (#421).
   *
   * New work is refused immediately, in-flight exchanges are aborted and fail with
   * {@link ConnectionClosed}, and abandoned correlation state is cleared. `onmessage`
   * never fires after `onclose` — a message delivered to an application that believes it
   * has disconnected is worse than a dropped one.
   *
   * **Abortive, matching the upstream client's rejection of pending requests.** It makes
   * no claim that already-dispatched remote work has stopped: the server may have
   * received the request and acted on it. Only that this client will not process an
   * answer.
   */
  async close(): Promise<void> {
    if (this.#state === TransportState.Closing || this.#state === TransportState.Closed) {
      return; // idempotent
    }
    this.#state = TransportState.Closing;
    this.#abort.abort(new ConnectionClosed("the transport was closed"));
    // Abandoned correlation entries would otherwise outlive the transport that owns them.
    this.#correlation.expireBefore(Number.MAX_SAFE_INTEGER);
    this.#state = TransportState.Closed;
    this.onclose?.();
  }

  /**
   * Sign one notification, POST it, and verify the acknowledgement it earns.
   *
   * A notification is signed by the ordinary request rules — same evidence block, same
   * covered components, same freshness triple. What it gets back is a signed bodyless
   * 202 whose `;req` components plus `mcp-re-request-evidence` bind it to THIS
   * transmission (owner ruling C019b), so a 202 captured from an earlier send of the
   * same notification does not verify here.
   *
   * There is deliberately no "sent it anyway" path: an unverified acknowledgement
   * establishes nothing, and treating it as delivery is what the profile removes.
   */
  async #notify(method: string, params: unknown): Promise<void> {
    const config = this.#config;
    const now = this.#clock;
    const created = now();
    const expires = created + (config.requestTtl ?? 300);
    const bindingsJson = this.#bindingsJson(method);

    const signed = config.signer.signNotification({
      method,
      paramsJson: JSON.stringify(params ?? {}),
      targetUri: config.targetUri,
      audienceId: config.audienceId,
      route: config.route ?? null,
      dpopToken: config.dpopToken,
      nonce: checkedNonce(config.nonceFactory ?? defaultNonce),
      created,
      expires,
      bindingsJson,
    });

    const httpReply = await this.#poster(
      signed.method,
      signed.targetUri,
      signed.headers,
      signed.body,
    );

    let accepted;
    try {
      accepted = verifyAccepted202(
        httpReply.status,
        httpReply.headers,
        httpReply.body,
        signed.method,
        signed.targetUri,
        signed.headers,
        signed.body,
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
    } catch (e) {
      // The same normalization the request path applies: `wireCode` is documented as the
      // frozen token, and the napi binding spells a core failure `"mcp-re: mcp-re.<x>"`,
      // so the prefix is stripped. Anything that is not a token is a local condition and
      // says so, rather than travelling as an invented wire code.
      throw new NotificationNotAcknowledged(
        method,
        e instanceof McpReError
          ? e.wireCode
          : e instanceof Error
            ? (peerWireCode(e.message) ?? `mcp-re-sdk: ${e.name}: ${e.message}`)
            : String(e),
      );
    }

    config.onNotificationAcknowledged?.(method, accepted.serverKeyid);
  }

  /**
   * Run one logical call to a terminal result: sign, POST, verify, correlate.
   *
   * An ADR-MCPS-047 elicitation does not end the call — it pauses it. So this drives the
   * whole chain: every leg is signed, posted and verified here, and an answer leg binds
   * to the verified handles of the leg before it. What returns is the TERMINAL result the
   * client asked for, or a JSON-RPC error carrying the frozen wire code from whichever
   * hop failed.
   *
   * Because every hop verified, handing up the terminal result is honest under §9.3 of
   * the continuation profile: a chain with an unverifiable middle hop never gets here.
   */
  async #exchange(
    request: JSONRPCMessage & { method: string; id: RequestId },
  ): Promise<JSONRPCMessage> {
    const config = this.#config;
    const now = this.#clock;
    const method = request.method;
    let params: Record<string, unknown> =
      "params" in request && request.params !== undefined
        ? (request.params as Record<string, unknown>)
        : {};
    let legId: RequestId = request.id;
    let cont: ContinuationHandles | null = null;
    let round = 0;
    // Correlation entries this call still holds. An open leg stays outstanding while its
    // answer leg runs — ADR-MCPS-047 associates without consuming — so there can be more
    // than one, and every entry left here when the call ends is retired below.
    const outstanding = new Set<string>();

    try {
      for (;;) {
        // Checked every leg, not only before the first. `Promise.race` in `send()`
        // decides which result the CALLER sees; it does not stop the losing arm, so
        // without this an ADR-MCPS-047 continuation chain would go on signing and POSTing
        // fresh answer legs, re-populating the correlation store, and re-prompting a
        // human through `answerInputRequired`, after `close()` has aborted and `onclose`
        // has fired. A queued or continuing leg is not already-dispatched work: emitting it
        // after close() hands the server a valid, fresh, correctly-signed request the
        // caller believes it cancelled. The Python twin's task group really cancels.
        if (this.#abort.signal.aborted) throw this.#abort.signal.reason;
        const created = now();
        const expires = created + (config.requestTtl ?? 300);
        const bindingsJson = this.#bindingsJson(method);

        const signed = config.signer.signRequest({
          idJson: JSON.stringify(legId),
          method,
          paramsJson: JSON.stringify(params),
          targetUri: config.targetUri,
          audienceId: config.audienceId,
          route: config.route ?? null,
          dpopToken: config.dpopToken,
          nonce: checkedNonce(config.nonceFactory ?? defaultNonce),
          created,
          expires,
          bindingsJson,
          ...(cont ? cont.asSignArgs() : {}),
        });

        const correlationId = this.#correlation.record(signed, {
          requestId: String(legId),
          // The nonce rode into the signature; the handle is the evidence digest.
          nonce: "",
          audienceId: config.audienceId,
          expectedSignerId: config.issuerKeyId,
          created,
          expires,
          route: config.route ?? null,
          authzBindingDigest: authzBindingDigest(bindingsJson),
        });
        outstanding.add(correlationId);

        const httpReply = await this.#poster(
          signed.method,
          signed.targetUri,
          signed.headers,
          signed.body,
        );

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

        // A verified rejection receipt is genuine evidence, but it is NOT an acceptance:
        // it must reach the app as an error, never as a result.
        //
        // `bound` is the core's verdict on whether the receipt is tied to THIS
        // transmission. A preflight-unbound receipt carries no binding to this request's
        // nonce or evidence, so one such signed receipt answers any request from any
        // client of that issuer for the credential's whole validity window. It is still
        // an error and never a result, but the application must be able to tell "the
        // boundary rejected MY request" from "a generic rejection arrived" (RSP-7), so
        // the binding fact travels in `data` — beside the frozen token rather than
        // inside it, because the token is what the peer said.
        if (verified.outcome !== "success") {
          this.#correlation.take(correlationId, now());
          outstanding.delete(correlationId);
          // An EMPTY wire code is substituted too, not just a missing one. A rejection
          // receipt whose `error.data` carries no usable token yields `Some("")` from the
          // core reader, and `??` would let that through as a JSON-RPC error with an empty
          // message — an error the application cannot act on or log meaningfully. Python's
          // truthiness check already substituted here; this is the side that diverged.
          return errorMessage(
            request.id,
            verified.wireCode ? verified.wireCode : "mcp-re.response_sig_invalid",
            rejectionData(verified),
          );
        }

        if (verified.requestState === undefined || verified.requestState === null) {
          this.#correlation.take(correlationId, now());
          outstanding.delete(correlationId);
          // The shape check runs BEFORE the union schema, which accepts a request arm:
          // a verified body carrying a `method` would otherwise be dispatched by
          // `Client` as a server-initiated request. `plainMcpReply` rebuilds the
          // envelope, so nothing beyond `result` / `error` can reach the parser.
          let plain: unknown;
          try {
            plain = plainMcpReply(httpReply.body, request.id);
          } catch (e) {
            if (!(e instanceof VerifiedReplyNotAResponse)) throw e;
            return errorMessage(request.id, "mcp-re.malformed_envelope", {
              detail: e.message,
            });
          }
          return JSONRPCMessageSchema.parse(plain);
        }

        // A pause. Associate without consuming — the open leg is answered by its answer
        // leg, not by this response — and hand up the handles it signs over.
        const handles = this.#correlation.recordInputRequired(correlationId, {
          responseDigestAlg: verified.respEvidenceDigestAlg,
          responseDigestValue: verified.respEvidenceDigestValue,
          requestState: verified.requestState,
          now: now(),
        });
        config.onInputRequired?.(handles);

        round += 1;
        // Checked BEFORE the handler runs: a call that has already used up its
        // continuation budget must not prompt for an answer it cannot send.
        if (round > (config.maxContinuationRounds ?? 4)) {
          throw new ContinuationNotAnswered(
            `'${method}' elicited ${round} times, past the maxContinuationRounds ceiling ` +
              `of ${config.maxContinuationRounds ?? 4}`,
          );
        }
        if (!config.answerInputRequired) {
          throw new ContinuationNotAnswered(
            `'${method}' returned an ADR-MCPS-047 elicitation and no answerInputRequired ` +
              `handler is installed, so no answer leg can be signed`,
          );
        }

        // Re-checked immediately before the handler runs: `answerInputRequired` is where
        // a human is prompted, and a transport the caller has already closed must not
        // raise a prompt for an answer leg it will never send.
        if (this.#abort.signal.aborted) throw this.#abort.signal.reason;

        const responses = await config.answerInputRequired({
          handles,
          method,
          params,
          result: verifiedResult(httpReply.body),
          round,
        });
        if (responses === null || responses === undefined) {
          throw new ContinuationNotAnswered(
            `the elicitation from '${method}' was declined by answerInputRequired`,
          );
        }
        if (typeof responses !== "object" || Array.isArray(responses)) {
          throw new ContinuationNotAnswered(
            `answerInputRequired returned ${Array.isArray(responses) ? "an array" : typeof responses}; ` +
              `the MRTR answer leg carries \`inputResponses\` as a JSON object`,
          );
        }

        // The next leg: the same call, carrying the answers and echoing the opaque state
        // back, bound to the handles of the exchange that asked for them.
        params = { ...params, inputResponses: responses, requestState: handles.requestState };
        legId = answerLegId(request.id, round);
        cont = handles;
      }
    } finally {
      // Whatever is still outstanding can never be bound now: a failed leg gets no
      // answer, and an open leg's answer leg has either terminated the call or failed
      // with it. Everything that lands here is remotely triggerable — a reset connection,
      // an unverifiable reply, an elicitation nobody answers — so leaving entries
      // outstanding would let a peer grow the store one call at a time, for the life of
      // the session. Retiring them is not a security decision: a response arriving for
      // one afterwards is refused either way.
      for (const id of outstanding) this.#correlation.abandon(id);
    }
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

/**
 * Internals exposed for this package's own tests only. Not part of the public API and
 * not re-exported from the package entry point; the security check itself runs on the
 * ordinary signing path, not through this seam.
 */
export const __testing = { checkedNonce, defaultNonce, MIN_NONCE_CHARS };
