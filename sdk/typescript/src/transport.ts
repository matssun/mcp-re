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
 * **One-way notifications are carried, not dropped.** A notification is its own signed
 * POST, and the acknowledgement it earns — a signed bodyless 202 bound to that exact
 * transmission — is verified before the adapter treats it as delivered. See
 * {@link NotificationNotAcknowledged} for what happens when it is not.
 *
 * MCP-RE is HTTP-profile only: one signed POST per request. The POST itself is injected as
 * a `poster` so this layer stays transport-agnostic and testable, which also means
 * establishing and hardening the connection (mTLS, pooling, timeouts) is the caller's.
 * There is no mTLS construction helper in this SDK — see
 * {@link https://github.com/matssun/mcp-re/issues/413 | #413}. The Rust client leg ships
 * one (`mcp_re_transport::remote::MtlsRemoteTransport`).
 */
import { createHash, randomBytes } from "node:crypto";

import type { JSONRPCMessage, RequestId } from "@modelcontextprotocol/sdk/types.js";
import { JSONRPCMessageSchema } from "@modelcontextprotocol/sdk/types.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

import {
  verifyAccepted202,
  verifyResponse,
  type HttpHeader,
  type SignedRequestJs,
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
 * The response-side body evidence block. Stripped before the result reaches the app:
 * MCP-RE's own evidence is not part of the MCP result.
 */
const RESPONSE_BLOCK_KEY = "se.syncom/mcp-re.http.response";

/**
 * JSON-RPC application error code for a delivered MCP-RE failure. The precise cause is
 * always the frozen `mcp-re.*` token in `.message`.
 */
const MCP_RE_ERROR_CODE = -32001;

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
const checkedNonce = (factory: () => string): string => {
  const nonce = factory();
  if (typeof nonce !== "string" || nonce.length < MIN_NONCE_CHARS) {
    const got = typeof nonce === "string" ? `${nonce.length} characters` : typeof nonce;
    throw new Error(
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

/** A JSON-RPC error correlated to the request, so the awaiting call rejects. */
const errorMessage = (id: RequestId, wireCode: string): JSONRPCMessage => ({
  jsonrpc: "2.0",
  id,
  error: { code: MCP_RE_ERROR_CODE, message: wireCode },
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
        reply = errorMessage(
          request.id,
          /^mcp-re\.[a-z0-9_]+$/.test(e.message)
            ? e.message
            : `mcp-re-sdk: ${e.name}: ${e.message}`,
        );
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
      throw new NotificationNotAcknowledged(
        method,
        e instanceof McpReError ? e.wireCode : e instanceof Error ? e.message : String(e),
      );
    }

    config.onNotificationAcknowledged?.(method, accepted.serverKeyid);
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
    const bindingsJson = this.#bindingsJson(request.method);

    const signed = config.signer.signRequest({
      idJson: JSON.stringify(request.id),
      method: request.method,
      paramsJson: JSON.stringify(params),
      targetUri: config.targetUri,
      audienceId: config.audienceId,
      route: config.route ?? null,
      dpopToken: config.dpopToken,
      nonce: checkedNonce(config.nonceFactory ?? defaultNonce),
      created,
      expires,
      bindingsJson,
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
      authzBindingDigest: authzBindingDigest(bindingsJson),
    });

    try {
      return await this.#exchangeBound(request, signed, correlationId);
    } catch (e) {
      // This exchange produced no answer, so nothing will ever bind this entry.
      // Everything that lands here is remotely triggerable — a reset connection, a reply
      // that fails verification, a rejection whose own bookkeeping threw — so leaving the
      // entry outstanding would let a peer grow the store one failed request at a time,
      // for the life of the session. Retiring it is not a security decision: a response
      // that arrives for it afterwards is refused either way.
      this.#correlation.abandon(correlationId);
      throw e;
    }
  }

  /** The part of an exchange that runs with the correlation entry already recorded. */
  async #exchangeBound(
    request: JSONRPCMessage & { method: string; id: RequestId },
    signed: SignedRequestJs,
    correlationId: string,
  ): Promise<JSONRPCMessage> {
    const config = this.#config;
    const now = this.#clock;

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
      // An EMPTY wire code is substituted too, not just a missing one. A rejection
      // receipt whose `error.data` carries no usable token yields `Some("")` from the
      // core reader, and `??` would let that through as a JSON-RPC error with an empty
      // message — an error the application cannot act on or log meaningfully. Python's
      // truthiness check already substituted here; this is the side that diverged.
      return errorMessage(
        request.id,
        verified.wireCode ? verified.wireCode : "mcp-re.response_sig_invalid",
      );
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

/**
 * Internals exposed for this package's own tests only. Not part of the public API and
 * not re-exported from the package entry point; the security check itself runs on the
 * ordinary signing path, not through this seam.
 */
export const __testing = { checkedNonce, defaultNonce, MIN_NONCE_CHARS };
