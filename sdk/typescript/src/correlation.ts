// SPDX-License-Identifier: Apache-2.0
/**
 * In-flight request correlation (ADR-MCPS-044 §In-flight correlation state).
 *
 * Stateless means no discovery-session state — it does not mean no in-flight state. A
 * conforming client MUST track every outstanding request and bind each response back to
 * the exact request it answers, failing closed when it cannot.
 *
 * This store keeps, per outstanding request, the fields the ADR enumerates: correlation
 * id, request evidence handle, nonce / JSON-RPC id, issued-at, expiry, route, audience,
 * expected signer, and the authorization-binding digest for audit.
 *
 * The correlation id is the request's evidence digest value: it is unique per request and
 * is the very handle a signed response binds to, so correlation and cryptographic binding
 * cannot drift apart.
 *
 * Fail-closed, using the frozen `mcp-re.*` taxonomy — no code is invented here:
 *
 * | A response that...                | fails as                          |
 * | --------------------------------- | --------------------------------- |
 * | matches no outstanding request    | `mcp-re.request_binding_mismatch` |
 * | arrives after its request expired | `mcp-re.expired_request`          |
 * | answers an already-answered one   | `mcp-re.replay_detected`          |
 */
import { McpReError } from "./custody.js";
import type { SignedRequestJs } from "../native/binding.js";

/** One outstanding request, as ADR-MCPS-044 §In-flight correlation state requires. */
export interface PendingRequest {
  readonly correlationId: string;
  readonly requestId: string;
  readonly nonce: string;
  readonly evidenceDigestAlg: string;
  readonly evidenceDigestValue: string;
  readonly audienceId: string;
  readonly expectedSignerId: string;
  readonly created: number;
  readonly expires: number;
  readonly route?: string | null;
  /** Retained for audit only — never re-interpreted (bind-not-interpret). */
  readonly authzBindingDigest?: string | null;
}

/** What {@link CorrelationStore.record} needs beyond the signed request itself. */
export interface RecordArgs {
  requestId: string;
  nonce: string;
  audienceId: string;
  expectedSignerId: string;
  created: number;
  expires: number;
  route?: string | null;
  authzBindingDigest?: string | null;
}

/**
 * The two evidence handles + opaque state an ADR-MCPS-047 answer leg signs over.
 * Spread {@link ContinuationHandles.asSignArgs} into `signRequest`.
 */
export class ContinuationHandles {
  constructor(
    readonly prevAlg: string,
    readonly prevValue: string,
    readonly irrAlg: string,
    readonly irrValue: string,
    readonly requestState: string,
  ) {}

  /** The continuation arguments for `signRequest` / `Signer.signRequest`. */
  asSignArgs(): {
    contPrevAlg: string;
    contPrevValue: string;
    contIrrAlg: string;
    contIrrValue: string;
    contRequestState: string;
  } {
    return {
      contPrevAlg: this.prevAlg,
      contPrevValue: this.prevValue,
      contIrrAlg: this.irrAlg,
      contIrrValue: this.irrValue,
      contRequestState: this.requestState,
    };
  }
}

const isExpired = (p: PendingRequest, now: number): boolean => now > p.expires;

/**
 * Tracks outstanding requests and binds responses back to them, fail-closed.
 *
 * Hold one store per client session: the request/response cycle that drives it is
 * already serialized per connection.
 */
export class CorrelationStore {
  readonly #pending = new Map<string, PendingRequest>();
  // Consumed correlation ids, so a second response for the same request is a replay
  // rather than an unknown-request mismatch. The distinction matters: one is a
  // duplicate, the other is an unrelated message.
  readonly #consumed = new Set<string>();

  /** How many requests are outstanding. */
  get size(): number {
    return this.#pending.size;
  }

  /** The outstanding requests, in insertion order. */
  pending(): PendingRequest[] {
    return [...this.#pending.values()];
  }

  /** Register a signed request as outstanding; returns its correlation id. */
  record(signed: SignedRequestJs, a: RecordArgs): string {
    const correlationId = signed.evidenceDigestValue;
    if (this.#pending.has(correlationId)) {
      // The evidence digest is unique per request; a collision means the same request
      // was recorded twice, which would let one response consume the wrong entry.
      throw new McpReError(
        "mcp-re.replay_detected",
        `request '${correlationId}' is already outstanding`,
      );
    }
    this.#pending.set(correlationId, {
      correlationId,
      requestId: a.requestId,
      nonce: a.nonce,
      evidenceDigestAlg: signed.evidenceDigestAlg,
      evidenceDigestValue: signed.evidenceDigestValue,
      audienceId: a.audienceId,
      expectedSignerId: a.expectedSignerId,
      created: a.created,
      expires: a.expires,
      route: a.route ?? null,
      authzBindingDigest: a.authzBindingDigest ?? null,
    });
    return correlationId;
  }

  /** The outstanding request, or undefined. Does not consume. */
  peek(correlationId: string): PendingRequest | undefined {
    return this.#pending.get(correlationId);
  }

  /**
   * Consume the outstanding request a response answers.
   *
   * Fails closed if the response matches nothing outstanding, answers a request that
   * already expired, or duplicates one already answered.
   */
  take(correlationId: string, now: number): PendingRequest {
    const pending = this.#missOrPending(correlationId, "response");
    if (isExpired(pending, now)) {
      // A late response is dropped AND the entry consumed: it must not stay outstanding
      // for a later, even later, answer.
      this.#retire(correlationId);
      throw new McpReError(
        "mcp-re.expired_request",
        `response arrived at ${now} for a request that expired at ${pending.expires}`,
      );
    }
    this.#retire(correlationId);
    return pending;
  }

  /**
   * Associate a verified `InputRequiredResult` WITHOUT consuming its request.
   *
   * An ADR-MCPS-047 elicitation is not the end of the exchange: the open leg stays
   * outstanding until the answer leg terminates it, so this associates rather than
   * consumes. The returned handles are what the answer leg signs over.
   */
  recordInputRequired(
    correlationId: string,
    args: { responseDigestAlg: string; responseDigestValue: string; requestState: string; now: number },
  ): ContinuationHandles {
    const pending = this.#missOrPending(correlationId, "input-required response");
    if (isExpired(pending, args.now)) {
      this.#retire(correlationId);
      throw new McpReError(
        "mcp-re.expired_request",
        `input-required response arrived at ${args.now} for a request that expired at ${pending.expires}`,
      );
    }
    return new ContinuationHandles(
      pending.evidenceDigestAlg,
      pending.evidenceDigestValue,
      args.responseDigestAlg,
      args.responseDigestValue,
      args.requestState,
    );
  }

  /**
   * Drop every outstanding request past its deadline; returns those dropped.
   *
   * Reaping bounds the store: without it, requests that never get an answer accumulate
   * for the life of the session.
   */
  expireBefore(now: number): PendingRequest[] {
    const dead = this.pending().filter((p) => isExpired(p, now));
    for (const p of dead) this.#retire(p.correlationId);
    return dead;
  }

  #missOrPending(correlationId: string, what: string): PendingRequest {
    const pending = this.#pending.get(correlationId);
    if (pending) return pending;
    if (this.#consumed.has(correlationId)) {
      throw new McpReError(
        "mcp-re.replay_detected",
        `request '${correlationId}' was already answered`,
      );
    }
    throw new McpReError(
      "mcp-re.request_binding_mismatch",
      `${what} does not bind to any outstanding request ('${correlationId}')`,
    );
  }

  #retire(correlationId: string): void {
    this.#pending.delete(correlationId);
    this.#consumed.add(correlationId);
  }
}
