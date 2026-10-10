// SPDX-License-Identifier: Apache-2.0
//
// In-flight correlation (ADR-MCPS-044 §In-flight correlation state).
//
// The obligation: every outstanding request is tracked, and every response binds back to
// the exact request it answers or fails closed. These tests pin the three fail-closed
// boundaries onto the frozen `mcp-re.*` taxonomy — an unbound response, a late response,
// and a duplicate — plus the ADR-MCPS-047 rule that an elicitation *associates without
// consuming*.
import { describe, it, expect } from "vitest";
import {
  CorrelationStore,
  McpReError,
  signRequest,
  type RecordArgs,
  type SignedRequestJs,
} from "../src/index.js";

const SEED = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const CREATED = 1000;
const EXPIRES = 2000;
const IN_WINDOW = 1500;
const LATE = 2001;

/** Pad an ad-hoc test nonce to the 22-char (128-bit) emission floor the core enforces. */
const N = (s: string): string => `${s}-padded-to-the-128-bit-floor`;

function sign(nonce = "nonce-corr-0001-128bit", idJson = "1"): SignedRequestJs {
  return signRequest(
    SEED,
    "key-1",
    idJson,
    "tools/list",
    "{}",
    "https://proxy.internal:8600/mcp",
    "did:example:server-1",
    null,
    "dpop-token",
    nonce,
    CREATED,
    EXPIRES,
  );
}

const ARGS = (over: Partial<RecordArgs> = {}): RecordArgs => ({
  requestId: "1",
  nonce: "nonce-corr-0001-128bit",
  audienceId: "did:example:server-1",
  expectedSignerId: "did:example:server-1",
  created: CREATED,
  expires: EXPIRES,
  ...over,
});

/** Assert a thrown McpReError carries the exact frozen wire code. */
function expectWireCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(McpReError);
    expect((e as McpReError).wireCode).toBe(code);
    return;
  }
  throw new Error(`expected ${code}, but nothing was thrown`);
}

describe("record and take", () => {
  it("uses the request evidence handle as the correlation id", () => {
    const store = new CorrelationStore();
    const signed = sign();
    const cid = store.record(signed, ARGS());
    // Correlation and cryptographic binding must be the same handle, or they drift.
    expect(cid).toBe(signed.evidenceDigestValue);
    expect(store.size).toBe(1);
  });

  it("consumes the outstanding request", () => {
    const store = new CorrelationStore();
    const signed = sign();
    const cid = store.record(signed, ARGS());
    const p = store.take(cid, IN_WINDOW);
    expect(p.correlationId).toBe(cid);
    expect(p.requestId).toBe("1");
    expect(p.nonce).toBe("nonce-corr-0001-128bit");
    expect(p.evidenceDigestValue).toBe(signed.evidenceDigestValue);
    expect(store.size).toBe(0);
  });

  it("peek does not consume", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    expect(store.peek(cid)).toBeDefined();
    expect(store.peek(cid)).toBeDefined();
    expect(store.size).toBe(1);
    expect(store.peek("no-such-id")).toBeUndefined();
  });

  it("carries the audit fields the ADR enumerates", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS({ route: "route-a", authzBindingDigest: "abc123" }));
    const p = store.take(cid, IN_WINDOW);
    expect(p.route).toBe("route-a");
    expect(p.authzBindingDigest).toBe("abc123");
    expect(p.created).toBe(CREATED);
    expect(p.expires).toBe(EXPIRES);
    expect(p.expectedSignerId).toBe("did:example:server-1");
  });

  it("lists the outstanding requests", () => {
    const store = new CorrelationStore();
    store.record(sign(N("n-1")), ARGS({ nonce: N("n-1") }));
    store.record(sign(N("n-2")), ARGS({ nonce: N("n-2") }));
    expect(store.size).toBe(2);
    expect(new Set(store.pending().map((p) => p.nonce))).toEqual(new Set([N("n-1"), N("n-2")]));
  });
});

describe("fails closed", () => {
  it("rejects a response binding to nothing outstanding", () => {
    const store = new CorrelationStore();
    expectWireCode(() => store.take("not-an-outstanding-handle", IN_WINDOW), "mcp-re.request_binding_mismatch");
  });

  it("rejects a late response", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    expectWireCode(() => store.take(cid, LATE), "mcp-re.expired_request");
  });

  it("retires the entry when a response is late", () => {
    // A dropped-late request must not linger for an even later answer.
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    expect(() => store.take(cid, LATE)).toThrow();
    expect(store.size).toBe(0);
    expectWireCode(() => store.take(cid, LATE), "mcp-re.replay_detected");
  });

  it("treats a duplicate response as a replay, not a mismatch", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    store.take(cid, IN_WINDOW);
    expectWireCode(() => store.take(cid, IN_WINDOW), "mcp-re.replay_detected");
  });

  it("rejects recording the same request twice", () => {
    const store = new CorrelationStore();
    const signed = sign();
    store.record(signed, ARGS());
    expectWireCode(() => store.record(signed, ARGS()), "mcp-re.replay_detected");
  });

  it("treats the deadline itself as in-window", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    expect(() => store.take(cid, EXPIRES)).not.toThrow();
  });
});

describe("reaping", () => {
  it("drops only the dead", () => {
    const store = new CorrelationStore();
    store.record(sign(N("n-live")), ARGS({ nonce: N("n-live"), expires: 9000 }));
    const cidDead = store.record(sign(N("n-dead")), ARGS({ nonce: N("n-dead"), expires: 1200 }));
    const dropped = store.expireBefore(1500);
    expect(dropped.map((p) => p.correlationId)).toEqual([cidDead]);
    expect(store.size).toBe(1);
  });

  it("a reaped request cannot later be answered", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    store.expireBefore(LATE);
    expectWireCode(() => store.take(cid, LATE), "mcp-re.replay_detected");
  });

  it("reaping an empty store is a no-op", () => {
    expect(new CorrelationStore().expireBefore(LATE)).toEqual([]);
  });
});

describe("the store is bounded", () => {
  // Neither half may grow for the life of the session. The pending half is reaped by
  // `expireBefore`. The consumed half is what remembers "already answered", and it gains
  // an entry on every single request — so without its own retention rule it is an
  // unbounded set a peer can grow one request at a time.

  it("drops consumed ids once they can no longer answer anything", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    store.take(cid, IN_WINDOW);

    // Still remembered while a late response could plausibly still arrive.
    expectWireCode(() => store.take(cid, LATE), "mcp-re.replay_detected");

    // Past the retention grace it is dropped, and the refusal degrades from "duplicate"
    // to "unbound" — less precise, never an acceptance.
    expect(store.pruneConsumed(EXPIRES + 301)).toBe(1);
    expectWireCode(() => store.take(cid, EXPIRES + 301), "mcp-re.request_binding_mismatch");
  });

  it("keeps ids that can still be answered", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    store.take(cid, IN_WINDOW);
    expect(store.pruneConsumed(EXPIRES)).toBe(0);
  });

  it("does not grow across a long session of failed exchanges", () => {
    // `abandon` is the failure path's retirement, and it must feed the same retention
    // rule — otherwise the leak simply moves from the pending half to the consumed one.
    const store = new CorrelationStore();
    for (let i = 0; i < 50; i += 1) {
      const cid = store.record(sign(N(`n-${i}`)), ARGS({ nonce: N(`n-${i}`) }));
      store.abandon(cid);
    }
    expect(store.size).toBe(0);
    expect(store.pruneConsumed(EXPIRES + 301)).toBe(50);
    expect(store.pruneConsumed(EXPIRES + 301)).toBe(0);
  });

  it("abandon is idempotent and never throws", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    store.abandon(cid);
    store.abandon(cid); // the failure path may run after the entry was consumed
    store.abandon("never-recorded");
    expect(store.size).toBe(0);
  });
});

describe("an input-required result associates without consuming", () => {
  // A well-formed response-role handle: the signer refuses a continuation whose handles are not.
  const irr = { responseDigestAlg: "sha256", responseDigestValue: "CQybwHow5Uec0w7Tb6kcd7vWOEhRNCCGhfvkNUGvIIA", requestState: "opaque-state-xyz" };

  it("leaves the open leg outstanding", () => {
    const store = new CorrelationStore();
    const signed = sign();
    const cid = store.record(signed, ARGS());
    const h = store.recordInputRequired(cid, { ...irr, now: IN_WINDOW });
    // ADR-MCPS-047: the exchange is not over, so the request must NOT be consumed.
    expect(store.size).toBe(1);
    expect(store.peek(cid)).toBeDefined();
    expect(h.prevAlg).toBe(signed.evidenceDigestAlg);
    expect(h.prevValue).toBe(signed.evidenceDigestValue);
    expect(h.irrValue).toBe("CQybwHow5Uec0w7Tb6kcd7vWOEhRNCCGhfvkNUGvIIA");
    expect(h.requestState).toBe("opaque-state-xyz");
  });

  it("hands back handles that feed straight into the answer leg", () => {
    const store = new CorrelationStore();
    const signed = sign();
    const cid = store.record(signed, ARGS());
    const a = store.recordInputRequired(cid, { ...irr, now: IN_WINDOW }).asSignArgs();
    const answer = signRequest(
      SEED,
      "key-1",
      "2",
      "tools/call",
      "{}",
      "https://proxy.internal:8600/mcp",
      "did:example:server-1",
      null,
      "dpop-token",
      "nonce-corr-answer-128bit",
      CREATED,
      EXPIRES,
      a.contPrevAlg,
      a.contPrevValue,
      a.contIrrAlg,
      a.contIrrValue,
      a.contRequestState,
    );
    // The signed continuation must actually change the evidence.
    expect(answer.evidenceDigestValue).not.toBe(signed.evidenceDigestValue);
    expect(answer.body.toString()).toContain("tools/call");
  });

  it("refuses a partially supplied continuation instead of dropping it", () => {
    // r12 R12-1455/1456/1466 — the five handles used to be folded in under one
    // `if let (Some, Some, Some, Some, Some)`. With one to four present the `if let`
    // did not fire, the request was signed and returned carrying NO continuation and
    // NO error, and a server processed it as an unrelated new call — so a caller bug
    // silently converted an approved-continuation flow into an UNapproved fresh request.
    const full = ["sha256", "Imp8EIIBTYo1GafV0toSPuMJpP40j5pH5x7VDVU1il8", "sha256", "CQybwHow5Uec0w7Tb6kcd7vWOEhRNCCGhfvkNUGvIIA", "opaque-state"];
    const answer = (handles: (string | null)[]): void => {
      signRequest(
        SEED,
        "key-1",
        "2",
        "tools/call",
        "{}",
        "https://proxy.internal:8600/mcp",
        "did:example:server-1",
        null,
        "dpop-token",
        "nonce-corr-partial-128bit",
        CREATED,
        EXPIRES,
        handles[0],
        handles[1],
        handles[2],
        handles[3],
        handles[4],
      );
    };
    // Every proper non-empty subset of the five, not a sampled one: the old `if let`
    // fell through on each of the 30 identically.
    for (let mask = 1; mask < 31; mask += 1) {
      const given = full.map((h, i) => ((mask & (1 << i)) !== 0 ? h : null));
      const supplied = given.filter((h) => h !== null).length;
      expect(() => answer(given)).toThrow(new RegExp(`${supplied} of 5`));
    }
    // POSITIVE CONTROL: all five still sign, so this is not satisfied by a signer that
    // refuses every answer leg. (All-absent is covered by `sign()` throughout the file.)
    expect(() => answer(full)).not.toThrow();
  });

  it("refuses an empty dpop token rather than binding over nothing", () => {
    // r12 R12-1460/1461/1462 — measured unrefused ANYWHERE before this: an empty token
    // minted a binding whose digest is the digest of zero bytes beside a signed
    // `Authorization: Bearer ` header carrying no credential.
    expect(() =>
      signRequest(
        SEED,
        "key-1",
        "1",
        "tools/list",
        "{}",
        "https://proxy.internal:8600/mcp",
        "did:example:server-1",
        null,
        "",
        "nonce-corr-empty-dpop-128b",
        CREATED,
        EXPIRES,
      ),
    ).toThrow(/empty/);
    // POSITIVE CONTROL: an ordinary token still signs.
    expect(sign().body.length).toBeGreaterThan(0);
  });

  it("still lets the terminal answer take the open leg", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    store.recordInputRequired(cid, { ...irr, now: IN_WINDOW });
    expect(store.take(cid, IN_WINDOW).correlationId).toBe(cid);
  });

  it("rejects an unbound elicitation", () => {
    const store = new CorrelationStore();
    expectWireCode(
      () => store.recordInputRequired("not-outstanding", { ...irr, now: IN_WINDOW }),
      "mcp-re.request_binding_mismatch",
    );
  });

  it("rejects a late elicitation", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    expectWireCode(() => store.recordInputRequired(cid, { ...irr, now: LATE }), "mcp-re.expired_request");
  });

  it("treats an elicitation for an answered request as a replay", () => {
    const store = new CorrelationStore();
    const cid = store.record(sign(), ARGS());
    store.take(cid, IN_WINDOW);
    expectWireCode(() => store.recordInputRequired(cid, { ...irr, now: IN_WINDOW }), "mcp-re.replay_detected");
  });
});
