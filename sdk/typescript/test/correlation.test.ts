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

function sign(nonce = "nonce-corr-0001", idJson = "1"): SignedRequestJs {
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
  nonce: "nonce-corr-0001",
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
    expect(p.nonce).toBe("nonce-corr-0001");
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
    store.record(sign("n-1"), ARGS({ nonce: "n-1" }));
    store.record(sign("n-2"), ARGS({ nonce: "n-2" }));
    expect(store.size).toBe(2);
    expect(new Set(store.pending().map((p) => p.nonce))).toEqual(new Set(["n-1", "n-2"]));
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
    store.record(sign("n-live"), ARGS({ nonce: "n-live", expires: 9000 }));
    const cidDead = store.record(sign("n-dead"), ARGS({ nonce: "n-dead", expires: 1200 }));
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

describe("an input-required result associates without consuming", () => {
  const irr = { responseDigestAlg: "sha-256", responseDigestValue: "aXJyLWhhbmRsZQ", requestState: "opaque-state-xyz" };

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
    expect(h.irrValue).toBe("aXJyLWhhbmRsZQ");
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
      "nonce-corr-answer",
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
