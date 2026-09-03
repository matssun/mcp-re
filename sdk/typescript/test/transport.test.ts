// SPDX-License-Identifier: Apache-2.0
//
// Offline unit tests for `McpReHttpTransport`: the obligations that hold regardless of
// what a counterparty says. The live proof — a real MCP `Client` against the real proxy
// and a real FastMCP backend — is in `transport_e2e.test.ts`; these cover the paths a
// happy round-trip never reaches, with an injected `poster` and no network.
//
// The theme throughout: **a failure must be DELIVERED, not dropped.** A transport that
// swallowed a failed exchange would leave `Client` awaiting a reply that never comes, and
// a hang is a worse failure mode than a raise.
import { createHash } from "node:crypto";

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it, vi } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/client";

// The core's `bound` verdict on a rejection receipt, forced. The recorded receipt in
// `transport_replay.test.ts` is request-bound, and no fixture can carry an unbound one:
// a preflight-unbound receipt is signed WITHOUT the `;req` request components, so it
// cannot be derived from a recording without the server's delegated private key. The
// unbound case is the security-relevant one, so the verdict is overridden here and the
// real core answers everything else — with the override unset this is a pass-through,
// and every other test in this file runs against the genuine binding.
const boundVerdict = vi.hoisted(() => ({ override: null as boolean | null }));
// A whole forced verdict, for the properties that are about what the transport DOES with
// a verdict rather than about producing one. `boundVerdict` stays as the narrow knob the
// binding tests already use.
const coreVerdict = vi.hoisted(() => ({ override: null as Record<string, unknown> | null }));
vi.mock("../native/binding.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../native/binding.js")>();
  return {
    ...actual,
    verifyResponse: (...args: Parameters<typeof actual.verifyResponse>) => {
      if (coreVerdict.override !== null) return coreVerdict.override;
      return boundVerdict.override === null
        ? actual.verifyResponse(...args)
        : {
            outcome: "rejection",
            wireCode: "mcp-re.authorization_binding_missing",
            bound: boundVerdict.override,
            requestState: null,
          };
    },
  };
});

import { bindingsJson } from "../src/authorization.js";
import type { HttpHeader } from "../native/binding.js";
import type { PendingRequest } from "../src/correlation.js";

import {
  McpReError,
  McpReSdkError,
  OpaqueBytesProvider,
  Signer,
  SignerPolicy,
  SignerUnavailable,
  SigningDevice,
} from "../src/index.js";
import {
  ClientResponseUnsupported,
  ConnectionClosed,
  McpReHttpTransport,
  NotificationNotAcknowledged,
  TransportState,
  type HttpReply,
  type McpReConfig,
  type Poster,
} from "../src/transport.js";

const CLIENT_SEED = Buffer.alloc(32, 11);
const TARGET = "https://proxy.internal:8600/mcp";
/** The `server-key-1` root issuer of `sdk/fixtures/delegated_response_replay.json`, so the
 * anchor these tests carry is the one the recorded session actually verifies against. */
const ISSUER_PUBKEY = "URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo";

/** The minimum a config can carry: every optional knob left to its default, so the
 * default side of each branch is what runs. */
function minimalConfig(over: Partial<McpReConfig> = {}): McpReConfig {
  return {
    signer: Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
    audienceId: "verifier-1",
    targetUri: TARGET,
    dpopToken: "access-token-xyz",
    issuerKeyId: "server-key-1",
    issuerPubkeyB64Url: ISSUER_PUBKEY,
    issuerTrustDomain: "example.com",
    issuerSubject: "did:example:server-1",
    verifierAudiences: ["verifier-1"],
    expectedAudienceHash: "aud-scope-1",
    acceptedEpochs: ["epoch-1"],
    ...over,
  };
}

const REQUEST: JSONRPCMessage = { jsonrpc: "2.0", id: 7, method: "tools/list", params: {} };

/** Drive one message through a transport and capture what it hands the client. */
async function sendAndCapture(
  config: McpReConfig,
  poster: Poster,
  message: JSONRPCMessage = REQUEST,
): Promise<JSONRPCMessage | undefined> {
  const transport = new McpReHttpTransport(config, poster);
  let seen: JSONRPCMessage | undefined;
  transport.onmessage = (m) => {
    seen = m;
  };
  await transport.start();
  await transport.send(message);
  return seen;
}

const throwingPoster = (e: unknown): Poster => async () => {
  throw e;
};

describe("McpReHttpTransport lifecycle", () => {
  it("checks the signer against the route policy in start(), before anything is signed", async () => {
    const poster = vi.fn<Poster>();
    const transport = new McpReHttpTransport(
      minimalConfig({ policy: SignerPolicy.hardened("did:example:host-a") }),
      poster,
    );

    await expect(transport.start()).rejects.toThrow(McpReError);
    // A custody violation must fail the CONNECTION; nothing may reach the wire.
    expect(poster).not.toHaveBeenCalled();
  });

  it("checks the authorization policy in start() too", async () => {
    const transport = new McpReHttpTransport(
      minimalConfig({
        authorizationPolicy: { check: () => { throw new McpReError("mcp-re.authorization_binding_missing"); } } as never,
      }),
      vi.fn<Poster>(),
    );
    await expect(transport.start()).rejects.toThrow(/authorization_binding_missing/);
  });

  it("accepts a signer that satisfies the policy", async () => {
    const transport = new McpReHttpTransport(
      minimalConfig({ policy: new SignerPolicy("did:example:host-a", "development") }),
      vi.fn<Poster>(),
    );
    await expect(transport.start()).resolves.toBeUndefined();
  });

  it("refuses a second start()", async () => {
    // A second start would sign under a policy that was already accepted, hiding the
    // first one.
    const transport = new McpReHttpTransport(minimalConfig(), vi.fn<Poster>());
    await transport.start();
    await expect(transport.start()).rejects.toThrow(McpReSdkError);
  });

  it("fires onclose when closed, and is single-use afterwards", async () => {
    // NEW -> OPEN -> CLOSING -> CLOSED is one-way (#421): start() is not a reset, and
    // reopening would sign under a policy accepted for a connection that is gone.
    const transport = new McpReHttpTransport(minimalConfig(), vi.fn<Poster>());
    const onclose = vi.fn();
    transport.onclose = onclose;
    await transport.start();
    await transport.close();
    expect(onclose).toHaveBeenCalledOnce();
    await expect(transport.start()).rejects.toThrow(McpReSdkError);
  });

  it("walks NEW -> OPEN -> CLOSED", async () => {
    const transport = new McpReHttpTransport(minimalConfig(), vi.fn<Poster>());
    expect(transport.state).toBe(TransportState.New);
    await transport.start();
    expect(transport.state).toBe(TransportState.Open);
    await transport.close();
    expect(transport.state).toBe(TransportState.Closed);
  });

  it("refuses work before start and after close", async () => {
    const poster = vi.fn<Poster>();
    const transport = new McpReHttpTransport(minimalConfig(), poster);
    await expect(transport.send(REQUEST)).rejects.toThrow(ConnectionClosed);
    await transport.start();
    await transport.close();
    await expect(transport.send(REQUEST)).rejects.toThrow(ConnectionClosed);
    expect(poster, "a closed transport must not emit a signed request").not.toHaveBeenCalled();
  });

  it("closes idempotently", async () => {
    const transport = new McpReHttpTransport(minimalConfig(), vi.fn<Poster>());
    const onclose = vi.fn();
    transport.onclose = onclose;
    await transport.start();
    await transport.close();
    await transport.close();
    await transport.close();
    expect(onclose).toHaveBeenCalledOnce();
  });

  it("aborts an in-flight exchange and never delivers after onclose", async () => {
    // The two failures this prevents: a message handed to an application that believes it
    // has disconnected, and an in-flight request that hangs forever because close() ate
    // its reply.
    const events: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const poster: Poster = async () => {
      events.push("poster-hit");
      await gate;
      throw new McpReError("mcp-re.replay_detected");
    };
    const transport = new McpReHttpTransport(minimalConfig(), poster);
    transport.onmessage = () => events.push("onmessage");
    transport.onclose = () => events.push("onclose");
    await transport.start();

    const inflight = transport.send(REQUEST);
    await new Promise((r) => setTimeout(r, 20));
    await transport.close();

    await expect(inflight, "an in-flight request fails connection-closed").rejects.toThrow(
      ConnectionClosed,
    );
    release();
    await new Promise((r) => setTimeout(r, 20));
    expect(events).toEqual(["poster-hit", "onclose"]);
  });

  it("says nothing about execution when close() aborts an in-flight exchange", async () => {
    // WHERE THE ABORT MEETS EXECUTION HONESTY, and the reason ASM-0043's second half is
    // not needed: nothing local can know whether a request already on the wire reached the
    // server, and this transport does not pretend to. `ConnectionClosed` is a LOCAL
    // outcome — no `mcp-re.*` wire code the peer never sent, and no execution or retry
    // verdict — so a caller cannot read a teardown as "it did not run" and repeat a side
    // effect the server may already have performed. A premise is needed to CLAIM
    // something; asserting nothing needs none (#747).
    const transport = new McpReHttpTransport(minimalConfig(), async () => {
      await new Promise((r) => setTimeout(r, 10_000));
      throw new Error("the poster must never settle in this test");
    });
    await transport.start();
    const inFlight = transport.send(REQUEST);
    await new Promise((r) => setTimeout(r, 20));
    await transport.close();

    const raised = await inFlight.catch((e: unknown) => e);
    expect(raised, "an aborted exchange must fail its caller").toBeInstanceOf(ConnectionClosed);
    const rendered = JSON.stringify({
      message: (raised as Error).message,
      ...Object.fromEntries(
        Object.entries(raised as object).map(([k, v]) => [k, v as unknown]),
      ),
    });
    for (const forbidden of ["mcp-re.", "not_executed", "notExecuted", "executionStatus", "retrySafety", "retry_safe"]) {
      expect(rendered.includes(forbidden), `a local teardown must not state ${forbidden}`).toBe(
        false,
      );
    }
  });

  it("does not sign or POST a request still queued at the semaphore when close() lands", async () => {
    // The gap the in-flight test above does NOT cover. close() is documented as making
    // no claim about already-DISPATCHED work — but a request waiting for a concurrency
    // slot has not been dispatched. Before the fix, the OPEN check ran before the queue
    // wait and `Promise.race` started the exchange regardless, so every queued request
    // was signed and POSTed after teardown: the server executed work the caller believed
    // it had cancelled, with valid signatures and fresh nonces.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const posted: string[] = [];
    const poster: Poster = async (req) => {
      posted.push(String(req.headers?.["signature-input"] ?? "signed"));
      await gate;
      throw new McpReError("mcp-re.replay_detected");
    };
    // One slot, so the second and third sends are stuck in the queue.
    const transport = new McpReHttpTransport(
      minimalConfig({ maxConcurrentExchanges: 1 }),
      poster,
    );
    await transport.start();

    const first = transport.send(REQUEST);
    await new Promise((r) => setTimeout(r, 20));
    expect(posted.length, "the first request holds the only slot").toBe(1);

    const queued = [transport.send(REQUEST), transport.send(REQUEST)];
    await new Promise((r) => setTimeout(r, 20));
    expect(posted.length, "the queued requests are still waiting for a slot").toBe(1);

    await transport.close();
    release();

    await expect(first).rejects.toThrow(ConnectionClosed);
    for (const q of queued) {
      await expect(q, "a queued request must fail closed, not be emitted").rejects.toThrow(
        ConnectionClosed,
      );
    }
    await new Promise((r) => setTimeout(r, 20));
    expect(
      posted.length,
      "no request queued at close() may reach the server",
    ).toBe(1);
  });

  it("clears abandoned correlation state on close", async () => {
    // Correlation entries would otherwise outlive the transport that owns them.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const transport = new McpReHttpTransport(minimalConfig(), async () => {
      await gate;
      throw new McpReError("mcp-re.replay_detected");
    });
    transport.onmessage = () => {};
    await transport.start();
    const inflight = transport.send(REQUEST);
    await new Promise((r) => setTimeout(r, 20));
    await transport.close();
    await expect(inflight).rejects.toThrow(ConnectionClosed);
    release();
    expect(transport.pendingCorrelations).toBe(0);
  });

  it("closes cleanly with no onclose installed", async () => {
    await expect(new McpReHttpTransport(minimalConfig(), vi.fn<Poster>()).close()).resolves.toBeUndefined();
  });
});

describe("McpReHttpTransport notification handling", () => {
  const NOTIFICATION: JSONRPCMessage = { jsonrpc: "2.0", method: "notifications/initialized" };

  /** A poster that records what went out and answers with `reply`. */
  const capturing = (
    calls: { headers: HttpHeader[]; body: Buffer }[],
    reply: HttpReply,
  ): Poster => {
    return async (_method, _targetUri, headers, body) => {
      calls.push({ headers, body });
      return reply;
    };
  };

  const unsignedAck: HttpReply = { status: 202, headers: [], body: Buffer.alloc(0) };

  it("transmits a notification as a signed POST", async () => {
    // The adapter used to refuse or drop it: MCP-RE had no ratified one-way profile, so
    // a `notifications/cancelled` silently became "keep going". The profile exists now
    // (#418 / C019b), so the message is carried and its acknowledgement is checked.
    const calls: { headers: HttpHeader[]; body: Buffer }[] = [];
    const transport = new McpReHttpTransport(minimalConfig(), capturing(calls, unsignedAck));
    await transport.start();

    // The unsigned ack fails the check below; what this test reads is what DID go out.
    await expect(transport.send(NOTIFICATION)).rejects.toThrow(NotificationNotAcknowledged);

    expect(calls).toHaveLength(1);
    const names = new Set(calls[0].headers.map((h) => h.key.toLowerCase()));
    for (const required of ["signature", "signature-input", "content-digest"]) {
      expect(names).toContain(required);
    }
    const body = JSON.parse(calls[0].body.toString("utf8"));
    expect(body.method).toBe("notifications/initialized");
    // The serving path classifies a notification by an ABSENT id. `null` is a present id
    // and would be dispatched as a request, answered with a bodied reply nothing awaits.
    expect("id" in body).toBe(false);
    expect(body._meta, "the request evidence block rides along").toBeTruthy();
  });

  it("fails closed on an unsigned acknowledgement", async () => {
    // A 202 with no evidence establishes nothing, so it must not pass as delivery. The
    // caller that sent the notification is the one told, because there is no reply for a
    // JSON-RPC error to ride back on.
    const transport = new McpReHttpTransport(minimalConfig(), async () => unsignedAck);
    await transport.start();

    await expect(transport.send(NOTIFICATION)).rejects.toMatchObject({
      name: "NotificationNotAcknowledged",
      method: "notifications/initialized",
    });
  });

  it("reports the ack failure as the frozen token, not the binding's prefixed spelling", async () => {
    // `wireCode` is documented as the frozen `mcp-re.*` token a caller branches on
    // without parsing prose. The napi binding spells a core failure
    // `"mcp-re: mcp-re.<token>"`, and the request path already strips that; the
    // notification path passed the prefixed string straight through, so the same wire
    // event reached an application under two different spellings depending on which
    // message shape carried it. The Python twin pins the same assertion.
    const transport = new McpReHttpTransport(minimalConfig(), async () => unsignedAck);
    await transport.start();

    const error = await transport.send(NOTIFICATION).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(NotificationNotAcknowledged);
    expect((error as NotificationNotAcknowledged).wireCode).toMatch(/^mcp-re\.[a-z0-9_]+$/);
  });

  it("fails closed on a bodied 200 in place of an acknowledgement", async () => {
    // The named bodyless set is checked as a set: a bodied 200 is not an
    // acknowledgement, however well-formed it looks.
    const transport = new McpReHttpTransport(minimalConfig(), async () => ({
      status: 200,
      headers: [{ key: "Content-Type", value: "application/json" }],
      body: Buffer.from('{"jsonrpc":"2.0","id":null,"result":{"ok":true}}'),
    }));
    await transport.start();

    await expect(
      transport.send({ jsonrpc: "2.0", method: "notifications/cancelled" }),
    ).rejects.toThrow(NotificationNotAcknowledged);
  });

  it("aborts an in-flight notification on close rather than waiting out the poster", async () => {
    // #421 applies to a notification for the same reason it applies to a request: the
    // caller has torn the transport down, and an acknowledgement it will never look at
    // must not hold the close open.
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const transport = new McpReHttpTransport(minimalConfig(), async () => {
      await gate;
      return unsignedAck;
    });
    await transport.start();
    const inflight = transport.send(NOTIFICATION);
    await new Promise((r) => setTimeout(r, 20));
    await transport.close();
    await expect(inflight).rejects.toThrow(ConnectionClosed);
    release();
  });

  it("refuses a sub-floor nonce override before a notification is signed", async () => {
    // A notification signed under a guessable nonce is exactly as replayable as a
    // request signed under one; a check that covered only requests would be a hole
    // shaped like the message the caller cares least about.
    const poster = vi.fn<Poster>();
    const transport = new McpReHttpTransport(minimalConfig({ nonceFactory: () => "short" }), poster);
    await transport.start();

    await expect(transport.send(NOTIFICATION)).rejects.toThrow(/at least 22/);
    expect(poster, "nothing may reach the wire under a sub-floor nonce").not.toHaveBeenCalled();
  });

  it("refuses a client-side RESPONSE rather than carrying it as a notification", async () => {
    // A response has no `method`. Signing one as a notification would fabricate a
    // message and then report ITS acknowledgement as if the response had been delivered.
    const poster = vi.fn<Poster>();
    const transport = new McpReHttpTransport(minimalConfig(), poster);
    await transport.start();

    await expect(
      transport.send({ jsonrpc: "2.0", id: 1, result: {} } as JSONRPCMessage),
    ).rejects.toThrow(ClientResponseUnsupported);
    expect(poster, "nothing fabricated may reach the wire").not.toHaveBeenCalled();
  });

  it("opens under a hardened policy with a non-exporting signer", async () => {
    const transport = new McpReHttpTransport(
      minimalConfig({
        signer: Signer.fromDevice(
          "did:example:host-a",
          "client-key-1",
          SigningDevice.fromSeed(CLIENT_SEED),
        ),
        policy: SignerPolicy.hardened("did:example:host-a"),
      }),
      vi.fn<Poster>(),
    );
    await expect(transport.start()).resolves.toBeUndefined();
  });
});

describe("McpReHttpTransport failure delivery", () => {
  it("delivers a wire failure as a JSON-RPC error carrying the frozen code", async () => {
    const seen = await sendAndCapture(
      minimalConfig(),
      throwingPoster(new McpReError("mcp-re.replay_detected", "seen before")),
    );
    expect(seen).toMatchObject({ id: 7, error: { code: -31001, message: "mcp-re.replay_detected" } });
  });

  it("delivers a local signer failure WITHOUT claiming a wire code", async () => {
    // The device broke on this side of the boundary; nothing was transmitted, so no peer
    // rejected anything. Reporting `mcp-re.invalid_signature` here would be a lie.
    const seen = await sendAndCapture(
      minimalConfig(),
      throwingPoster(new SignerUnavailable("kms timeout")),
    );
    const message = (seen as { error: { message: string } }).error.message;
    expect(message).toContain("mcp-re-sdk:");
    expect(message).not.toMatch(/^mcp-re\./);
  });

  it("delivers the core's own fail-closed Error rather than letting the caller hang", async () => {
    const seen = await sendAndCapture(
      minimalConfig(),
      throwingPoster(new Error("mcp-re.response_sig_invalid")),
    );
    expect(seen).toMatchObject({ error: { message: "mcp-re.response_sig_invalid" } });
  });

  it("delivers a network error under the local prefix, not as something the peer said", async () => {
    // The `poster` does real I/O, so a reset connection arrives here as a plain Error
    // exactly like a frozen core token does. Passing it through verbatim would put
    // "socket hang up" in the field that otherwise only ever holds a wire outcome.
    // Mirrors `test_an_unexpected_exception_is_delivered_without_claiming_a_wire_code`.
    const seen = await sendAndCapture(minimalConfig(), throwingPoster(new Error("socket hang up")));
    const message = (seen as { error: { message: string } }).error.message;
    expect(message).toBe("mcp-re-sdk: Error: socket hang up");
    expect(message).not.toMatch(/^mcp-re\./);
  });

  it("keeps a failed exchange from taking down the session's other requests", async () => {
    // Mirrors `test_one_exchanges_network_error_does_not_take_down_the_session`: a
    // per-request failure must stay per-request. A peer that can cause a reset would
    // otherwise end the session and every other in-flight request with it.
    const ids: unknown[] = [];
    const poster: Poster = async (_m, _u, _h, body) => {
      const id = JSON.parse(body.toString("utf8")).id;
      ids.push(id);
      if (id === 1) throw new Error("connection reset by peer");
      throw new McpReError("mcp-re.replay_detected");
    };
    const transport = new McpReHttpTransport(minimalConfig(), poster);
    const seen: Record<string, string> = {};
    transport.onmessage = (m) => {
      const e = m as { id: number; error: { message: string } };
      seen[String(e.id)] = e.error.message;
    };
    await transport.start();
    await Promise.all(
      [1, 2, 3].map((id) => transport.send({ jsonrpc: "2.0", id, method: "tools/list", params: {} })),
    );

    expect(ids.slice().sort()).toEqual([1, 2, 3]);
    expect(seen["1"]).toBe("mcp-re-sdk: Error: connection reset by peer");
    expect(seen["2"]).toBe("mcp-re.replay_detected");
    expect(seen["3"]).toBe("mcp-re.replay_detected");
  });

  it("does not accumulate an abort listener per request", async () => {
    // The AbortController lives as long as the transport, so a listener registered for
    // one request's close-race and never removed is retained — with its captured promise
    // — for the whole session. `{ once: true }` does not help: it only fires on close,
    // which is the rare case. A long-lived client would hold one per request it ever sent.
    const added = vi.spyOn(AbortSignal.prototype, "addEventListener");
    const removed = vi.spyOn(AbortSignal.prototype, "removeEventListener");
    try {
      const transport = new McpReHttpTransport(
        minimalConfig(),
        throwingPoster(new McpReError("mcp-re.replay_detected")),
      );
      await transport.start();
      for (let i = 0; i < 5; i += 1) {
        await transport.send({ jsonrpc: "2.0", id: i, method: "tools/list", params: {} });
      }
      const abortAdds = added.mock.calls.filter(([type]) => type === "abort").length;
      const abortRemoves = removed.mock.calls.filter(([type]) => type === "abort").length;
      expect(abortAdds).toBe(5);
      expect(abortRemoves).toBe(abortAdds);
    } finally {
      added.mockRestore();
      removed.mockRestore();
    }
  });

  it("does not leave a failed exchange's correlation entry outstanding", async () => {
    // The entry is recorded before the POST and consumed by the response. A failure in
    // between produces no response to consume it, and everything that can fail an
    // exchange is remotely triggerable — so without an explicit retirement the store
    // grows by one per failed request for the life of the session.
    for (const thrown of [
      new Error("connection reset by peer"),
      new McpReError("mcp-re.replay_detected"),
      new Error("mcp-re.response_sig_invalid"),
    ]) {
      const transport = new McpReHttpTransport(minimalConfig(), throwingPoster(thrown));
      await transport.start();
      await transport.send(REQUEST);
      expect(transport.pendingCorrelations, `${thrown} left its entry outstanding`).toBe(0);
    }
  });

  it("re-throws a non-Error, which is a defect rather than a protocol outcome", async () => {
    const transport = new McpReHttpTransport(minimalConfig(), throwingPoster("not an error"));
    await transport.start();
    await expect(transport.send(REQUEST)).rejects.toBe("not an error");
  });

  it("still completes when no onmessage is installed", async () => {
    const transport = new McpReHttpTransport(
      minimalConfig(),
      throwingPoster(new McpReError("mcp-re.replay_detected")),
    );
    await transport.start();
    await expect(transport.send(REQUEST)).resolves.toBeUndefined();
  });
});

describe("McpReHttpTransport concurrency", () => {
  // Mirrors `concurrency` in sdk/python/tests/test_transport.py: the two SDKs must agree
  // on how many exchanges may be in flight, not just on the bytes they emit.

  /** Count how many posts are in flight at once. */
  function gatedPoster(hold = 50): { poster: Poster; peak: () => number } {
    let now = 0;
    let max = 0;
    const poster: Poster = async () => {
      now += 1;
      max = Math.max(max, now);
      await new Promise((r) => setTimeout(r, hold));
      now -= 1;
      throw new McpReError("mcp-re.replay_detected"); // stop before native verification
    };
    return { poster, peak: () => max };
  }

  /** Send `count` requests at once and wait for all their replies. */
  async function drive(config: McpReConfig, poster: Poster, count: number) {
    const transport = new McpReHttpTransport(config, poster);
    const seen: JSONRPCMessage[] = [];
    transport.onmessage = (m) => seen.push(m);
    await transport.start();
    await Promise.all(
      Array.from({ length: count }, (_, id) =>
        transport.send({ jsonrpc: "2.0", id, method: "tools/list", params: {} }),
      ),
    );
    return seen;
  }

  it("runs exchanges concurrently rather than head-of-line blocking", async () => {
    // MCP is not lock-step. Serializing would make one slow tool call block every other
    // request on the session.
    const { poster, peak } = gatedPoster();
    const seen = await drive(minimalConfig(), poster, 4);

    expect(peak(), "exchanges serialized").toBe(4);
    expect(seen, "every request must still get its reply").toHaveLength(4);
  });

  it("bounds concurrency so a burst cannot exhaust the poster", async () => {
    // Each in-flight exchange holds a connection and a signing operation (a KMS round
    // trip under non-exporting custody); unbounded fan-out would exhaust either.
    const { poster, peak } = gatedPoster();
    const seen = await drive(minimalConfig({ maxConcurrentExchanges: 2 }), poster, 6);

    expect(peak(), "the bound was not honoured").toBe(2);
    expect(seen, "bounding must delay a request, never drop it").toHaveLength(6);
  });

  it.each([0, -1, 2.5, NaN, Infinity, "8" as unknown as number])(
    "refuses an invalid bound (%s) rather than deadlocking",
    async (bad) => {
      // A bound of 0 does not throttle — it deadlocks. Every sender waits for a slot that
      // can never be released, and the session hangs in silence. Nothing about that is
      // recoverable at runtime, so it must be refused where the value enters.
      expect(
        () => new McpReHttpTransport(minimalConfig({ maxConcurrentExchanges: bad }), vi.fn<Poster>()),
      ).toThrow(McpReSdkError);
    },
  );

  it("accepts a valid bound", () => {
    expect(
      () => new McpReHttpTransport(minimalConfig({ maxConcurrentExchanges: 1 }), vi.fn<Poster>()),
    ).not.toThrow();
  });

  it("correlates every concurrent reply to its own request", async () => {
    // Concurrency must not let one request's outcome land on another's id.
    const { poster } = gatedPoster();
    const seen = await drive(minimalConfig(), poster, 4);
    expect(seen.map((m) => (m as { id: number }).id).sort()).toEqual([0, 1, 2, 3]);
  });

  it("does not leak a slot when an exchange throws a non-Error", async () => {
    // The non-Error branch re-throws; a leaked slot there would shrink the pool
    // permanently and eventually deadlock the session.
    const transport = new McpReHttpTransport(
      minimalConfig({ maxConcurrentExchanges: 1 }),
      throwingPoster("not an error"),
    );
    transport.onmessage = () => {};
    await transport.start();
    for (let i = 0; i < 3; i++) {
      await expect(transport.send({ ...REQUEST, id: i })).rejects.toBe("not an error");
    }
    // A leaked slot would have deadlocked the second send rather than reaching here.
  });
});

describe("McpReHttpTransport signing inputs", () => {
  /** Capture what the transport actually put on the wire. */
  function capturingPoster(): { poster: Poster; calls: { headers: { key: string; value: string }[]; body: Buffer }[] } {
    const calls: { headers: { key: string; value: string }[]; body: Buffer }[] = [];
    const poster: Poster = async (_m, _u, headers, body) => {
      calls.push({ headers, body });
      throw new McpReError("mcp-re.replay_detected"); // stop before native verification
    };
    return { poster, calls };
  }

  it("generates its own freshness, so a caller cannot repeat a nonce", async () => {
    // A nonce that repeats inside the window is a defect, not a policy knob.
    const { poster, calls } = capturingPoster();
    await sendAndCapture(minimalConfig(), poster);
    await sendAndCapture(minimalConfig(), poster);

    const sigs = calls.map((c) => c.headers.find((h) => h.key.toLowerCase() === "signature")?.value);
    expect(sigs[0]).toBeDefined();
    expect(sigs[0]).not.toEqual(sigs[1]);
  });

  it("signs the request body the caller's message described", async () => {
    const { poster, calls } = capturingPoster();
    await sendAndCapture(minimalConfig(), poster);
    const body = JSON.parse(calls[0].body.toString("utf8"));
    expect(body).toMatchObject({ method: "tools/list", id: 7 });
  });

  it("signs a request with no params", async () => {
    const { poster, calls } = capturingPoster();
    await sendAndCapture(minimalConfig(), poster, { jsonrpc: "2.0", id: 1, method: "ping" });
    expect(calls).toHaveLength(1);
  });

  it("honours an injected clock and ttl", async () => {
    const { poster, calls } = capturingPoster();
    await sendAndCapture(minimalConfig({ clock: () => 1_000, requestTtl: 30, route: "a" }), poster);
    const input = calls[0].headers.find((h) => h.key.toLowerCase() === "signature-input")?.value;
    expect(input).toContain("created=1000");
    expect(input).toContain("expires=1030");
  });

  it("passes authorization bindings to the core, which digests the real bytes", async () => {
    // bind-not-interpret: the provider supplies the artifact; the core digests it. The
    // bytes themselves must never appear in the evidence.
    const material = Buffer.from("human-approval-record");
    const { poster, calls } = capturingPoster();
    await sendAndCapture(
      minimalConfig({ authorization: [new OpaqueBytesProvider("human-approval", material)] }),
      poster,
    );

    const evidence = calls[0].body.toString("utf8");
    expect(evidence).toContain("human-approval");
    expect(evidence).not.toContain("human-approval-record");
    expect(evidence).not.toContain(material.toString("base64url"));
  });

  /** Hold an exchange open at the POST so its correlation entry can be inspected. */
  async function inspectPending(config: McpReConfig): Promise<PendingRequest> {
    const transport = new McpReHttpTransport(config, () => new Promise<never>(() => {}));
    await transport.start();
    void transport.send(REQUEST).catch(() => {}); // close() aborts it below
    await new Promise((r) => setImmediate(r));
    const [pending] = transport.pendingRequests();
    await transport.close();
    return pending;
  }

  it("records the authorization-binding digest on the correlation entry", async () => {
    // ADR-MCPS-044 enumerates it; retained for audit only, never re-interpreted. It must
    // be the digest of the bytes that were SIGNED, not of anything recomputed later.
    const providers = [new OpaqueBytesProvider("human-approval", Buffer.from("doc"))];
    const config = minimalConfig({ authorization: providers });
    const signedBindings = bindingsJson(providers, {
      audienceId: config.audienceId,
      targetUri: config.targetUri,
      method: "tools/list",
      route: null,
    });

    // LITERALS, not a recomputation. Recomputing the expectation with each SDK's own
    // serializer is what let the two drift: Python's `json.dumps` defaults to `", "`
    // / `": "` separators and `JSON.stringify` emits none, so identical bindings
    // produced different digests and an audit pipeline reconciling records across the
    // two saw a false "artifact binding changed". The Python twin pins these same two
    // strings — that is the point of writing them down.
    expect(signedBindings).toBe(
      '[{"artifact_type":"human-approval","form":"opaque-bytes","material_b64url":"ZG9j"}]',
    );
    expect((await inspectPending(config)).authzBindingDigest).toBe(
      "sha-256:huucRBvtO7V1Xm8EFbC6ci-xlsf8EYyNZQix9sJx64Q",
    );
  });

  it("records no binding digest for a request that carries no bindings", async () => {
    expect((await inspectPending(minimalConfig())).authzBindingDigest).toBeNull();
  });
});

describe("McpReHttpTransport peer wire codes", () => {
  // The napi binding formats every core failure as `mcp-re: mcp-re.<token>`, so a
  // regex applied to the WHOLE message could never match one — every genuine
  // peer-evidence failure was relabelled as a local `mcp-re-sdk:` condition, and the
  // Python twin delivered the bare token for the same event.
  it("delivers a core failure as its frozen token, not as a local SDK error", async () => {
    const poster: Poster = async () => {
      throw new Error("mcp-re: mcp-re.response_sig_invalid");
    };
    const transport = new McpReHttpTransport(minimalConfig(), poster);
    const delivered: JSONRPCMessage[] = [];
    transport.onmessage = (m) => delivered.push(m);
    await transport.start();
    await transport.send({ jsonrpc: "2.0", id: 1, method: "tools/list" } as JSONRPCMessage);
    await transport.close();

    expect(delivered).toHaveLength(1);
    const error = (delivered[0] as { error: { message: string } }).error;
    expect(error.message).toBe("mcp-re.response_sig_invalid");
  });

  it("still labels a genuine local failure as one", async () => {
    const poster: Poster = async () => {
      throw new Error("socket hang up");
    };
    const transport = new McpReHttpTransport(minimalConfig(), poster);
    const delivered: JSONRPCMessage[] = [];
    transport.onmessage = (m) => delivered.push(m);
    await transport.start();
    await transport.send({ jsonrpc: "2.0", id: 1, method: "tools/list" } as JSONRPCMessage);
    await transport.close();

    const error = (delivered[0] as { error: { message: string } }).error;
    expect(error.message).toMatch(/^mcp-re-sdk: Error: socket hang up$/);
  });
});

describe("McpReHttpTransport delegated-verification anchor", () => {
  // Empty is not a relaxed check — it is a check nothing can satisfy. An empty
  // `acceptedEpochs` rejects every response as a stale trust epoch, an empty
  // `verifierAudiences` as an audience mismatch. The client is unusable rather than
  // unsafe, but it should not have to send a request to find that out. Mirrors
  // `test_an_incomplete_trust_anchor_fails_at_construction`.
  const BLANK: Partial<Record<keyof McpReConfig, unknown>> = {
    issuerKeyId: "",
    issuerPubkeyB64Url: "",
    issuerTrustDomain: "",
    issuerSubject: "",
    expectedAudienceHash: "",
    verifierAudiences: [],
    acceptedEpochs: [],
  };

  for (const field of Object.keys(BLANK) as (keyof McpReConfig)[]) {
    it(`refuses a config with an empty ${field}`, () => {
      expect(
        () =>
          new McpReHttpTransport(
            minimalConfig({ [field]: BLANK[field] } as Partial<McpReConfig>),
            vi.fn<Poster>(),
          ),
      ).toThrow(new RegExp(`trust anchor is incomplete[\\s\\S]*${field}`));
    });
  }
});

describe("McpReHttpTransport revocation denylist shape", () => {
  // `revokedIdentifiers` is the one config field whose wrong value fails OPEN. Every
  // sibling anchor field degrades into "nothing verifies"; a malformed denylist degrades
  // into "nothing is revoked" while still reporting a denylist as configured.

  it("refuses a bare string, which would spread into a per-character denylist", () => {
    // `[..."kid-compromised"]` is a NON-EMPTY list of single characters, none of which
    // can match a delegated kid, issuer kid or credential `jti`. The compromised key
    // stays accepted for its whole TTL and epoch window while the operator believes
    // revocation is in force. `readonly string[]` cannot catch it: the type is erased.
    expect(
      () =>
        new McpReHttpTransport(
          minimalConfig({ revokedIdentifiers: "kid-compromised" as unknown as string[] }),
          vi.fn<Poster>(),
        ),
    ).toThrow(/revokedIdentifiers must be an array/);
  });

  it("refuses an entry that is not a non-empty string", () => {
    // An empty string matches no identifier either, so it is a denylist entry that
    // revokes nothing while making the list look populated.
    expect(
      () =>
        new McpReHttpTransport(
          minimalConfig({ revokedIdentifiers: ["kid-1", ""] }),
          vi.fn<Poster>(),
        ),
    ).toThrow(/non-empty strings/);
    expect(
      () =>
        new McpReHttpTransport(
          minimalConfig({ revokedIdentifiers: [7 as unknown as string] }),
          vi.fn<Poster>(),
        ),
    ).toThrow(/non-empty strings/);
  });

  it("accepts a well-formed denylist, and the empty TTL-only posture", () => {
    expect(
      () => new McpReHttpTransport(minimalConfig({ revokedIdentifiers: ["kid-1"] }), vi.fn<Poster>()),
    ).not.toThrow();
    expect(
      () => new McpReHttpTransport(minimalConfig({ revokedIdentifiers: [] }), vi.fn<Poster>()),
    ).not.toThrow();
    expect(() => new McpReHttpTransport(minimalConfig(), vi.fn<Poster>())).not.toThrow();
  });
});

describe("McpReHttpTransport rejection receipt binding", () => {
  // `transport_replay.test.ts` pins the BOUND value against a recorded receipt. It cannot
  // distinguish reading `verified.bound` from hard-coding `true`, and the unbound case is
  // the security-relevant one, so both verdicts are pinned here against a forced core
  // answer. The Python twin pins the same pair.

  async function rejectionError(bound: boolean): Promise<{ message: string; data: unknown }> {
    boundVerdict.override = bound;
    try {
      const transport = new McpReHttpTransport(minimalConfig(), async () => ({
        status: 409,
        headers: [],
        body: Buffer.from("{}"),
      }));
      await transport.start();
      const delivered: JSONRPCMessage[] = [];
      transport.onmessage = (m) => delivered.push(m);
      await transport.send(REQUEST);
      return (delivered[0] as { error: { message: string; data: unknown } }).error;
    } finally {
      boundVerdict.override = null;
    }
  }

  it("reports a preflight-unbound receipt as NOT request-bound", async () => {
    // The core verifies a rejection receipt request-bound first and preflight-unbound
    // second, and says which one succeeded. An unbound receipt is genuine evidence from a
    // trusted issuer, but it answers no particular transmission — one of them is an answer
    // to every request from every client of that issuer for the credential's validity
    // window — so an application must be able to tell "the boundary rejected MY request"
    // from "a generic rejection arrived" (RSP-7). It is still an error and never a result.
    const error = await rejectionError(false);
    expect(error.message, "the frozen token is what the peer said and must not be rewritten").toBe(
      "mcp-re.authorization_binding_missing",
    );
    expect(error.data).toEqual({ requestBound: false });
  });

  it("reports a request-bound receipt as request-bound", async () => {
    expect((await rejectionError(true)).data).toEqual({ requestBound: true });
  });
});

// The members every forced verdict in this file is built from. Declared once, and checked
// against the binding's OWN declared contract by the control below: four separately written
// object literals could not track a rename in the core, so each would keep passing while the
// transport read `undefined` in production. That is R9-C094's shape one level over — a
// control that cannot fail for the reason that matters (#747).
const FORCED_VERDICT_MEMBERS = [
  "outcome",
  "wireCode",
  "bound",
  "requestState",
  "executionStatus",
  "retrySafety",
  "respEvidenceDigestAlg",
  "respEvidenceDigestValue",
] as const;

describe("the forced verdicts are the core's own shape", () => {
  it("declares no member the binding does not", () => {
    // `native/binding.d.ts` is GENERATED from the Rust type by napi, so a renamed field
    // regenerates it and takes this control red. Read as text rather than imported,
    // because a type-only import is erased at runtime and would assert nothing.
    const declaration = readFileSync(
      resolve(__dirname, "..", "native", "binding.d.ts"),
      "utf8",
    );
    const start = declaration.indexOf("export interface VerifyResultJs {");
    expect(start, "the binding no longer declares VerifyResultJs").toBeGreaterThanOrEqual(0);
    const body = declaration.slice(start, declaration.indexOf("\n}", start));
    const declared = new Set(
      [...body.matchAll(/^\s{2}(\w+)\??:/gm)].map((match) => match[1]),
    );
    expect(declared.size, "no members parsed out of VerifyResultJs").toBeGreaterThan(0);
    const missing = FORCED_VERDICT_MEMBERS.filter((member) => !declared.has(member));
    expect(
      missing,
      `forced verdicts declare ${missing.join(", ")}, which VerifyResultJs does not — the ` +
        `transport would read undefined there in production while these controls stayed green`,
    ).toEqual([]);
  });
});

describe("McpReHttpTransport verified-reply shape", () => {
  /** Drive one exchange with a forced verdict and a chosen reply body. */
  async function deliver(
    verdict: Record<string, unknown>,
    body: string,
  ): Promise<JSONRPCMessage> {
    coreVerdict.override = verdict;
    try {
      const transport = new McpReHttpTransport(minimalConfig(), async () => ({
        status: 200,
        headers: [],
        body: Buffer.from(body),
      }));
      await transport.start();
      const delivered: JSONRPCMessage[] = [];
      transport.onmessage = (m) => delivered.push(m);
      await transport.send(REQUEST);
      return delivered[0];
    } finally {
      coreVerdict.override = null;
    }
  }

  const OK = {
    outcome: "success",
    wireCode: null,
    bound: true,
    requestState: null,
    respEvidenceDigestAlg: "sha-256",
    respEvidenceDigestValue: "x",
  };

  it("refuses a verified reply carrying a top-level method instead of dispatching it", async () => {
    // `JSONRPCMessageSchema` is a union that accepts a request, so a body carrying both a
    // legal `result` and a `method` validated as a JSONRPCRequest and was dispatched by
    // `Client` as a SERVER-INITIATED request — driving sampling / elicitation / roots on
    // peer-chosen params. The awaiting `callTool` never resolved either, because its id
    // had been consumed as an inbound request id.
    const delivered = await deliver(
      OK,
      '{"jsonrpc":"2.0","id":1,"result":{"ok":true},"method":"sampling/createMessage","params":{"x":1}}',
    );
    expect("method" in delivered, `a method-bearing body reached the client: ${JSON.stringify(delivered)}`).toBe(false);
    expect((delivered as { error: { message: string } }).error.message).toBe(
      "mcp-re.malformed_envelope",
    );
  });

  it("refuses a verified reply that is not a JSON-RPC response at all", async () => {
    for (const body of [
      '{"jsonrpc":"2.0","id":1}',
      '{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}',
      '[{"jsonrpc":"2.0","id":1,"result":{}}]',
      '"ok"',
    ]) {
      const delivered = await deliver(OK, body);
      expect(
        (delivered as { error?: { message: string } }).error?.message,
        `${body} must not be delivered as a result`,
      ).toBe("mcp-re.malformed_envelope");
    }
  });

  it("still delivers an ordinary verified reply", async () => {
    const delivered = await deliver(OK, '{"jsonrpc":"2.0","id":9,"result":{"ok":true}}');
    expect((delivered as { result: unknown }).result).toEqual({ ok: true });
  });

  it("reports the execution and retry contract a post-dispatch rejection carried", async () => {
    // ADR-MCPRE-058 §10 (SL-10). Nothing on the client side read these, so an application
    // receiving a post-dispatch 503 saw a bare wire code and a retry-friendly status,
    // retried, and the tool call ran a second time on a fresh nonce that passes replay
    // admission. Byte-parity fixtures cannot see this; the Python twin pins the same keys.
    const delivered = await deliver(
      {
        outcome: "rejection",
        wireCode: "mcp-re.upstream_unavailable",
        bound: true,
        requestState: null,
        executionStatus: "possibly_executed",
        retrySafety: "unsafe_without_reconciliation",
        continuationStatus: "consumed",
        retentionStatus: null,
      },
      "{}",
    );
    const error = (delivered as { error: { message: string; data: unknown } }).error;
    expect(error.message).toBe("mcp-re.upstream_unavailable");
    expect(error.data, "a member the receipt did not carry must not be invented").toEqual({
      requestBound: true,
      executionStatus: "possibly_executed",
      retrySafety: "unsafe_without_reconciliation",
      continuationStatus: "consumed",
    });
  });

  it("invents no disposition for a receipt that stated none", async () => {
    const delivered = await deliver(
      {
        outcome: "rejection",
        wireCode: "mcp-re.request_signature_invalid",
        bound: false,
        requestState: null,
      },
      "{}",
    );
    expect((delivered as { error: { data: unknown } }).error.data).toEqual({
      requestBound: false,
    });
  });
});
