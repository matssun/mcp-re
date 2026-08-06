// SPDX-License-Identifier: Apache-2.0
//
// Replay a RECORDED delegated session through the transport adapter, offline.
//
// `transport_e2e.test.ts` proves the adapter against the real proxy, but it needs a built
// Rust example and `fastmcp` on PATH, so it self-skips in the npm downloader CI lane —
// exactly where the shipped artifact is gated. This replays a frozen recording of a
// genuine delegated session instead, so the whole verification path (credential chain,
// trust epoch, audience, RFC 9530 content-digest, request binding, evidence stripping) is
// exercised with no infrastructure at all.
//
// The bytes are RECORDINGS, not constructions: the proxy signed them with a real delegated
// key under a real credential the root issued. Nothing here imitates the wire format, so a
// change to it fails this test rather than passing a hand-rolled lookalike.
//
// The replay is only legitimate if the adapter reproduces the request the recorded response
// was signed against, so `replayingPoster` asserts exactly that, byte for byte, before
// serving each reply. It is also the cross-language claim: this fixture was recorded by the
// PYTHON adapter, so TypeScript reproducing the same request bytes and accepting the same
// responses is the parity oracle applied to the transport itself.
//
// Re-record with `tools/gen_sdk_transport_fixture.py`. Mirrors
// `sdk/python/tests/test_transport_replay.py` — same fixture, same assertions.
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import type { JSONRPCMessage } from "@modelcontextprotocol/client";

import { ContinuationHandles, Signer } from "../src/index.js";
import {
  McpReHttpTransport,
  type HttpReply,
  type InputRequired,
  type McpReConfig,
  type Poster,
} from "../src/transport.js";

const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const FIXTURE = JSON.parse(
  readFileSync(join(REPO_ROOT, "sdk", "fixtures", "delegated_response_replay.json"), "utf8"),
);

/** The recorded sequence: deterministic, but never repeating. */
function nonceSequence(): () => string {
  let n = 0;
  return () => `${FIXTURE.nonce_prefix}${String(n++).padStart(4, "0")}`;
}

function config(over: Partial<McpReConfig> = {}): McpReConfig {
  return {
    signer: Signer.software(
      Buffer.from(FIXTURE.client_seed_b64, "base64"),
      FIXTURE.signer_id,
      FIXTURE.key_id,
    ),
    audienceId: FIXTURE.audience_id,
    targetUri: FIXTURE.target_uri,
    route: FIXTURE.route,
    dpopToken: FIXTURE.dpop_token,
    issuerKeyId: FIXTURE.issuer.key_id,
    issuerPubkeyB64Url: FIXTURE.issuer.pubkey_b64url,
    issuerRole: FIXTURE.issuer.role,
    issuerTrustDomain: FIXTURE.issuer.trust_domain,
    issuerSubject: FIXTURE.issuer.subject,
    verifierAudiences: FIXTURE.verifier_audiences,
    expectedAudienceHash: FIXTURE.expected_audience_hash,
    acceptedEpochs: FIXTURE.accepted_epochs,
    maxClockSkew: FIXTURE.max_clock_skew,
    requestTtl: FIXTURE.request_ttl,
    // A response is bound to the request that produced it, so the request must be
    // byte-reproducible: pin the only two inputs that float. The same frozen instant is
    // handed to verification, keeping the recorded credential inside its window.
    nonceFactory: nonceSequence(),
    clock: () => FIXTURE.created,
    ...over,
  };
}

/** Serve the recorded replies in order, refusing to serve one for a request the recording
 * was not made against. */
function replayingPoster(mutate?: (r: HttpReply) => HttpReply): Poster {
  let i = 0;
  return async (_method, _targetUri, _headers, body) => {
    const exchange = FIXTURE.exchanges[i++];
    // If the adapter did not reproduce the recorded request byte-for-byte, the recorded
    // response does not answer it and replaying it would prove nothing.
    expect(
      body.toString("base64"),
      `exchange ${i - 1}: the adapter's request bytes drifted from the recording ` +
        `(re-record with tools/gen_sdk_transport_fixture.py)`,
    ).toBe(exchange.request_body_b64);
    const reply: HttpReply = {
      status: exchange.status,
      headers: (exchange.headers as [string, string][]).map(([key, value]) => ({ key, value })),
      body: Buffer.from(exchange.body_b64, "base64"),
    };
    return mutate ? mutate(reply) : reply;
  };
}

/** The recorded `initialize`, built here rather than taken from `Client`.
 *
 * The recording pins exact request bytes, and the JSON-RPC id counter belongs to the
 * session layer, not to this adapter. At MCP 2.0 the two official SDKs disagree about it:
 * `mcp` (Python) numbers from 1 and adds an empty `params._meta`, while
 * `@modelcontextprotocol/client` numbers from 0 and adds neither — so a recording
 * captured through either session could not be replayed by both. Driving the script
 * explicitly keeps the fixture a claim about the bytes THIS adapter signs. A real
 * `Client` session is covered end-to-end in `transport_e2e.test.ts`.
 *
 * `initialize` params carry the MCP CLIENT LIBRARY's own identity and the negotiated
 * protocol revision; both are read from the recording so the bytes match for reasons that
 * have nothing to do with either SDK's defaults drifting.
 */
function initializeRequest(): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id: 0,
    method: "initialize",
    params: {
      capabilities: {},
      clientInfo: FIXTURE.expect.client_info,
      protocolVersion: FIXTURE.expect.protocol_version,
    },
  };
}

/** Drive the recorded script through the transport and return the tool result. */
async function callTool(c: McpReConfig, poster: Poster) {
  const replies: JSONRPCMessage[] = [];
  const transport = new McpReHttpTransport(c, poster);
  transport.onmessage = (m) => {
    replies.push(m);
  };
  await transport.start();
  try {
    await transport.send(initializeRequest());
    await transport.send({ jsonrpc: "2.0", method: "notifications/initialized" });
    await transport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: FIXTURE.tool.name, arguments: FIXTURE.tool.arguments },
    });
  } finally {
    await transport.close();
  }
  const last = replies[replies.length - 1] as { result: Record<string, unknown> };
  return last.result;
}

describe("McpReHttpTransport replaying a recorded delegated session", () => {
  it("verifies the recording and hands the app plain MCP", async () => {
    const result = await callTool(config(), replayingPoster());

    expect(result.structuredContent).toEqual(FIXTURE.expect.structured_content);
    expect((result.content as { text: string }[])[0].text).toBe(FIXTURE.expect.text);
    // MCP-RE's own evidence is not part of the MCP result.
    expect(result.structuredContent).not.toHaveProperty("_meta");
  });

  it("fails closed when one byte is appended to the recorded body", async () => {
    // RFC 9530 content-digest covers the raw body. A trailing space keeps the JSON valid
    // on purpose: the response must be refused on its evidence, not on a parse error.
    const tamper = (r: HttpReply): HttpReply => ({
      ...r,
      body: Buffer.concat([r.body, Buffer.from(" ")]),
    });
    await expect(callTool(config(), replayingPoster(tamper))).rejects.toThrow(/mcp-re\./);
  });

  it("refuses the same recorded response under an untrusted root anchor", async () => {
    // The recording is genuine; the anchor is wrong. A delegated response is only as good
    // as the root it chains to, so this must fail as loudly as a forgery. The recorded key
    // is a REAL Ed25519 public key from a different seed — a malformed one would be
    // refused as bad configuration and would prove nothing about the trust decision.
    await expect(
      callTool(config({ issuerPubkeyB64Url: FIXTURE.foreign_root_pubkey_b64url }), replayingPoster()),
    ).rejects.toThrow(/mcp-re\./);
  });

  it("refuses a response outside the accepted trust epoch", async () => {
    await expect(
      callTool(config({ acceptedEpochs: ["epoch-does-not-match"] }), replayingPoster()),
    ).rejects.toThrow(/mcp-re\.delegation_trust_epoch_stale/);
  });

  it("refuses a response for a different audience", async () => {
    await expect(
      callTool(config({ expectedAudienceHash: "aud-scope-somewhere-else" }), replayingPoster()),
    ).rejects.toThrow(/mcp-re\./);
  });

  it("refuses a revoked delegated key", async () => {
    // Revocation is checked against the credential's own delegated kid.
    await expect(
      callTool(config({ revokedIdentifiers: [FIXTURE.delegated_key_id] }), replayingPoster()),
    ).rejects.toThrow(/mcp-re\./);
  });

  // --- ADR-MCPS-047: the continuation chain ---------------------------------------
  //
  // Mirrors `test_transport_replay.py`'s continuation group — same fixture, same
  // assertions.

  const ELICIT = FIXTURE.elicitation;
  const ANSWER = ELICIT.answer;

  /** The open leg's nonce, then the answer leg's. A continuation turn is a fresh signed
   * request with its own freshness (continuation profile §10.1). */
  const elicitNonces = () => {
    const nonces = [ELICIT.nonce, ANSWER.nonce];
    let i = 0;
    return () => nonces[i++];
  };

  /** Serve the recorded legs in order, refusing to serve one for a request the recording
   * was not made against. */
  const chainPoster = (legs: { request_body_b64: string; status: number; headers: [string, string][]; body_b64: string }[]) => {
    let i = 0;
    return async (_m: string, _u: string, _h: unknown, body: Buffer) => {
      expect(i, "the adapter sent more legs than were recorded").toBeLessThan(legs.length);
      const leg = legs[i++];
      expect(
        body.toString("base64"),
        `leg ${i - 1}: the adapter's request bytes drifted from the recording ` +
          "(re-record with tools/gen_sdk_transport_fixture.py)",
      ).toBe(leg.request_body_b64);
      return {
        status: leg.status,
        headers: leg.headers.map(([key, value]) => ({ key, value })),
        body: Buffer.from(leg.body_b64, "base64"),
      };
    };
  };

  /** Run one `tools/call` through the adapter against the recorded legs. */
  const drive = async (cfg: McpReConfig, legs: Parameters<typeof chainPoster>[0]) => {
    const transport = new McpReHttpTransport(cfg, chainPoster(legs));
    let reply: any;
    transport.onmessage = (m) => {
      reply = m;
    };
    await transport.start();
    await transport.send({
      jsonrpc: "2.0",
      id: 0,
      method: "tools/call",
      params: { name: ELICIT.tool, arguments: {} },
    });
    return { reply, transport };
  };

  it("drives the answer leg to a terminal result", async () => {
    // The whole point of #419: a multi-round-trip tool is an ordinary call. An
    // `InputRequiredResult` is not a `CallToolResult`, so `Client` cannot carry it — the
    // convention lives BELOW the session layer, which is where the adapter implements
    // it. So the adapter answers the elicitation itself: it signs the answer leg over the
    // VERIFIED handles, posts it, verifies the reply, and hands up the terminal result.
    //
    // The recorded answer-leg request is the load-bearing assertion. Reproducing it
    // byte-for-byte means the adapter built the continuation binding, echoed the opaque
    // `requestState`, and carried `inputResponses` exactly as the profile specifies — the
    // proxy accepted these very bytes when the fixture was recorded.
    const handles: ContinuationHandles[] = [];
    const prompts: InputRequired[] = [];
    const { reply } = await drive(
      config({
        nonceFactory: elicitNonces(),
        onInputRequired: (h) => handles.push(h),
        answerInputRequired: (p) => {
          prompts.push(p);
          return ANSWER.responses;
        },
      }),
      [ELICIT.exchange, ANSWER.exchange],
    );

    expect(handles, "the adapter did not surface the elicitation").toHaveLength(1);
    expect({ ...handles[0] }).toMatchObject({
      prevAlg: ELICIT.expect_handles.prev_alg,
      prevValue: ELICIT.expect_handles.prev_value,
      irrAlg: ELICIT.expect_handles.irr_alg,
      irrValue: ELICIT.expect_handles.irr_value,
      requestState: ELICIT.expect_handles.request_state,
    });

    // The handler is asked with everything answering needs, read from the VERIFIED reply.
    expect(prompts).toHaveLength(1);
    expect(prompts[0].method).toBe("tools/call");
    expect(prompts[0].round).toBe(1);
    expect(prompts[0].result.resultType).toBe("input_required");
    expect(prompts[0].result.requestState).toBe(ELICIT.expect_handles.request_state);
    expect(prompts[0].handles).toBe(handles[0]);

    // A TERMINAL result, not the pause — and under the id the CALLER issued, not the
    // answer leg's own `0/mrt-1`.
    expect(reply.result).toEqual(ANSWER.expect_result);
    expect(reply.id).toBe(ANSWER.expect_id);
  });

  it("refuses an unanswerable elicitation rather than delivering it as a result", async () => {
    // A pause is not an outcome (continuation profile §5.2, §9.3). With no handler
    // installed there is no answer leg to sign, so the call cannot complete. Delivering
    // the `InputRequiredResult` up as the reply would present a call still waiting for
    // input as one that finished.
    const { reply } = await drive(config({ nonceFactory: elicitNonces() }), [ELICIT.exchange]);

    expect(reply.error, "the pause was delivered as a completed call").toBeDefined();
    expect(reply.error.message).toContain("no answerInputRequired handler");
  });

  it("refuses a declined elicitation", async () => {
    // Declining is a decision not to continue, not a decision to accept the pause.
    const { reply } = await drive(
      config({ nonceFactory: elicitNonces(), answerInputRequired: () => null }),
      [ELICIT.exchange],
    );

    expect(reply.error).toBeDefined();
    expect(reply.error.message).toContain("declined");
  });

  it("enforces the continuation ceiling before asking the caller", async () => {
    // A server decides how long a chain runs, so the client must bound it. The ceiling is
    // checked BEFORE the handler: a call that has already spent its continuation budget
    // must not prompt for an answer it cannot send.
    const asked: InputRequired[] = [];
    const { reply } = await drive(
      config({
        nonceFactory: elicitNonces(),
        maxContinuationRounds: 0,
        answerInputRequired: (p) => {
          asked.push(p);
          return {};
        },
      }),
      [ELICIT.exchange],
    );

    expect(reply.error).toBeDefined();
    expect(reply.error.message).toContain("maxContinuationRounds");
    expect(asked, "the handler was asked for an answer that could not be sent").toHaveLength(0);
  });

  it("leaves no correlation entry outstanding after a completed chain", async () => {
    // An open leg is associated, not consumed (ADR-MCPS-047), so something must retire
    // it. Left outstanding, every elicitation would leak an entry for the life of the
    // session — and a peer that can elicit could grow the store at will.
    const { transport } = await drive(
      config({ nonceFactory: elicitNonces(), answerInputRequired: () => ANSWER.responses }),
      [ELICIT.exchange, ANSWER.exchange],
    );
    expect(transport.pendingCorrelations, "the chain left correlation state behind").toBe(0);
  });

  it("leaves no correlation entry outstanding after an unanswered elicitation", async () => {
    // The same bound on the failure path, which is the one a peer can drive.
    const { transport } = await drive(config({ nonceFactory: elicitNonces() }), [ELICIT.exchange]);
    expect(transport.pendingCorrelations).toBe(0);
  });

  it("delivers a verified rejection receipt as an error, not a result", async () => {
    // A recorded DELEGATED rejection: the proxy refused a replayed nonce and signed the
    // refusal. That is genuine evidence but NOT an acceptance. The adapter must verify
    // the receipt, read its frozen wire code from the TRUSTED body (never from the HTTP
    // status), and deliver it as a JSON-RPC error correlated to the request — so the
    // caller rejects instead of hanging, and the refusal never lands as a result.
    const rejection = FIXTURE.rejection;
    const transport = new McpReHttpTransport(
      config({ nonceFactory: () => FIXTURE.elicitation.nonce }),
      async (_m, _u, _h, body) => {
        expect(body.toString("base64")).toBe(rejection.request_body_b64);
        return {
          status: rejection.status,
          headers: (rejection.headers as [string, string][]).map(([key, value]) => ({
            key,
            value,
          })),
          body: Buffer.from(rejection.body_b64, "base64"),
        };
      },
    );

    let reply: unknown;
    transport.onmessage = (m) => {
      reply = m;
    };
    await transport.start();
    await transport.send({
      jsonrpc: "2.0",
      id: 0,
      method: "tools/call",
      params: { name: FIXTURE.elicitation.tool, arguments: {} },
    });

    expect(reply).toMatchObject({
      id: 0,
      error: { code: -31001, message: rejection.expect_wire_code },
    });
    // The core computes whether the receipt is bound to THIS transmission, and that fact
    // must reach the application. An unbound (preflight) receipt carries no binding to
    // this request's nonce or evidence, so one such signed receipt answers any request
    // from any client of that issuer — the caller has to be able to tell "the boundary
    // rejected MY request" from "a generic rejection arrived" (RSP-7). It travels beside
    // the frozen token, never inside it. The Python twin pins the same value.
    expect((reply as { error: { data: unknown } }).error.data).toEqual({ requestBound: true });
  });

  it("stops the continuation chain when close() lands mid-call", async () => {
    // close() aborts, but `Promise.race` in send() only decides which result the CALLER
    // sees — the losing arm keeps running. Without an abort check inside the loop the
    // chain went on signing and POSTing fresh answer legs, re-populating the correlation
    // store, after `onclose` had already fired: valid, correctly-signed requests reaching
    // the server for a call the caller believes it cancelled.
    const legs = [ELICIT.exchange, ANSWER.exchange];
    let posted = 0;
    let transport!: McpReHttpTransport;
    transport = new McpReHttpTransport(
      config({
        nonceFactory: elicitNonces(),
        answerInputRequired: async () => {
          // The application closes while the elicitation is being answered — a timeout,
          // a user cancelling, a shutdown.
          await transport.close();
          return ANSWER.responses;
        },
      }),
      async (_m: string, _u: string, _h: unknown, body: Buffer) => {
        const leg = legs[posted++];
        expect(body.toString("base64")).toBe(leg.request_body_b64);
        return {
          status: leg.status,
          headers: (leg.headers as [string, string][]).map(([key, value]) => ({ key, value })),
          body: Buffer.from(leg.body_b64, "base64"),
        };
      },
    );
    await transport.start();
    await expect(
      transport.send({
        jsonrpc: "2.0",
        id: 0,
        method: "tools/call",
        params: { name: ELICIT.tool, arguments: {} },
      }),
    ).rejects.toThrow(/transport was closed/);

    // The mechanism, not just the status: exactly ONE leg reached the wire. The answer
    // leg was never signed and never posted.
    expect(posted, "an answer leg was signed and POSTed after close()").toBe(1);
    expect(transport.pendingCorrelations, "correlation state outlived the transport").toBe(0);
  });

  it("does not prompt a human for an answer leg a closed transport will never send", async () => {
    // The other half of the same obligation: close() can also land BEFORE the handler
    // runs, and `answerInputRequired` is where a human is asked to approve something.
    // Prompting for an answer leg that can never be signed spends a person's attention
    // on a call the caller already abandoned, and an approval collected that way has
    // nowhere to go.
    let transport!: McpReHttpTransport;
    let prompted = 0;
    let posted = 0;
    transport = new McpReHttpTransport(
      config({
        nonceFactory: elicitNonces(),
        onInputRequired: () => {
          void transport.close();
        },
        answerInputRequired: async () => {
          prompted += 1;
          return ANSWER.responses;
        },
      }),
      async () => {
        posted += 1;
        return {
          status: ELICIT.exchange.status,
          headers: (ELICIT.exchange.headers as [string, string][]).map(([key, value]) => ({
            key,
            value,
          })),
          body: Buffer.from(ELICIT.exchange.body_b64, "base64"),
        };
      },
    );
    await transport.start();
    await expect(
      transport.send({
        jsonrpc: "2.0",
        id: 0,
        method: "tools/call",
        params: { name: ELICIT.tool, arguments: {} },
      }),
    ).rejects.toThrow(/transport was closed/);

    expect(prompted, "a human was prompted after close()").toBe(0);
    expect(posted, "an answer leg reached the wire after close()").toBe(1);
    expect(transport.pendingCorrelations, "correlation state outlived the transport").toBe(0);
  });
});
