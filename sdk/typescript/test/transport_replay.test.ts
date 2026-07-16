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
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

import { Signer } from "../src/index.js";
import { McpReHttpTransport, type HttpReply, type McpReConfig, type Poster } from "../src/transport.js";

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

async function callTool(c: McpReConfig, poster: Poster) {
  // `initialize` params carry the MCP CLIENT LIBRARY's own identity, so they must match
  // what the recording's client announced or the request bytes differ for a reason that
  // has nothing to do with MCP-RE. The fixture records the Python SDK's defaults.
  const client = new Client(FIXTURE.expect.client_info);
  await client.connect(new McpReHttpTransport(c, poster));
  try {
    return await client.callTool({ name: FIXTURE.tool.name, arguments: FIXTURE.tool.arguments });
  } finally {
    await client.close();
  }
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
});
