// SPDX-License-Identifier: Apache-2.0
//
// A verified reply whose `resultType` is outside the set MCP 2026-07-28 defines.
//
// The specification names `complete` and `input_required`, lets extensions add values the
// client has advertised support for, and then closes the set: an unrecognized value MUST
// be considered invalid. This SDK advertises no extension result types.
//
// Reading an unrecognized value as terminal is the failure worth naming precisely. An
// extension's NON-terminal result would end the exchange: the correlation entry closes,
// `onInputRequired` never fires, no answer leg is ever signed, and a continuation reaches
// the application as a finished tool result — the same silent completion
// `malformed_elicitation.test.ts` covers, arrived at from the other direction.
//
// The fixture is a REAL delegated-signed exchange; only its result type is unreadable, and
// the generator asserts the response still verifies as genuine evidence before freezing it.
// A conformant MCP-RE proxy refuses to sign such a reply at all, so this stands for a
// non-conformant or hostile server — which is exactly why the SDK must refuse it too.
// Regenerate with the command in `sdk/fixtures/unrecognized_result_type.json`'s `_comment`.
//
// Mirrors `sdk/python/tests/test_unrecognized_result_type.py` — same fixture, same
// assertions.
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { verifyResponse } from "../src/index.js";

const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const FIXTURE = JSON.parse(
  readFileSync(join(REPO_ROOT, "sdk", "fixtures", "unrecognized_result_type.json"), "utf8"),
);

const b64url = (s: string): Buffer => Buffer.from(s, "base64url");
const headers = (pairs: [string, string][]) => pairs.map(([key, value]) => ({ key, value }));

/** Run the frozen exchange through the binding, with `body` as the reply. */
function verify(body: Buffer) {
  const f = FIXTURE;
  const x = f.exchange;
  return verifyResponse(
    x.status,
    headers(x.headers),
    body,
    x.request_method,
    x.request_target_uri,
    headers(x.request_headers),
    b64url(x.request_body_b64url),
    x.request_evidence_digest_alg,
    x.request_evidence_digest_value,
    f.issuer.key_id,
    f.issuer.pubkey_b64url,
    f.issuer.role,
    f.issuer.trust_domain,
    f.issuer.subject,
    [f.audience_id],
    f.expected_audience_hash,
    f.accepted_epochs,
    f.max_clock_skew,
    [],
    f.now,
  );
}

describe("a reply carrying an unrecognized resultType", () => {
  it("is refused rather than read as terminal", () => {
    let raised: unknown;
    try {
      verify(b64url(FIXTURE.exchange.body_b64url));
    } catch (e) {
      raised = e;
    }
    expect(raised, "the unclassifiable reply was accepted as a result").toBeDefined();
    // Refused for the RIGHT reason: the message declares a continuation model this
    // reader does not implement — not that the evidence was bad, which it was not.
    expect(String(raised)).toContain("continuation_type_unsupported");
  });

  // The precondition that makes the test above meaningful. If the fixture failed
  // verification outright, refusal would prove nothing about classification: tampering
  // with one byte of the signed body must produce a DIFFERENT failure, which is only
  // observable if the untampered bytes get as far as classification.
  it("is otherwise genuine evidence", () => {
    const tampered = Buffer.from(b64url(FIXTURE.exchange.body_b64url));
    tampered[tampered.length - 2] ^= 0xff;
    let raised: unknown;
    try {
      verify(tampered);
    } catch (e) {
      raised = e;
    }
    expect(raised, "a tampered body must fail").toBeDefined();
    expect(String(raised)).not.toContain("continuation_type_unsupported");
  });
});
