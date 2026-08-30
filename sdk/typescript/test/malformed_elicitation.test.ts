// SPDX-License-Identifier: Apache-2.0
//
// A verified reply that declares itself non-terminal and withholds its state.
//
// The binding used to hand-roll its own JSON walk over the verified body and collapse
// every failure of that walk to `undefined` — which the transport reads as "terminal".
// So a delegated-signed, fully verified `input_required` reply carrying no usable
// `requestState` was reported as an ordinary completed result: the open leg's
// correlation entry was consumed, `onInputRequired` never fired, no answer leg was ever
// signed, and an elicitation reached the application as a finished tool result.
//
// Classification now runs in the audited core, which refuses the malformed middle ground
// instead of resolving it to "terminal".
//
// The fixture is a REAL delegated-signed exchange, not a construction: only its body is
// malformed, and the generator asserts the response still verifies as genuine evidence
// before freezing it — otherwise this would prove refusal for the wrong reason. It cannot
// be recorded from the proxy, because a conformant MCP-RE proxy now rejects this body
// rather than serving it; it stands for a non-conformant or hostile server. Regenerate
// with the command in `sdk/fixtures/malformed_elicitation.json`'s `_comment`.
//
// Mirrors `sdk/python/tests/test_malformed_elicitation.py` — same fixture, same
// assertions.
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { verifyResponse } from "../src/index.js";

const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const FIXTURE = JSON.parse(
  readFileSync(join(REPO_ROOT, "sdk", "fixtures", "malformed_elicitation.json"), "utf8"),
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

describe("a non-terminal reply that withholds its request state", () => {
  // THE regression: refused, not reported as a terminal result.
  it("is refused rather than reported as terminal", () => {
    let raised: unknown;
    try {
      verify(b64url(FIXTURE.exchange.body_b64url));
    } catch (e) {
      raised = e;
    }
    expect(raised, "the malformed reply was accepted as a result").toBeDefined();
    // Refused for the RIGHT reason: the body is malformed, not the signature.
    expect(String(raised)).toContain("malformed_envelope");
  });

  // The precondition that makes the test above meaningful. If the fixture failed
  // verification outright, refusal would prove nothing about classification: tampering
  // with one byte of the signed body must produce a DIFFERENT failure than the
  // malformed-classification one, which is only observable if the untampered bytes get
  // as far as classification.
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
    expect(String(raised)).not.toContain("malformed_envelope");
  });
});
