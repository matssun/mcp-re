// SPDX-License-Identifier: Apache-2.0
//
// Cross-language parity gate (ADR-MCPS-044 §shared seam).
//
// Both SDKs bind the SAME audited `mcp-re-client-core`, so the canonical signed
// preimage is byte-identical across them *by construction*. This file turns that claim
// into a gate: `sdk/fixtures/parity_vectors.json` freezes the bytes, and both this file
// and its Python twin (`sdk/python/tests/test_parity.py`) assert against them.
//
// Either binding drifting from the other — or from the core — fails here rather than
// shipping. Regenerate the oracle with `tools/gen_sdk_parity_fixture.py`.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, it, expect } from "vitest";
import { profileTag, signRequest, Signer, SigningDevice } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(HERE, "..", "..", "fixtures", "parity_vectors.json");

interface Expected {
  method: string;
  target_uri: string;
  headers: [string, string][];
  body_b64: string;
  evidence_digest_alg: string;
  evidence_digest_value: string;
}
interface Case {
  inputs: Record<string, unknown>;
  expected: Expected;
}
interface Oracle {
  schema: string;
  profile_tag: string;
  cases: Record<string, Case>;
}

const ORACLE: Oracle = JSON.parse(readFileSync(FIXTURE, "utf8"));
const NAMES = Object.keys(ORACLE.cases).sort();

/** Reproduce a frozen case with this SDK. */
function sign(name: string) {
  const c = ORACLE.cases[name];
  const i = c.inputs as Record<string, never>;
  const seed = Buffer.from(i["seed_b64"] as unknown as string, "base64");
  const keyId = i["key_id"] as unknown as string;
  const args = {
    idJson: i["id_json"] as unknown as string,
    method: i["method"] as unknown as string,
    paramsJson: i["params_json"] as unknown as string,
    targetUri: i["target_uri"] as unknown as string,
    audienceId: i["audience_id"] as unknown as string,
    route: (i["route"] ?? null) as unknown as string | null,
    dpopToken: i["dpop_token"] as unknown as string,
    nonce: i["nonce"] as unknown as string,
    created: i["created"] as unknown as number,
    expires: i["expires"] as unknown as number,
    contPrevAlg: (i["cont_prev_alg"] ?? null) as unknown as string | null,
    contPrevValue: (i["cont_prev_value"] ?? null) as unknown as string | null,
    contIrrAlg: (i["cont_irr_alg"] ?? null) as unknown as string | null,
    contIrrValue: (i["cont_irr_value"] ?? null) as unknown as string | null,
    contRequestState: (i["cont_request_state"] ?? null) as unknown as string | null,
  };
  if (name.startsWith("non_exporting")) {
    const signer = Signer.fromDevice("did:example:client", keyId, SigningDevice.fromSeed(seed));
    return { signed: signer.signRequest(args), expected: c.expected };
  }
  const signed = signRequest(
    seed,
    keyId,
    args.idJson,
    args.method,
    args.paramsJson,
    args.targetUri,
    args.audienceId,
    args.route,
    args.dpopToken,
    args.nonce,
    args.created,
    args.expires,
    args.contPrevAlg,
    args.contPrevValue,
    args.contIrrAlg,
    args.contIrrValue,
    args.contRequestState,
  );
  return { signed, expected: c.expected };
}

describe("the frozen parity oracle", () => {
  it("is the expected schema and is non-empty", () => {
    expect(ORACLE.schema).toBe("mcp-re-sdk-parity/v1");
    expect(NAMES.length).toBeGreaterThan(0);
  });

  it("agrees with this SDK on the profile tag", () => {
    expect(profileTag()).toBe(ORACLE.profile_tag);
  });
});

describe("signed bytes match the frozen oracle", () => {
  it.each(NAMES)("%s reproduces byte-for-byte", (name) => {
    const { signed, expected } = sign(name);
    expect(signed.method).toBe(expected.method);
    expect(signed.targetUri).toBe(expected.target_uri);
    expect(signed.headers.map((h) => [h.key, h.value])).toEqual(expected.headers);
    expect(signed.body.toString("base64")).toBe(expected.body_b64);
    expect(signed.evidenceDigestAlg).toBe(expected.evidence_digest_alg);
    expect(signed.evidenceDigestValue).toBe(expected.evidence_digest_value);
  });

  it.each(NAMES)("%s signs deterministically", (name) => {
    const a = sign(name).signed;
    const b = sign(name).signed;
    expect(Buffer.compare(a.body, b.body)).toBe(0);
    expect(a.evidenceDigestValue).toBe(b.evidenceDigestValue);
  });
});

describe("the oracle bytes witness the custody claim", () => {
  it("non-exporting custody equals software custody", () => {
    const sw = ORACLE.cases["software_tools_list"].expected;
    const ne = ORACLE.cases["non_exporting_tools_list"].expected;
    expect(ne.body_b64).toBe(sw.body_b64);
    expect(ne.headers).toEqual(sw.headers);
    expect(ne.evidence_digest_value).toBe(sw.evidence_digest_value);
  });

  it("a signed continuation changes the evidence it rides in", () => {
    const base = ORACLE.cases["software_tools_list"].expected;
    const cont = ORACLE.cases["continuation_answer_leg"].expected;
    expect(cont.body_b64).not.toBe(base.body_b64);
    expect(cont.evidence_digest_value).not.toBe(base.evidence_digest_value);
  });
});
