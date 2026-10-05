// SPDX-License-Identifier: Apache-2.0
//
// The pinned root anchor is judged at the caller's `now`, and its identity is never empty.
// Replays the recorded proxy exchanges in `sdk/fixtures/delegated_response_replay.json`:
// re-signing a recorded request reproduces its bytes, so the recorded reply answers it.
// Mirrors `TestPinnedRoot` in `sdk/python/bazel_tests/core_lane_test.py`.
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  signNotification,
  signRequest,
  verifyAccepted202,
  verifyResponse,
} from "../src/index.js";

const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const F = JSON.parse(
  readFileSync(join(REPO_ROOT, "sdk", "fixtures", "delegated_response_replay.json"), "utf8"),
);
const NOW: number = F.created;

type Signed = ReturnType<typeof signRequest>;
type Issuer = { key_id: string; role: string; trust_domain: string; subject: string };

function signed(index: number): [Signed, any] {
  const seed = Buffer.from(F.client_seed_b64, "base64");
  const nonce = `${F.nonce_prefix}${String(index).padStart(4, "0")}`;
  const expires = F.created + F.request_ttl;
  const s =
    index === 0
      ? signRequest(
          seed,
          F.key_id,
          "0",
          "initialize",
          JSON.stringify({
            capabilities: {},
            clientInfo: F.expect.client_info,
            protocolVersion: F.expect.protocol_version,
          }),
          F.target_uri,
          F.audience_id,
          F.route,
          F.dpop_token,
          nonce,
          F.created,
          expires,
        )
      : signNotification(
          seed,
          F.key_id,
          "notifications/initialized",
          "{}",
          F.target_uri,
          F.audience_id,
          F.route,
          F.dpop_token,
          nonce,
          F.created,
          expires,
        );
  const exchange = F.exchanges[index];
  expect(s.body.equals(Buffer.from(exchange.request_body_b64, "base64"))).toBe(true);
  return [s, exchange];
}

function verify(
  fn: typeof verifyResponse | typeof verifyAccepted202,
  [s, exchange]: [Signed, any],
  over: Partial<Issuer> = {},
  retiredUntil?: number,
) {
  const issuer = { ...F.issuer, ...over };
  return fn(
    exchange.status,
    exchange.headers.map(([key, value]: [string, string]) => ({ key, value })),
    Buffer.from(exchange.body_b64, "base64"),
    s.method,
    s.targetUri,
    s.headers,
    s.body,
    issuer.key_id,
    issuer.pubkey_b64url,
    issuer.role,
    issuer.trust_domain,
    issuer.subject,
    F.verifier_audiences,
    F.expected_audience_hash,
    F.accepted_epochs,
    F.max_clock_skew,
    [],
    NOW,
    retiredUntil,
  );
}

describe("the pinned root anchor", () => {
  it("a current root verifies the recorded reply", () => {
    expect(verify(verifyResponse, signed(0)).outcome).toBe("success");
  });

  it("a retired root verifies through its deadline and not after", () => {
    expect(verify(verifyResponse, signed(0), {}, NOW).outcome).toBe("success");
    expect(() => verify(verifyResponse, signed(0), {}, NOW - 1)).toThrow(
      "mcp-re.delegation_issuer_untrusted",
    );
  });

  it("a retired root acknowledges a notification only inside its window", () => {
    verify(verifyAccepted202, signed(1), {}, NOW);
    expect(() => verify(verifyAccepted202, signed(1), {}, NOW - 1)).toThrow(
      "mcp-re.delegation_issuer_untrusted",
    );
  });

  it("an empty identity field is refused by name", () => {
    const names: Record<keyof Issuer, string> = {
      key_id: "issuerKeyId",
      role: "issuerRole",
      trust_domain: "issuerTrustDomain",
      subject: "issuerSubject",
    };
    for (const [field, name] of Object.entries(names)) {
      for (const blank of ["", "  "]) {
        for (const fn of [verifyResponse, verifyAccepted202]) {
          expect(() => verify(fn, signed(0), { [field]: blank })).toThrow(
            `invalid issuer identity: ${name} is empty`,
          );
        }
      }
    }
  });
});
