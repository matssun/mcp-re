// SPDX-License-Identifier: Apache-2.0
//
// Smoke tests for the built TypeScript SDK downloader package (see the
// `downloader — TypeScript napi package` CI lane). They prove the artifact stands
// on its own: the native napi addon loads, the audited version/profile are
// exposed, and the RFC 9421 signing path produces a signed request with the
// expected header + evidence shape. No live transport or workspace binary is
// required, so this lane never self-skips.
import { describe, it, expect } from "vitest";
import { coreVersion, profileTag, signRequest } from "../src/index.js";

describe("mcp-re-sdk smoke (built package)", () => {
  it("reports the audited core's version, not this wrapper's", () => {
    // r12 R12-1474 — `coreVersion` used to return the N-API wrapper's own
    // CARGO_PKG_VERSION (0.1.x), which moves independently of the audited code. A
    // consumer asking which core they have was told the version of the shim in front
    // of it, and "non-empty string" could not see that: 0.1.1 is non-empty too.
    const v = coreVersion();
    expect(typeof v).toBe("string");
    const [major, minor] = v.split(".").map(Number);
    expect(major > 0 || minor >= 17).toBe(true);
    expect(typeof profileTag()).toBe("string");
    expect(profileTag().length).toBeGreaterThan(0);
  });

  it("signs an MCP request as an RFC 9421 message", () => {
    const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
    const signed = signRequest(
      seed,
      "key-1",
      "1", // id (JSON)
      "tools/list", // JSON-RPC method
      "{}", // params (JSON object)
      "https://proxy.internal:8600/mcp", // targetUri
      "did:example:server-1", // audienceId
      undefined, // route
      "dpop-token",
      "nonce-smoke-0001-128bit", // >= the 22-char (128-bit) emission floor
      1000, // created
      2000, // expires
    );
    const headers = new Map(
      signed.headers.map((h) => [h.key.toLowerCase(), h.value]),
    );
    expect(headers.has("signature")).toBe(true);
    expect(headers.has("signature-input")).toBe(true);
    expect(headers.has("content-digest")).toBe(true);
    expect(signed.method).toBe("POST"); // HTTP method carrying the JSON-RPC body
    expect(signed.targetUri).toBe("https://proxy.internal:8600/mcp");
    expect(signed.evidenceDigestValue.length).toBeGreaterThan(0);
    expect(signed.body.length).toBeGreaterThan(0);
  });
});
