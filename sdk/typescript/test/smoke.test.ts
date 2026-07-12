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
  it("exposes a non-empty core version and RFC 9421 profile tag", () => {
    expect(typeof coreVersion()).toBe("string");
    expect(coreVersion().length).toBeGreaterThan(0);
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
      "nonce-smoke-0001",
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
