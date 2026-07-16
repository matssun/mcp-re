// SPDX-License-Identifier: Apache-2.0
//
// Key custody (ADR-MCPS-044 §Compliance): the two explicit custody classes and the
// hardening policy that accepts only the stronger one.
//
// The load-bearing claim is that NON-EXPORTING custody is a pure custody change: the
// signed preimage — and therefore every byte of evidence — is identical to the
// software path. The key has moved behind a device; the protocol has not changed.
import { describe, it, expect } from "vitest";
import {
  CustodyClass,
  McpReError,
  Signer,
  SignerPolicy,
  SigningDevice,
  signPreimage,
  type SignRequestArgs,
} from "../src/index.js";

const SEED = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const OTHER_SEED = Buffer.from(Array.from({ length: 32 }, () => 7));
const SIGNER_ID = "did:example:client";
const KEY_ID = "key-1";

const ARGS: SignRequestArgs = {
  idJson: "1",
  method: "tools/list",
  paramsJson: "{}",
  targetUri: "https://proxy.internal:8600/mcp",
  audienceId: "did:example:server-1",
  route: null,
  dpopToken: "dpop-token",
  nonce: "nonce-custody-0001",
  created: 1000,
  expires: 2000,
};

describe("custody classes", () => {
  it("labels a software signer and a non-exporting signer distinctly", () => {
    const sw = Signer.software(SEED, SIGNER_ID, KEY_ID);
    const ne = Signer.nonExporting(SIGNER_ID, KEY_ID, (p) => signPreimage(SEED, p));
    expect(sw.custody).toBe(CustodyClass.Software);
    expect(ne.custody).toBe(CustodyClass.NonExporting);
  });

  it("rejects a seed that is not exactly 32 bytes", () => {
    expect(() => Signer.software(Buffer.alloc(31), SIGNER_ID, KEY_ID)).toThrow(/32 bytes/);
    expect(() => SigningDevice.fromSeed(Buffer.alloc(33))).toThrow(/32 bytes/);
  });

  it("rejects a non-callable sign callback", () => {
    // @ts-expect-error deliberately wrong type at the boundary
    expect(() => Signer.nonExporting(SIGNER_ID, KEY_ID, "not-a-function")).toThrow(TypeError);
  });

  it("never renders key material", () => {
    const dev = SigningDevice.fromSeed(SEED);
    expect(dev.toString()).toBe("SigningDevice(<sealed>)");
    const s = Signer.software(SEED, SIGNER_ID, KEY_ID).toString();
    expect(s).toContain(SIGNER_ID);
    expect(s).not.toContain(SEED.toString("hex"));
  });
});

describe("non-exporting custody is byte-identical to software custody", () => {
  it("produces the same evidence, body, and headers via a SigningDevice", () => {
    const sw = Signer.software(SEED, SIGNER_ID, KEY_ID);
    const ne = Signer.fromDevice(SIGNER_ID, KEY_ID, SigningDevice.fromSeed(SEED));

    const a = sw.signRequest(ARGS);
    const b = ne.signRequest(ARGS);

    expect(b.evidenceDigestAlg).toBe(a.evidenceDigestAlg);
    expect(b.evidenceDigestValue).toBe(a.evidenceDigestValue);
    expect(Buffer.compare(b.body, a.body)).toBe(0);
    expect(b.headers).toEqual(a.headers);
    expect(b.targetUri).toBe(a.targetUri);
    expect(b.method).toBe(a.method);
  });

  it("holds only the callback — the device is the sole holder of the key", () => {
    const dev = SigningDevice.fromSeed(SEED);
    let sawPreimage: Buffer | undefined;
    const signer = Signer.nonExporting(SIGNER_ID, KEY_ID, (preimage) => {
      sawPreimage = preimage; // the RFC 9421 signature base, not key material
      return dev.sign(preimage);
    });
    const signed = signer.signRequest(ARGS);
    expect(sawPreimage).toBeDefined();
    expect(sawPreimage!.length).toBeGreaterThan(0);
    // The device returns a 64-byte detached Ed25519 signature over that exact base.
    expect(dev.sign(sawPreimage!).length).toBe(64);
    expect(signed.evidenceDigestValue.length).toBeGreaterThan(0);
  });
});

describe("a device that cannot sign fails closed", () => {
  it("maps a throwing device to mcp-re.invalid_signature", () => {
    const signer = Signer.nonExporting(SIGNER_ID, KEY_ID, () => {
      throw new Error("HSM unavailable");
    });
    expect(() => signer.signRequest(ARGS)).toThrow(/mcp-re\.invalid_signature/);
  });

  it("maps a wrong-length signature to mcp-re.invalid_signature", () => {
    const signer = Signer.nonExporting(SIGNER_ID, KEY_ID, () => Buffer.alloc(63));
    expect(() => signer.signRequest(ARGS)).toThrow(/mcp-re\.invalid_signature/);
  });

  it("never emits unsigned evidence when the device misbehaves", () => {
    const signer = Signer.nonExporting(SIGNER_ID, KEY_ID, () => Buffer.alloc(0));
    expect(() => signer.signRequest(ARGS)).toThrow();
  });
});

describe("SignerPolicy fails closed", () => {
  const sw = Signer.software(SEED, SIGNER_ID, KEY_ID);
  const ne = Signer.fromDevice(SIGNER_ID, KEY_ID, SigningDevice.fromSeed(SEED));

  it("hardening rejects software custody with mcp-re.actor_binding_failed", () => {
    try {
      SignerPolicy.hardened(SIGNER_ID).check(sw);
      throw new Error("expected the hardening profile to reject software custody");
    } catch (e) {
      expect(e).toBeInstanceOf(McpReError);
      expect((e as McpReError).wireCode).toBe("mcp-re.actor_binding_failed");
    }
  });

  it("hardening accepts non-exporting custody", () => {
    expect(() => SignerPolicy.hardened(SIGNER_ID).check(ne)).not.toThrow();
  });

  it("rejects a signer whose id is not the route's expected signer", () => {
    const wrong = Signer.software(OTHER_SEED, "did:example:impostor", KEY_ID);
    try {
      new SignerPolicy(SIGNER_ID).check(wrong);
      throw new Error("expected the policy to reject a foreign signer id");
    } catch (e) {
      expect((e as McpReError).wireCode).toBe("mcp-re.actor_binding_failed");
    }
  });

  it("the permissive profile accepts software custody", () => {
    expect(() => new SignerPolicy(SIGNER_ID, "development").check(sw)).not.toThrow();
  });
});
