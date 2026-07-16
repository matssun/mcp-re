// SPDX-License-Identifier: Apache-2.0
//
// Authorization-binding providers (ADR-MCPS-044 §Authorization-binding hook).
//
// Bind, do not interpret. The provider supplies the artifact; the core digests it and puts
// the digest — never the bytes — into the signed evidence.
//
// The digest is checked against an INDEPENDENT node:crypto SHA-256 oracle, not against the
// core's own opinion of what it computed.
import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
import {
  AuthorizationBindingPolicy,
  AuthzSystemReferenceProvider,
  McpReError,
  OpaqueBytesProvider,
  signRequest,
  bindingsJson,
  type AuthorizationBindingProvider,
  type BindingRequestContext,
  type SignedRequestJs,
} from "../src/index.js";

const SEED = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const BLOCK_KEY = "se.syncom/mcp-re.http.request";
const MATERIAL = Buffer.from("pdp-decision-document-v1");
const OTHER_MATERIAL = Buffer.from("pdp-decision-document-v2");

const CTX: BindingRequestContext = {
  audienceId: "did:example:server-1",
  targetUri: "https://proxy.internal:8600/mcp",
  method: "tools/list",
};

/** An INDEPENDENT digest: node:crypto SHA-256, not the core's. */
const oracleDigest = (material: Buffer): string =>
  createHash("sha256").update(material).digest("base64url");

function sign(providers: AuthorizationBindingProvider[] = [], bj?: string | null): SignedRequestJs {
  const json = bj !== undefined ? bj : bindingsJson(providers, CTX);
  return signRequest(
    SEED,
    "key-1",
    "1",
    "tools/list",
    "{}",
    "https://proxy.internal:8600/mcp",
    "did:example:server-1",
    null,
    "dpop-token",
    "nonce-authz-0001",
    1000,
    2000,
    null,
    null,
    null,
    null,
    null,
    json,
  );
}

interface Binding {
  artifact_type: string;
  binding_type: string;
  digest_alg: string;
  digest_value: string;
  authorization_system_id?: string;
  reference_scheme_id?: string;
  reference_value?: string;
}

const bindings = (s: SignedRequestJs): Binding[] =>
  JSON.parse(s.body.toString())._meta[BLOCK_KEY].artifact_bindings;

const ofType = (s: SignedRequestJs, t: string): Binding =>
  bindings(s).find((b) => b.artifact_type === t)!;

describe("opaque bytes", () => {
  it("has the core digest the real artifact", () => {
    const b = ofType(sign([new OpaqueBytesProvider("pdp-decision", MATERIAL)]), "pdp-decision");
    expect(b.binding_type).toBe("opaque-digest");
    expect(b.digest_alg).toBe("sha256");
    // Checked against node:crypto SHA-256 — an independent oracle.
    expect(b.digest_value).toBe(oracleDigest(MATERIAL));
  });

  it("carries metadata only, never the artifact", () => {
    const s = sign([new OpaqueBytesProvider("pdp-decision", MATERIAL)]);
    expect(s.body.includes(MATERIAL)).toBe(false);
    expect(s.body.toString()).not.toContain(MATERIAL.toString("base64url"));
    expect(Object.keys(ofType(s, "pdp-decision")).sort()).toEqual([
      "artifact_type",
      "binding_type",
      "digest_alg",
      "digest_value",
    ]);
  });

  it("changes the digest when the artifact bytes change", () => {
    const a = sign([new OpaqueBytesProvider("pdp-decision", MATERIAL)]);
    const b = sign([new OpaqueBytesProvider("pdp-decision", OTHER_MATERIAL)]);
    expect(ofType(a, "pdp-decision").digest_value).not.toBe(ofType(b, "pdp-decision").digest_value);
    // ...and therefore the signed evidence differs too.
    expect(a.evidenceDigestValue).not.toBe(b.evidenceDigestValue);
  });

  it("digests deterministically", () => {
    const a = sign([new OpaqueBytesProvider("pdp-decision", MATERIAL)]);
    const b = sign([new OpaqueBytesProvider("pdp-decision", MATERIAL)]);
    expect(Buffer.compare(a.body, b.body)).toBe(0);
  });

  it("gives a caller no way to pass a precomputed digest", () => {
    const spec = new OpaqueBytesProvider("pdp-decision", MATERIAL).spec(CTX);
    expect(spec).not.toHaveProperty("digest_value");
    expect(spec).toHaveProperty("material_b64url");
    // And the core refuses a spec that tries to smuggle one in.
    const smuggled = JSON.stringify([{ ...spec, digest_value: "ZmFrZQ" }]);
    expect(() => sign([], smuggled)).toThrow(/invalid bindings json/);
  });

  it("fails closed on empty material", () => {
    try {
      new OpaqueBytesProvider("pdp-decision", Buffer.alloc(0));
      throw new Error("expected empty material to fail closed");
    } catch (e) {
      expect((e as McpReError).wireCode).toBe("mcp-re.authorization_binding_missing");
    }
  });

  it("fails closed on an unregistered artifact type", () => {
    try {
      new OpaqueBytesProvider("not-a-registry-token", MATERIAL);
      throw new Error("expected an unregistered type to fail closed");
    } catch (e) {
      expect((e as McpReError).wireCode).toBe("mcp-re.authorization_binding_type_unsupported");
    }
  });
});

describe("authz-system reference", () => {
  const REF = {
    authorizationSystemId: "authz-1",
    referenceSchemeId: "scheme-1",
    referenceValue: "grant-123",
  };
  const provider = (over: Partial<typeof REF> = {}) =>
    new AuthzSystemReferenceProvider("pdp-decision", MATERIAL, { ...REF, ...over });

  it("binds the real bytes and names the system", () => {
    const b = ofType(sign([provider()]), "pdp-decision");
    expect(b.binding_type).toBe("reference-digest");
    expect(b.digest_value).toBe(oracleDigest(MATERIAL)); // still a real digest
    expect(b.authorization_system_id).toBe("authz-1");
    expect(b.reference_scheme_id).toBe("scheme-1");
    expect(b.reference_value).toBe("grant-123");
  });

  it("leaks no secret material", () => {
    const s = sign([provider()]);
    expect(s.body.includes(MATERIAL)).toBe(false);
    expect(s.body.toString()).not.toContain(MATERIAL.toString("base64url"));
  });

  it("produces the same digest as the opaque form for the same bytes", () => {
    // The form names the issuer; it does not change what is bound.
    const ref = ofType(sign([provider()]), "pdp-decision");
    const opq = ofType(sign([new OpaqueBytesProvider("pdp-decision", MATERIAL)]), "pdp-decision");
    expect(ref.digest_value).toBe(opq.digest_value);
  });

  it.each(["authorizationSystemId", "referenceSchemeId", "referenceValue"] as const)(
    "fails closed when %s is missing",
    (field) => {
      try {
        provider({ [field]: "" });
        throw new Error("expected a partial reference to fail closed");
      } catch (e) {
        expect((e as McpReError).wireCode).toBe("mcp-re.authorization_binding_malformed");
      }
    },
  );
});

describe("DPoP stays built-in", () => {
  it("is present and first with no provider", () => {
    const b = bindings(sign());
    expect(b.map((x) => x.artifact_type)).toEqual(["oauth-dpop"]);
    expect(b[0].digest_value).toBe(oracleDigest(Buffer.from("dpop-token")));
  });

  it("has provider bindings append after it", () => {
    const b = bindings(sign([new OpaqueBytesProvider("pdp-decision", MATERIAL)]));
    expect(b.map((x) => x.artifact_type)).toEqual(["oauth-dpop", "pdp-decision"]);
  });

  it("signs the no-bindings path unchanged", () => {
    // Omitting the parameter must sign exactly as before — frozen vectors depend on it.
    expect(Buffer.compare(sign().body, sign([], null).body)).toBe(0);
  });

  it("binds several providers in order", () => {
    const b = bindings(
      sign([
        new OpaqueBytesProvider("pdp-decision", MATERIAL),
        new OpaqueBytesProvider("human-approval", Buffer.from("approved-by-alice")),
      ]),
    );
    expect(b.map((x) => x.artifact_type)).toEqual(["oauth-dpop", "pdp-decision", "human-approval"]);
  });
});

describe("policy fails closed", () => {
  it("passes a permitted type", () => {
    const p = AuthorizationBindingPolicy.permitting(["pdp-decision"]);
    expect(() => p.check([new OpaqueBytesProvider("pdp-decision", MATERIAL)])).not.toThrow();
  });

  it("fails closed on an unpermitted type", () => {
    const p = AuthorizationBindingPolicy.permitting(["pdp-decision"]);
    try {
      p.check([new OpaqueBytesProvider("human-approval", MATERIAL)]);
      throw new Error("expected an unpermitted type to fail closed");
    } catch (e) {
      expect((e as McpReError).wireCode).toBe("mcp-re.authorization_binding_type_unsupported");
    }
  });

  it("fails closed when a required binding is absent", () => {
    const p = AuthorizationBindingPolicy.permitting(["pdp-decision"], true);
    try {
      p.check([]);
      throw new Error("expected a missing required binding to fail closed");
    } catch (e) {
      expect((e as McpReError).wireCode).toBe("mcp-re.authorization_binding_missing");
    }
  });

  it("allows an optional binding to be absent", () => {
    expect(() => AuthorizationBindingPolicy.permitting(["pdp-decision"]).check([])).not.toThrow();
  });
});
