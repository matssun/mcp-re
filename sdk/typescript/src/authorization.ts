// SPDX-License-Identifier: Apache-2.0
/**
 * Authorization-binding providers (ADR-MCPS-044 §Authorization-binding hook).
 *
 * **Bind, do not interpret.** A provider hands the SDK the *artifact itself*; the audited
 * core digests it and puts the digest — never the bytes — into the signed evidence. MCP-RE
 * never dereferences a reference, evaluates a permission, or parses authorization
 * semantics. It proves *which* artifact authorized a request, and nothing about what the
 * artifact means.
 *
 * Two base forms:
 *
 * - `OpaqueBytesProvider` — the client holds the artifact bytes (a capability token, a PDP
 *   decision document). The binding digest is `base64url-no-pad(SHA-256(bytes))`, computed
 *   in Rust.
 * - `AuthzSystemReferenceProvider` — the same digest over the same real bytes, plus the
 *   external system's identity and grant handle for cross-audit. The record stays
 *   verifiable independently of that system's live state.
 *
 * Neither accepts a precomputed digest: the digest is always derived from material the
 * caller actually presents, so a caller cannot assert a binding to an artifact it does not
 * have.
 *
 * Providers here are **synchronous and supply already-acquired material.** Fetching a
 * decision from a PDP belongs in the application or transport layer, above this one.
 */
import { McpReError } from "./custody.js";

/**
 * The seven artifact-type registry tokens the RFC 9421 profile defines
 * (ADR-MCPRE-050 §Resolved Q5). `oauth-dpop` is the SDK's built-in header-derived
 * binding and is not provider-supplied.
 */
export const ARTIFACT_TYPES = [
  "oauth-dpop",
  "oauth-mtls",
  "oauth-rar",
  "pdp-decision",
  "dtr-approval",
  "classifier-result",
  "human-approval",
] as const;

export type ArtifactType = (typeof ARTIFACT_TYPES)[number];

const REGISTRY: ReadonlySet<string> = new Set(ARTIFACT_TYPES);

const b64url = (raw: Buffer): string => raw.toString("base64url");

/**
 * What a provider may branch on when choosing a binding.
 *
 * The route/method/audience a request is about — never the request bytes, so a provider
 * cannot make the binding depend on content the core has not yet signed.
 */
export interface BindingRequestContext {
  audienceId: string;
  targetUri: string;
  method: string;
  route?: string | null;
  deadline?: number | null;
}

/** The binding spec the native core consumes. */
export interface BindingSpec {
  artifact_type: string;
  form: "opaque-bytes" | "authz-system-reference";
  material_b64url: string;
  authorization_system_id?: string;
  reference_scheme_id?: string;
  reference_value?: string;
}

/**
 * Given a request context, produce one artifact binding spec.
 *
 * Implementations return the artifact MATERIAL; the core digests it.
 */
export interface AuthorizationBindingProvider {
  /** The `artifact_type` registry token this provider binds. */
  bindingType(): string;
  /** The binding spec the native core consumes. */
  spec(context: BindingRequestContext): BindingSpec;
}

function assertRegistered(artifactType: string): void {
  if (!REGISTRY.has(artifactType)) {
    throw new McpReError(
      "mcp-re.authorization_binding_type_unsupported",
      `'${artifactType}' is not an artifact-type registry token`,
    );
  }
}

function assertMaterial(material: Buffer, what: string): void {
  if (!Buffer.isBuffer(material) || material.length === 0) {
    throw new McpReError(
      "mcp-re.authorization_binding_missing",
      `${what} binding requires non-empty artifact material`,
    );
  }
}

/**
 * Bind the exact artifact bytes the client holds.
 *
 * The digest is computed by the core from `material`; the bytes themselves never enter
 * the evidence block.
 */
export class OpaqueBytesProvider implements AuthorizationBindingProvider {
  readonly #artifactType: string;
  readonly #material: Buffer;

  constructor(artifactType: string, material: Buffer) {
    assertRegistered(artifactType);
    assertMaterial(material, "opaque");
    this.#artifactType = artifactType;
    this.#material = Buffer.from(material);
  }

  bindingType(): string {
    return this.#artifactType;
  }

  spec(_context: BindingRequestContext): BindingSpec {
    return {
      artifact_type: this.#artifactType,
      form: "opaque-bytes",
      material_b64url: b64url(this.#material),
    };
  }
}

/**
 * Bind real artifact bytes AND name the external system that issued them.
 *
 * The digest still comes from `material` — the reference fields identify the decision for
 * cross-audit, they do not replace the binding. Nothing secret belongs in them: they are
 * emitted verbatim into the evidence block.
 */
export class AuthzSystemReferenceProvider implements AuthorizationBindingProvider {
  readonly #artifactType: string;
  readonly #material: Buffer;
  readonly #authorizationSystemId: string;
  readonly #referenceSchemeId: string;
  readonly #referenceValue: string;

  constructor(
    artifactType: string,
    material: Buffer,
    ref: { authorizationSystemId: string; referenceSchemeId: string; referenceValue: string },
  ) {
    assertRegistered(artifactType);
    assertMaterial(material, "reference");
    if (!ref.authorizationSystemId || !ref.referenceSchemeId || !ref.referenceValue) {
      // The core rejects a partial reference form; catch it here with a message that
      // names the hook rather than the wire shape.
      throw new McpReError(
        "mcp-re.authorization_binding_malformed",
        "reference binding requires authorizationSystemId, referenceSchemeId, and referenceValue",
      );
    }
    this.#artifactType = artifactType;
    this.#material = Buffer.from(material);
    this.#authorizationSystemId = ref.authorizationSystemId;
    this.#referenceSchemeId = ref.referenceSchemeId;
    this.#referenceValue = ref.referenceValue;
  }

  bindingType(): string {
    return this.#artifactType;
  }

  spec(_context: BindingRequestContext): BindingSpec {
    return {
      artifact_type: this.#artifactType,
      form: "authz-system-reference",
      material_b64url: b64url(this.#material),
      authorization_system_id: this.#authorizationSystemId,
      reference_scheme_id: this.#referenceSchemeId,
      reference_value: this.#referenceValue,
    };
  }
}

/**
 * Which artifact types a route will carry, and whether one is required.
 *
 * Enforced before signing: a provider whose type is not permitted fails the route closed
 * rather than emitting evidence the verifier would reject.
 */
export class AuthorizationBindingPolicy {
  readonly permittedTypes: ReadonlySet<string>;
  readonly requireBinding: boolean;

  constructor(permittedTypes: Iterable<string>, requireBinding = false) {
    this.permittedTypes = new Set(permittedTypes);
    this.requireBinding = requireBinding;
  }

  static permitting(types: Iterable<string>, requireBinding = false): AuthorizationBindingPolicy {
    return new AuthorizationBindingPolicy(types, requireBinding);
  }

  /** Fail closed unless every provider is permitted (and one exists if required). */
  check(providers: readonly AuthorizationBindingProvider[]): void {
    if (this.requireBinding && providers.length === 0) {
      throw new McpReError(
        "mcp-re.authorization_binding_missing",
        "this route requires an authorization binding",
      );
    }
    for (const p of providers) {
      if (!this.permittedTypes.has(p.bindingType())) {
        throw new McpReError(
          "mcp-re.authorization_binding_type_unsupported",
          `'${p.bindingType()}' is not permitted on this route (permitted: ${[
            ...this.permittedTypes,
          ]
            .sort()
            .join(", ")})`,
        );
      }
    }
  }
}

/** Serialize provider specs for the native `bindingsJson` parameter. */
export function bindingsJson(
  providers: readonly AuthorizationBindingProvider[],
  context: BindingRequestContext,
): string | null {
  if (providers.length === 0) return null;
  return JSON.stringify(providers.map((p) => p.spec(context)));
}
