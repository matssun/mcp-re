//! The client-side authorization-binding hook (MCPS-45, #192; ADR-MCPS-044
//! §Authorization-binding hook; ADR-MCPS-039 binding forms).
//!
//! MCP-RE **binds, never interprets** authorization evidence (bind-not-interpret).
//! The client core includes a typed [`AuthorizationBinding`] in the signed request
//! preimage (via [`crate::RequestSigningInputs::authorization_binding`]) and
//! enforces its PRESENCE and TYPE by route policy — but it never inspects the
//! artifact's meaning, dereferences a reference, or evaluates a decision. That is
//! the job of a configured authorization profile on the verifying side.
//!
//! This module defines the [`AuthorizationBindingProvider`] hook the deploying
//! application implements: given the request context (audience, route, optional
//! method/tool id, deadline) it returns a base-form binding or a typed
//! missing/unsupported error. Two base forms exist in v0.6:
//!
//! - **opaque-bytes** ([`OpaqueBytesProvider`]) — binds the EXACT transport-decoded
//!   artifact bytes: `digest_value = base64url-no-pad(SHA-256(bytes))`.
//! - **authz-system-reference** ([`AuthzSystemReferenceProvider`]) — an external
//!   authorization system's self-contained digest + cross-audit reference, produced
//!   by a configured [`AuthorizationReferenceResolver`]. Without a resolver it fails
//!   closed.
//!
//! Structured authorization-OBJECT hashing (case 3) is OUT of the base profile: it
//! requires an explicit authorization-binding profile (schema + canonicalization +
//! hash + vectors), so [`StructuredObjectHashingProvider`] always fails closed with
//! [`McpReError::AuthorizationBindingProfileRequired`].

use mcp_re_core::ids::DIGEST_ALG_SHA256;
use mcp_re_core::sha256_hash_id;
use mcp_re_core::AuthorizationBinding;
use mcp_re_core::McpReError;

/// The base-form binding-type tags a route policy can permit. Mirrors the two
/// `AuthorizationBinding` variants without exposing their payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingTypeTag {
    /// `opaque-bytes`.
    OpaqueBytes,
    /// `authz-system-reference`.
    AuthzSystemReference,
}

/// The tag of a concrete [`AuthorizationBinding`].
pub fn binding_tag(binding: &AuthorizationBinding) -> BindingTypeTag {
    match binding {
        AuthorizationBinding::OpaqueBytes { .. } => BindingTypeTag::OpaqueBytes,
        AuthorizationBinding::AuthzSystemReference { .. } => BindingTypeTag::AuthzSystemReference,
    }
}

/// Per-route authorization-binding policy: which base forms are permitted on this
/// route. The base draft-02 profile always REQUIRES a binding (it is a mandatory
/// wire field), so absence from the provider fails closed; this policy governs the
/// permitted TYPE set on top of that.
#[derive(Debug, Clone)]
pub struct AuthorizationBindingPolicy {
    allowed_types: Vec<BindingTypeTag>,
}

impl AuthorizationBindingPolicy {
    /// A policy permitting exactly the given base forms. An empty set rejects every
    /// binding (a deliberately closed route).
    pub fn new(allowed_types: impl IntoIterator<Item = BindingTypeTag>) -> Self {
        AuthorizationBindingPolicy {
            allowed_types: allowed_types.into_iter().collect(),
        }
    }

    /// Permit both base forms (the common v0.6 default).
    pub fn both_base_forms() -> Self {
        Self::new([
            BindingTypeTag::OpaqueBytes,
            BindingTypeTag::AuthzSystemReference,
        ])
    }

    /// Whether this policy permits `tag`.
    pub fn permits(&self, tag: BindingTypeTag) -> bool {
        self.allowed_types.contains(&tag)
    }
}

/// The request context handed to a provider. Bind-not-interpret: a provider uses
/// this to LOCATE/produce the right authorization artifact; the client core never
/// reads the artifact's meaning out of it.
#[derive(Debug, Clone)]
pub struct BindingRequestContext<'a> {
    /// The resolved verifier identity (audience tuple's identity — MCPS-43).
    pub audience: &'a str,
    /// The route id this request is bound to.
    pub route_id: &'a str,
    /// The MCP method, if relevant to artifact selection (e.g. `tools/call`).
    pub method: Option<&'a str>,
    /// The tool id, if this is a tool call.
    pub tool_id: Option<&'a str>,
    /// The request deadline (unix seconds) — a provider may need it to fetch a
    /// fresh grant within the window.
    pub deadline_unix: i64,
}

/// The application-implemented hook producing the authorization binding for a
/// request. Returns a base-form [`AuthorizationBinding`] or a typed error
/// ([`McpReError::AuthorizationBindingMissing`] /
/// [`McpReError::AuthorizationBindingProfileRequired`]). The returned binding is
/// included verbatim in the signed preimage and never interpreted by the core.
pub trait AuthorizationBindingProvider {
    /// Produce the binding for `ctx`, or a typed missing/unsupported error.
    fn provide(&self, ctx: &BindingRequestContext) -> Result<AuthorizationBinding, McpReError>;
}

/// Resolve and policy-check the authorization binding for a request.
///
/// Calls `provider`, then enforces the route's permitted TYPE set: a binding whose
/// type the route does not permit is [`McpReError::AuthorizationBindingTypeUnsupported`].
/// A provider that cannot produce the (mandatory) binding propagates its typed
/// error (e.g. [`McpReError::AuthorizationBindingMissing`]) — fail closed. The
/// returned binding is ready to place in [`crate::RequestSigningInputs`].
pub fn resolve_authorization_binding(
    provider: &dyn AuthorizationBindingProvider,
    policy: &AuthorizationBindingPolicy,
    ctx: &BindingRequestContext,
) -> Result<AuthorizationBinding, McpReError> {
    let binding = provider.provide(ctx)?;
    if !policy.permits(binding_tag(&binding)) {
        return Err(McpReError::AuthorizationBindingTypeUnsupported);
    }
    Ok(binding)
}

/// Compute the bare opaque-bytes digest (`base64url-no-pad(SHA-256(bytes))`, no
/// `sha256:` prefix) over the transport-DECODED artifact bytes — the exact
/// representation ADR-MCPS-039 / decision E.1 specifies.
fn opaque_digest_value(artifact_bytes: &[u8]) -> String {
    let prefixed = sha256_hash_id(artifact_bytes);
    prefixed
        .strip_prefix("sha256:")
        .expect("sha256_hash_id always returns the sha256: prefix")
        .to_string()
}

/// Provider binding the EXACT transport-decoded artifact bytes as `opaque-bytes`.
/// The digest is over the raw bytes the caller supplies (already base64url-decoded
/// off the transport), never the base64 text or a JSON string.
pub struct OpaqueBytesProvider {
    artifact_bytes: Vec<u8>,
}

impl OpaqueBytesProvider {
    /// Bind these exact decoded artifact bytes.
    pub fn new(artifact_bytes: impl Into<Vec<u8>>) -> Self {
        OpaqueBytesProvider {
            artifact_bytes: artifact_bytes.into(),
        }
    }
}

impl AuthorizationBindingProvider for OpaqueBytesProvider {
    fn provide(&self, _ctx: &BindingRequestContext) -> Result<AuthorizationBinding, McpReError> {
        Ok(AuthorizationBinding::OpaqueBytes {
            digest_alg: DIGEST_ALG_SHA256.to_string(),
            digest_value: opaque_digest_value(&self.artifact_bytes),
        })
    }
}

/// An external authorization-system reference: a self-contained digest plus the
/// cross-audit metadata. The digest (not the reference) is the cryptographic
/// binding, so the record stays verifiable independent of the external system.
#[derive(Debug, Clone)]
pub struct AuthzReference {
    /// Namespace of the external authorization system.
    pub authorization_system_id: String,
    /// The authz system's scheme: what `reference_value` means / how the digest was
    /// produced.
    pub reference_scheme_id: String,
    /// Decision id / grant id / reference handle (cross-audit metadata).
    pub reference_value: String,
    /// `base64url-no-pad` digest produced by the authz system (bare, no prefix).
    pub digest_value: String,
}

/// The configured resolver that turns a request context into an [`AuthzReference`].
/// This is the "matching resolver" the reference form requires; the client core
/// never interprets the artifact, only binds the resolver's digest.
pub trait AuthorizationReferenceResolver {
    /// Resolve the reference + digest for `ctx`, or a typed error.
    fn resolve(&self, ctx: &BindingRequestContext) -> Result<AuthzReference, McpReError>;
}

/// Provider for the `authz-system-reference` form. WITHOUT a configured resolver it
/// fails closed ([`McpReError::AuthorizationBindingMissing`]) — the reference form
/// cannot be produced, so the mandatory binding is missing.
pub struct AuthzSystemReferenceProvider {
    resolver: Option<Box<dyn AuthorizationReferenceResolver>>,
}

impl AuthzSystemReferenceProvider {
    /// A provider backed by `resolver`.
    pub fn with_resolver(resolver: Box<dyn AuthorizationReferenceResolver>) -> Self {
        AuthzSystemReferenceProvider {
            resolver: Some(resolver),
        }
    }

    /// A provider with NO resolver — every `provide` fails closed. Models a route
    /// configured for the reference form on a deployment that did not wire one.
    pub fn without_resolver() -> Self {
        AuthzSystemReferenceProvider { resolver: None }
    }
}

impl AuthorizationBindingProvider for AuthzSystemReferenceProvider {
    fn provide(&self, ctx: &BindingRequestContext) -> Result<AuthorizationBinding, McpReError> {
        let resolver = self
            .resolver
            .as_ref()
            .ok_or(McpReError::AuthorizationBindingMissing)?;
        let reference = resolver.resolve(ctx)?;
        Ok(AuthorizationBinding::AuthzSystemReference {
            authorization_system_id: reference.authorization_system_id,
            reference_scheme_id: reference.reference_scheme_id,
            reference_value: reference.reference_value,
            digest_alg: DIGEST_ALG_SHA256.to_string(),
            digest_value: reference.digest_value,
        })
    }
}

/// Provider standing in for a caller attempting STRUCTURED authorization-object
/// hashing (case 3). The base v0.6 profile forbids it without an explicit
/// authorization-binding profile, so this always fails closed with
/// [`McpReError::AuthorizationBindingProfileRequired`].
pub struct StructuredObjectHashingProvider;

impl AuthorizationBindingProvider for StructuredObjectHashingProvider {
    fn provide(&self, _ctx: &BindingRequestContext) -> Result<AuthorizationBinding, McpReError> {
        Err(McpReError::AuthorizationBindingProfileRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> BindingRequestContext<'static> {
        BindingRequestContext {
            audience: "did:example:server",
            route_id: "route-a",
            method: Some("tools/call"),
            tool_id: Some("echo"),
            deadline_unix: 1_900_000_000,
        }
    }

    struct FixedResolver;
    impl AuthorizationReferenceResolver for FixedResolver {
        fn resolve(&self, _ctx: &BindingRequestContext) -> Result<AuthzReference, McpReError> {
            Ok(AuthzReference {
                authorization_system_id: "sys-1".to_string(),
                reference_scheme_id: "scheme-1".to_string(),
                reference_value: "grant-42".to_string(),
                digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
            })
        }
    }

    #[test]
    fn opaque_bytes_binds_the_exact_artifact_bytes() {
        let provider = OpaqueBytesProvider::new(b"the-exact-artifact".to_vec());
        let binding = provider.provide(&ctx()).unwrap();
        match binding {
            AuthorizationBinding::OpaqueBytes {
                digest_alg,
                digest_value,
            } => {
                assert_eq!(digest_alg, "sha256");
                // Independently recompute: base64url-no-pad(SHA-256(bytes)) bare.
                let expected = sha256_hash_id(b"the-exact-artifact")
                    .strip_prefix("sha256:")
                    .unwrap()
                    .to_string();
                assert_eq!(digest_value, expected);
                assert!(
                    !digest_value.contains(':'),
                    "digest_value is bare (no prefix)"
                );
            }
            _ => panic!("expected opaque-bytes"),
        }
    }

    #[test]
    fn different_artifacts_produce_different_digests() {
        let a = OpaqueBytesProvider::new(b"a".to_vec())
            .provide(&ctx())
            .unwrap();
        let b = OpaqueBytesProvider::new(b"b".to_vec())
            .provide(&ctx())
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn authz_system_reference_binds_resolver_digest() {
        let provider = AuthzSystemReferenceProvider::with_resolver(Box::new(FixedResolver));
        let binding = provider.provide(&ctx()).unwrap();
        match binding {
            AuthorizationBinding::AuthzSystemReference {
                authorization_system_id,
                reference_value,
                digest_value,
                digest_alg,
                ..
            } => {
                assert_eq!(authorization_system_id, "sys-1");
                assert_eq!(reference_value, "grant-42");
                assert_eq!(digest_alg, "sha256");
                assert_eq!(digest_value, "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o");
            }
            _ => panic!("expected authz-system-reference"),
        }
    }

    #[test]
    fn authz_system_reference_without_resolver_fails_closed() {
        let provider = AuthzSystemReferenceProvider::without_resolver();
        assert_eq!(
            provider.provide(&ctx()).unwrap_err(),
            McpReError::AuthorizationBindingMissing
        );
    }

    #[test]
    fn structured_object_hashing_rejected_in_base_profile() {
        assert_eq!(
            StructuredObjectHashingProvider.provide(&ctx()).unwrap_err(),
            McpReError::AuthorizationBindingProfileRequired
        );
    }

    #[test]
    fn policy_rejects_a_disallowed_binding_type() {
        // Route permits only the reference form, but the opaque provider returns
        // opaque-bytes -> type unsupported, fail closed.
        let policy = AuthorizationBindingPolicy::new([BindingTypeTag::AuthzSystemReference]);
        let provider = OpaqueBytesProvider::new(b"x".to_vec());
        assert_eq!(
            resolve_authorization_binding(&provider, &policy, &ctx()).unwrap_err(),
            McpReError::AuthorizationBindingTypeUnsupported
        );
    }

    #[test]
    fn policy_permits_an_allowed_binding_type() {
        let policy = AuthorizationBindingPolicy::both_base_forms();
        let provider = OpaqueBytesProvider::new(b"x".to_vec());
        let binding = resolve_authorization_binding(&provider, &policy, &ctx()).unwrap();
        assert_eq!(binding_tag(&binding), BindingTypeTag::OpaqueBytes);
    }

    #[test]
    fn missing_binding_propagates_through_resolve() {
        // A provider that cannot produce the mandatory binding fails closed even
        // under a permissive policy (presence enforcement).
        let policy = AuthorizationBindingPolicy::both_base_forms();
        let provider = AuthzSystemReferenceProvider::without_resolver();
        assert_eq!(
            resolve_authorization_binding(&provider, &policy, &ctx()).unwrap_err(),
            McpReError::AuthorizationBindingMissing
        );
    }
}
