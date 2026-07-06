//! The `AuthorizationProfile` abstraction (ADR-MCPS-013).
//!
//! A profile interprets the authorization artifact behind Core's opaque
//! `authorization_hash` and renders an allow/deny decision. The trait is
//! deliberately object-safe so a `PolicyEvaluator` can dispatch over
//! `Box<dyn AuthorizationProfile>` keyed by `profile_id`. The first concrete
//! implementation is the Reference Signed Authorization Profile (MCPS-020);
//! Biscuit / UCAN / OAuth-bound are later pluggable profiles.

use mcp_re_core::TrustResolver;
use mcp_re_core::VerifiedRequest;
use serde_json::Value;

use crate::decision::AuthorizationDecision;
use crate::error::PolicyError;
use crate::revocation::RevocationSource;

/// Interprets an authorization artifact and decides whether a verified request is
/// authorized.
///
/// The Core layer has already proven authenticity, freshness, replay-safety, and
/// audience; the profile is given the resulting [`VerifiedRequest`] plus the raw
/// artifact bytes and the original request object (for method/tool/argument
/// scope). Issuer keys are resolved through the SAME injected
/// [`TrustResolver`](mcp_re_core::TrustResolver) Core uses; revocation through an
/// injected [`RevocationSource`].
pub trait AuthorizationProfile {
    /// The profile identifier carried in the authorization block's `profile`
    /// field (e.g. `se.syncom/mcp-re-authz-reference-v1`).
    fn profile_id(&self) -> &str;

    /// The `authorization_hash` this profile expects for `artifact_bytes`:
    /// `sha256:<b64url(SHA-256(canonical artifact bytes))>`. The evaluator
    /// compares this against the Core-verified `authorization_hash` BEFORE
    /// trusting the artifact's claims. Malformed bytes that cannot even be hashed
    /// into the expected form map to [`PolicyError::AuthorizationMalformed`].
    fn expected_authorization_hash(&self, artifact_bytes: &[u8]) -> Result<String, PolicyError>;

    /// Parse + validate the artifact's signature/chain and evaluate it against
    /// the verified request: signer / subject / audience binding, validity
    /// window, revocation, and method/tool/argument scope. Returns
    /// [`AuthorizationDecision::Allow`] only when every check passes; otherwise
    /// [`AuthorizationDecision::Deny`] with the precise [`PolicyError`].
    ///
    /// The hash-binding check is the evaluator's responsibility and is performed
    /// before this call; implementations may assume `artifact_bytes` hashes to
    /// the verified `authorization_hash`.
    fn authorize(
        &self,
        artifact_bytes: &[u8],
        verified: &VerifiedRequest,
        request: &Value,
        resolver: &dyn TrustResolver,
        revocation: &dyn RevocationSource,
        now_unix: i64,
    ) -> AuthorizationDecision;
}

/// Validates a draft-02 `authz-system-reference` authorization binding
/// (ADR-MCPS-039 / decision E.2). An external authorization system produced the
/// `digest_value` under `reference_scheme_id`; MCP-RE has already **bound** that
/// evidence (Core validated the binding's structure and it is inside the signed
/// preimage). This resolver decides allow/deny for one `authorization_system_id`
/// **without MCP-RE interpreting authorization semantics** — the resolver owns the
/// system's meaning of the reference, MCP-RE owns only the binding.
///
/// If no resolver is registered for a presented `authorization_system_id`, the
/// evaluator fails closed with
/// [`PolicyError::AuthorizationBindingProfileRequired`] — never a silent accept.
pub trait AuthorizationReferenceResolver {
    /// The `authorization_system_id` this resolver validates references for.
    fn authorization_system_id(&self) -> &str;

    /// Decide allow/deny for the bound `authz-system-reference` evidence. The
    /// `binding` is the verified [`AuthorizationBinding::AuthzSystemReference`]
    /// (all six fields structurally validated by Core); `verified`/`request`
    /// give the request context. Returns [`AuthorizationDecision::Allow`] only
    /// when the system's own validation of the reference passes.
    fn authorize_reference(
        &self,
        binding: &mcp_re_core::AuthorizationBinding,
        verified: &VerifiedRequest,
        request: &Value,
        resolver: &dyn TrustResolver,
        revocation: &dyn RevocationSource,
        now_unix: i64,
    ) -> AuthorizationDecision;
}

#[cfg(test)]
mod tests {
    use super::AuthorizationProfile;
    use mcp_re_core::VerifiedAuthorization;
    use crate::decision::AuthorizationDecision;
    use crate::error::PolicyError;
    use crate::revocation::InMemoryRevocationSource;
    use crate::revocation::RevocationSource;
    use mcp_re_core::sha256_hash_id;
    use mcp_re_core::InMemoryTrustResolver;
    use mcp_re_core::TrustResolver;
    use mcp_re_core::VerifiedRequest;
    use serde_json::json;

    /// A trivial stub used only to prove the trait is object-safe and usable
    /// through `&dyn AuthorizationProfile`. The real logic lands in MCPS-020.
    struct AllowAllStub;

    impl AuthorizationProfile for AllowAllStub {
        fn profile_id(&self) -> &str {
            "test/allow-all"
        }
        fn expected_authorization_hash(
            &self,
            artifact_bytes: &[u8],
        ) -> Result<String, PolicyError> {
            Ok(sha256_hash_id(artifact_bytes))
        }
        fn authorize(
            &self,
            _artifact_bytes: &[u8],
            _verified: &VerifiedRequest,
            _request: &serde_json::Value,
            _resolver: &dyn TrustResolver,
            _revocation: &dyn RevocationSource,
            _now_unix: i64,
        ) -> AuthorizationDecision {
            AuthorizationDecision::Allow
        }
    }

    fn sample_verified() -> VerifiedRequest {
        VerifiedRequest {
            verified_signer: "did:example:agent-1".to_string(),
            key_id: "key-1".to_string(),
            on_behalf_of: "did:example:user-1".to_string(),
            audience: "did:example:server-1".to_string(),
            authorization: VerifiedAuthorization::Draft01Hash {
                authorization_hash: sha256_hash_id(b"artifact"),
            },
            request_hash: "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
            nonce: "nonce-1".to_string(),
            issued_at: "2026-05-28T20:00:00Z".to_string(),
            expires_at: "2026-05-28T20:05:00Z".to_string(),
            canonicalization_id: None,
        }
    }

    #[test]
    fn trait_is_object_safe_and_dispatchable() {
        let profile: Box<dyn AuthorizationProfile> = Box::new(AllowAllStub);
        let resolver = InMemoryTrustResolver::new();
        let revocation = InMemoryRevocationSource::new();
        let verified = sample_verified();
        let request = json!({ "method": "tools/call", "params": { "name": "echo" } });

        assert_eq!(profile.profile_id(), "test/allow-all");
        assert_eq!(
            profile
                .expected_authorization_hash(b"artifact")
                .expect("hash"),
            sha256_hash_id(b"artifact")
        );
        let decision = profile.authorize(
            b"artifact",
            &verified,
            &request,
            &resolver,
            &revocation,
            1_700_000_000,
        );
        assert_eq!(decision, AuthorizationDecision::Allow);
    }
}
