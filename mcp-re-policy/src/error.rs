//! Phase 5 authorization error taxonomy (ADR-MCPS-013).
//!
//! A SEPARATE taxonomy from the frozen Core `mcp_re_core::McpReError`. Core proves a
//! request is authentic, fresh, non-replayed and audience-correct; this is what an
//! authorization MECHANISM refuses in, under ADR-MCPRE-065.
//!
//! The tokens are frozen. The prose is not, and it says what each one means for the RFC 9421
//! carrier rather than for the `_meta`/`authorization_hash` model ADR-MCPRE-050 replaced —
//! a taxonomy whose explanations describe a deleted carrier sends an operator looking for
//! fields that no longer exist.

/// The frozen Phase 5 authorization-error taxonomy (ADR-MCPS-013). One variant
/// per `mcp-re.authorization_*` wire token. `Display` (via `thiserror`) and
/// [`PolicyError::wire_code`] both render the bare token; any human-readable
/// context is kept out of the token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The request verified, and carries none of the authorization evidence the active
    /// profile requires.
    #[error("mcp-re.authorization_block_missing")]
    AuthorizationBlockMissing,

    /// The presented authorization artifact's bytes do not match the digest its verified
    /// binding committed to — the artifact is not the one the request signed over.
    #[error("mcp-re.authorization_hash_mismatch")]
    AuthorizationHashMismatch,

    /// The `profile` identifier in the authorization block is not registered
    /// with this verifier.
    #[error("mcp-re.authorization_profile_unsupported")]
    AuthorizationProfileUnsupported,

    /// The artifact bytes do not parse into the profile's expected shape.
    #[error("mcp-re.authorization_malformed")]
    AuthorizationMalformed,

    /// The artifact could not be AUTHENTICATED under the deployment's configured
    /// authorization-authority trust: the signature did not verify, or its issuer is not one
    /// this deployment trusts to decide.
    ///
    /// Those two are different facts and only the diagnostic channel separates them — an
    /// authority a deployment has not been told about is not a forgery. The token is
    /// nevertheless truthful for both, and the taxonomy is frozen; the cost is named here
    /// rather than hidden. Distinct from
    /// [`AuthorizationBindingProfileRequired`](Self::AuthorizationBindingProfileRequired),
    /// which is the deployment having configured no authorization authority at all.
    #[error("mcp-re.authorization_signature_invalid")]
    AuthorizationSignatureInvalid,

    /// The decision's actor coordinate does not match the verified actor, at the scope the
    /// active profile binds (ADR-MCPRE-065 Law A-2).
    #[error("mcp-re.authorization_signer_mismatch")]
    AuthorizationSignerMismatch,

    /// The artifact's subject did not match the verified delegating subject.
    #[error("mcp-re.authorization_subject_mismatch")]
    AuthorizationSubjectMismatch,

    /// The artifact's audience did not match the verified `audience`.
    #[error("mcp-re.authorization_audience_mismatch")]
    AuthorizationAudienceMismatch,

    /// `now` fell outside the artifact's `[not_before, expires_at]` window.
    #[error("mcp-re.authorization_expired")]
    AuthorizationExpired,

    /// The artifact's `revocation_id` was present in the revocation source.
    #[error("mcp-re.authorization_revoked")]
    AuthorizationRevoked,

    /// The revocation source could NOT determine the artifact's status (the
    /// backend was unavailable). M-10 (audit follow-up): this is DISTINCT from
    /// [`PolicyError::AuthorizationRevoked`] — both fail closed (deny), but an
    /// operational outage gets its own diagnosable token instead of being
    /// silently reported as a revocation. Mirrors Core's
    /// `trust_resolver_unavailable` / `replay_cache_unavailable` split.
    #[error("mcp-re.authorization_revocation_unavailable")]
    AuthorizationRevocationUnavailable,

    /// The action is not permitted: the requested operation or target is outside what the
    /// evidence grants, or an authority evaluated this request and explicitly denied it.
    ///
    /// The taxonomy has no generic `authorization_denied`, so this is the coarse
    /// policy-denial surface. A profile that renders an explicit deny here says so in its
    /// own refusal algebra, where the two remain distinct.
    #[error("mcp-re.authorization_scope_denied")]
    AuthorizationScopeDenied,

    /// Authorization evidence was presented and this deployment has configured NO
    /// authorization authority to validate it against.
    ///
    /// A statement about the DEPLOYMENT, not about the caller: without a configured
    /// resolver there is nobody to validate against, so the policy fails closed
    /// (ADR-MCPS-039 / decision E.2). Deliberately distinct from
    /// [`AuthorizationSignatureInvalid`](Self::AuthorizationSignatureInvalid), which is a
    /// configured authority REFUSING an issuer or a signature — the two send an operator to
    /// entirely different places. Also distinct from
    /// [`AuthorizationProfileUnsupported`](Self::AuthorizationProfileUnsupported), which is
    /// about the artifact-interpretation profile rather than the authority.
    #[error("mcp-re.authorization_binding_profile_required")]
    AuthorizationBindingProfileRequired,
}

impl PolicyError {
    /// Returns the exact frozen wire token (`mcp-re.authorization_*`) for this error.
    /// The bare token only — never any human-readable context.
    pub fn wire_code(&self) -> &'static str {
        match self {
            PolicyError::AuthorizationBlockMissing => "mcp-re.authorization_block_missing",
            PolicyError::AuthorizationHashMismatch => "mcp-re.authorization_hash_mismatch",
            PolicyError::AuthorizationProfileUnsupported => {
                "mcp-re.authorization_profile_unsupported"
            }
            PolicyError::AuthorizationMalformed => "mcp-re.authorization_malformed",
            PolicyError::AuthorizationSignatureInvalid => "mcp-re.authorization_signature_invalid",
            PolicyError::AuthorizationSignerMismatch => "mcp-re.authorization_signer_mismatch",
            PolicyError::AuthorizationSubjectMismatch => "mcp-re.authorization_subject_mismatch",
            PolicyError::AuthorizationAudienceMismatch => "mcp-re.authorization_audience_mismatch",
            PolicyError::AuthorizationExpired => "mcp-re.authorization_expired",
            PolicyError::AuthorizationRevoked => "mcp-re.authorization_revoked",
            PolicyError::AuthorizationRevocationUnavailable => {
                "mcp-re.authorization_revocation_unavailable"
            }
            PolicyError::AuthorizationScopeDenied => "mcp-re.authorization_scope_denied",
            PolicyError::AuthorizationBindingProfileRequired => {
                "mcp-re.authorization_binding_profile_required"
            }
        }
    }
}

/// Result alias over the Phase 5 authorization-error taxonomy.
pub type PolicyResult<T> = Result<T, PolicyError>;

#[cfg(test)]
mod tests {
    use super::PolicyError;

    fn check(err: PolicyError, expected: &str) {
        assert_eq!(err.wire_code(), expected);
        assert_eq!(err.to_string(), expected);
        assert!(expected.starts_with("mcp-re.authorization_"));
        assert!(!expected.contains(' '));
    }

    #[test]
    fn every_variant_renders_its_exact_wire_token() {
        check(
            PolicyError::AuthorizationBlockMissing,
            "mcp-re.authorization_block_missing",
        );
        check(
            PolicyError::AuthorizationHashMismatch,
            "mcp-re.authorization_hash_mismatch",
        );
        check(
            PolicyError::AuthorizationProfileUnsupported,
            "mcp-re.authorization_profile_unsupported",
        );
        check(
            PolicyError::AuthorizationMalformed,
            "mcp-re.authorization_malformed",
        );
        check(
            PolicyError::AuthorizationSignatureInvalid,
            "mcp-re.authorization_signature_invalid",
        );
        check(
            PolicyError::AuthorizationSignerMismatch,
            "mcp-re.authorization_signer_mismatch",
        );
        check(
            PolicyError::AuthorizationSubjectMismatch,
            "mcp-re.authorization_subject_mismatch",
        );
        check(
            PolicyError::AuthorizationAudienceMismatch,
            "mcp-re.authorization_audience_mismatch",
        );
        check(
            PolicyError::AuthorizationExpired,
            "mcp-re.authorization_expired",
        );
        check(
            PolicyError::AuthorizationRevoked,
            "mcp-re.authorization_revoked",
        );
        check(
            PolicyError::AuthorizationRevocationUnavailable,
            "mcp-re.authorization_revocation_unavailable",
        );
        check(
            PolicyError::AuthorizationScopeDenied,
            "mcp-re.authorization_scope_denied",
        );
        check(
            PolicyError::AuthorizationBindingProfileRequired,
            "mcp-re.authorization_binding_profile_required",
        );
    }

    /// M-10: the two revocation-denial tokens are DISTINCT (an outage is not a
    /// revocation), so a caller can tell them apart on the wire.
    #[test]
    fn revoked_and_unavailable_are_distinct_tokens() {
        assert_ne!(
            PolicyError::AuthorizationRevoked.wire_code(),
            PolicyError::AuthorizationRevocationUnavailable.wire_code()
        );
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(
            PolicyError::AuthorizationRevoked,
            PolicyError::AuthorizationRevoked
        );
        assert_ne!(
            PolicyError::AuthorizationRevoked,
            PolicyError::AuthorizationExpired
        );
    }
}
