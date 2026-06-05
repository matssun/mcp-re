//! Signed tool-manifest error taxonomy (issue #3866).
//!
//! A SEPARATE taxonomy from both the frozen Core `mcps_core::McpsError` and the
//! Phase 5 [`crate::error::PolicyError`]. A signed manifest lets a client
//! cryptographically verify the set of tools an MCP server exposes (their names,
//! versions, and input/output schemas) and detect a "rug pull" — a server that
//! silently changes a tool's behaviour/schema after the client first trusted it.
//!
//! Every variant is a REJECT reason: the verifier fails closed and never accepts
//! on any of these. `Display` (via `thiserror`) and [`ManifestError::wire_code`]
//! both render the bare `mcps.manifest_*` token; human-readable context is kept
//! out of the token (mirrors [`crate::error::PolicyError`]).

/// The signed tool-manifest reject taxonomy (issue #3866). One variant per
/// `mcps.manifest_*` wire token. Fail-closed: there is no "accept" variant — a
/// successful verification returns the verified manifest, any failure returns one
/// of these.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// The manifest bytes do not parse into the expected `ToolManifest` shape, or
    /// a tool schema is not a canonicalizable JCS-safe value.
    #[error("mcps.manifest_malformed")]
    ManifestMalformed,

    /// The manifest's `signature.alg` is not the supported Ed25519 algorithm.
    #[error("mcps.manifest_unsupported_alg")]
    ManifestUnsupportedAlg,

    /// The manifest's signing authority `(signer, key_id)` could not be resolved
    /// to a verification key — unknown signer, revoked binding, or malformed key.
    #[error("mcps.manifest_signer_unresolved")]
    ManifestSignerUnresolved,

    /// The Ed25519 signature over the canonical manifest (minus `signature.value`)
    /// did not verify against the resolved signing-authority key.
    #[error("mcps.manifest_signature_invalid")]
    ManifestSignatureInvalid,

    /// A tool's recorded `schema_hash` did not equal the recomputed
    /// `sha256_hash_id(canonicalize(schema))` — the manifest is internally
    /// inconsistent and is rejected before its identity is trusted.
    #[error("mcps.manifest_schema_hash_mismatch")]
    ManifestSchemaHashMismatch,

    /// The manifest id (or `signer`+`version`) was present in the revocation
    /// source.
    #[error("mcps.manifest_revoked")]
    ManifestRevoked,

    /// The revocation source could not determine the manifest's revocation
    /// status (it was unavailable). Fail closed: this denies just like
    /// [`ManifestError::ManifestRevoked`], but with a distinct token so an
    /// outage is never conflated with an actual revocation (M-10, #3839).
    #[error("mcps.manifest_revocation_unavailable")]
    ManifestRevocationUnavailable,

    /// The manifest's `expires_at` is at or before the supplied `now` (or
    /// `issued_at` is in the future relative to `now`) — the manifest is outside
    /// its validity window.
    #[error("mcps.manifest_expired")]
    ManifestExpired,

    /// A rug pull: a tool's schema (and therefore its `schema_hash`) changed for
    /// the SAME `(name, version)` pin recorded on first trust. A legitimate
    /// version bump is NOT this error.
    #[error("mcps.manifest_rug_pull")]
    ManifestRugPull,
}

impl ManifestError {
    /// Returns the exact frozen wire token (`mcps.manifest_*`) for this error. The
    /// bare token only — never any human-readable context.
    pub fn wire_code(&self) -> &'static str {
        match self {
            ManifestError::ManifestMalformed => "mcps.manifest_malformed",
            ManifestError::ManifestUnsupportedAlg => "mcps.manifest_unsupported_alg",
            ManifestError::ManifestSignerUnresolved => "mcps.manifest_signer_unresolved",
            ManifestError::ManifestSignatureInvalid => "mcps.manifest_signature_invalid",
            ManifestError::ManifestSchemaHashMismatch => "mcps.manifest_schema_hash_mismatch",
            ManifestError::ManifestRevoked => "mcps.manifest_revoked",
            ManifestError::ManifestRevocationUnavailable => {
                "mcps.manifest_revocation_unavailable"
            }
            ManifestError::ManifestExpired => "mcps.manifest_expired",
            ManifestError::ManifestRugPull => "mcps.manifest_rug_pull",
        }
    }
}

/// Result alias over the signed tool-manifest reject taxonomy.
pub type ManifestResult<T> = Result<T, ManifestError>;

#[cfg(test)]
mod tests {
    use super::ManifestError;

    fn check(err: ManifestError, expected: &str) {
        assert_eq!(err.wire_code(), expected);
        assert_eq!(err.to_string(), expected);
        assert!(expected.starts_with("mcps.manifest_"));
        assert!(!expected.contains(' '));
    }

    #[test]
    fn every_variant_renders_its_exact_wire_token() {
        check(ManifestError::ManifestMalformed, "mcps.manifest_malformed");
        check(
            ManifestError::ManifestUnsupportedAlg,
            "mcps.manifest_unsupported_alg",
        );
        check(
            ManifestError::ManifestSignerUnresolved,
            "mcps.manifest_signer_unresolved",
        );
        check(
            ManifestError::ManifestSignatureInvalid,
            "mcps.manifest_signature_invalid",
        );
        check(
            ManifestError::ManifestSchemaHashMismatch,
            "mcps.manifest_schema_hash_mismatch",
        );
        check(ManifestError::ManifestRevoked, "mcps.manifest_revoked");
        check(
            ManifestError::ManifestRevocationUnavailable,
            "mcps.manifest_revocation_unavailable",
        );
        check(ManifestError::ManifestExpired, "mcps.manifest_expired");
        check(ManifestError::ManifestRugPull, "mcps.manifest_rug_pull");
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(ManifestError::ManifestRugPull, ManifestError::ManifestRugPull);
        assert_ne!(
            ManifestError::ManifestRugPull,
            ManifestError::ManifestRevoked
        );
    }
}
