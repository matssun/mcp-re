//! Frozen MCP-S error taxonomy (MCPS_SPEC §8 / ADR-002, ADR-007, ADR-009).
//!
//! Every `mcps.*` constant in the frozen oracle is represented by exactly one
//! variant. `Display` and [`McpsError::wire_code`] both render the bare
//! `mcps.<name>` token; any human-readable `details` payload is kept separate so
//! the wire token is never polluted.

/// The complete frozen MCP-S error taxonomy. One variant per `mcps.*` constant.
///
/// `Display` (via `thiserror`) and [`McpsError::wire_code`] both yield the exact
/// wire string (e.g. `mcps.invalid_signature`). Variants that can usefully carry
/// diagnostic context hold a `details: String`; the wire token NEVER includes it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpsError {
    /// No MCP-S envelope present under the expected `_meta` key.
    #[error("mcps.missing_envelope")]
    MissingEnvelope,

    /// Envelope `version` is not `draft-01`.
    #[error("mcps.unsupported_version")]
    UnsupportedVersion,

    /// Signature did not verify, or an unsupported algorithm was presented.
    #[error("mcps.invalid_signature")]
    InvalidSignature,

    /// The protected message violated the JCS-safe value domain (duplicate keys,
    /// unsafe integers, invalid UTF-8, non-integer numbers, ...).
    #[error("mcps.canonicalization_failed")]
    CanonicalizationFailed,

    /// The request fell outside its freshness window (stale or future-dated
    /// beyond the configured clock skew).
    #[error("mcps.expired_request")]
    ExpiredRequest,

    /// A previously seen `(signer, audience, nonce)` triple was replayed.
    #[error("mcps.replay_detected")]
    ReplayDetected,

    /// The envelope `audience` did not match the expected verifier identity.
    #[error("mcps.invalid_audience")]
    InvalidAudience,

    /// Trust resolution found no usable binding for `(signer, key_id)`
    /// (not-found / revoked / disabled / malformed key). Name kept verbatim per
    /// ADR-007 despite the field rename `actor` -> `signer`.
    #[error("mcps.actor_binding_failed")]
    ActorBindingFailed,

    /// Transport-level channel binding check failed.
    #[error("mcps.transport_binding_failed")]
    TransportBindingFailed,

    /// Required `authorization_hash` field absent. Renamed from the brief's
    /// `capability_hash_missing` (field renamed).
    #[error("mcps.authorization_hash_missing")]
    AuthorizationHashMissing,

    /// Required `on_behalf_of` field absent. Renamed from the brief's
    /// `missing_principal` ("principal" term rejected).
    #[error("mcps.on_behalf_of_missing")]
    OnBehalfOfMissing,

    /// `on_behalf_of` was present but malformed (e.g. empty). Renamed from the
    /// brief's `invalid_principal_format`.
    #[error("mcps.on_behalf_of_invalid_format")]
    OnBehalfOfInvalidFormat,

    /// Response signature did not verify, or an unsupported algorithm was used.
    #[error("mcps.response_sig_invalid")]
    ResponseSigInvalid,

    /// The response's `request_hash` did not match the locally verified request
    /// hash (binding mismatch).
    #[error("mcps.response_hash_mismatch")]
    ResponseHashMismatch,

    /// A security downgrade was attempted and refused.
    #[error("mcps.downgrade_forbidden")]
    DowngradeForbidden,

    /// A JSON-RPC batch (top-level array) was presented; forbidden in Core.
    #[error("mcps.batch_forbidden")]
    BatchForbidden,

    /// A security-consequential notification (no `id`) was presented; such
    /// operations must be id-bearing requests.
    #[error("mcps.notification_forbidden")]
    NotificationForbidden,

    /// An unknown field appeared inside an envelope (fail closed).
    #[error("mcps.unknown_envelope_field")]
    UnknownEnvelopeField,

    /// Operational/transient trust-resolver failure (distinct from a binding
    /// verdict). ADR-007 addition. Never falls back to allow.
    #[error("mcps.trust_resolver_unavailable")]
    TrustResolverUnavailable,

    /// Replay-cache failure (distinct from a replay verdict). Oracle addition
    /// (ADR-006: cache failure fails closed). Parallels
    /// `trust_resolver_unavailable`.
    #[error("mcps.replay_cache_unavailable")]
    ReplayCacheUnavailable,
}

impl McpsError {
    /// Returns the exact frozen wire token (`mcps.<name>`) for this error.
    ///
    /// This is the bare token only — never any `details` payload.
    pub fn wire_code(&self) -> &'static str {
        match self {
            McpsError::MissingEnvelope => "mcps.missing_envelope",
            McpsError::UnsupportedVersion => "mcps.unsupported_version",
            McpsError::InvalidSignature => "mcps.invalid_signature",
            McpsError::CanonicalizationFailed => "mcps.canonicalization_failed",
            McpsError::ExpiredRequest => "mcps.expired_request",
            McpsError::ReplayDetected => "mcps.replay_detected",
            McpsError::InvalidAudience => "mcps.invalid_audience",
            McpsError::ActorBindingFailed => "mcps.actor_binding_failed",
            McpsError::TransportBindingFailed => "mcps.transport_binding_failed",
            McpsError::AuthorizationHashMissing => "mcps.authorization_hash_missing",
            McpsError::OnBehalfOfMissing => "mcps.on_behalf_of_missing",
            McpsError::OnBehalfOfInvalidFormat => "mcps.on_behalf_of_invalid_format",
            McpsError::ResponseSigInvalid => "mcps.response_sig_invalid",
            McpsError::ResponseHashMismatch => "mcps.response_hash_mismatch",
            McpsError::DowngradeForbidden => "mcps.downgrade_forbidden",
            McpsError::BatchForbidden => "mcps.batch_forbidden",
            McpsError::NotificationForbidden => "mcps.notification_forbidden",
            McpsError::UnknownEnvelopeField => "mcps.unknown_envelope_field",
            McpsError::TrustResolverUnavailable => "mcps.trust_resolver_unavailable",
            McpsError::ReplayCacheUnavailable => "mcps.replay_cache_unavailable",
        }
    }
}

/// Result alias over the frozen MCP-S error taxonomy.
pub type McpsResult<T> = Result<T, McpsError>;

#[cfg(test)]
mod tests {
    use super::McpsError;

    /// Every variant's `Display` output must equal its `wire_code`, and both
    /// must be a bare `mcps.*` token (no whitespace, no details).
    fn check(err: McpsError, expected: &str) {
        assert_eq!(err.wire_code(), expected);
        assert_eq!(err.to_string(), expected);
        assert!(expected.starts_with("mcps."));
        assert!(!expected.contains(' '));
    }

    #[test]
    fn renamed_and_kept_variants_render_exact_wire_strings() {
        check(
            McpsError::CanonicalizationFailed,
            "mcps.canonicalization_failed",
        );
        check(
            McpsError::AuthorizationHashMissing,
            "mcps.authorization_hash_missing",
        );
        check(McpsError::OnBehalfOfMissing, "mcps.on_behalf_of_missing");
        check(
            McpsError::OnBehalfOfInvalidFormat,
            "mcps.on_behalf_of_invalid_format",
        );
        check(
            McpsError::TrustResolverUnavailable,
            "mcps.trust_resolver_unavailable",
        );
        check(
            McpsError::ReplayCacheUnavailable,
            "mcps.replay_cache_unavailable",
        );
        // KEPT verbatim despite field rename actor -> signer (ADR-007).
        check(McpsError::ActorBindingFailed, "mcps.actor_binding_failed");
    }

    #[test]
    fn full_taxonomy_wire_strings() {
        check(McpsError::MissingEnvelope, "mcps.missing_envelope");
        check(McpsError::UnsupportedVersion, "mcps.unsupported_version");
        check(McpsError::InvalidSignature, "mcps.invalid_signature");
        check(McpsError::ExpiredRequest, "mcps.expired_request");
        check(McpsError::ReplayDetected, "mcps.replay_detected");
        check(McpsError::InvalidAudience, "mcps.invalid_audience");
        check(
            McpsError::TransportBindingFailed,
            "mcps.transport_binding_failed",
        );
        check(McpsError::ResponseSigInvalid, "mcps.response_sig_invalid");
        check(
            McpsError::ResponseHashMismatch,
            "mcps.response_hash_mismatch",
        );
        check(McpsError::DowngradeForbidden, "mcps.downgrade_forbidden");
        check(McpsError::BatchForbidden, "mcps.batch_forbidden");
        check(
            McpsError::NotificationForbidden,
            "mcps.notification_forbidden",
        );
        check(
            McpsError::UnknownEnvelopeField,
            "mcps.unknown_envelope_field",
        );
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(McpsError::ReplayDetected, McpsError::ReplayDetected);
        assert_ne!(McpsError::ReplayDetected, McpsError::ExpiredRequest);
    }
}
