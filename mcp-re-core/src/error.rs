//! Frozen MCP-RE error taxonomy (MCP_RE_SPEC §8 / ADR-002, ADR-007, ADR-009).
//!
//! Every `mcp-re.*` constant in the frozen oracle is represented by exactly one
//! variant. `Display` and [`McpReError::wire_code`] both render the bare
//! `mcp-re.<name>` token; any human-readable `details` payload is kept separate so
//! the wire token is never polluted.

/// The complete frozen MCP-RE error taxonomy. One variant per `mcp-re.*` constant.
///
/// `Display` (via `thiserror`) and [`McpReError::wire_code`] both yield the exact
/// wire string (e.g. `mcp-re.invalid_signature`). Variants that can usefully carry
/// diagnostic context hold a `details: String`; the wire token NEVER includes it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpReError {
    /// No MCP-RE envelope present under the expected `_meta` key.
    #[error("mcp-re.missing_envelope")]
    MissingEnvelope,

    /// Envelope `version` is not `draft-01`.
    #[error("mcp-re.unsupported_version")]
    UnsupportedVersion,

    /// Signature did not verify, or an unsupported algorithm was presented.
    #[error("mcp-re.invalid_signature")]
    InvalidSignature,

    /// The protected message violated the JCS-safe value domain (duplicate keys,
    /// unsafe integers, invalid UTF-8, non-integer numbers, ...).
    #[error("mcp-re.canonicalization_failed")]
    CanonicalizationFailed,

    /// The request fell outside its freshness window (stale or future-dated
    /// beyond the configured clock skew).
    #[error("mcp-re.expired_request")]
    ExpiredRequest,

    /// A previously seen `(signer, audience, nonce)` triple was replayed.
    #[error("mcp-re.replay_detected")]
    ReplayDetected,

    /// The envelope `audience` did not match the expected verifier identity.
    #[error("mcp-re.invalid_audience")]
    InvalidAudience,

    /// Trust resolution found no usable binding for `(signer, key_id)`
    /// (not-found / revoked / disabled / malformed key). Name kept verbatim per
    /// ADR-007 despite the field rename `actor` -> `signer`.
    #[error("mcp-re.actor_binding_failed")]
    ActorBindingFailed,

    /// Transport-level channel binding check failed.
    #[error("mcp-re.transport_binding_failed")]
    TransportBindingFailed,

    /// Required `authorization_hash` field absent. Renamed from the brief's
    /// `capability_hash_missing` (field renamed).
    #[error("mcp-re.authorization_hash_missing")]
    AuthorizationHashMissing,

    /// Required `on_behalf_of` field absent. Renamed from the brief's
    /// `missing_principal` ("principal" term rejected).
    #[error("mcp-re.on_behalf_of_missing")]
    OnBehalfOfMissing,

    /// `on_behalf_of` was present but malformed (e.g. empty). Renamed from the
    /// brief's `invalid_principal_format`.
    #[error("mcp-re.on_behalf_of_invalid_format")]
    OnBehalfOfInvalidFormat,

    /// Response signature did not verify, or an unsupported algorithm was used.
    #[error("mcp-re.response_sig_invalid")]
    ResponseSigInvalid,

    /// The response's `request_hash` did not match the locally verified request
    /// hash (binding mismatch).
    #[error("mcp-re.response_hash_mismatch")]
    ResponseHashMismatch,

    /// A security downgrade was attempted and refused.
    #[error("mcp-re.downgrade_forbidden")]
    DowngradeForbidden,

    /// A JSON-RPC batch (top-level array) was presented; forbidden in Core.
    #[error("mcp-re.batch_forbidden")]
    BatchForbidden,

    /// A security-consequential notification (no `id`) was presented; such
    /// operations must be id-bearing requests.
    #[error("mcp-re.notification_forbidden")]
    NotificationForbidden,

    /// An unknown field appeared inside an envelope (fail closed).
    #[error("mcp-re.unknown_envelope_field")]
    UnknownEnvelopeField,

    /// Operational/transient trust-resolver failure (distinct from a binding
    /// verdict). ADR-007 addition. Never falls back to allow.
    #[error("mcp-re.trust_resolver_unavailable")]
    TrustResolverUnavailable,

    /// Replay-cache failure (distinct from a replay verdict). Oracle addition
    /// (ADR-006: cache failure fails closed). Parallels
    /// `trust_resolver_unavailable`.
    #[error("mcp-re.replay_cache_unavailable")]
    ReplayCacheUnavailable,

    // ----- Draft-02 (v0.6) fail-closed codes (ADR-MCPS-040 / decision F.1) -----
    // Granular for protocol/profile-confusion failures; low-level JSON
    // value-domain failures stay coarse under `CanonicalizationFailed`. All nine
    // are draft-02-scoped: draft-01 verification never emits them (ADR-MCPS-041).
    /// Draft-02 envelope lacks the protected `canonicalization_id` member.
    #[error("mcp-re.canonicalization_id_missing")]
    CanonicalizationIdMissing,

    /// `canonicalization_id` names no canonicalization scheme the verifier knows
    /// (unrecognized token — an unknown-id probe).
    #[error("mcp-re.canonicalization_id_unknown")]
    CanonicalizationIdUnknown,

    /// `canonicalization_id` is a recognized scheme but is not in the active
    /// draft-02 profile allowlist (e.g. a future floats scheme presented under the
    /// int53-only v0.6 profile) — a disallowed-future-scheme probe.
    #[error("mcp-re.canonicalization_id_not_allowed")]
    CanonicalizationIdNotAllowed,

    /// The presented `canonicalization_id` does not match the value bound into the
    /// signed evidence (request/response disagreement or a signed-wrong-scheme
    /// presentation).
    #[error("mcp-re.canonicalization_id_mismatch")]
    CanonicalizationIdMismatch,

    /// Required draft-02 `authorization_binding` object absent. MINTED for
    /// draft-02 (ADR-MCPS-040): NOT a reuse of `authorization_hash_missing`, which
    /// names a draft-01 field that no longer exists on the draft-02 wire.
    #[error("mcp-re.authorization_binding_missing")]
    AuthorizationBindingMissing,

    /// `authorization_binding.binding_type` is not one of the base draft-02 forms
    /// (`opaque-bytes` / `authz-system-reference`).
    #[error("mcp-re.authorization_binding_type_unsupported")]
    AuthorizationBindingTypeUnsupported,

    /// `authorization_binding` is structurally invalid for its `binding_type`
    /// (missing mandatory field, malformed digest shape, ...).
    #[error("mcp-re.authorization_binding_malformed")]
    AuthorizationBindingMalformed,

    /// A structured authorization-object binding (case 3) was presented; the base
    /// draft-02 profile forbids it without an explicit authorization-binding
    /// profile defining artifact schema / canonicalization / hash / vectors.
    #[error("mcp-re.authorization_binding_profile_required")]
    AuthorizationBindingProfileRequired,

    /// The opaque-bytes binding cannot be reduced to one unambiguous byte string
    /// (e.g. both binding forms present, or an ambiguous artifact representation).
    #[error("mcp-re.authorization_binding_ambiguous_bytes")]
    AuthorizationBindingAmbiguousBytes,

    /// The optional draft-02 `continuation` object is present but `type` is not the
    /// supported multi-round-trip token (`mcp-mrt`) — ADR-MCPS-047 / D4. A future
    /// continuation profile would be a distinct token; anything unrecognized fails
    /// closed rather than being treated as a bare (unbound) request.
    #[error("mcp-re.continuation_type_unsupported")]
    ContinuationTypeUnsupported,

    /// The draft-02 `continuation` object is structurally invalid for its `type`
    /// (missing/extra field, empty value, or a hash that is not a well-formed
    /// `sha256:<base64url>` identifier) — ADR-MCPS-047 / D4. Core validates the
    /// binding SHAPE only; the policy/server layer checks the hashes against the
    /// verified `InputRequiredResult` it is answering.
    #[error("mcp-re.continuation_malformed")]
    ContinuationMalformed,

    // ----- HTTP-profile signed-rejection codes (ADR-MCPRE-050, MCPRE-92) -----
    // Added to the frozen taxonomy (no parallel namespace) so the HTTP profile's
    // signed rejections carry precise, security-grouped wire codes rather than
    // folding onto the coarser draft-01/02 tokens. Ratified 2026-07-07.
    /// An evidence structure is present but structurally invalid — a signature
    /// base, `Signature-Input` member, or evidence block that does not parse
    /// against the profile's closed grammar. Distinct from
    /// [`McpReError::MissingEnvelope`] (evidence entirely absent).
    #[error("mcp-re.malformed_envelope")]
    MalformedEnvelope,

    /// The message content does not match its signed `Content-Digest`
    /// (RFC 9530). Distinct from [`McpReError::InvalidSignature`]: the content
    /// commitment itself is wrong, before any signature statement about it is
    /// weighed.
    #[error("mcp-re.digest_mismatch")]
    DigestMismatch,

    /// An `artifact_bindings[]` proof (DPoP `ath`, mTLS `x5t#S256`, RAR
    /// authorization-details digest) does not bind to the covered credential
    /// surface.
    #[error("mcp-re.artifact_binding_failed")]
    ArtifactBindingFailed,

    /// A signed response's `;req` / `request_evidence` binding does not match
    /// the signed request it claims to answer (a splice). Distinct from
    /// [`McpReError::ResponseHashMismatch`], which names the native-profile
    /// `request_hash` field.
    #[error("mcp-re.request_binding_mismatch")]
    RequestBindingMismatch,

    /// An MRTR continuation handle does not match its mandated signature-base
    /// digest (previous-request, input-required-response, or `requestState`).
    #[error("mcp-re.continuation_binding_failed")]
    ContinuationBindingFailed,

    // Delegated signing-key attestation (ADR-MCPRE-052 §8). A delegated-key
    // response is fail-closed on any uncertainty in the credential → root chain.
    /// A delegated-key-signed response carried no inline delegation credential
    /// (in required delegation mode, a directly root-signed response also lands
    /// here). ADR-MCPRE-052 §3 step 1.
    #[error("mcp-re.delegation_credential_missing")]
    DelegationCredentialMissing,

    /// The delegation JWS is malformed, `alg` ≠ `EdDSA`, JWS `kid` ≠ `issuer_kid`,
    /// or the root signature does not verify. ADR-MCPRE-052 §3 step 3.
    #[error("mcp-re.delegation_credential_invalid")]
    DelegationCredentialInvalid,

    /// `now` is outside the credential's `[nbf, exp]` window (+ skew).
    /// ADR-MCPRE-052 §3 step 4.
    #[error("mcp-re.delegation_credential_expired")]
    DelegationCredentialExpired,

    /// The credential's `issuer_kid` is not a trusted root anchor.
    /// ADR-MCPRE-052 §3 step 2.
    #[error("mcp-re.delegation_issuer_untrusted")]
    DelegationIssuerUntrusted,

    /// `mcp_re_profile` is not the active HTTP profile id. ADR-MCPRE-052 §3 step 5.
    #[error("mcp-re.delegation_profile_mismatch")]
    DelegationProfileMismatch,

    /// The verifier is not named in `aud`, or `mcp_re_audience_hash` /
    /// `mcp_re_server_signer` do not match the expected service/audience scope —
    /// a credential lifted outside its scope. ADR-MCPRE-052 §3 step 5.
    #[error("mcp-re.delegation_audience_mismatch")]
    DelegationAudienceMismatch,

    /// `mcp_re_key_use` does not permit this signature use. ADR-MCPRE-052 §3 step 5.
    #[error("mcp-re.delegation_key_use_invalid")]
    DelegationKeyUseInvalid,

    /// The credential's `trust_epoch` is not in the verifier's active accepted
    /// epoch set — a coarse, coherent invalidation independent of targeted
    /// revocation. ADR-MCPRE-052 §3 step 6.
    #[error("mcp-re.delegation_trust_epoch_stale")]
    DelegationTrustEpochStale,

    /// The RFC 9421 response `keyid` ≠ `delegated_kid`, or the response signature
    /// does not verify under `cnf.jwk`. ADR-MCPRE-052 §3 step 8.
    #[error("mcp-re.delegation_key_mismatch")]
    DelegationKeyMismatch,

    /// `delegated_kid` or `issuer_kid` is revoked at the current trust epoch.
    /// ADR-MCPRE-052 §3 step 7.
    #[error("mcp-re.delegation_revoked")]
    DelegationRevoked,
}

impl McpReError {
    /// Returns the exact frozen wire token (`mcp-re.<name>`) for this error.
    ///
    /// This is the bare token only — never any `details` payload.
    pub fn wire_code(&self) -> &'static str {
        match self {
            McpReError::MissingEnvelope => "mcp-re.missing_envelope",
            McpReError::UnsupportedVersion => "mcp-re.unsupported_version",
            McpReError::InvalidSignature => "mcp-re.invalid_signature",
            McpReError::CanonicalizationFailed => "mcp-re.canonicalization_failed",
            McpReError::ExpiredRequest => "mcp-re.expired_request",
            McpReError::ReplayDetected => "mcp-re.replay_detected",
            McpReError::InvalidAudience => "mcp-re.invalid_audience",
            McpReError::ActorBindingFailed => "mcp-re.actor_binding_failed",
            McpReError::TransportBindingFailed => "mcp-re.transport_binding_failed",
            McpReError::AuthorizationHashMissing => "mcp-re.authorization_hash_missing",
            McpReError::OnBehalfOfMissing => "mcp-re.on_behalf_of_missing",
            McpReError::OnBehalfOfInvalidFormat => "mcp-re.on_behalf_of_invalid_format",
            McpReError::ResponseSigInvalid => "mcp-re.response_sig_invalid",
            McpReError::ResponseHashMismatch => "mcp-re.response_hash_mismatch",
            McpReError::DowngradeForbidden => "mcp-re.downgrade_forbidden",
            McpReError::BatchForbidden => "mcp-re.batch_forbidden",
            McpReError::NotificationForbidden => "mcp-re.notification_forbidden",
            McpReError::UnknownEnvelopeField => "mcp-re.unknown_envelope_field",
            McpReError::TrustResolverUnavailable => "mcp-re.trust_resolver_unavailable",
            McpReError::ReplayCacheUnavailable => "mcp-re.replay_cache_unavailable",
            // Draft-02 (v0.6) — ADR-MCPS-040 / decision F.1.
            McpReError::CanonicalizationIdMissing => "mcp-re.canonicalization_id_missing",
            McpReError::CanonicalizationIdUnknown => "mcp-re.canonicalization_id_unknown",
            McpReError::CanonicalizationIdNotAllowed => "mcp-re.canonicalization_id_not_allowed",
            McpReError::CanonicalizationIdMismatch => "mcp-re.canonicalization_id_mismatch",
            McpReError::AuthorizationBindingMissing => "mcp-re.authorization_binding_missing",
            McpReError::AuthorizationBindingTypeUnsupported => {
                "mcp-re.authorization_binding_type_unsupported"
            }
            McpReError::AuthorizationBindingMalformed => "mcp-re.authorization_binding_malformed",
            McpReError::AuthorizationBindingProfileRequired => {
                "mcp-re.authorization_binding_profile_required"
            }
            McpReError::AuthorizationBindingAmbiguousBytes => {
                "mcp-re.authorization_binding_ambiguous_bytes"
            }
            McpReError::ContinuationTypeUnsupported => "mcp-re.continuation_type_unsupported",
            McpReError::ContinuationMalformed => "mcp-re.continuation_malformed",
            // HTTP-profile signed-rejection codes (ADR-MCPRE-050, MCPRE-92).
            McpReError::MalformedEnvelope => "mcp-re.malformed_envelope",
            McpReError::DigestMismatch => "mcp-re.digest_mismatch",
            McpReError::ArtifactBindingFailed => "mcp-re.artifact_binding_failed",
            McpReError::RequestBindingMismatch => "mcp-re.request_binding_mismatch",
            McpReError::ContinuationBindingFailed => "mcp-re.continuation_binding_failed",
            // Delegated signing-key attestation (ADR-MCPRE-052 §8).
            McpReError::DelegationCredentialMissing => "mcp-re.delegation_credential_missing",
            McpReError::DelegationCredentialInvalid => "mcp-re.delegation_credential_invalid",
            McpReError::DelegationCredentialExpired => "mcp-re.delegation_credential_expired",
            McpReError::DelegationIssuerUntrusted => "mcp-re.delegation_issuer_untrusted",
            McpReError::DelegationProfileMismatch => "mcp-re.delegation_profile_mismatch",
            McpReError::DelegationAudienceMismatch => "mcp-re.delegation_audience_mismatch",
            McpReError::DelegationKeyUseInvalid => "mcp-re.delegation_key_use_invalid",
            McpReError::DelegationTrustEpochStale => "mcp-re.delegation_trust_epoch_stale",
            McpReError::DelegationKeyMismatch => "mcp-re.delegation_key_mismatch",
            McpReError::DelegationRevoked => "mcp-re.delegation_revoked",
        }
    }
}

/// Result alias over the frozen MCP-RE error taxonomy.
pub type McpReResult<T> = Result<T, McpReError>;

#[cfg(test)]
mod tests {
    use super::McpReError;

    /// Every variant's `Display` output must equal its `wire_code`, and both
    /// must be a bare `mcp-re.*` token (no whitespace, no details).
    fn check(err: McpReError, expected: &str) {
        assert_eq!(err.wire_code(), expected);
        assert_eq!(err.to_string(), expected);
        assert!(expected.starts_with("mcp-re."));
        assert!(!expected.contains(' '));
    }

    #[test]
    fn renamed_and_kept_variants_render_exact_wire_strings() {
        check(
            McpReError::CanonicalizationFailed,
            "mcp-re.canonicalization_failed",
        );
        check(
            McpReError::AuthorizationHashMissing,
            "mcp-re.authorization_hash_missing",
        );
        check(McpReError::OnBehalfOfMissing, "mcp-re.on_behalf_of_missing");
        check(
            McpReError::OnBehalfOfInvalidFormat,
            "mcp-re.on_behalf_of_invalid_format",
        );
        check(
            McpReError::TrustResolverUnavailable,
            "mcp-re.trust_resolver_unavailable",
        );
        check(
            McpReError::ReplayCacheUnavailable,
            "mcp-re.replay_cache_unavailable",
        );
        // KEPT verbatim despite field rename actor -> signer (ADR-007).
        check(
            McpReError::ActorBindingFailed,
            "mcp-re.actor_binding_failed",
        );
    }

    #[test]
    fn full_taxonomy_wire_strings() {
        check(McpReError::MissingEnvelope, "mcp-re.missing_envelope");
        check(McpReError::UnsupportedVersion, "mcp-re.unsupported_version");
        check(McpReError::InvalidSignature, "mcp-re.invalid_signature");
        check(McpReError::ExpiredRequest, "mcp-re.expired_request");
        check(McpReError::ReplayDetected, "mcp-re.replay_detected");
        check(McpReError::InvalidAudience, "mcp-re.invalid_audience");
        check(
            McpReError::TransportBindingFailed,
            "mcp-re.transport_binding_failed",
        );
        check(
            McpReError::ResponseSigInvalid,
            "mcp-re.response_sig_invalid",
        );
        check(
            McpReError::ResponseHashMismatch,
            "mcp-re.response_hash_mismatch",
        );
        check(McpReError::DowngradeForbidden, "mcp-re.downgrade_forbidden");
        check(McpReError::BatchForbidden, "mcp-re.batch_forbidden");
        check(
            McpReError::NotificationForbidden,
            "mcp-re.notification_forbidden",
        );
        check(
            McpReError::UnknownEnvelopeField,
            "mcp-re.unknown_envelope_field",
        );
    }

    #[test]
    fn delegation_wire_strings() {
        check(
            McpReError::DelegationCredentialMissing,
            "mcp-re.delegation_credential_missing",
        );
        check(
            McpReError::DelegationCredentialInvalid,
            "mcp-re.delegation_credential_invalid",
        );
        check(
            McpReError::DelegationCredentialExpired,
            "mcp-re.delegation_credential_expired",
        );
        check(
            McpReError::DelegationIssuerUntrusted,
            "mcp-re.delegation_issuer_untrusted",
        );
        check(
            McpReError::DelegationProfileMismatch,
            "mcp-re.delegation_profile_mismatch",
        );
        check(
            McpReError::DelegationAudienceMismatch,
            "mcp-re.delegation_audience_mismatch",
        );
        check(
            McpReError::DelegationKeyUseInvalid,
            "mcp-re.delegation_key_use_invalid",
        );
        check(
            McpReError::DelegationTrustEpochStale,
            "mcp-re.delegation_trust_epoch_stale",
        );
        check(
            McpReError::DelegationKeyMismatch,
            "mcp-re.delegation_key_mismatch",
        );
        check(McpReError::DelegationRevoked, "mcp-re.delegation_revoked");
    }

    #[test]
    fn draft02_wire_strings() {
        // ADR-MCPS-040 / decision F.1 — the nine new draft-02 fail-closed codes.
        check(
            McpReError::CanonicalizationIdMissing,
            "mcp-re.canonicalization_id_missing",
        );
        check(
            McpReError::CanonicalizationIdUnknown,
            "mcp-re.canonicalization_id_unknown",
        );
        check(
            McpReError::CanonicalizationIdNotAllowed,
            "mcp-re.canonicalization_id_not_allowed",
        );
        check(
            McpReError::CanonicalizationIdMismatch,
            "mcp-re.canonicalization_id_mismatch",
        );
        check(
            McpReError::AuthorizationBindingMissing,
            "mcp-re.authorization_binding_missing",
        );
        check(
            McpReError::AuthorizationBindingTypeUnsupported,
            "mcp-re.authorization_binding_type_unsupported",
        );
        check(
            McpReError::AuthorizationBindingMalformed,
            "mcp-re.authorization_binding_malformed",
        );
        check(
            McpReError::AuthorizationBindingProfileRequired,
            "mcp-re.authorization_binding_profile_required",
        );
        check(
            McpReError::AuthorizationBindingAmbiguousBytes,
            "mcp-re.authorization_binding_ambiguous_bytes",
        );
    }

    /// `authorization_binding_missing` is MINTED for draft-02 and is distinct from
    /// the retained draft-01 `authorization_hash_missing` (ADR-MCPS-040).
    #[test]
    fn draft02_binding_missing_is_distinct_from_draft01_hash_missing() {
        assert_ne!(
            McpReError::AuthorizationBindingMissing.wire_code(),
            McpReError::AuthorizationHashMissing.wire_code(),
        );
        check(
            McpReError::AuthorizationHashMissing,
            "mcp-re.authorization_hash_missing",
        );
    }

    #[test]
    fn http_profile_signed_rejection_wire_strings() {
        // ADR-MCPRE-050 / MCPRE-92 — the five HTTP-profile additions, grouped
        // by security meaning and frozen before they go wire-visible in signed
        // rejections.
        check(McpReError::MalformedEnvelope, "mcp-re.malformed_envelope");
        check(McpReError::DigestMismatch, "mcp-re.digest_mismatch");
        check(
            McpReError::ArtifactBindingFailed,
            "mcp-re.artifact_binding_failed",
        );
        check(
            McpReError::RequestBindingMismatch,
            "mcp-re.request_binding_mismatch",
        );
        check(
            McpReError::ContinuationBindingFailed,
            "mcp-re.continuation_binding_failed",
        );
    }

    /// The new codes are distinct from the coarser tokens the HTTP profile used
    /// to fold onto — a `Content-Digest` mismatch is no longer `invalid_signature`,
    /// and a response splice is no longer the native `response_hash_mismatch`.
    #[test]
    fn http_profile_codes_are_distinct_from_the_folds_they_replace() {
        assert_ne!(
            McpReError::DigestMismatch.wire_code(),
            McpReError::InvalidSignature.wire_code(),
        );
        assert_ne!(
            McpReError::RequestBindingMismatch.wire_code(),
            McpReError::ResponseHashMismatch.wire_code(),
        );
        assert_ne!(
            McpReError::MalformedEnvelope.wire_code(),
            McpReError::MissingEnvelope.wire_code(),
        );
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(McpReError::ReplayDetected, McpReError::ReplayDetected);
        assert_ne!(McpReError::ReplayDetected, McpReError::ExpiredRequest);
    }
}
