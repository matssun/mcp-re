//! MCP-RE audit-evidence vocabulary (ADR-MCPS-035).
//!
//! The audit layer emits security evidence for the verdicts MCP-RE Core reaches.
//! Its **rejection reasons are derived from the frozen `McpReError::wire_code()`
//! taxonomy** ([`crate::error`] is the sole authority): a rejection event carries
//! the EXACT `mcp-re.*` wire token as its `reason`, never a parallel sub-name. The
//! net-new surface is the pair of success events the error enum cannot express
//! (`mcp-re.request.accepted`, `mcp-re.response.signed`) plus the three
//! delegated-key lifecycle events authorized by ADR-MCPRE-052 §7
//! (`mcp-re.delegated_key.{issued,rotated,retired}`).
//!
//! This keeps the audit layer inside the same bind-not-interpret boundary as the
//! rest of Core: there is no `authorization_hash_mismatch` audit reason, because
//! "mismatch" would imply Core semantically compared the authorization artifact —
//! which is the configured AuthorizationProfile's job (ADR-MCPS-013), not Core's.
//!
//! **Non-goal:** this vocabulary is NOT a full SIEM schema and does not replace
//! deployment audit policy. It fixes only the stable machine tokens; the optional
//! [`reason_label`](AuditEvent::reason_label) is non-normative display text.
//!
//! A CI drift guard (`//mcp-re-conformance:audit_vocabulary_guard_test`,
//! ADR-MCPS-035/036) asserts every rejection `reason` this module can emit is a
//! member of `McpReError::wire_code()`, and that the success set is exactly the
//! two-item allowlist below.

use crate::error::McpReError;

/// The fixed `event_type` of every MCP-RE audit event. Rejections reuse two of
/// these; the two success events are the only net-new tokens (the error enum
/// cannot express a success/lifecycle outcome).
pub mod event_type {
    /// A request envelope passed verification (net-new success/lifecycle event).
    pub const REQUEST_ACCEPTED: &str = "mcp-re.request.accepted";
    /// A response was signed after the request verified (net-new success event).
    pub const RESPONSE_SIGNED: &str = "mcp-re.response.signed";
    /// A request was rejected; `reason` is the exact `McpReError::wire_code()`.
    pub const REQUEST_REJECTED: &str = "mcp-re.request.rejected";
    /// A response was rejected; `reason` is the exact `McpReError::wire_code()`.
    pub const RESPONSE_REJECTED: &str = "mcp-re.response.rejected";

    // Delegated-key lifecycle events (ADR-MCPRE-052 §7 — the authorizing ADR for
    // this third audit category). Emitted by the custody layer at issuance /
    // rotation / retirement; they carry no `reason` (not a verdict) and no key
    // material or nonce/correlation data (ADR-MCPS-020 startup-line discipline).
    /// A delegated signing key + credential was issued.
    pub const DELEGATED_KEY_ISSUED: &str = "mcp-re.delegated_key.issued";
    /// A successor delegated key was minted during the rotation-overlap window.
    pub const DELEGATED_KEY_ROTATED: &str = "mcp-re.delegated_key.rotated";
    /// A delegated key reached `exp` (or was revoked) and was retired.
    pub const DELEGATED_KEY_RETIRED: &str = "mcp-re.delegated_key.retired";
}

/// The exact, exhaustive success/lifecycle allowlist (ADR-MCPS-035 §3). These
/// are the ONLY audit events the frozen error taxonomy cannot express; no third
/// success event may be minted without an ADR. The drift guard pins this set.
pub const SUCCESS_EVENT_TYPES: &[&str] =
    &[event_type::REQUEST_ACCEPTED, event_type::RESPONSE_SIGNED];

/// The rejection `event_type` allowlist. Both carry an `McpReError::wire_code()`
/// token in `reason`; neither mints a rejection sub-name (no
/// `mcp-re.request.rejected.bad_signature`, no `…authorization_hash_mismatch`).
pub const REJECTION_EVENT_TYPES: &[&str] =
    &[event_type::REQUEST_REJECTED, event_type::RESPONSE_REJECTED];

/// The delegated-key lifecycle `event_type` allowlist — the third audit category,
/// authorized by ADR-MCPRE-052 §7 (issuance / rotation / retirement). Like the
/// success events these carry no `reason` (not a verdict); unlike them they are
/// emitted by the custody layer, not by a Core verification outcome. The drift
/// guard pins this set to exactly these three.
pub const KEY_LIFECYCLE_EVENT_TYPES: &[&str] = &[
    event_type::DELEGATED_KEY_ISSUED,
    event_type::DELEGATED_KEY_ROTATED,
    event_type::DELEGATED_KEY_RETIRED,
];

/// The frozen rejection reason for an `McpReError` — its EXACT `wire_code()`.
///
/// This is the single point that maps a Core verdict to an audit `reason`. It is
/// `wire_code()` verbatim: no rename, no sub-name, no interpretation. A new
/// rejection outcome therefore requires a new `McpReError` variant first (the
/// frozen-taxonomy process), which the audit layer then inherits automatically.
pub fn rejection_reason(error: &McpReError) -> &'static str {
    error.wire_code()
}

/// A non-normative, human-readable label for an `McpReError`, suitable for the
/// optional [`AuditEvent::reason_label`] display field. SIEM readability only —
/// the stable machine token is always [`rejection_reason`]; this MUST NOT be
/// parsed. Provided as a convenience so consumers need not maintain their own
/// map; absence of a label is always acceptable.
pub fn reason_label(error: &McpReError) -> &'static str {
    match error {
        McpReError::MissingEnvelope => "Missing MCP-RE envelope",
        McpReError::UnsupportedVersion => "Unsupported envelope version",
        McpReError::InvalidSignature => "Invalid signature",
        McpReError::SerializationFailed => "Serialization failed",
        McpReError::ExpiredRequest => "Expired request",
        McpReError::ReplayDetected => "Replay detected",
        McpReError::InvalidAudience => "Invalid audience",
        McpReError::ActorBindingFailed => "Signer trust binding failed",
        McpReError::TransportBindingFailed => "Transport binding failed",
        McpReError::AuthorizationHashMissing => "Authorization hash missing",
        McpReError::OnBehalfOfMissing => "on_behalf_of missing",
        McpReError::OnBehalfOfInvalidFormat => "on_behalf_of malformed",
        McpReError::ResponseSigInvalid => "Invalid response signature",
        McpReError::ResponseHashMismatch => "Response/request hash mismatch",
        McpReError::DowngradeForbidden => "Security downgrade forbidden",
        McpReError::BatchForbidden => "JSON-RPC batch forbidden",
        McpReError::NotificationForbidden => "Security notification forbidden",
        McpReError::UnknownEnvelopeField => "Unknown envelope field",
        McpReError::TrustResolverUnavailable => "Trust resolver unavailable",
        McpReError::ReplayCacheUnavailable => "Replay cache unavailable",
        // Draft-02 (v0.6) — ADR-MCPS-040 / decision F.1.
        McpReError::AuthorizationBindingMissing => "authorization_binding missing",
        McpReError::AuthorizationBindingTypeUnsupported => "authorization_binding type unsupported",
        McpReError::AuthorizationBindingMalformed => "authorization_binding malformed",
        McpReError::AuthorizationBindingProfileRequired => "authorization_binding profile required",
        McpReError::AuthorizationBindingAmbiguousBytes => "authorization_binding ambiguous bytes",
        McpReError::ContinuationTypeUnsupported => "continuation type unsupported",
        McpReError::ContinuationMalformed => "continuation malformed",
        // HTTP-profile signed-rejection codes (ADR-MCPRE-050, MCPRE-92).
        McpReError::MalformedEnvelope => "Malformed evidence structure",
        McpReError::DigestMismatch => "Content-Digest mismatch",
        McpReError::ArtifactBindingFailed => "Artifact binding failed",
        McpReError::RequestBindingMismatch => "Response/request binding mismatch",
        McpReError::ContinuationBindingFailed => "Continuation binding failed",
        // Delegated signing-key attestation (ADR-MCPRE-052).
        McpReError::DelegationCredentialMissing => "Delegation credential missing",
        McpReError::DelegationCredentialInvalid => "Delegation credential invalid",
        McpReError::DelegationCredentialExpired => "Delegation credential expired",
        McpReError::DelegationIssuerUntrusted => "Delegation issuer untrusted",
        McpReError::DelegationProfileMismatch => "Delegation profile mismatch",
        McpReError::DelegationAudienceMismatch => "Delegation audience/scope mismatch",
        McpReError::DelegationKeyUseInvalid => "Delegation key-use invalid",
        McpReError::DelegationTrustEpochStale => "Delegation trust epoch stale",
        McpReError::DelegationKeyMismatch => "Delegation key mismatch",
        McpReError::DelegationRevoked => "Delegation revoked",
    }
}

/// A minimal MCP-RE audit event. The fields mirror ADR-MCPS-035 §6 (the kept seed
/// §5.8 fields). Only `event_type` and `decision` are always present; the rest are
/// optional context populated by the emit site. `reason` is set ONLY on rejection
/// events and is always an `McpReError::wire_code()` token.
///
/// This is a deliberately small value type, not a SIEM record: emit sites map it
/// to whatever sink they use. Core itself does not perform I/O (ADR-MCPS-011/012),
/// so this type only *describes* an event; transport/host layers serialize it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// One of [`SUCCESS_EVENT_TYPES`] or [`REJECTION_EVENT_TYPES`].
    pub event_type: &'static str,
    /// `accepted`/`signed` for success, `rejected` for rejection.
    pub decision: Decision,
    /// Frozen `McpReError::wire_code()` token; `None` for success events.
    pub reason: Option<&'static str>,
    /// Optional non-normative display label; never parsed.
    pub reason_label: Option<&'static str>,
}

/// The decision an audit event records. Success events are accept/sign; rejection
/// events are reject. There is no "mismatch" or other interpreted verdict here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Request passed verification (`mcp-re.request.accepted`).
    Accepted,
    /// Response was signed (`mcp-re.response.signed`).
    Signed,
    /// Request or response was rejected (`reason` carries the wire_code).
    Rejected,
}

impl AuditEvent {
    /// A `mcp-re.request.accepted` success event.
    pub fn request_accepted() -> Self {
        AuditEvent {
            event_type: event_type::REQUEST_ACCEPTED,
            decision: Decision::Accepted,
            reason: None,
            reason_label: None,
        }
    }

    /// A `mcp-re.response.signed` success event.
    pub fn response_signed() -> Self {
        AuditEvent {
            event_type: event_type::RESPONSE_SIGNED,
            decision: Decision::Signed,
            reason: None,
            reason_label: None,
        }
    }

    /// A `mcp-re.request.rejected` event whose `reason` is `error.wire_code()`.
    pub fn request_rejected(error: &McpReError) -> Self {
        AuditEvent {
            event_type: event_type::REQUEST_REJECTED,
            decision: Decision::Rejected,
            reason: Some(rejection_reason(error)),
            reason_label: Some(reason_label(error)),
        }
    }

    /// A `mcp-re.response.rejected` event whose `reason` is `error.wire_code()`.
    pub fn response_rejected(error: &McpReError) -> Self {
        AuditEvent {
            event_type: event_type::RESPONSE_REJECTED,
            decision: Decision::Rejected,
            reason: Some(rejection_reason(error)),
            reason_label: Some(reason_label(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rejection event's `reason` is the EXACT frozen wire token — never a
    /// minted sub-name and never an interpreted "mismatch".
    #[test]
    fn rejection_reason_is_exact_wire_code() {
        for err in [
            McpReError::InvalidSignature,
            McpReError::ExpiredRequest,
            McpReError::ReplayDetected,
            McpReError::ActorBindingFailed,
            McpReError::AuthorizationHashMissing,
        ] {
            let ev = AuditEvent::request_rejected(&err);
            assert_eq!(ev.reason, Some(err.wire_code()));
            assert_eq!(ev.event_type, "mcp-re.request.rejected");
            assert_eq!(ev.decision, Decision::Rejected);
            // No interpreted sub-name leaked into the token.
            assert!(
                !ev.reason.unwrap().contains("mismatch") || err == McpReError::ResponseHashMismatch
            );
        }
    }

    /// The success set is exactly the two-item allowlist; success events never
    /// carry a `reason`.
    #[test]
    fn success_events_are_the_two_item_allowlist() {
        assert_eq!(
            SUCCESS_EVENT_TYPES,
            &["mcp-re.request.accepted", "mcp-re.response.signed"]
        );
        assert_eq!(AuditEvent::request_accepted().reason, None);
        assert_eq!(AuditEvent::response_signed().reason, None);
    }

    /// There is no `authorization_hash_mismatch` audit reason: Core binds, never
    /// interprets the authorization artifact (ADR-MCPS-013).
    #[test]
    fn no_authorization_hash_mismatch_audit_reason() {
        for err in [
            McpReError::AuthorizationHashMissing,
            McpReError::ActorBindingFailed,
        ] {
            let reason = rejection_reason(&err);
            assert_ne!(reason, "mcp-re.authorization_hash_mismatch");
            assert_ne!(reason, "authorization_hash_mismatch");
        }
    }
}
