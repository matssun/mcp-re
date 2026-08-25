// SPDX-License-Identifier: Apache-2.0
//! Non-normative display text for a Core verdict.
//!
//! Kept apart from [`super`] because they are different kinds of fact with different rules.
//! The audit vocabulary next door is FROZEN: its tokens are machine-stable, a drift guard
//! pins them, and adding one is the frozen-taxonomy process. What is here is prose for a
//! human reading a dashboard — it may be reworded at any time, and
//! [`AuditEvent::reason_label`](super::AuditEvent::reason_label) documents that it MUST NOT
//! be parsed.
//!
//! Sharing a file made one look like the other: a map of English sentences sat beside the
//! frozen token map, in the module whose whole claim is that its tokens do not drift.

use crate::error::McpReError;

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
        McpReError::EvidenceRetentionUnavailable => "Retained-evidence store unavailable",
        McpReError::EvidenceRetentionIndeterminate => {
            "Retained-evidence write failed after the call had already executed"
        }
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
        McpReError::DelegatedSigningUnavailable => "Delegated signing unavailable",
        // Response region (ADR-MCPRE-058 §10).
        McpReError::UpstreamResponseInvalid => "Upstream response is not a legal MCP response",
        McpReError::InnerDispatchIndeterminate => {
            "Inner transport failed after the request was transmitted; execution unknown"
        }
        McpReError::InnerPlaneUnavailable => "Inner plane could not begin a dispatch",
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;

    /// A label is prose, not a token: it must never be mistaken for one, because a consumer
    /// that parses it has built a dependency on text this file is free to reword.
    #[test]
    fn a_label_is_never_a_wire_token() {
        for e in [
            McpReError::InvalidSignature,
            McpReError::ReplayDetected,
            McpReError::TrustResolverUnavailable,
        ] {
            let label = reason_label(&e);
            assert!(!label.starts_with("mcp-re."), "got: {label}");
            assert_ne!(label, e.wire_code());
        }
    }

    /// The map is total by exhaustive match, so a new verdict cannot ship label-less — and
    /// no two verdicts share a sentence, which would make the dashboard lie about which
    /// one happened.
    #[test]
    fn every_verdict_has_its_own_sentence() {
        let labels: std::collections::BTreeSet<&'static str> =
            crate::ALL_ERRORS.iter().map(reason_label).collect();
        assert_eq!(labels.len(), crate::ALL_ERRORS.len());
    }
}
