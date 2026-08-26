// SPDX-License-Identifier: Apache-2.0
//! What this crate's failures mean in Core's terms — ADR-MCPRE-066 Slice 2.
//!
//! ONE file per crate decides this, for every taxonomy the crate owns
//! ([`HttpProfileError`] and [`DispatchError`]), and every `wire_code` is derived from it.
//! Two projection sites would be two tables again, one file further apart.
//!
//! # Why this is a projection and not a table of strings
//!
//! `HttpProfileError::wire_code` used to be a match returning `&'static str`, beside a
//! doc note and a unit test asserting every string it returned was also a token
//! `McpReError::wire_code` returns. Two things were wrong with that, and only the second
//! is about size:
//!
//! * **The containment was a coincidence a test rechecked**, not a relationship the code
//!   stated. The carrier and Core agreed because both spelled the same string; nothing
//!   said *this carrier failure IS that Core verdict*. A renamed Core token would have
//!   left the carrier emitting the old one, and the test would have caught it — after the
//!   fact, as drift, rather than as a compile error.
//! * **A string is the wrong currency at a stage boundary.** Once the verdict is a string
//!   it can be handed to anything that takes one, which is how a `PolicyError` token
//!   reached `AuditEvent.reason` (#637). The audit boundary now takes an `McpReError`, so
//!   the carrier must state which Core verdict it *is*, and here is where it does.
//!
//! `wire_code` is therefore **derived** from this projection rather than duplicated beside
//! it: there is exactly one place that decides what a carrier failure means, and the wire
//! token is a consequence of that decision instead of a parallel statement of it.
//!
//! # The grouping is the ratified one
//!
//! The arms below are the mapping ratified by owner ruling 2026-07-07 (MCPRE-92), moved
//! whole. Which failures share a Core verdict, and why, is the security argument — an
//! absent header and a duplicated exactly-once header are both *the evidence you needed is
//! not there*; a foreign covered component and a self-contradictory body are both
//! *malformed*. Those groupings are preserved verbatim, comments included, because
//! restating them would be an opportunity to get one wrong.
//!
//! No wildcard arm. A new [`HttpProfileError`] variant is a compile error here until it
//! says which Core verdict it is, which is the whole point of the projection being
//! exhaustive rather than defaulted.

use mcp_re_core::McpReError;

use super::HttpProfileError;
use crate::dispatch::DispatchError;

impl From<&HttpProfileError> for McpReError {
    fn from(e: &HttpProfileError) -> McpReError {
        match e {
            // Evidence entirely absent (nothing to parse). A duplicated
            // exactly-once header and a genuinely missing covered component are
            // both "the evidence you needed is not there".
            HttpProfileError::MissingEvidence(_)
            | HttpProfileError::DuplicateHeader(_)
            | HttpProfileError::McpTransportHeaderMissing(_)
            | HttpProfileError::MissingCoveredComponent(_) => McpReError::MissingEnvelope,
            // Evidence present but structurally invalid (MCPRE-92): a foreign
            // component/parameter, an unparseable inner list, a wrong-shaped
            // digest member. Grouped away from "absent" so a rejection reason
            // distinguishes tampering from omission.
            // Self-contradictory evidence is malformed evidence: the covered
            // header and the covered body state different methods (§4.1), so
            // there is nothing coherent to act on.
            HttpProfileError::MalformedEvidence(_)
            | HttpProfileError::McpMethodDivergence
            | HttpProfileError::McpTransportDivergence(_) => McpReError::MalformedEnvelope,
            // Content-model / value-domain violation of the protected message:
            // an encoded body, or a media type outside JSON mode (§3.4).
            HttpProfileError::ContentEncodingPresent | HttpProfileError::NonJsonMediaType => {
                McpReError::SerializationFailed
            }
            // The content commitment itself is wrong — precise digest code
            // (MCPRE-92), no longer folded onto invalid_signature.
            HttpProfileError::ContentDigestMismatch => McpReError::DigestMismatch,
            // The signature does not authenticate the bytes.
            HttpProfileError::InvalidSignature | HttpProfileError::ReceiptInvalid => {
                McpReError::InvalidSignature
            }
            // Profile-selection failure: cannot select this profile.
            HttpProfileError::UnknownProfileTag
            | HttpProfileError::UnsupportedAlgorithm
            | HttpProfileError::McpProtocolVersionUnsupported => McpReError::UnsupportedVersion,
            HttpProfileError::StaleWindow | HttpProfileError::AdmissionAssertionExpired => {
                McpReError::ExpiredRequest
            }
            // A keyid outside trust is an actor-binding failure, not a broken
            // signature: the crypto may verify under an untrusted key.
            // An outage is not a binding failure: the resolver never rendered a
            // verdict, so reporting one would misattribute an availability fault to
            // the caller's key.
            HttpProfileError::TrustResolverUnavailable => McpReError::TrustResolverUnavailable,
            HttpProfileError::UnresolvedKeyId
            | HttpProfileError::ActorSlotMismatch
            | HttpProfileError::AdmissionAssertionInvalid
            | HttpProfileError::AdmissionIssuerUntrusted
            | HttpProfileError::AdmissionNotCurrent
            | HttpProfileError::AdmissionStateUnavailable
            | HttpProfileError::ReceiptIssuerUntrusted => McpReError::ActorBindingFailed,
            HttpProfileError::ArtifactBindingFailed => McpReError::ArtifactBindingFailed,
            HttpProfileError::AudienceMismatch => McpReError::InvalidAudience,
            // A response bound to a different request is a request-binding
            // splice — precise code (MCPRE-92), not the native response_hash
            // field name.
            HttpProfileError::ResponseBindingMismatch
            | HttpProfileError::AdmissionBindingMismatch
            | HttpProfileError::ReceiptInclusionInvalid
            | HttpProfileError::ReceiptPositionUnbound
            | HttpProfileError::ReceiptPositionMismatch => McpReError::RequestBindingMismatch,
            HttpProfileError::ResponseSignatureInvalid => McpReError::ResponseSigInvalid,
            HttpProfileError::ContinuationBindingFailed => McpReError::ContinuationBindingFailed,
            // An unrecognized `resultType` and an unrecognized continuation `type`
            // are one fact: the message declares a continuation model this reader
            // does not implement, so it cannot be classified and must not be
            // treated as an ordinary terminal answer.
            HttpProfileError::UnrecognizedResultType => McpReError::ContinuationTypeUnsupported,
            // The backend answered, and what it said is not a legal response. Its own
            // frozen token, because "the caller's evidence is malformed" sends an
            // operator to the wrong system.
            HttpProfileError::UpstreamResponseInvalid(_) => McpReError::UpstreamResponseInvalid,
            // Delegated signing-key attestation (ADR-MCPRE-052 §8).
            HttpProfileError::DelegationCredentialMissing => {
                McpReError::DelegationCredentialMissing
            }
            HttpProfileError::DelegationCredentialInvalid => {
                McpReError::DelegationCredentialInvalid
            }
            HttpProfileError::DelegationCredentialExpired => {
                McpReError::DelegationCredentialExpired
            }
            HttpProfileError::DelegationIssuerUntrusted => McpReError::DelegationIssuerUntrusted,
            HttpProfileError::DelegationProfileMismatch => McpReError::DelegationProfileMismatch,
            HttpProfileError::DelegationAudienceMismatch => McpReError::DelegationAudienceMismatch,
            HttpProfileError::DelegationKeyUseInvalid => McpReError::DelegationKeyUseInvalid,
            HttpProfileError::DelegationTrustEpochStale => McpReError::DelegationTrustEpochStale,
            HttpProfileError::DelegationKeyMismatch => McpReError::DelegationKeyMismatch,
            HttpProfileError::DelegationRevoked => McpReError::DelegationRevoked,
        }
    }
}

/// [`DispatchError`] projects the same way, and its profile arm delegates to the carrier's
/// projection above — one decision per failure, and no second table to keep in step.
impl From<&DispatchError> for McpReError {
    fn from(e: &DispatchError) -> McpReError {
        match e {
            DispatchError::ReplayDetected => McpReError::ReplayDetected,
            DispatchError::ReplayCacheUnavailable | DispatchError::NonSharedReplayTier => {
                McpReError::ReplayCacheUnavailable
            }
            DispatchError::Profile(e) => McpReError::from(e),
        }
    }
}

impl HttpProfileError {
    /// The frozen `mcp-re.*` wire token this failure maps to.
    ///
    /// Derived, not chosen: the projection above decides which Core verdict this failure
    /// is, and the token is that verdict's own. There is no string here to get wrong, and
    /// no second table to keep in step.
    pub fn wire_code(&self) -> &'static str {
        McpReError::from(self).wire_code()
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;

    /// The projection is what makes the no-parallel-namespace rule true, so the derived
    /// token must still be the one the ratified mapping named.
    #[test]
    fn the_derived_token_is_the_projected_verdicts_own() {
        for (e, expected) in [
            (
                HttpProfileError::ContentDigestMismatch,
                McpReError::DigestMismatch,
            ),
            (
                HttpProfileError::InvalidSignature,
                McpReError::InvalidSignature,
            ),
            (
                HttpProfileError::UnresolvedKeyId,
                McpReError::ActorBindingFailed,
            ),
            (
                HttpProfileError::TrustResolverUnavailable,
                McpReError::TrustResolverUnavailable,
            ),
            (
                HttpProfileError::NonJsonMediaType,
                McpReError::SerializationFailed,
            ),
        ] {
            assert_eq!(McpReError::from(&e), expected);
            assert_eq!(e.wire_code(), expected.wire_code());
        }
    }

    /// A store outage and an unknown keyid are different facts, and the projection keeps
    /// them apart — collapsing them once told an operator "untrusted key" during an
    /// outage.
    #[test]
    fn an_outage_does_not_project_onto_an_actor_binding_failure() {
        assert_ne!(
            McpReError::from(&HttpProfileError::TrustResolverUnavailable),
            McpReError::from(&HttpProfileError::UnresolvedKeyId)
        );
    }

    /// The carrier distinguishes exactly this many Core verdicts.
    ///
    /// A golden count, and it states something the named pairs below cannot: that no edit
    /// has quietly MERGED two groups or split one. Which failures share a verdict is the
    /// MCPRE-92 security argument — collapsing two is a change to what a rejection reason
    /// can say, and it must be a deliberate one with this number moved on purpose.
    #[test]
    fn the_projection_preserves_the_ratified_group_count() {
        let verdicts: std::collections::BTreeSet<&'static str> = every_variant()
            .iter()
            .map(|e| McpReError::from(e).wire_code())
            .collect();
        assert_eq!(verdicts.len(), 26, "distinct Core verdicts: {verdicts:?}");
    }

    fn every_variant() -> Vec<HttpProfileError> {
        // The match is on a value only so the compiler proves the arms exhaustive; the
        // returned vector is what the caller compares against.
        fn _exhaustive(e: &HttpProfileError) {
            match e {
                HttpProfileError::MissingEvidence(_)
                | HttpProfileError::MalformedEvidence(_)
                | HttpProfileError::DuplicateHeader(_)
                | HttpProfileError::ContentEncodingPresent
                | HttpProfileError::NonJsonMediaType
                | HttpProfileError::ContentDigestMismatch
                | HttpProfileError::MissingCoveredComponent(_)
                | HttpProfileError::UnknownProfileTag
                | HttpProfileError::UnsupportedAlgorithm
                | HttpProfileError::InvalidSignature
                | HttpProfileError::StaleWindow
                | HttpProfileError::UnresolvedKeyId
                | HttpProfileError::ActorSlotMismatch
                | HttpProfileError::ArtifactBindingFailed
                | HttpProfileError::AudienceMismatch
                | HttpProfileError::ResponseBindingMismatch
                | HttpProfileError::ResponseSignatureInvalid
                | HttpProfileError::ContinuationBindingFailed
                | HttpProfileError::McpMethodDivergence
                | HttpProfileError::McpTransportHeaderMissing(_)
                | HttpProfileError::McpProtocolVersionUnsupported
                | HttpProfileError::McpTransportDivergence(_)
                | HttpProfileError::AdmissionAssertionInvalid
                | HttpProfileError::AdmissionIssuerUntrusted
                | HttpProfileError::AdmissionAssertionExpired
                | HttpProfileError::AdmissionBindingMismatch
                | HttpProfileError::AdmissionNotCurrent
                | HttpProfileError::AdmissionStateUnavailable
                | HttpProfileError::ReceiptInvalid
                | HttpProfileError::ReceiptInclusionInvalid
                | HttpProfileError::ReceiptPositionUnbound
                | HttpProfileError::ReceiptPositionMismatch
                | HttpProfileError::ReceiptIssuerUntrusted
                | HttpProfileError::UnrecognizedResultType
                | HttpProfileError::UpstreamResponseInvalid(_)
                | HttpProfileError::TrustResolverUnavailable
                | HttpProfileError::DelegationCredentialMissing
                | HttpProfileError::DelegationCredentialInvalid
                | HttpProfileError::DelegationCredentialExpired
                | HttpProfileError::DelegationIssuerUntrusted
                | HttpProfileError::DelegationProfileMismatch
                | HttpProfileError::DelegationAudienceMismatch
                | HttpProfileError::DelegationKeyUseInvalid
                | HttpProfileError::DelegationTrustEpochStale
                | HttpProfileError::DelegationKeyMismatch
                | HttpProfileError::DelegationRevoked => {}
            }
        }
        vec![
            HttpProfileError::MissingEvidence("x"),
            HttpProfileError::MalformedEvidence("x"),
            HttpProfileError::DuplicateHeader("x"),
            HttpProfileError::ContentEncodingPresent,
            HttpProfileError::NonJsonMediaType,
            HttpProfileError::ContentDigestMismatch,
            HttpProfileError::MissingCoveredComponent("x"),
            HttpProfileError::UnknownProfileTag,
            HttpProfileError::UnsupportedAlgorithm,
            HttpProfileError::InvalidSignature,
            HttpProfileError::StaleWindow,
            HttpProfileError::UnresolvedKeyId,
            HttpProfileError::ActorSlotMismatch,
            HttpProfileError::ArtifactBindingFailed,
            HttpProfileError::AudienceMismatch,
            HttpProfileError::ResponseBindingMismatch,
            HttpProfileError::ResponseSignatureInvalid,
            HttpProfileError::ContinuationBindingFailed,
            HttpProfileError::McpMethodDivergence,
            HttpProfileError::McpTransportHeaderMissing("x"),
            HttpProfileError::McpProtocolVersionUnsupported,
            HttpProfileError::McpTransportDivergence("x"),
            HttpProfileError::AdmissionAssertionInvalid,
            HttpProfileError::AdmissionIssuerUntrusted,
            HttpProfileError::AdmissionAssertionExpired,
            HttpProfileError::AdmissionBindingMismatch,
            HttpProfileError::AdmissionNotCurrent,
            HttpProfileError::AdmissionStateUnavailable,
            HttpProfileError::ReceiptInvalid,
            HttpProfileError::ReceiptInclusionInvalid,
            HttpProfileError::ReceiptIssuerUntrusted,
            HttpProfileError::UnrecognizedResultType,
            HttpProfileError::UpstreamResponseInvalid("clause"),
            HttpProfileError::TrustResolverUnavailable,
            HttpProfileError::DelegationCredentialMissing,
            HttpProfileError::DelegationCredentialInvalid,
            HttpProfileError::DelegationCredentialExpired,
            HttpProfileError::DelegationIssuerUntrusted,
            HttpProfileError::DelegationProfileMismatch,
            HttpProfileError::DelegationAudienceMismatch,
            HttpProfileError::DelegationKeyUseInvalid,
            HttpProfileError::DelegationTrustEpochStale,
            HttpProfileError::DelegationKeyMismatch,
            HttpProfileError::DelegationRevoked,
        ]
    }

    /// MCPRE-92: each HTTP-profile failure class maps to its intended precise
    /// token and only that token — the folds this taxonomy replaced are gone.
    #[test]
    fn failure_classes_map_to_their_precise_codes() {
        assert_eq!(
            HttpProfileError::ContentDigestMismatch.wire_code(),
            "mcp-re.digest_mismatch"
        );
        assert_eq!(
            HttpProfileError::MalformedEvidence("inner list").wire_code(),
            "mcp-re.malformed_envelope"
        );
        assert_eq!(
            HttpProfileError::MissingEvidence("signature label").wire_code(),
            "mcp-re.missing_envelope"
        );
        assert_eq!(
            HttpProfileError::ArtifactBindingFailed.wire_code(),
            "mcp-re.artifact_binding_failed"
        );
        assert_eq!(
            HttpProfileError::ResponseBindingMismatch.wire_code(),
            "mcp-re.request_binding_mismatch"
        );
        assert_eq!(
            HttpProfileError::ContinuationBindingFailed.wire_code(),
            "mcp-re.continuation_binding_failed"
        );
        // A digest mismatch is no longer reported as a broken signature.
        assert_ne!(
            HttpProfileError::ContentDigestMismatch.wire_code(),
            HttpProfileError::InvalidSignature.wire_code()
        );
    }

    /// Omission and tampering stay distinguishable: MCPRE-92 split them precisely so a
    /// rejection reason could say which one happened.
    #[test]
    fn absent_evidence_and_malformed_evidence_are_different_verdicts() {
        assert_eq!(
            McpReError::from(&HttpProfileError::MissingEvidence("signature")),
            McpReError::MissingEnvelope
        );
        assert_eq!(
            McpReError::from(&HttpProfileError::MalformedEvidence("signature-input")),
            McpReError::MalformedEnvelope
        );
    }
}
