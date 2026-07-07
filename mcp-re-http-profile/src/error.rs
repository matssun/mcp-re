// SPDX-License-Identifier: Apache-2.0
//! Fail-closed error taxonomy for the HTTP profile.
//!
//! No parallel namespace (v0.11 grill E-11): every `wire_code()` is a token of
//! the frozen `mcp_re_core::McpReError` taxonomy. The per-variant mapping below
//! was ratified by owner ruling 2026-07-07 (MCPRE-92), which added five
//! security-grouped codes to the frozen taxonomy for the signed-rejection
//! surface — `malformed_envelope`, `digest_mismatch`, `artifact_binding_failed`,
//! `request_binding_mismatch`, `continuation_binding_failed` — so the HTTP
//! profile no longer folds distinct failures onto coarser draft-01/02 tokens.
//! The `every_wire_code_is_a_frozen_core_token` test machine-checks the no-
//! parallel-namespace rule.

#[cfg(test)]
use mcp_re_core::McpReError;

/// A fail-closed HTTP-profile verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProfileError {
    /// A required header or signature member is entirely absent — there is no
    /// evidence to parse. Maps to `mcp-re.missing_envelope`.
    MissingEvidence(&'static str),
    /// Evidence is present but structurally invalid against the profile's
    /// closed grammar (an unparseable `Signature-Input` member, a foreign
    /// covered component or parameter, a wrong-shaped digest member). Distinct
    /// from [`HttpProfileError::MissingEvidence`]; maps to
    /// `mcp-re.malformed_envelope` (MCPRE-92).
    MalformedEvidence(&'static str),
    /// A header that MUST appear exactly once appears more than once.
    DuplicateHeader(&'static str),
    /// `Content-Encoding` present on a signed MCP message (forbidden — the
    /// profile signs unencoded content bytes; v0.11 grill B.1).
    ContentEncodingPresent,
    /// The message content does not match the signed `Content-Digest`.
    ContentDigestMismatch,
    /// A covered component required by the profile is not covered.
    MissingCoveredComponent(&'static str),
    /// The signature parameters carry an unknown/foreign profile tag.
    UnknownProfileTag,
    /// The signature algorithm is not the profile's `ed25519`.
    UnsupportedAlgorithm,
    /// The Ed25519 signature does not verify over the reconstructed base.
    InvalidSignature,
    /// The `created`/`expires` window is stale, future-dated, or degenerate.
    StaleWindow,
    /// The `keyid` does not resolve to a trusted verification key.
    UnresolvedKeyId,
    /// An `artifact_bindings[]` proof (DPoP `ath`, mTLS `x5t#S256`, RAR
    /// authorization-details digest) does not bind to the covered credential
    /// surface (MCPRE-95). Maps to `mcp-re.artifact_binding_failed`.
    ArtifactBindingFailed,
    /// Response evidence does not bind to the expected request (`;req`
    /// component mismatch or `request_evidence` mismatch) — a splice. Maps to
    /// `mcp-re.request_binding_mismatch` (MCPRE-92).
    ResponseBindingMismatch,
    /// The response signature does not verify.
    ResponseSignatureInvalid,
    /// An MRTR continuation handle does not match its mandated signature-base
    /// digest (MCPRE-97). Maps to `mcp-re.continuation_binding_failed`.
    ContinuationBindingFailed,
}

impl HttpProfileError {
    /// The frozen `mcp-re.*` wire token this failure maps to (reuse-only —
    /// tokens from `McpReError::wire_code()`, never new strings).
    pub fn wire_code(&self) -> &'static str {
        match self {
            // Evidence entirely absent (nothing to parse). A duplicated
            // exactly-once header and a genuinely missing covered component are
            // both "the evidence you needed is not there".
            HttpProfileError::MissingEvidence(_)
            | HttpProfileError::DuplicateHeader(_)
            | HttpProfileError::MissingCoveredComponent(_) => "mcp-re.missing_envelope",
            // Evidence present but structurally invalid (MCPRE-92): a foreign
            // component/parameter, an unparseable inner list, a wrong-shaped
            // digest member. Grouped away from "absent" so a rejection reason
            // distinguishes tampering from omission.
            HttpProfileError::MalformedEvidence(_) => "mcp-re.malformed_envelope",
            // Content-model / value-domain violation of the protected message.
            HttpProfileError::ContentEncodingPresent => "mcp-re.canonicalization_failed",
            // The content commitment itself is wrong — precise digest code
            // (MCPRE-92), no longer folded onto invalid_signature.
            HttpProfileError::ContentDigestMismatch => "mcp-re.digest_mismatch",
            // The signature does not authenticate the bytes.
            HttpProfileError::InvalidSignature => "mcp-re.invalid_signature",
            // Profile-selection failure: cannot select this profile.
            HttpProfileError::UnknownProfileTag | HttpProfileError::UnsupportedAlgorithm => {
                "mcp-re.unsupported_version"
            }
            HttpProfileError::StaleWindow => "mcp-re.expired_request",
            // A keyid outside trust is an actor-binding failure, not a broken
            // signature: the crypto may verify under an untrusted key.
            HttpProfileError::UnresolvedKeyId => "mcp-re.actor_binding_failed",
            HttpProfileError::ArtifactBindingFailed => "mcp-re.artifact_binding_failed",
            // A response bound to a different request is a request-binding
            // splice — precise code (MCPRE-92), not the native response_hash
            // field name.
            HttpProfileError::ResponseBindingMismatch => "mcp-re.request_binding_mismatch",
            HttpProfileError::ResponseSignatureInvalid => "mcp-re.response_sig_invalid",
            HttpProfileError::ContinuationBindingFailed => "mcp-re.continuation_binding_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E-11 drift guard: every wire_code() this crate emits must be a token the
    /// frozen core taxonomy also emits — no parallel namespace, machine-checked.
    #[test]
    fn every_wire_code_is_a_frozen_core_token() {
        let frozen: Vec<&str> = vec![
            McpReError::MissingEnvelope.wire_code(),
            McpReError::MalformedEnvelope.wire_code(),
            McpReError::CanonicalizationFailed.wire_code(),
            McpReError::InvalidSignature.wire_code(),
            McpReError::DigestMismatch.wire_code(),
            McpReError::UnsupportedVersion.wire_code(),
            McpReError::ExpiredRequest.wire_code(),
            McpReError::ActorBindingFailed.wire_code(),
            McpReError::ArtifactBindingFailed.wire_code(),
            McpReError::RequestBindingMismatch.wire_code(),
            McpReError::ResponseHashMismatch.wire_code(),
            McpReError::ResponseSigInvalid.wire_code(),
            McpReError::ContinuationBindingFailed.wire_code(),
        ];
        let all = [
            HttpProfileError::MissingEvidence("x"),
            HttpProfileError::MalformedEvidence("x"),
            HttpProfileError::DuplicateHeader("x"),
            HttpProfileError::ContentEncodingPresent,
            HttpProfileError::ContentDigestMismatch,
            HttpProfileError::MissingCoveredComponent("x"),
            HttpProfileError::UnknownProfileTag,
            HttpProfileError::UnsupportedAlgorithm,
            HttpProfileError::InvalidSignature,
            HttpProfileError::StaleWindow,
            HttpProfileError::UnresolvedKeyId,
            HttpProfileError::ArtifactBindingFailed,
            HttpProfileError::ResponseBindingMismatch,
            HttpProfileError::ResponseSignatureInvalid,
            HttpProfileError::ContinuationBindingFailed,
        ];
        for e in all {
            assert!(
                frozen.contains(&e.wire_code()),
                "wire_code {:?} not in the frozen core taxonomy",
                e.wire_code()
            );
        }
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
}
