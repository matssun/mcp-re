// SPDX-License-Identifier: Apache-2.0
//! Fail-closed error taxonomy for the HTTP profile proof path.
//!
//! No new wire codes are minted (v0.11 grill E-11: HTTP-profile rejections
//! REUSE the frozen `mcp-re.*` tokens — no parallel namespace). `wire_code()`
//! maps each failure to the frozen token whose semantics it instantiates; the
//! per-variant mapping below is the proof-stage proposal recorded in
//! `docs/spec/http-profile-open-questions.md` for ratification before signed
//! rejections ship. Tokens come verbatim from `mcp_re_core::McpReError`.

use mcp_re_core::McpReError;

/// A fail-closed HTTP-profile verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProfileError {
    /// A required header/component is absent or the signature membership is
    /// missing/malformed — there is no complete evidence to verify.
    MissingEvidence(&'static str),
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
    /// Response evidence does not bind to the expected request (`;req`
    /// component mismatch or `request_evidence` mismatch) — a splice.
    ResponseBindingMismatch,
    /// The response signature does not verify.
    ResponseSignatureInvalid,
}

impl HttpProfileError {
    /// The frozen `mcp-re.*` wire token this failure maps to (reuse-only —
    /// tokens from `McpReError::wire_code()`, never new strings).
    pub fn wire_code(&self) -> &'static str {
        match self {
            // No complete/verifiable evidence on the message.
            HttpProfileError::MissingEvidence(_)
            | HttpProfileError::DuplicateHeader(_)
            | HttpProfileError::MissingCoveredComponent(_) => "mcp-re.missing_envelope",
            // Content-model / value-domain violation of the protected message.
            HttpProfileError::ContentEncodingPresent => "mcp-re.canonicalization_failed",
            // Integrity failures: the evidence does not authenticate the bytes.
            HttpProfileError::ContentDigestMismatch | HttpProfileError::InvalidSignature => {
                "mcp-re.invalid_signature"
            }
            // Profile-selection failure: cannot select this profile.
            HttpProfileError::UnknownProfileTag | HttpProfileError::UnsupportedAlgorithm => {
                "mcp-re.unsupported_version"
            }
            HttpProfileError::StaleWindow => "mcp-re.expired_request",
            // A keyid outside trust is an actor-binding failure, not a broken
            // signature: the crypto may verify under an untrusted key.
            HttpProfileError::UnresolvedKeyId => "mcp-re.actor_binding_failed",
            HttpProfileError::ResponseBindingMismatch => "mcp-re.response_hash_mismatch",
            HttpProfileError::ResponseSignatureInvalid => "mcp-re.response_sig_invalid",
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
            McpReError::CanonicalizationFailed.wire_code(),
            McpReError::InvalidSignature.wire_code(),
            McpReError::UnsupportedVersion.wire_code(),
            McpReError::ExpiredRequest.wire_code(),
            McpReError::ActorBindingFailed.wire_code(),
            McpReError::ResponseHashMismatch.wire_code(),
            McpReError::ResponseSigInvalid.wire_code(),
        ];
        let all = [
            HttpProfileError::MissingEvidence("x"),
            HttpProfileError::DuplicateHeader("x"),
            HttpProfileError::ContentEncodingPresent,
            HttpProfileError::ContentDigestMismatch,
            HttpProfileError::MissingCoveredComponent("x"),
            HttpProfileError::UnknownProfileTag,
            HttpProfileError::UnsupportedAlgorithm,
            HttpProfileError::InvalidSignature,
            HttpProfileError::StaleWindow,
            HttpProfileError::UnresolvedKeyId,
            HttpProfileError::ResponseBindingMismatch,
            HttpProfileError::ResponseSignatureInvalid,
        ];
        for e in all {
            assert!(
                frozen.contains(&e.wire_code()),
                "wire_code {:?} not in the frozen core taxonomy",
                e.wire_code()
            );
        }
    }
}
