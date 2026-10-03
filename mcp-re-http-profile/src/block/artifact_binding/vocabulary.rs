// SPDX-License-Identifier: Apache-2.0
//! The two closed tag vocabularies of an artifact binding.

use serde::Deserialize;
use serde::Serialize;

/// The seven artifact-type registry tokens (ADR-MCPRE-050 §Resolved Q5 / grill
/// E-8). DPoP, mTLS, and RAR get typed verification in MCPRE-95; the other four
/// bind via digest/reference until a consumer appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactType {
    #[serde(rename = "oauth-dpop")]
    OauthDpop,
    #[serde(rename = "oauth-mtls")]
    OauthMtls,
    #[serde(rename = "oauth-rar")]
    OauthRar,
    #[serde(rename = "pdp-decision")]
    PdpDecision,
    #[serde(rename = "dtr-approval")]
    DtrApproval,
    #[serde(rename = "classifier-result")]
    ClassifierResult,
    #[serde(rename = "human-approval")]
    HumanApproval,
}

/// How an artifact is bound. Both forms are digest-carrying — the digest, never
/// the artifact bytes, is the cryptographic binding (mirrors the native
/// `AuthorizationBinding` split). Typed OAuth proofs (`ath`, `x5t#S256`) layer
/// on top of `opaque-digest`/`reference-digest` in MCPRE-95.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingType {
    /// The digest is over the decoded artifact bytes, held locally.
    #[serde(rename = "opaque-digest")]
    OpaqueDigest,
    /// The digest is produced by an external system named by the reference
    /// fields; the record stays verifiable independent of that system's live
    /// state.
    #[serde(rename = "reference-digest")]
    ReferenceDigest,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vocabularies are closed: their wire tokens are the registry's and no other.
    #[test]
    fn the_tags_serialize_to_their_registry_tokens() {
        assert_eq!(
            serde_json::to_value(ArtifactType::OauthDpop).expect("serializes"),
            "oauth-dpop"
        );
        assert_eq!(
            serde_json::to_value(BindingType::ReferenceDigest).expect("serializes"),
            "reference-digest"
        );
        assert!(serde_json::from_value::<ArtifactType>("acme".into()).is_err());
    }
}
