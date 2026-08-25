// SPDX-License-Identifier: Apache-2.0
//! The artifact-binding vocabulary — ADR-MCPRE-050 §Resolved Q5, grill E-8.
//!
//! `artifact_bindings[]` proves that a request is bound to specific external authorization
//! artifacts without ever carrying raw secret bytes in evidence. This module is the
//! vocabulary and its structural invariant; [`crate::artifact`] is the typed verification
//! layered on top, and [`super::HttpRequestEvidenceBlock`] is what carries the entries.
//!
//! # The two axes are independent, and deliberately so
//!
//! `artifact_type` says WHAT the artifact is; `binding_type` says HOW it is bound. The
//! product of the two is the expressive surface, and ADR-MCPRE-065 Slice 2 is the first
//! consumer to use one `artifact_type` in both forms with different meanings:
//!
//! ```text
//! pdp-decision + reference-digest  ->  decision LINKAGE
//!                                      the call names an external decision; MCP-RE neither
//!                                      authenticates nor interprets it, and an EMA-native
//!                                      backend remains the enforcement point
//!
//! pdp-decision + opaque-digest     ->  decision EVIDENCE
//!                                      the decision document travels with the request, and
//!                                      MCP-RE verifies and enforces it
//! ```
//!
//! That is not a special case bolted on. It is what the `artifact_type` × `binding_type`
//! product was for.

use mcp_re_core::b64url_encode;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use super::is_b64url_no_pad;
use crate::error::HttpProfileError;
use crate::ids::EVIDENCE_DIGEST_ALG;
#[cfg(feature = "verify")]
use verus_builtin_macros::verus_verify;
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

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

/// One `artifact_bindings[]` entry: the `artifact_type`/`binding_type` axis
/// split plus the digest (and reference metadata for the reference form). No
/// field can hold a raw secret — only digests and cross-audit references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    pub artifact_type: ArtifactType,
    pub binding_type: BindingType,
    /// Digest algorithm token; `"sha256"` in v0.11.
    pub digest_alg: String,
    /// `base64url-no-pad` digest — bare, no prefix (v0.11 grill E-5).
    pub digest_value: String,
    /// External authorization-system namespace (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_system_id: Option<String>,
    /// The external scheme: what `reference_value` means and how the digest was
    /// produced (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_scheme_id: Option<String>,
    /// Decision/grant handle for cross-audit (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_value: Option<String>,
}

impl ArtifactBinding {
    /// Producer side: build an `opaque-digest` binding whose digest is
    /// `base64url-no-pad(SHA-256(credential))`. This is how a client mints a
    /// DPoP `ath` / mTLS `x5t#S256` / RAR binding from the credential surface —
    /// the credential bytes are hashed, never stored.
    pub fn opaque_digest(artifact_type: ArtifactType, credential: &[u8]) -> Self {
        ArtifactBinding {
            artifact_type,
            binding_type: BindingType::OpaqueDigest,
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: b64url_encode(&Sha256::digest(credential)),
            authorization_system_id: None,
            reference_scheme_id: None,
            reference_value: None,
        }
    }

    /// Structural validation, fail-closed. The digest must be a non-empty
    /// base64url token; the reference fields are all-present for
    /// `reference-digest` and all-absent for `opaque-digest`.
    // ADR-MCPRE-059 ASM-0019: structural validation, opaque to the typed-verifier
    // theorem. Its own contract — digest token shape and the reference-field all-or-none
    // rule — is a separate property, and the theorem above holds whatever it returns.
    #[cfg_attr(feature = "verify", verus_verify(external_body))]
    pub fn validate(&self) -> Result<(), HttpProfileError> {
        if self.digest_alg != EVIDENCE_DIGEST_ALG {
            return Err(HttpProfileError::MalformedEvidence("artifact digest_alg"));
        }
        if self.digest_value.is_empty() || !is_b64url_no_pad(&self.digest_value) {
            return Err(HttpProfileError::MalformedEvidence("artifact digest_value"));
        }
        let has_ref = self.authorization_system_id.is_some()
            || self.reference_scheme_id.is_some()
            || self.reference_value.is_some();
        let all_ref = self.authorization_system_id.is_some()
            && self.reference_scheme_id.is_some()
            && self.reference_value.is_some();
        match self.binding_type {
            BindingType::OpaqueDigest if has_ref => Err(HttpProfileError::MalformedEvidence(
                "opaque binding carries reference fields",
            )),
            BindingType::ReferenceDigest if !all_ref => Err(HttpProfileError::MalformedEvidence(
                "reference binding missing reference fields",
            )),
            _ => Ok(()),
        }
    }
}
