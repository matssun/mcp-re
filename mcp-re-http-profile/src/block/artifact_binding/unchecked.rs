// SPDX-License-Identifier: Apache-2.0
//! The wire form of an `artifact_bindings[]` entry and the one validation that turns it into
//! an [`ArtifactBinding`].
//!
//! A child of the binding's module on purpose: the value's representation is private to its
//! owner, and this is the only code that may build one from fields it did not derive itself.

use mcp_re_core::b64url_decode;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;

use super::ArtifactBinding;
use super::ArtifactType;
use super::BindingType;
use super::EvidenceDigest;
use crate::block::is_b64url_no_pad;
use crate::error::HttpProfileError;
use crate::ids::EVIDENCE_DIGEST_ALG;

/// One `artifact_bindings[]` entry as it arrives on the wire: the shape, with no claim that
/// it is a legal binding. [`ArtifactBinding`] is what a legal one is, and
/// [`ArtifactBinding::try_from`] is the only way across.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UncheckedArtifactBinding {
    pub artifact_type: ArtifactType,
    pub binding_type: BindingType,
    pub digest_alg: String,
    pub digest_value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_system_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_scheme_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_value: Option<String>,
}

/// The one way an unchecked wire entry becomes a binding: fail-closed structural validation.
/// The digest must be a non-empty base64url token of the digest function's length; the
/// reference fields are all-present for `reference-digest` and all-absent for
/// `opaque-digest`.
impl TryFrom<UncheckedArtifactBinding> for ArtifactBinding {
    type Error = HttpProfileError;

    fn try_from(raw: UncheckedArtifactBinding) -> Result<Self, HttpProfileError> {
        if raw.digest_alg != EVIDENCE_DIGEST_ALG {
            return Err(HttpProfileError::MalformedEvidence("artifact digest_alg"));
        }
        let is_digest = is_b64url_no_pad(&raw.digest_value)
            && b64url_decode(&raw.digest_value)
                .is_ok_and(|d| d.len() == <EvidenceDigest as Digest>::output_size());
        if !is_digest {
            return Err(HttpProfileError::MalformedEvidence("artifact digest_value"));
        }
        let has_ref = raw.authorization_system_id.is_some()
            || raw.reference_scheme_id.is_some()
            || raw.reference_value.is_some();
        let named = |f: &Option<String>| f.as_deref().is_some_and(|s| !s.is_empty());
        let all_ref = named(&raw.authorization_system_id)
            && named(&raw.reference_scheme_id)
            && named(&raw.reference_value);
        match raw.binding_type {
            BindingType::OpaqueDigest if has_ref => {
                return Err(HttpProfileError::MalformedEvidence(
                    "opaque binding carries reference fields",
                ))
            }
            BindingType::ReferenceDigest if !all_ref => {
                return Err(HttpProfileError::MalformedEvidence(
                    "reference binding missing reference fields",
                ))
            }
            BindingType::OpaqueDigest | BindingType::ReferenceDigest => {}
        }
        Ok(ArtifactBinding {
            artifact_type: raw.artifact_type,
            binding_type: raw.binding_type,
            digest_alg: raw.digest_alg,
            digest_value: raw.digest_value,
            authorization_system_id: raw.authorization_system_id,
            reference_scheme_id: raw.reference_scheme_id,
            reference_value: raw.reference_value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire form carries the shape and nothing else: it round-trips an entry that is not
    /// a legal binding, which is exactly what a binding must never do.
    #[test]
    fn the_unchecked_form_holds_what_a_binding_refuses() {
        let raw = UncheckedArtifactBinding {
            artifact_type: ArtifactType::OauthDpop,
            binding_type: BindingType::OpaqueDigest,
            digest_alg: "md5".into(),
            digest_value: String::new(),
            authorization_system_id: None,
            reference_scheme_id: None,
            reference_value: None,
        };
        let json = serde_json::to_value(&raw).expect("serializes");
        let back: UncheckedArtifactBinding = serde_json::from_value(json).expect("parses");
        assert_eq!(back, raw);
        assert!(ArtifactBinding::try_from(back).is_err());
    }
}
