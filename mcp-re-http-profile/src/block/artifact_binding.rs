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

mod unchecked;
mod vocabulary;
pub use unchecked::UncheckedArtifactBinding;
pub use vocabulary::ArtifactType;
pub use vocabulary::BindingType;

use crate::error::HttpProfileError;
use crate::ids::EVIDENCE_DIGEST_ALG;
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus_spec, verus_verify};

/// One `artifact_bindings[]` entry: the `artifact_type`/`binding_type` axis
/// split plus the digest (and reference metadata for the reference form). No
/// field can hold a raw secret — only digests and cross-audit references.
///
/// Every inhabitant is structurally valid: the digest algorithm is the profile's, the digest
/// is a canonical base64url token of the digest function's length, and the reference fields
/// are all present for `reference-digest` and all absent for `opaque-digest`. The
/// representation is private and the constructors below — and deserialization, which goes
/// through [`UncheckedArtifactBinding`] — are fallible where the input is not already
/// proven, so holding a binding means those rules hold with no caller having remembered to
/// check. Consumers read it through the named projections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactBinding {
    artifact_type: ArtifactType,
    binding_type: BindingType,
    /// Digest algorithm token; `"sha256"` in v0.11.
    digest_alg: String,
    /// `base64url-no-pad` digest — bare, no prefix (v0.11 grill E-5).
    digest_value: String,
    /// External authorization-system namespace (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_system_id: Option<String>,
    /// The external scheme: what `reference_value` means and how the digest was
    /// produced (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reference_scheme_id: Option<String>,
    /// Decision/grant handle for cross-audit (reference form only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reference_value: Option<String>,
}

/// The digest function `EVIDENCE_DIGEST_ALG` names; the producer and the digest
/// length rule both go through it.
type EvidenceDigest = Sha256;

const _: () = assert!(
    matches!(EVIDENCE_DIGEST_ALG.as_bytes(), b"sha256"),
    "EVIDENCE_DIGEST_ALG no longer names the function EvidenceDigest applies"
);

/// Deserialization is construction: the entry parses as an [`UncheckedArtifactBinding`] and
/// crosses through [`TryFrom`], so a wire value that is not a legal binding is a parse error
/// carrying the frozen `malformed_envelope` token and the structural reason.
impl<'de> Deserialize<'de> for ArtifactBinding {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = UncheckedArtifactBinding::deserialize(deserializer)?;
        Self::try_from(raw)
            .map_err(|e| serde::de::Error::custom(format!("{}: {e:?}", e.wire_code())))
    }
}

impl ArtifactBinding {
    /// Producer side: build an `opaque-digest` binding whose digest is
    /// `base64url-no-pad(SHA-256(credential))`. This is how a client mints a
    /// DPoP `ath` / mTLS `x5t#S256` / RAR binding from the credential surface —
    /// the credential bytes are hashed, never stored. Valid by construction.
    pub fn opaque_digest(artifact_type: ArtifactType, credential: &[u8]) -> Self {
        ArtifactBinding {
            artifact_type,
            binding_type: BindingType::OpaqueDigest,
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: b64url_encode(&EvidenceDigest::digest(credential)),
            authorization_system_id: None,
            reference_scheme_id: None,
            reference_value: None,
        }
    }

    /// An `opaque-digest` binding over a digest the caller already holds, or the refusal
    /// of a digest that is not a canonical token of the digest function's length.
    pub fn opaque_from_digest(
        artifact_type: ArtifactType,
        digest_value: &str,
    ) -> Result<Self, HttpProfileError> {
        Self::try_from(UncheckedArtifactBinding {
            artifact_type,
            binding_type: BindingType::OpaqueDigest,
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: digest_value.to_owned(),
            authorization_system_id: None,
            reference_scheme_id: None,
            reference_value: None,
        })
    }

    /// A `reference-digest` binding: the digest an external system produced, with the three
    /// reference fields that name that system, its scheme and the decision handle. Refused
    /// unless the digest is canonical and every reference field is non-empty.
    pub fn reference(
        artifact_type: ArtifactType,
        digest_value: &str,
        authorization_system_id: &str,
        reference_scheme_id: &str,
        reference_value: &str,
    ) -> Result<Self, HttpProfileError> {
        Self::try_from(UncheckedArtifactBinding {
            artifact_type,
            binding_type: BindingType::ReferenceDigest,
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: digest_value.to_owned(),
            authorization_system_id: Some(authorization_system_id.to_owned()),
            reference_scheme_id: Some(reference_scheme_id.to_owned()),
            reference_value: Some(reference_value.to_owned()),
        })
    }

    /// What the artifact is.
    // ADR-MCPRE-059 ASM-0062: a field read, told to the typed-verifier theorem as an opaque
    // function of the binding, which is quantified over rather than interpreted.
    #[cfg_attr(feature = "verify", verus_verify(external_body))]
    #[cfg_attr(feature = "verify", verus_spec(out =>
        ensures out == crate::verus_std_specs::artifact_type_of(self),
    ))]
    pub fn artifact_type(&self) -> ArtifactType {
        self.artifact_type
    }

    /// How the artifact is bound.
    // ADR-MCPRE-059 ASM-0062, as `artifact_type`.
    #[cfg_attr(feature = "verify", verus_verify(external_body))]
    #[cfg_attr(feature = "verify", verus_spec(out =>
        ensures out == crate::verus_std_specs::binding_type_of(self),
    ))]
    pub fn binding_type(&self) -> BindingType {
        self.binding_type
    }

    /// The digest algorithm token (always the profile's).
    pub fn digest_alg(&self) -> &str {
        &self.digest_alg
    }

    /// The `base64url-no-pad` digest.
    pub fn digest_value(&self) -> &str {
        &self.digest_value
    }

    /// The external authorization-system namespace; `Some` exactly for the reference form.
    pub fn authorization_system_id(&self) -> Option<&str> {
        self.authorization_system_id.as_deref()
    }

    /// The external scheme; `Some` exactly for the reference form.
    pub fn reference_scheme_id(&self) -> Option<&str> {
        self.reference_scheme_id.as_deref()
    }

    /// The decision/grant handle; `Some` exactly for the reference form.
    pub fn reference_value(&self) -> Option<&str> {
        self.reference_value.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_43: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn reference_wire() -> UncheckedArtifactBinding {
        UncheckedArtifactBinding {
            artifact_type: ArtifactType::PdpDecision,
            binding_type: BindingType::ReferenceDigest,
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: DIGEST_43.to_owned(),
            authorization_system_id: Some("sys".into()),
            reference_scheme_id: Some("scheme".into()),
            reference_value: Some("handle".into()),
        }
    }

    fn opaque_wire() -> UncheckedArtifactBinding {
        UncheckedArtifactBinding {
            artifact_type: ArtifactType::OauthDpop,
            binding_type: BindingType::OpaqueDigest,
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: DIGEST_43.to_owned(),
            authorization_system_id: None,
            reference_scheme_id: None,
            reference_value: None,
        }
    }

    fn malformed(b: UncheckedArtifactBinding, token: &'static str) {
        assert!(matches!(
            ArtifactBinding::try_from(b),
            Err(HttpProfileError::MalformedEvidence(t)) if t == token
        ));
    }

    #[test]
    fn opaque_digest_value_is_the_named_function_output() {
        let b = ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"x");
        assert_eq!(b.digest_alg(), "sha256");
        let decoded = mcp_re_core::b64url_decode(b.digest_value()).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded.as_slice(), Sha256::digest(b"x").as_slice());
    }

    #[test]
    fn a_foreign_digest_alg_is_refused() {
        let mut b = opaque_wire();
        b.digest_alg = "md5".into();
        malformed(b, "artifact digest_alg");
    }

    #[test]
    fn a_one_character_digest_is_refused() {
        let mut b = opaque_wire();
        b.digest_value = "A".into();
        malformed(b, "artifact digest_value");
    }

    #[test]
    fn a_digest_one_character_short_or_long_is_refused() {
        for len in [42, 44] {
            let mut b = opaque_wire();
            b.digest_value = "A".repeat(len);
            malformed(b, "artifact digest_value");
        }
    }

    #[test]
    fn an_opaque_binding_with_a_reference_field_is_refused() {
        for v in [Some("x".to_owned()), Some(String::new())] {
            let mut b = opaque_wire();
            b.authorization_system_id = v.clone();
            malformed(b, "opaque binding carries reference fields");
            let mut b = opaque_wire();
            b.reference_scheme_id = v.clone();
            malformed(b, "opaque binding carries reference fields");
            let mut b = opaque_wire();
            b.reference_value = v;
            malformed(b, "opaque binding carries reference fields");
        }
    }

    #[test]
    fn a_reference_binding_missing_a_field_is_refused() {
        let mut b = reference_wire();
        b.authorization_system_id = None;
        malformed(b, "reference binding missing reference fields");
        let mut b = reference_wire();
        b.reference_scheme_id = None;
        malformed(b, "reference binding missing reference fields");
        let mut b = reference_wire();
        b.reference_value = None;
        malformed(b, "reference binding missing reference fields");
    }

    #[test]
    fn a_reference_binding_with_an_empty_field_is_refused() {
        let mut b = reference_wire();
        b.authorization_system_id = Some(String::new());
        malformed(b, "reference binding missing reference fields");
        let mut b = reference_wire();
        b.reference_scheme_id = Some(String::new());
        malformed(b, "reference binding missing reference fields");
        let mut b = reference_wire();
        b.reference_value = Some(String::new());
        malformed(b, "reference binding missing reference fields");
    }

    #[test]
    fn a_fully_named_reference_binding_validates() {
        let b =
            ArtifactBinding::reference(ArtifactType::PdpDecision, DIGEST_43, "sys", "scheme", "h")
                .expect("a legal reference binding");
        assert_eq!(b.reference_value(), Some("h"));
        assert_eq!(b.binding_type(), BindingType::ReferenceDigest);
    }

    /// Deserialization is the same refusal as construction: a wire entry that disagrees with
    /// its own binding form is not a value, so no caller can hold one.
    #[test]
    fn deserialization_refuses_what_construction_refuses() {
        let json = serde_json::json!({
            "artifact_type": "oauth-rar",
            "binding_type": "opaque-digest",
            "digest_alg": "sha256",
            "digest_value": DIGEST_43,
            "reference_value": "decision-123",
        });
        assert!(serde_json::from_value::<ArtifactBinding>(json).is_err());
        let ok = serde_json::json!({
            "artifact_type": "oauth-rar",
            "binding_type": "opaque-digest",
            "digest_alg": "sha256",
            "digest_value": DIGEST_43,
        });
        let b: ArtifactBinding = serde_json::from_value(ok.clone()).expect("a legal entry parses");
        assert_eq!(serde_json::to_value(&b).expect("serializes"), ok);
    }

    #[test]
    fn an_opaque_binding_over_a_held_digest_is_checked() {
        assert!(ArtifactBinding::opaque_from_digest(ArtifactType::OauthMtls, DIGEST_43).is_ok());
        assert!(ArtifactBinding::opaque_from_digest(ArtifactType::OauthMtls, "A").is_err());
    }
}
