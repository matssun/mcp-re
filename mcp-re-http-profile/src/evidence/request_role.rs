// SPDX-License-Identifier: Apache-2.0
//! The REQUEST-role evidence handle: derived, never assembled.

use serde::Serialize;

use super::role::labeled_digest_value;
use super::role::EvidenceRole;
use super::RequestEvidenceDigest;
use crate::ids::EVIDENCE_DIGEST_ALG;

/// The request-role handle over a request's exact RFC 9421 signature base (v0.11 grill
/// C.1/E-5). It commits to the body digest, method, target URI, media type, key id,
/// signature parameters and covered-component set, and serves MRTR continuation, audit
/// correlation and response binding.
///
/// Sealed: the representation is private and [`from_signature_base`](Self::from_signature_base)
/// is the only producer, so holding one means its value IS the request-role labeled digest
/// of some signature base. A response-role handle is a different type, so a slot typed for
/// this role cannot hold one, whether or not that slot compares anything. A handle read
/// from a peer is a [`RequestEvidenceDigest`] claim and is checked with
/// [`matches`](Self::matches).
///
/// Serializes to the wire's split form, `{digest_alg, digest_value}`.
///
/// Code outside this crate cannot write the value in:
///
/// ```compile_fail
/// use mcp_re_http_profile::RequestRoleEvidence;
/// let _ = RequestRoleEvidence { digest_value: String::new() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRoleEvidence {
    digest_value: String,
}

impl RequestRoleEvidence {
    /// Derive the handle from the exact request signature-base bytes.
    pub fn from_signature_base(base: &[u8]) -> Self {
        RequestRoleEvidence {
            digest_value: labeled_digest_value(EvidenceRole::Request, base),
        }
    }

    /// The digest algorithm, always the profile's.
    pub fn digest_alg(&self) -> &'static str {
        EVIDENCE_DIGEST_ALG
    }

    /// The unpadded base64url digest value.
    pub fn digest_value(&self) -> &str {
        &self.digest_value
    }

    /// The wire form of this handle, for a block that carries it.
    pub fn to_digest(&self) -> RequestEvidenceDigest {
        RequestEvidenceDigest {
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: self.digest_value.clone(),
        }
    }

    /// Whether `claim` names this handle: the same algorithm and value.
    pub fn matches(&self, claim: &RequestEvidenceDigest) -> bool {
        claim.digest_alg == EVIDENCE_DIGEST_ALG && claim.digest_value == self.digest_value
    }
}

impl Serialize for RequestRoleEvidence {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_digest().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_is_split_form_and_deterministic() {
        let a = RequestRoleEvidence::from_signature_base(b"base bytes");
        assert_eq!(a, RequestRoleEvidence::from_signature_base(b"base bytes"));
        assert_eq!(a.digest_alg(), "sha256");
        assert!(a.to_digest().is_well_formed(), "{a:?}");
        assert_ne!(a, RequestRoleEvidence::from_signature_base(b"base bytez"));
    }

    #[test]
    fn it_is_the_request_role_digest_and_no_other() {
        let a = RequestRoleEvidence::from_signature_base(b"base");
        assert!(a
            .to_digest()
            .matches_labeled(EvidenceRole::Request, b"base"));
        assert!(!a
            .to_digest()
            .matches_labeled(EvidenceRole::Response, b"base"));
    }

    #[test]
    fn matches_its_own_claim_only() {
        let a = RequestRoleEvidence::from_signature_base(b"base");
        assert!(a.matches(&a.to_digest()));
        let response_role = RequestEvidenceDigest::over_labeled(EvidenceRole::Response, b"base");
        assert!(!a.matches(&response_role));
        let other_alg = RequestEvidenceDigest {
            digest_alg: "sha-256".into(),
            ..a.to_digest()
        };
        assert!(!a.matches(&other_alg));
    }

    /// The wire bytes are the split form the unsealed type serialized to.
    #[test]
    fn serializes_to_the_split_wire_form() {
        let a = RequestRoleEvidence::from_signature_base(b"base");
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::json!({ "digest_alg": "sha256", "digest_value": a.digest_value() })
        );
    }
}
