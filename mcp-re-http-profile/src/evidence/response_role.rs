// SPDX-License-Identifier: Apache-2.0
//! The RESPONSE-role evidence handle: derived, never assembled.

use serde::Serialize;

use super::role::labeled_digest_value;
use super::role::EvidenceRole;
use super::RequestEvidenceDigest;
use crate::ids::EVIDENCE_DIGEST_ALG;

/// The response-role handle over a response's exact RFC 9421 signature base. An MRTR
/// continuation binds to it as the `InputRequiredResult` it answers, and the SCITT
/// commitment records it beside the request-role handle.
///
/// Sealed like [`super::RequestRoleEvidence`]: [`from_signature_base`](Self::from_signature_base)
/// is the only producer, so holding one means its value IS the response-role labeled digest
/// of some signature base, and no request-role value can sit where this type is expected.
///
/// Serializes to the wire's split form, `{digest_alg, digest_value}`.
///
/// Code outside this crate cannot write the value in:
///
/// ```compile_fail
/// use mcp_re_http_profile::ResponseRoleEvidence;
/// let _ = ResponseRoleEvidence { digest_value: String::new() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseRoleEvidence {
    digest_value: String,
}

impl ResponseRoleEvidence {
    /// Derive the handle from the exact response signature-base bytes.
    pub fn from_signature_base(base: &[u8]) -> Self {
        ResponseRoleEvidence {
            digest_value: labeled_digest_value(EvidenceRole::Response, base),
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

impl Serialize for ResponseRoleEvidence {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_digest().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::RequestRoleEvidence;

    /// §7.3: over the SAME bytes the two roles differ, so a handle lifted from one field
    /// to the other does not verify.
    #[test]
    fn roles_are_domain_separated_over_identical_bytes() {
        let base = b"identical signature base bytes";
        let response = ResponseRoleEvidence::from_signature_base(base);
        let request = RequestRoleEvidence::from_signature_base(base);
        assert_ne!(response.digest_value(), request.digest_value());
        assert!(!response.matches(&request.to_digest()));
    }

    #[test]
    fn it_is_the_response_role_digest_and_no_other() {
        let a = ResponseRoleEvidence::from_signature_base(b"base");
        assert!(a.to_digest().is_well_formed());
        assert!(a
            .to_digest()
            .matches_labeled(EvidenceRole::Response, b"base"));
        assert!(!a
            .to_digest()
            .matches_labeled(EvidenceRole::Request, b"base"));
        assert!(a.matches(&a.to_digest()));
    }

    #[test]
    fn serializes_to_the_split_wire_form() {
        let a = ResponseRoleEvidence::from_signature_base(b"base");
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::json!({ "digest_alg": "sha256", "digest_value": a.digest_value() })
        );
    }
}
