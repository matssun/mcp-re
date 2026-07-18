// SPDX-License-Identifier: Apache-2.0
//! The compact request-evidence handle (v0.11 grill C.1/E-5): SHA-256 over the
//! request's RFC 9421 signature-base bytes, split `{digest_alg, digest_value}`
//! form (the draft-02 binding convention — no `sha256:`/`sha-256:` prefix
//! forms on new fields). It commits to the body digest, method, target URI,
//! media type, key id, signature parameters, and the covered-component set,
//! and serves MRTR continuation, audit correlation, and rejection linkage.

use mcp_re_core::b64url_encode;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use crate::ids::EVIDENCE_DIGEST_ALG;
use crate::ids::EVIDENCE_LABEL_REQUEST;
use crate::ids::EVIDENCE_LABEL_RESPONSE;

/// The domain-separated handle preimage (#416 rev 2 §7.1/§7.3): the role label,
/// a `0x00` separator, then the mandated input bytes. The separator is what makes
/// the encoding injective — the labels are ASCII and cannot contain a NUL, so no
/// two (label, input) pairs can produce the same preimage.
pub(crate) fn labeled_digest_value(label: &str, bytes: &[u8]) -> String {
    let mut preimage = Vec::with_capacity(label.len() + 1 + bytes.len());
    preimage.extend_from_slice(label.as_bytes());
    preimage.push(0x00);
    preimage.extend_from_slice(bytes);
    b64url_encode(&Sha256::digest(&preimage))
}

/// The split-form evidence handle carried in the response's body evidence
/// block (`se.syncom/mcp-re.http.response`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEvidence {
    pub digest_alg: String,
    pub digest_value: String,
}

impl RequestEvidence {
    /// Derive the REQUEST-role handle from the exact request signature-base bytes.
    pub fn from_signature_base(base: &[u8]) -> Self {
        RequestEvidence {
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: labeled_digest_value(EVIDENCE_LABEL_REQUEST, base),
        }
    }

    /// Derive the RESPONSE-role handle from the exact response signature-base
    /// bytes. Distinct from [`RequestEvidence::from_signature_base`] by domain
    /// separation, not merely by which field the result is stored in: the two
    /// roles are different values even over identical bytes.
    pub fn from_response_signature_base(base: &[u8]) -> Self {
        RequestEvidence {
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: labeled_digest_value(EVIDENCE_LABEL_RESPONSE, base),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_is_split_form_and_deterministic() {
        let a = RequestEvidence::from_signature_base(b"base bytes");
        let b = RequestEvidence::from_signature_base(b"base bytes");
        assert_eq!(a, b);
        assert_eq!(a.digest_alg, "sha256");
        assert!(!a.digest_value.contains(':'), "no prefix form (E-5)");
        assert!(!a.digest_value.ends_with('='), "base64url no-pad");
    }

    #[test]
    fn different_base_different_handle() {
        let a = RequestEvidence::from_signature_base(b"base bytes");
        let b = RequestEvidence::from_signature_base(b"base bytez");
        assert_ne!(a.digest_value, b.digest_value);
    }

    /// §7.3: the request and response roles are separated cryptographically, not
    /// positionally. Over the SAME bytes the two roles must differ — otherwise a
    /// handle lifted from one field to the other would verify.
    #[test]
    fn roles_are_domain_separated_over_identical_bytes() {
        let base = b"identical signature base bytes";
        assert_ne!(
            RequestEvidence::from_signature_base(base).digest_value,
            RequestEvidence::from_response_signature_base(base).digest_value,
            "a request-role handle must not be substitutable for a response-role one"
        );
    }

    /// The label/input encoding is injective: moving bytes across the separator
    /// must not produce the same preimage. Without the `0x00`, label "ab" + input
    /// "c" and label "a" + input "bc" would collide.
    #[test]
    fn label_and_input_cannot_be_confused() {
        assert_ne!(
            labeled_digest_value("ab", b"c"),
            labeled_digest_value("a", b"bc"),
        );
    }

    /// A handle is bound to its own profile-scoped label, so it is not a plain
    /// SHA-256 of the base that some other profile might also produce.
    #[test]
    fn handle_is_not_a_bare_digest_of_the_base() {
        use mcp_re_core::b64url_encode;
        let base = b"base bytes";
        assert_ne!(
            RequestEvidence::from_signature_base(base).digest_value,
            b64url_encode(&Sha256::digest(base)),
        );
    }
}
