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

/// The split-form evidence handle carried in the response's body evidence
/// block (`se.syncom/mcp-re.http.response`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEvidence {
    pub digest_alg: String,
    pub digest_value: String,
}

impl RequestEvidence {
    /// Derive the handle from the exact request signature-base bytes.
    pub fn from_signature_base(base: &[u8]) -> Self {
        RequestEvidence {
            digest_alg: EVIDENCE_DIGEST_ALG.to_owned(),
            digest_value: b64url_encode(&Sha256::digest(base)),
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
}
