// SPDX-License-Identifier: Apache-2.0
//! RFC 9530 `Content-Digest` — sha-256 over the unencoded message content
//! bytes, serialized as a Structured Fields dictionary with a byte-sequence
//! value: `sha-256=:<base64>:` (standard base64 WITH padding, per RFC 8941
//! byte sequences — distinct from the profile's base64url evidence values).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::Digest;
use sha2::Sha256;

use crate::error::HttpProfileError;

/// Compute the `Content-Digest` header value for `body`.
pub fn content_digest_sha256(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("sha-256=:{}:", STANDARD.encode(digest))
}

/// Verify that `header_value` is this profile's sha-256 digest of `body`.
///
/// Fail-closed: the value must contain a well-formed `sha-256` member whose
/// bytes equal the recomputed digest. Unknown additional members are ignored
/// for verification (RFC 9530 permits multiple algorithms) but a malformed or
/// missing `sha-256` member rejects.
pub fn verify_content_digest_sha256(
    header_value: &str,
    body: &[u8],
) -> Result<(), HttpProfileError> {
    let expected = content_digest_sha256(body);
    // Exact-member comparison: find a `sha-256=:...:` member among the
    // comma-separated dictionary members and require byte equality with the
    // recomputed serialization.
    for member in header_value.split(',') {
        let member = member.trim();
        if let Some(rest) = member.strip_prefix("sha-256=") {
            let recomputed = expected.strip_prefix("sha-256=").expect("own format");
            if rest == recomputed {
                return Ok(());
            }
            return Err(HttpProfileError::ContentDigestMismatch);
        }
    }
    Err(HttpProfileError::MissingEvidence("content-digest sha-256 member"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_round_trip() {
        let body = br#"{"hello": "world"}"#;
        let v = content_digest_sha256(body);
        assert!(v.starts_with("sha-256=:") && v.ends_with(':'));
        verify_content_digest_sha256(&v, body).expect("round trip verifies");
    }

    #[test]
    fn tampered_body_fails_closed() {
        let v = content_digest_sha256(br#"{"hello": "world"}"#);
        let err = verify_content_digest_sha256(&v, br#"{"hello": "worle"}"#).unwrap_err();
        assert_eq!(err, HttpProfileError::ContentDigestMismatch);
    }

    #[test]
    fn missing_sha256_member_fails_closed() {
        let err =
            verify_content_digest_sha256("sha-512=:AAAA:", b"x").unwrap_err();
        assert!(matches!(err, HttpProfileError::MissingEvidence(_)));
    }
}
