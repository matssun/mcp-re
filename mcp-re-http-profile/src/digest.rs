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
/// for verification (RFC 9530 permits multiple algorithms) but a wrong-valued
/// `sha-256` member rejects, and a `Content-Digest` header that is present yet
/// carries no `sha-256` member is malformed evidence (MCPRE-92) — a downgrade
/// to an unrecognized-only digest, distinct from an absent header.
pub fn verify_content_digest_sha256(
    header_value: &str,
    body: &[u8],
) -> Result<(), HttpProfileError> {
    let expected = content_digest_sha256(body);
    // Exact-member comparison: find a `sha-256=:...:` member among the
    // comma-separated dictionary members and require byte equality with the
    // recomputed serialization.
    // A DUPLICATED `sha-256` member is malformed, not first-wins. RFC 8941 forbids a
    // repeated dictionary key, and resolving it by taking the first meant one signed
    // message could bind two different bodies: an intermediary appending a second
    // member (or two implementations disagreeing on which to read) would have the same
    // signature accept different content. Counted before any comparison, so the
    // refusal does not depend on which one happened to match.
    let members = header_value.split(',').filter(|m| {
        let m = m.trim();
        m.strip_prefix("sha-256=").is_some()
    });
    if members.count() > 1 {
        return Err(HttpProfileError::MalformedEvidence(
            "content-digest carries more than one sha-256 member",
        ));
    }
    for member in header_value.split(',') {
        let member = member.trim();
        if member.starts_with("sha-256=") {
            // Class B: compared whole. Byte equality of the members IS byte equality of
            // what follows the prefix once both carry it, so nothing needs stripping.
            if member == expected {
                return Ok(());
            }
            return Err(HttpProfileError::ContentDigestMismatch);
        }
    }
    Err(HttpProfileError::MalformedEvidence(
        "content-digest sha-256 member",
    ))
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
    fn sha256_member_absent_from_present_header_is_malformed() {
        // A `Content-Digest` header carrying only an unrecognized algorithm is
        // present-but-malformed evidence (MCPRE-92), not an absent header.
        let err = verify_content_digest_sha256("sha-512=:AAAA:", b"x").unwrap_err();
        assert!(matches!(err, HttpProfileError::MalformedEvidence(_)));
        assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
    }
}
