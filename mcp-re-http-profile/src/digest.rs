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
/// Fail-closed: the value must contain exactly one `sha-256` member, a bare byte
/// sequence whose bytes equal the recomputed digest. Unknown additional members are ignored
/// for verification (RFC 9530 permits multiple algorithms) but a wrong-valued
/// `sha-256` member rejects, and a `Content-Digest` header that is present yet
/// carries no `sha-256` member is malformed evidence (MCPRE-92) — a downgrade
/// to an unrecognized-only digest, distinct from an absent header.
pub fn verify_content_digest_sha256(
    header_value: &str,
    body: &[u8],
) -> Result<(), HttpProfileError> {
    let expected = content_digest_sha256(body);
    let expected_value = expected.strip_prefix("sha-256=").unwrap_or(&expected);
    // Framing and the duplicate-label refusal belong to the dictionary reader, which is
    // quote- and escape-aware; a present header without a `sha-256` member is malformed
    // (MCPRE-92), not absent.
    let value = crate::verify::floor::sf_dictionary::member_value(header_value, "sha-256")
        .map_err(|e| match e {
            HttpProfileError::MissingEvidence(_) => {
                HttpProfileError::MalformedEvidence("content-digest sha-256 member")
            }
            other => other,
        })?;
    if !is_bare_byte_sequence(value) {
        return Err(HttpProfileError::MalformedEvidence(
            "content-digest sha-256 value",
        ));
    }
    if value == expected_value {
        return Ok(());
    }
    Err(HttpProfileError::ContentDigestMismatch)
}

/// `:` + one or more base64 characters + `:`, with no parameters after it.
fn is_bare_byte_sequence(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix(':')
        .and_then(|rest| rest.strip_suffix(':'))
    else {
        return false;
    };
    !inner.is_empty()
        && inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
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

    fn malformed(header: &str, body: &[u8]) -> bool {
        matches!(
            verify_content_digest_sha256(header, body),
            Err(HttpProfileError::MalformedEvidence(_))
        )
    }

    #[test]
    fn duplicate_sha256_member_is_malformed_in_either_order() {
        let body = b"one";
        let good = content_digest_sha256(body);
        let bad = content_digest_sha256(b"two");
        assert!(malformed(&format!("{good}, {bad}"), body));
        assert!(malformed(&format!("{bad}, {good}"), body));
    }

    #[test]
    fn sha256_text_inside_a_quoted_parameter_is_not_a_member() {
        let body = b"one";
        let good = content_digest_sha256(body);
        assert!(malformed(&format!("unknown=?1;p=\"a,{good},b\""), body));
    }

    #[test]
    fn genuine_member_beside_a_quoted_comma_is_read_once() {
        let body = b"one";
        let good = content_digest_sha256(body);
        let bad = content_digest_sha256(b"two");
        verify_content_digest_sha256(&format!("unknown=?1;p=\"x,{bad}\", {good}"), body)
            .expect("one genuine member");
    }

    #[test]
    fn parameterised_sha256_member_is_malformed_not_mismatch() {
        let body = b"one";
        let good = content_digest_sha256(body);
        assert!(malformed(&format!("{good};q=1"), body));
    }
}
