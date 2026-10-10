//! SHA-256 hash-identifier helpers (MCP_RE_SPEC §3).
//!
//! The MCP-RE hash identifier format is `sha256:<base64url-no-pad>` where the
//! body is the Base64URL-no-pad encoding of the 32-byte SHA-256 digest of the
//! relevant canonical bytes. `request_hash` and `authorization_hash` both use
//! this format.

use sha2::Digest;
use sha2::Sha256;

use crate::encoding::b64url_decode;
use crate::encoding::b64url_encode;
use crate::error::McpReError;

/// The frozen hash-identifier prefix.
const SHA256_PREFIX: &str = "sha256:";

/// The raw SHA-256 digest length in bytes.
const SHA256_LEN: usize = 32;

/// Compute the SHA-256 of `bytes` and format it as the MCP-RE hash identifier
/// `sha256:<base64url-no-pad>` (MCP_RE_SPEC §3).
pub fn sha256_hash_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{SHA256_PREFIX}{}", b64url_encode(&digest))
}

/// Parse and validate a `sha256:<base64url-no-pad>` identifier, returning the
/// raw 32-byte digest.
///
/// A missing/wrong prefix, an undecodable body, or a wrong digest length all map
/// to [`McpReError::SerializationFailed`] (a structural / domain failure — the
/// value is malformed, independent of any signature outcome). Used by response
/// binding (MCPS-008) to compare against a locally computed request hash.
pub fn parse_hash_id(s: &str) -> Result<[u8; SHA256_LEN], McpReError> {
    let body = s
        .strip_prefix(SHA256_PREFIX)
        .ok_or(McpReError::SerializationFailed)?;
    let bytes = b64url_decode(body)?;
    let array: [u8; SHA256_LEN] = bytes
        .try_into()
        .map_err(|_| McpReError::SerializationFailed)?;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::parse_hash_id;
    use super::sha256_hash_id;
    use crate::error::McpReError;

    #[test]
    fn hash_id_has_prefix_and_no_padding() {
        let id = sha256_hash_id(b"{}");
        assert!(id.starts_with("sha256:"));
        assert!(!id.contains('='));
    }

    #[test]
    fn hash_id_known_answer_for_empty_object_bytes() {
        // SHA-256 of the two ASCII bytes "{}" (the canonical form of an empty
        // JSON object). Computed once and pinned here.
        // hex digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
        let id = sha256_hash_id(b"{}");
        assert_eq!(id, "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o");
    }

    #[test]
    fn hash_id_is_deterministic() {
        assert_eq!(sha256_hash_id(b"abc"), sha256_hash_id(b"abc"));
        assert_ne!(sha256_hash_id(b"abc"), sha256_hash_id(b"abd"));
    }

    #[test]
    fn round_trip_parse() {
        let known: [u8; 32] = [
            0x44, 0x13, 0x6f, 0xa3, 0x55, 0xb3, 0x67, 0x8a, 0x11, 0x46, 0xad, 0x16, 0xf7, 0xe8,
            0x64, 0x9e, 0x94, 0xfb, 0x4f, 0xc2, 0x1f, 0xe7, 0x7e, 0x83, 0x10, 0xc0, 0x60, 0xf6,
            0x1c, 0xaa, 0xff, 0x8a,
        ];
        assert_eq!(
            parse_hash_id("sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o").expect("parse"),
            known
        );

        let expected: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(b"some bytes").into();
        assert_eq!(
            parse_hash_id(&sha256_hash_id(b"some bytes")).expect("parse"),
            expected
        );

        let abc = parse_hash_id(&sha256_hash_id(b"abc")).expect("parse abc");
        let abd = parse_hash_id(&sha256_hash_id(b"abd")).expect("parse abd");
        assert_ne!(abc, abd);
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        // A bare base64url body without the "sha256:" prefix.
        assert_eq!(
            parse_hash_id("RBNvo1WzZ4oRRq0W9-hknpT7T8If534DEMBg9hyq_4o").unwrap_err(),
            McpReError::SerializationFailed
        );
    }

    #[test]
    fn parse_rejects_wrong_length() {
        // "sha256:" + base64url of 3 bytes -> not 32 bytes.
        assert_eq!(
            parse_hash_id("sha256:AAAA").unwrap_err(),
            McpReError::SerializationFailed
        );
    }

    #[test]
    fn parse_rejects_bad_base64() {
        assert_eq!(
            parse_hash_id("sha256:!!!!").unwrap_err(),
            McpReError::SerializationFailed
        );
    }
}
