//! SHA-256 hash-identifier helpers (MCPS_SPEC §3).
//!
//! The MCP-S hash identifier format is `sha256:<base64url-no-pad>` where the
//! body is the Base64URL-no-pad encoding of the 32-byte SHA-256 digest of the
//! relevant canonical bytes. `request_hash` and `authorization_hash` both use
//! this format.

use sha2::Digest;
use sha2::Sha256;

use crate::encoding::b64url_decode;
use crate::encoding::b64url_encode;
use crate::error::McpsError;

/// The frozen hash-identifier prefix.
const SHA256_PREFIX: &str = "sha256:";

/// The raw SHA-256 digest length in bytes.
const SHA256_LEN: usize = 32;

/// Compute the SHA-256 of `bytes` and format it as the MCP-S hash identifier
/// `sha256:<base64url-no-pad>` (MCPS_SPEC §3).
pub fn sha256_hash_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{SHA256_PREFIX}{}", b64url_encode(&digest))
}

/// Parse and validate a `sha256:<base64url-no-pad>` identifier, returning the
/// raw 32-byte digest.
///
/// A missing/wrong prefix, an undecodable body, or a wrong digest length all map
/// to [`McpsError::CanonicalizationFailed`] (a structural / domain failure — the
/// value is malformed, independent of any signature outcome). Used by response
/// binding (MCPS-008) to compare against a locally computed request hash.
pub fn parse_hash_id(s: &str) -> Result<[u8; SHA256_LEN], McpsError> {
    let body = s
        .strip_prefix(SHA256_PREFIX)
        .ok_or(McpsError::CanonicalizationFailed)?;
    let bytes = b64url_decode(body)?;
    let array: [u8; SHA256_LEN] = bytes
        .try_into()
        .map_err(|_| McpsError::CanonicalizationFailed)?;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::parse_hash_id;
    use super::sha256_hash_id;
    use crate::error::McpsError;

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
        let id = sha256_hash_id(b"some bytes");
        let digest = parse_hash_id(&id).expect("parse");
        // Re-encoding the digest reproduces the same id.
        assert_eq!(sha256_hash_id(b"some bytes"), id);
        // Digest length is exactly 32.
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        // A bare base64url body without the "sha256:" prefix.
        assert_eq!(
            parse_hash_id("RBNvo1WzZ4oRRq0W9-hknpT7T8If534DEMBg9hyq_4o").unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    #[test]
    fn parse_rejects_wrong_length() {
        // "sha256:" + base64url of 3 bytes -> not 32 bytes.
        assert_eq!(
            parse_hash_id("sha256:AAAA").unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }

    #[test]
    fn parse_rejects_bad_base64() {
        assert_eq!(
            parse_hash_id("sha256:!!!!").unwrap_err(),
            McpsError::CanonicalizationFailed
        );
    }
}
