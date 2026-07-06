//! Base64URL (no padding) encoding helpers (MCP_RE_SPEC §3).
//!
//! All MCP-RE signature and hash values are Base64URL WITHOUT padding. These two
//! helpers are the single encoding/decoding choke point so the engine choice
//! (`URL_SAFE_NO_PAD`) is fixed in one place and never duplicated.
//!
//! Decode-failure mapping: [`b64url_decode`] returns
//! [`McpReError::CanonicalizationFailed`] as a neutral, structural decode error.
//! Callers that decode security-critical values (signature bytes, hash digests)
//! deliberately do NOT reuse this mapping — they decode and map failures to the
//! domain-appropriate error themselves (e.g. signature decode →
//! [`McpReError::InvalidSignature`] in [`crate::crypto`]).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::McpReError;

/// Encode bytes as Base64URL with no padding.
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a Base64URL-no-pad string into bytes.
///
/// A malformed input maps to [`McpReError::CanonicalizationFailed`] (a neutral
/// structural failure). Security-critical callers should instead decode with
/// their own mapping — see the module docs.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, McpReError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| McpReError::CanonicalizationFailed)
}

#[cfg(test)]
mod tests {
    use super::b64url_decode;
    use super::b64url_encode;
    use crate::error::McpReError;

    #[test]
    fn round_trip_arbitrary_bytes() {
        let original: Vec<u8> = (0u8..=255).collect();
        let encoded = b64url_encode(&original);
        let decoded = b64url_decode(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_known_answer() {
        // "hello" -> standard base64 "aGVsbG8=" -> URL-safe no-pad "aGVsbG8".
        assert_eq!(b64url_encode(b"hello"), "aGVsbG8");
    }

    #[test]
    fn encode_has_no_padding() {
        // "hi" is 2 bytes -> would be "aGk=" with padding; no-pad drops the '='.
        let encoded = b64url_encode(b"hi");
        assert_eq!(encoded, "aGk");
        assert!(!encoded.contains('='));
    }

    #[test]
    fn encode_uses_url_safe_alphabet() {
        // Bytes that produce '+' and '/' in standard base64 must become '-'/'_'.
        // 0xFB 0xFF 0xBF -> standard "+/+/"? choose bytes that exercise both.
        let encoded = b64url_encode(&[0xFBu8, 0xFF, 0xBF]);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        // round-trips back.
        assert_eq!(b64url_decode(&encoded).expect("decode"), vec![0xFBu8, 0xFF, 0xBF]);
    }

    #[test]
    fn decode_rejects_padding() {
        // The no-pad engine rejects an explicit '=' pad character.
        assert_eq!(b64url_decode("aGk=").unwrap_err(), McpReError::CanonicalizationFailed);
    }

    #[test]
    fn decode_rejects_non_alphabet() {
        // '*' is not in the URL-safe alphabet.
        assert_eq!(b64url_decode("ab*c").unwrap_err(), McpReError::CanonicalizationFailed);
    }

    #[test]
    fn decode_empty_is_empty() {
        assert_eq!(b64url_decode("").expect("decode"), Vec::<u8>::new());
    }
}
