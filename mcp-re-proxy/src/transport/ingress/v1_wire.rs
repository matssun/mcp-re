// SPDX-License-Identifier: Apache-2.0
//! The v1 assertion's WIRE FORM: five `.`-separated base64url fields, and the decoder that
//! reads one back.
//!
//! Its own authority for the reason [`super::v1`] holds the rest — the wire form is a
//! contract with the ingress that emits it, where the sibling holds what an assertion MEANS
//! once parsed. Keeping them apart is what makes the arity a single fact: a field cannot be
//! read from an assertion that does not have it.
//!
//! Every framing, decoding or shape violation fails closed as
//! [`LbAssertionRejection::Malformed`].

use mcp_re_core::b64url_decode;

use crate::transport::validate_asserted_identity_value;
use crate::transport::MAX_ASSERTED_IDENTITY_LEN;

use super::v1::LbAssertion;
use super::v1::LbAssertionRejection;

/// Parse a presented Tier-3 assertion header value into its fields.
///
/// Wire form (single header value): four `.`-separated base64url-no-pad fields
/// — `key_id . asserted_client_identity . request_hash . validation_time` —
/// followed by the base64url-no-pad Ed25519 `signature` as a fifth field:
/// `<key_id>.<identity>.<request_hash>.<validation_time>.<signature>`. Each
/// textual field is base64url-encoded so it can never contain the `.`
/// separator; this is a TRANSPORT encoding only — the SIGNATURE preimage is the
/// length-prefixed [`LbAssertion::signing_preimage`], which is what defeats the
/// delimiter-collision class. Any framing / decoding / shape violation fails
/// closed as [`LbAssertionRejection::Malformed`].
pub(super) fn parse(value: &str) -> Result<(LbAssertion, String), LbAssertionRejection> {
    let trimmed = value.trim();
    // Bound total length up front (anti-DoS / smuggling), reusing the asserted-
    // identity ceiling generously across the whole assertion.
    if trimmed.is_empty() || trimmed.len() > MAX_ASSERTED_IDENTITY_LEN {
        return Err(LbAssertionRejection::Malformed);
    }
    // Class B, as in the v2 parser: the arity check and the field extraction are ONE
    // operation.
    let parts: Vec<&str> = trimmed.split('.').collect();
    let [key_id_field, asserted_client_identity_field, request_hash_field, validation_time_field, signature_field] =
        parts.as_slice()
    else {
        return Err(LbAssertionRejection::Malformed);
    };
    let key_id = decode_b64url_field(key_id_field)?;
    let asserted_client_identity = decode_b64url_field(asserted_client_identity_field)?;
    let request_hash = decode_b64url_field(request_hash_field)?;
    let validation_time_bytes =
        b64url_decode(validation_time_field).map_err(|_| LbAssertionRejection::Malformed)?;
    // Fixed 8-byte big-endian i64.
    let validation_time = i64::from_be_bytes(
        validation_time_bytes
            .as_slice()
            .try_into()
            .map_err(|_| LbAssertionRejection::Malformed)?,
    );
    // The signature is carried as the raw base64url string (verify_ed25519_with
    // decodes + length-checks it); a non-base64url signature fails closed there.
    let signature_b64url = (*signature_field).to_string();
    if signature_b64url.is_empty() {
        return Err(LbAssertionRejection::Malformed);
    }
    // Strict shape on the asserted identity (length-bound, no control chars,
    // non-empty), mirroring the Tier-2 header path.
    if validate_asserted_identity_value(&asserted_client_identity).is_err() {
        return Err(LbAssertionRejection::Malformed);
    }
    // key_id and request_hash must be non-empty and control-char-free too.
    if key_id.is_empty()
        || request_hash.is_empty()
        || key_id.chars().any(|c| c.is_control())
        || request_hash.chars().any(|c| c.is_control())
    {
        return Err(LbAssertionRejection::Malformed);
    }
    Ok((
        LbAssertion {
            key_id,
            asserted_client_identity,
            request_hash,
            validation_time,
        },
        signature_b64url,
    ))
}

/// Decode one base64url-no-pad assertion field to a UTF-8 string; any decode or
/// UTF-8 error fails closed as [`LbAssertionRejection::Malformed`].
fn decode_b64url_field(field: &str) -> Result<String, LbAssertionRejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionRejection::Malformed)?;
    String::from_utf8(bytes).map_err(|_| LbAssertionRejection::Malformed)
}
