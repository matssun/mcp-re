// SPDX-License-Identifier: Apache-2.0
//! The v2 assertion's WIRE FORM: eleven `.`-separated base64url fields, and the field
//! decoders that read them back.
//!
//! Its own authority because the wire form is a contract with the ingress that emits it,
//! where [`super::v2`] holds what an assertion MEANS once parsed — the verification order,
//! the freshness window, the request binding. Keeping them apart is what makes the arity a
//! single fact: the emitter and the parser are the same eleven names in the same order, and
//! a field cannot be read from an assertion that does not have it.
//!
//! Every framing, decoding or shape violation fails closed as
//! [`LbAssertionV2Rejection::Malformed`].

use mcp_re_core::b64url_decode;

use super::v2::AttestedCertVerification;
use super::v2::AttestedRevocation;
use super::v2::LbAssertionV2;
use super::v2::LbAssertionV2Rejection;
use crate::transport::validate_asserted_identity_value;

/// Ceiling on a presented assertion's total wire length, before any field is decoded.
const MAX_V2_ASSERTION_WIRE_LEN: usize = 64 * 1024;

/// Decode one base64url-no-pad v2 field to a UTF-8 string; any decode or UTF-8
/// error fails closed as [`LbAssertionV2Rejection::Malformed`].
fn decode_v2_str(field: &str) -> Result<String, LbAssertionV2Rejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionV2Rejection::Malformed)?;
    String::from_utf8(bytes).map_err(|_| LbAssertionV2Rejection::Malformed)
}

/// Decode a single-byte enum discriminant field via `from_disc`; a wrong length or
/// an unassigned discriminant fails closed as [`LbAssertionV2Rejection::Malformed`].
fn decode_v2_enum<T>(
    field: &str,
    from_disc: fn(u8) -> Option<T>,
) -> Result<T, LbAssertionV2Rejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionV2Rejection::Malformed)?;
    match bytes.as_slice() {
        [b] => from_disc(*b).ok_or(LbAssertionV2Rejection::Malformed),
        _ => Err(LbAssertionV2Rejection::Malformed),
    }
}

/// Decode a fixed 8-byte big-endian `i64` field; a wrong length fails closed as
/// [`LbAssertionV2Rejection::Malformed`].
fn decode_v2_i64(field: &str) -> Result<i64, LbAssertionV2Rejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionV2Rejection::Malformed)?;
    let array: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| LbAssertionV2Rejection::Malformed)?;
    Ok(i64::from_be_bytes(array))
}

/// Decode the optional-`expires_at` field: a single presence byte `0` (absent) or
/// `1` followed by a fixed 8-byte big-endian `i64` (present). Any other framing —
/// including a stray sentinel — fails closed as [`LbAssertionV2Rejection::Malformed`].
fn decode_v2_expires_at(field: &str) -> Result<Option<i64>, LbAssertionV2Rejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionV2Rejection::Malformed)?;
    match bytes.as_slice() {
        [0] => Ok(None),
        [1, rest @ ..] => {
            let array: [u8; 8] = rest
                .try_into()
                .map_err(|_| LbAssertionV2Rejection::Malformed)?;
            Ok(Some(i64::from_be_bytes(array)))
        }
        _ => Err(LbAssertionV2Rejection::Malformed),
    }
}

/// Parse a presented v2 assertion header value into its fields + signature.
///
/// Wire form: eleven `.`-separated base64url-no-pad fields (see
/// [`LbAssertionV2::to_wire`]). Any framing / decoding / shape violation fails
/// closed as [`LbAssertionV2Rejection::Malformed`].
pub(super) fn parse(value: &str) -> Result<(LbAssertionV2, String), LbAssertionV2Rejection> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_V2_ASSERTION_WIRE_LEN {
        return Err(LbAssertionV2Rejection::Malformed);
    }
    // Class B: the arity check and the field extraction are ONE operation. A field
    // cannot be read from an assertion that does not have it, and the count cannot
    // drift away from the number of names bound here.
    let parts: Vec<&str> = trimmed.split('.').collect();
    let [key_id_field, ingress_identity_field, asserted_client_identity_field, request_hash_field, audience_field, cert_verification_field, revocation_field, validation_time_field, crl_next_update_field, expires_at_field, signature_field] =
        parts.as_slice()
    else {
        return Err(LbAssertionV2Rejection::Malformed);
    };
    let key_id = decode_v2_str(key_id_field)?;
    let ingress_identity = decode_v2_str(ingress_identity_field)?;
    let asserted_client_identity = decode_v2_str(asserted_client_identity_field)?;
    let request_hash = decode_v2_str(request_hash_field)?;
    let audience = decode_v2_str(audience_field)?;
    let cert_verification_result = decode_v2_enum(
        cert_verification_field,
        AttestedCertVerification::from_discriminant,
    )?;
    let revocation_result =
        decode_v2_enum(revocation_field, AttestedRevocation::from_discriminant)?;
    let validation_time = decode_v2_i64(validation_time_field)?;
    let crl_next_update = decode_v2_i64(crl_next_update_field)?;
    let expires_at = decode_v2_expires_at(expires_at_field)?;
    let signature_b64url = (*signature_field).to_string();
    if signature_b64url.is_empty() {
        return Err(LbAssertionV2Rejection::Malformed);
    }
    // Strict shape on the delegated identity (length-bound, no control chars,
    // non-empty), mirroring the Tier-2/Tier-3 header paths.
    if validate_asserted_identity_value(&asserted_client_identity).is_err() {
        return Err(LbAssertionV2Rejection::Malformed);
    }
    // key_id / ingress_identity / request_hash / audience must be non-empty and
    // control-char-free too.
    for field in [&key_id, &ingress_identity, &request_hash, &audience] {
        if field.is_empty() || field.chars().any(|c| c.is_control()) {
            return Err(LbAssertionV2Rejection::Malformed);
        }
    }
    Ok((
        LbAssertionV2 {
            key_id,
            ingress_identity,
            asserted_client_identity,
            request_hash,
            audience,
            cert_verification_result,
            revocation_result,
            validation_time,
            crl_next_update,
            expires_at,
        },
        signature_b64url,
    ))
}
