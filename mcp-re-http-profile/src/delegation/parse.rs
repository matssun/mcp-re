// SPDX-License-Identifier: Apache-2.0
//! Reading a compact delegation credential: the split and the decode, and nothing that
//! judges what comes out.
//!
//! One place, because a second parser over a security-relevant encoding is a second thing
//! that can disagree with the first — and both sides of this crate read these bytes: the
//! verifier deciding whether a presented credential may be believed, and the custody machine
//! deriving the window it will serve under from the credential it is about to publish.

use serde::Deserialize;

use mcp_re_core::b64url_decode;

use super::DelegationClaims;
use super::DelegationHeader;
use crate::error::HttpProfileError;

/// The header and claims a compact delegation credential states, with no judgement passed
/// on whether they may be believed.
///
/// `pub(crate)` for the issuance side: [`custody::ActiveDelegatedKey`](crate::custody)
/// derives its window from the exact credential it is about to publish, and needs the
/// credential's own statement of itself to do so. It must not re-implement the split and the
/// decode — a second parser over a security-relevant encoding is a second thing that can
/// disagree with the first. Deciding whether a credential is ACCEPTABLE stays here, in
/// [`verify_delegation_credential`], and is a different authority.
pub(crate) fn parse_credential(
    compact_jws: &str,
) -> Result<(DelegationHeader, DelegationClaims), HttpProfileError> {
    let (h, p, _) = split_compact_jws(compact_jws)?;
    Ok((decode_json(h)?, decode_json(p)?))
}

/// Split a compact JWS into its three base64url segments. Not exactly three parts,
/// or an empty segment ⇒ an invalid credential.
pub(super) fn split_compact_jws(jws: &str) -> Result<(&str, &str, &str), HttpProfileError> {
    let mut parts = jws.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok((h, p, s))
        }
        _ => Err(HttpProfileError::DelegationCredentialInvalid),
    }
}

/// Decode a base64url-no-pad JWS segment and parse its JSON. Any failure ⇒ an
/// invalid credential.
pub(super) fn decode_json<T: for<'de> Deserialize<'de>>(
    segment: &str,
) -> Result<T, HttpProfileError> {
    let bytes =
        b64url_decode(segment).map_err(|_| HttpProfileError::DelegationCredentialInvalid)?;
    serde_json::from_slice(&bytes).map_err(|_| HttpProfileError::DelegationCredentialInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::b64url_encode;

    #[test]
    fn three_non_empty_segments_split_in_order() {
        assert!(matches!(
            split_compact_jws("aa.bb.cc"),
            Ok(("aa", "bb", "cc"))
        ));
    }

    #[test]
    fn a_fourth_well_formed_segment_is_refused() {
        assert!(matches!(
            split_compact_jws("aa.bb.cc.dd"),
            Err(HttpProfileError::DelegationCredentialInvalid)
        ));
        let h = b64url_encode(br#"{"a":1}"#);
        let p = b64url_encode(br#"{"b":2}"#);
        assert!(decode_json::<serde_json::Value>(&h).is_ok());
        assert!(decode_json::<serde_json::Value>(&p).is_ok());
        assert!(matches!(
            parse_credential(&format!("{h}.{p}.cc.dd")),
            Err(HttpProfileError::DelegationCredentialInvalid)
        ));
    }

    #[test]
    fn an_empty_segment_at_the_right_count_is_refused() {
        for jws in ["aa..cc", ".bb.cc", "aa.bb.", "aa.bb"] {
            assert!(
                matches!(
                    split_compact_jws(jws),
                    Err(HttpProfileError::DelegationCredentialInvalid)
                ),
                "{jws}"
            );
        }
    }

    #[test]
    fn decode_json_refuses_bad_base64url_and_bad_json_separately() {
        assert!(matches!(
            decode_json::<serde_json::Value>("!!"),
            Err(HttpProfileError::DelegationCredentialInvalid)
        ));
        assert!(matches!(
            decode_json::<serde_json::Value>(&b64url_encode(b"not json")),
            Err(HttpProfileError::DelegationCredentialInvalid)
        ));
        assert!(decode_json::<serde_json::Value>(&b64url_encode(br#"{"a":1}"#)).is_ok());
    }
}
