// SPDX-License-Identifier: Apache-2.0
//! The signature-input parameter tail: what the signer said about its own signature.
//!
//! One authority: **the closed, ORDERED parameter set, each value in the one spelling this
//! profile emits.** Ordering is a security rule and not tidiness: the verifier normalises to
//! a canonical order when rebuilding `@signature-params`, so a reordered wire form would
//! silently verify under the same signature. It is therefore rejected structurally rather
//! than sorted away, and a `rank` that does not strictly increase catches reordering and
//! duplication with one comparison.
//!
//! The escape forms RFC 8941 permits inside a quoted value are REFUSED rather than decoded,
//! and `created=+1700000000` is refused rather than parsed, for the same reason
//! [`super::sf_dictionary`] states once: the base is rebuilt from parsed values, so every
//! accepted spelling of one value collapses to one signature base.

use crate::error::HttpProfileError;
use crate::sigbase::SignatureParams;

use super::sf_dictionary::split_parameters;

/// The ONE wire spelling this profile emits for the parameter tail.
///
/// EXACTLY `;k=v;k=v` — no space around a `;`, no empty slot, no trailing `;`.
/// `(...) ;created=1;` used to parse identically to `(...);created=1`, which is the same
/// wire-spelling collapse the inner-list check refuses: the base is rebuilt from parsed
/// values, so both spellings verify under one signature and the raw header stops matching
/// the signed bytes. The inner list is held to the same rule in `covered_components`.
fn check_tail_spelling(param_tail: &str) -> Result<(), HttpProfileError> {
    let spacing = || HttpProfileError::MalformedEvidence("signature parameter spacing");
    if param_tail.is_empty() {
        return Ok(());
    }
    if !param_tail.starts_with(';') {
        return Err(spacing());
    }
    // Only the segment before the FIRST `;` may be empty (there is nothing before it);
    // every other empty segment is a stray or trailing `;`.
    if split_parameters(param_tail)
        .iter()
        .skip(1)
        .any(|seg| seg.is_empty())
    {
        return Err(spacing());
    }
    // No space or tab OUTSIDE a quoted value. Inside one it is a legitimate byte of a
    // keyid or nonce (`validate_sf_string` admits printable ASCII); outside, it is a
    // spelling this profile never emits and would normalise away.
    let mut in_quotes = false;
    let mut escaped = false;
    for b in param_tail.bytes() {
        match b {
            _ if escaped => escaped = false,
            b'\\' if in_quotes => escaped = true,
            b'"' => in_quotes = !in_quotes,
            b' ' | b'\t' if !in_quotes => return Err(spacing()),
            _ => {}
        }
    }
    Ok(())
}

/// The closed, ordered parameter set; declaration order is the canonical order, so the
/// derived `Ord` is the rank that must strictly increase across the wire form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Parameter {
    Created,
    Expires,
    Nonce,
    Keyid,
    Alg,
    Tag,
}

/// An unknown parameter would change the signature base this verifier rebuilds, so it fails
/// closed rather than sign-what-you-did-not-say.
fn parameter(key: &str) -> Result<Parameter, HttpProfileError> {
    match key {
        "created" => Ok(Parameter::Created),
        "expires" => Ok(Parameter::Expires),
        "nonce" => Ok(Parameter::Nonce),
        "keyid" => Ok(Parameter::Keyid),
        "alg" => Ok(Parameter::Alg),
        "tag" => Ok(Parameter::Tag),
        _ => Err(HttpProfileError::MalformedEvidence(
            "unknown signature parameter",
        )),
    }
}

/// A quoted-string parameter's value, held to exactly what this profile will EMIT
/// (`sigbase::validate_sf_string`): printable ASCII with no `"` and no `\`.
///
/// The escape forms RFC 8941 permits are refused rather than decoded. The verifier rebuilds
/// `@signature-params` from these parsed values and re-serializes them canonically, so
/// decoding `\"` would make two wire spellings collapse to one signature base — the same
/// defect the profile already refuses for `created=+1` (see [`parse_i64`]). Refusing keeps
/// the received bytes and the signed bytes in one-to-one correspondence.
fn unquote(v: &str) -> Result<String, HttpProfileError> {
    let inner = v
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or(HttpProfileError::MalformedEvidence(
            "quoted signature parameter",
        ))?;
    crate::sigbase::validate_sf_string(inner, "quoted signature parameter")?;
    Ok(inner.to_owned())
}

/// Read one already-ranked parameter into the parsed set.
///
/// The match is total over [`Parameter`].
fn assign(params: &mut SignatureParams, param: Parameter, v: &str) -> Result<(), HttpProfileError> {
    match param {
        Parameter::Created => params.created = Some(parse_i64(v)?),
        Parameter::Expires => params.expires = Some(parse_i64(v)?),
        Parameter::Nonce => {
            let nonce = unquote(v)?;
            // A nonce is carried VERBATIM into the node-local replay key and retained for
            // up to `expires + skew`, and that tier bounds entry COUNT, not entry SIZE.
            // Without a length bound an authenticated client could pad each nonce to the
            // header limit and pin ~3 orders of magnitude more memory per admitted request,
            // ending in a self-inflicted `replay_cache_unavailable` for the whole replica.
            // The same bound is applied where the signer SERIALIZES the parameter
            // (`sigbase::validate_nonce_length`), so a value this profile cannot carry is
            // never emitted either.
            crate::sigbase::validate_nonce_length(&nonce)?;
            params.nonce = Some(nonce);
        }
        Parameter::Keyid => params.keyid = Some(unquote(v)?),
        Parameter::Alg => params.alg = Some(unquote(v)?),
        Parameter::Tag => params.tag = Some(unquote(v)?),
    }
    Ok(())
}

/// Parse the `;k=v;k=v` tail that follows the inner list.
pub(super) fn parse_signature_parameters(
    param_tail: &str,
) -> Result<SignatureParams, HttpProfileError> {
    check_tail_spelling(param_tail)?;
    let mut params = SignatureParams::default();
    let mut last: Option<Parameter> = None;
    for p in split_parameters(param_tail) {
        if p.is_empty() {
            continue;
        }
        let (k, v) = p
            .split_once('=')
            .ok_or(HttpProfileError::MalformedEvidence("signature parameter"))?;
        let param = parameter(k)?;
        if last.is_some_and(|prev| param <= prev) {
            return Err(HttpProfileError::MalformedEvidence(
                "signature parameter order",
            ));
        }
        last = Some(param);
        assign(&mut params, param, v)?;
    }
    Ok(params)
}

/// Leak-free integer parse for created/expires, restricted to the ONE spelling
/// RFC 8941 §3.3.1 allows: optional `-`, then digits with no leading zero (except
/// `0` itself).
///
/// Rust's `i64::from_str` also accepts `+1700000000` and `0017`, which this profile
/// must not: the verifier rebuilds `@signature-params` from the PARSED values and
/// re-serializes them canonically ([`crate::sigbase`]), so every accepted spelling of
/// the same number collapses to one signature base. An intermediary could then
/// rewrite `created=1700000000` to `created=+1700000000` and the signature would
/// still verify, leaving any consumer that reads the raw header looking at bytes
/// other than the ones that were signed. Rejecting the alternate spellings keeps the
/// on-wire form pinned, the same reason parameter reordering is rejected structurally
/// rather than normalized away.
pub(super) fn parse_i64(s: &str) -> Result<i64, HttpProfileError> {
    let malformed = || HttpProfileError::MalformedEvidence("integer signature parameter");
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed());
    }
    // No leading zeros: "0" is fine, "00" / "0017" / "-01" are not.
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(malformed());
    }
    // And no NEGATIVE ZERO. RFC 8941 §3.3.1's sf-integer has no `-0`, and it slipped
    // through the leading-zero rule above (`digits` is "0", length 1): it parsed to 0
    // and re-serialised as "0", so `created=-0` and `created=0` collapsed to one
    // signature base — the exact spelling-collapse this function exists to refuse.
    if s.starts_with('-') && digits == "0" {
        return Err(malformed());
    }
    s.parse::<i64>().map_err(|_| malformed())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8941 §3.3.1's sf-integer has no `-0`. It slipped past the leading-zero rule
    /// (the digits are just "0") and re-serialised as "0", so two spellings collapsed
    /// to one signature base.
    #[test]
    fn negative_zero_is_not_an_sf_integer() {
        assert_eq!(parse_i64("0").expect("zero parses"), 0);
        assert!(parse_i64("-0").is_err(), "-0 is not an sf-integer");
        assert!(parse_i64("-00").is_err());
        assert_eq!(parse_i64("-17").expect("negatives parse"), -17);
    }

    #[test]
    fn reordered_and_duplicated_parameters_are_refused() {
        let order = HttpProfileError::MalformedEvidence("signature parameter order");
        assert_eq!(
            parse_signature_parameters(";expires=2;created=1").expect_err("reordered"),
            order
        );
        assert_eq!(
            parse_signature_parameters(";created=1;created=2").expect_err("duplicated"),
            order
        );
        let ok = parse_signature_parameters(";created=1;expires=2").expect("ordered");
        assert_eq!(ok.created, Some(1));
        assert_eq!(ok.expires, Some(2));
    }

    #[test]
    fn an_unknown_signature_parameter_is_refused() {
        assert_eq!(
            parse_signature_parameters(";created=1;foo=1").expect_err("unknown"),
            HttpProfileError::MalformedEvidence("unknown signature parameter")
        );
    }

    #[test]
    fn plus_signed_and_leading_zero_integers_are_refused() {
        let bad = HttpProfileError::MalformedEvidence("integer signature parameter");
        for s in ["+1700000000", "0017", "-01"] {
            assert_eq!(parse_i64(s).expect_err(s), bad);
        }
        assert_eq!(
            parse_signature_parameters(";created=0017").expect_err("leading zero"),
            bad
        );
        assert_eq!(parse_i64("1700000000").expect("plain"), 1_700_000_000);
    }

    #[test]
    fn escaped_quoted_parameter_values_are_refused() {
        assert_eq!(
            parse_signature_parameters(r#";keyid="a\"b""#).expect_err("escaped"),
            HttpProfileError::MalformedEvidence("quoted signature parameter")
        );
        let ok = parse_signature_parameters(r#";keyid="a b""#).expect("plain");
        assert_eq!(ok.keyid, Some("a b".to_owned()));
    }

    #[test]
    fn a_tab_outside_quotes_is_refused() {
        assert_eq!(
            parse_signature_parameters(";created=1;\tkeyid=\"k\"").expect_err("tab"),
            HttpProfileError::MalformedEvidence("signature parameter spacing")
        );
    }
}
