// SPDX-License-Identifier: Apache-2.0
//! Which JSON this profile can carry through its own re-serialization unchanged.
//!
//! One authority, and it is the proxy's pass-through promise made checkable. Composing the
//! evidence block re-serializes the WHOLE body through `serde_json::Value`, and that happens
//! BEFORE `Content-Digest` and the signature — so anything the round trip alters is what
//! gets signed and delivered as authentic, with the client verifying the altered value as a
//! correctly bound response.
//!
//! The proxy is a pass-through for application payload, and this is the one place it could
//! stop being one. Every alteration that changes what a reader SEES is therefore refused
//! rather than performed. Member ORDER is the one exception, and it is not refusable: every
//! message this profile has ever signed carries the re-serialized order, so the order IS the
//! emitted form. RFC 8259 §4 states object members are unordered, so no reader may depend on
//! it, and unlike the refusals here it changes no value anyone reads.
//!
//! The scan runs AFTER the body has parsed, so it may assume well-formed JSON: it tracks
//! string literals (to avoid reading their contents as structure), object nesting, and
//! member names, and needs no error recovery.

use std::collections::HashSet;

use crate::error::HttpProfileError;

/// One frame per open composite: the member names seen so far in an object, or `None` for
/// an array, whose elements have no names.
type Frames = Vec<Option<HashSet<String>>>;

/// Scan one string literal, and — when it turns out to be a member NAME — record it in the
/// enclosing object's frame.
///
/// Returns the index just past the closing quote. A string followed by `:` is a member name;
/// nothing else can be. Duplication is decided on the DECODED name, because
/// `serde_json::Map` is keyed on the decoded string: `"x"` and `"\u0078"` are one member
/// name however differently they are spelled on the wire — and the last one would win,
/// making the others vanish from the signed bytes.
fn scan_string(body: &[u8], at: usize, frames: &mut Frames) -> Result<usize, HttpProfileError> {
    let start = at + 1;
    let mut j = start;
    while j < body.len() && body[j] != b'"' {
        j += if body[j] == b'\\' { 2 } else { 1 };
    }
    let raw = &body[start..j.min(body.len())];
    let after = j + 1;
    let mut k = after;
    while k < body.len() && body[k].is_ascii_whitespace() {
        k += 1;
    }
    if k < body.len() && body[k] == b':' {
        let name = decoded_member_name(raw)?;
        if let Some(Some(names)) = frames.last_mut() {
            if !names.insert(name) {
                return Err(HttpProfileError::MalformedEvidence(
                    "body object has a duplicate member name",
                ));
            }
        }
    }
    Ok(after)
}

/// Scan one number token and refuse it if the `f64` carrier would rewrite it.
///
/// Returns the index just past the token. Two refusals, because they are two different
/// losses:
///
///   * **An integer outside the i64/u64 range.** Without `arbitrary_precision`,
///     `serde_json` carries it as `f64`: `123456789012345678901234567890` comes back as
///     `1.2345678901234568e29`, having lost thirteen significant digits. A 128-bit
///     identifier, a nanosecond timestamp or a fixed-point monetary value would be silently
///     rewritten.
///   * **A decimal the `f64` carrier cannot hold.** Every non-integer is carried as `f64`,
///     so `1234567890123456789.5` comes back as `1.2345678901234568e18` — a fixed-point
///     amount or a high-precision measurement rewritten inside the signed bytes.
fn scan_number(body: &[u8], at: usize) -> Result<usize, HttpProfileError> {
    let start = at;
    let mut i = at;
    while i < body.len() && matches!(body[i], b'-' | b'+' | b'.' | b'0'..=b'9' | b'e' | b'E') {
        i += 1;
    }
    let token = &body[start..i];
    let text =
        std::str::from_utf8(token).map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
    if token.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) {
        if !decimal_survives_the_f64_carrier(text) {
            return Err(HttpProfileError::MalformedEvidence(
                "body carries a number this profile cannot sign without altering it",
            ));
        }
    } else if text.parse::<i64>().is_err() && text.parse::<u64>().is_err() {
        return Err(HttpProfileError::MalformedEvidence(
            "body carries an integer this profile cannot sign without altering it",
        ));
    }
    Ok(i)
}

/// Refuse a JSON body whose application payload this composer cannot carry unchanged.
///
/// The module documentation states what is refused and why. This is the walk: strings and
/// numbers are the only tokens that can carry a loss, and the brackets are tracked only so
/// that a member name is attributed to the object it belongs to.
pub fn reject_unrepresentable_json(body: &[u8]) -> Result<(), HttpProfileError> {
    let mut frames: Frames = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        i = match body[i] {
            b'"' => scan_string(body, i, &mut frames)?,
            b'-' | b'0'..=b'9' => scan_number(body, i)?,
            b'{' => {
                frames.push(Some(HashSet::new()));
                i + 1
            }
            b'[' => {
                frames.push(None);
                i + 1
            }
            b'}' | b']' => {
                frames.pop();
                i + 1
            }
            _ => i + 1,
        };
    }
    Ok(())
}

/// The member name as `serde_json` keys it: the raw bytes between the quotes with JSON
/// escapes decoded.
///
/// Duplication must be decided on this form. `serde_json::Map` is keyed on the decoded
/// string, so `"x"` and `"x"` are ONE member there and the earlier value is
/// dropped on the way into the signed bytes; keyed on the raw slice they are two
/// distinct names and the refusal never fires.
fn decoded_member_name(raw: &[u8]) -> Result<String, HttpProfileError> {
    let malformed = || HttpProfileError::MalformedEvidence("body json");
    if !raw.contains(&b'\\') {
        return std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| malformed());
    }
    let mut quoted = Vec::with_capacity(raw.len() + 2);
    quoted.push(b'"');
    quoted.extend_from_slice(raw);
    quoted.push(b'"');
    serde_json::from_slice::<String>(&quoted).map_err(|_| malformed())
}

/// Significant decimal digits an `f64` carries with no loss of value: within this many,
/// distinct decimals map to distinct `f64`s and are recovered from them exactly.
const EXACTLY_CARRIED_DECIMAL_DIGITS: usize = 15;

/// Whether a JSON number token carrying a fraction or an exponent keeps its value
/// through the `f64` the composer re-serializes it from.
///
/// `f64` → text → `f64` is exact, but the direction taken here is text → `f64` → text,
/// and that one is not: `1234567890123456789.5` is emitted as `1.2345678901234568e18`.
/// Two conditions make the emitted decimal equal the received one:
///
///   * the significand carries at most [`EXACTLY_CARRIED_DECIMAL_DIGITS`] significant
///     digits, so the shortest round-trip form `serde_json` emits has the same value; and
///   * the carrier neither overflowed to an infinity nor flushed a nonzero value to
///     zero.
///
/// Spelling is not value: `1e2` is emitted as `100.0` and is admitted, the same way
/// member ORDER is rewritten and admitted. What is refused is a change to the number a
/// reader sees.
fn decimal_survives_the_f64_carrier(text: &str) -> bool {
    let Ok(value) = text.parse::<f64>() else {
        return false;
    };
    if !value.is_finite() {
        return false;
    }
    let significand = text.split(['e', 'E']).next().unwrap_or(text);
    let digits: Vec<u8> = significand.bytes().filter(|b| b.is_ascii_digit()).collect();
    let Some(first) = digits.iter().position(|d| *d != b'0') else {
        // A zero significand — `0`, `0.000`, `0e10`. Exactly carried.
        return true;
    };
    if value == 0.0 {
        // A nonzero decimal the carrier flushed to zero.
        return false;
    }
    let last = digits
        .iter()
        .rposition(|d| *d != b'0')
        .expect("a nonzero digit was just found");
    let significant_digits = last - first + 1;
    significant_digits <= EXACTLY_CARRIED_DECIMAL_DIGITS
}
