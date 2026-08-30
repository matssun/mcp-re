// SPDX-License-Identifier: Apache-2.0
//! WHICH JSON numbers survive the `f64` carrier this profile re-serializes through.
//!
//! Its own authority because it answers a question about VALUES, where its sibling
//! [`super::representable`] answers one about STRUCTURE — string literals, member names,
//! nesting. Both refuse for the same reason (the composer re-serializes the whole body
//! before it is digested and signed, so anything the round trip alters is delivered as
//! authentic), but what each has to know is entirely different, and only this one has to
//! reason about floating point.
//!
//! Two refusals, because they are two different losses:
//!
//!   * **An integer outside the i64/u64 range.** Without `arbitrary_precision`,
//!     `serde_json` carries it as `f64`: `123456789012345678901234567890` comes back as
//!     `1.2345678901234568e29`, having lost thirteen significant digits. A 128-bit
//!     identifier, a nanosecond timestamp or a fixed-point monetary value would be
//!     silently rewritten.
//!   * **A decimal the `f64` carrier cannot hold.** Every non-integer is carried as `f64`,
//!     so `1234567890123456789.5` comes back as `1.2345678901234568e18` — a fixed-point
//!     amount or a high-precision measurement rewritten inside the signed bytes.

use crate::error::HttpProfileError;

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
// Class C: `i` advances one position at a time over `body` and stops at its end.
#[allow(clippy::arithmetic_side_effects)]
pub(super) fn scan_number(body: &[u8], at: usize) -> Result<usize, HttpProfileError> {
    let start = at;
    let mut i = at;
    while body
        .get(i)
        .is_some_and(|b| matches!(b, b'-' | b'+' | b'.' | b'0'..=b'9' | b'e' | b'E'))
    {
        i += 1;
    }
    let Some(token) = body.get(start..i) else {
        return Err(HttpProfileError::MalformedEvidence("body json"));
    };
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
    // Class B: the significant digits are taken as a SLICE, so the range constructor
    // checks the relation a `last - first + 1` would assume — that `rposition` does not
    // precede `position` for one predicate over one slice. A zero significand cannot
    // reach here (`first` returns for it), and the `else` agrees with that branch.
    let Some(last) = digits.iter().rposition(|d| *d != b'0') else {
        return true;
    };
    let Some(significant) = digits.get(first..=last) else {
        return true;
    };
    significant.len() <= EXACTLY_CARRIED_DECIMAL_DIGITS
}
