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

use super::decimal_token::DecimalToken;
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

/// Whether a JSON number token carrying a fraction or an exponent keeps its value
/// through the `f64` the composer re-serializes it from.
///
/// **The property, tested directly.** The composer parses the received token to an `f64`
/// and emits that `f64` again; a reader of the composed body reads whatever it emitted.
/// So the question is whether the emitted text denotes the same number as the received
/// text, and the way to answer it is to perform the round trip and compare the two
/// values. `1234567890123456789.5` comes back as `1.2345678901234568e18` and is refused;
/// `0.30000000000000004` comes back unchanged and is not.
///
/// **Why not a digit count.** Counting significant digits against a constant is a PROXY
/// for that property, and it is wrong in the admitting direction as well as the refusing
/// one: a shortest-round-trip formatter emits sixteen and seventeen significant digits for
/// ordinary computed values, and those values survive the carrier exactly. Raising the
/// constant moves the boundary and leaves the proxy in place. There is no count to pick,
/// because width is not what decides the question.
///
/// Both halves of the comparison go through the parser and the formatter the composer
/// itself uses, so what is measured is the composer's behaviour rather than a second
/// implementation of it.
///
/// Spelling is not value: `1e2` is emitted as `100.0` and is admitted, the same way member
/// ORDER is rewritten and admitted. What is refused is a change to the number a reader
/// sees. [`DecimalToken`] is what draws that line — see its module for why neither a
/// string comparison nor an `f64` comparison can.
fn decimal_survives_the_f64_carrier(text: &str) -> bool {
    // The carrier, run: the parse the composer performed to build the `Value`, and the
    // formatting it will perform to re-serialize it.
    let Ok(carried) = serde_json::from_str::<f64>(text) else {
        return false;
    };
    if !carried.is_finite() {
        return false;
    }
    let Ok(emitted) = serde_json::to_string(&carried) else {
        return false;
    };
    // An unparseable side is a refusal, never a pass: the values were not compared, so
    // nothing may be concluded about them. This is also what refuses a nonzero decimal
    // the carrier flushed to zero and a value it rounded to an infinity — those need no
    // case of their own, because both change the number a reader sees.
    let (Some(received), Some(emitted)) =
        (DecimalToken::parse(text), DecimalToken::parse(&emitted))
    else {
        return false;
    };
    received == emitted
}
