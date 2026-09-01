// SPDX-License-Identifier: Apache-2.0
//! The exact value a JSON number token denotes, in a form two tokens can be compared in.
//!
//! Its own authority because it answers a question with no security content at all — what
//! number does this text mean? — for a sibling that answers one with nothing but security
//! content. [`super::carried_number`] has to ask whether the text the composer will EMIT
//! means the same number as the text it RECEIVED, and neither obvious comparison answers
//! that question:
//!
//!   * comparing the two strings answers a question about SPELLING. `1e2` and `100.0` are
//!     one number written twice, and a reader of the composed body sees the same value
//!     either way.
//!   * comparing two `f64`s answers the question with the carrier under test. Both sides
//!     parse to the same `f64` by construction — that is what the emitted form IS — so the
//!     comparison is true for every input and measures nothing.
//!
//! So a token is normalized to an exact decimal instead: a sign, the significant digits,
//! and a power of ten. Nothing here rounds, nothing here converts to a binary float, and
//! the comparison is exact for every token a JSON body can carry.

/// One JSON number token as an exact decimal: `digits × 10^exponent`, negated if
/// `negative`.
///
/// The representation is normalized on construction and is private, so two values that
/// denote the same number are equal under `PartialEq` and there is no second spelling of
/// one number to compare against: `digits` carries no leading and no trailing zero, and
/// zero is the empty digit string with exponent 0 and no sign. That is what makes
/// derived equality the value comparison this exists to provide rather than a comparison
/// of representations that happen to agree.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DecimalToken {
    negative: bool,
    digits: Vec<u8>,
    exponent: i32,
}

impl DecimalToken {
    /// The exact value of one JSON number token, or `None` if the text is not one.
    ///
    /// `None` is not "zero" and not "unknown": every caller refuses on it. A token whose
    /// exponent does not fit an `i32`, or whose normalization would overflow one, is
    /// `None` for the same reason — the value cannot be stated exactly here, so nothing
    /// downstream may claim it was compared.
    pub(super) fn parse(text: &str) -> Option<Self> {
        let (negative, unsigned) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text.strip_prefix('+').unwrap_or(text)),
        };
        let (significand, exponent_text) = match unsigned.split_once(['e', 'E']) {
            Some((significand, exponent)) => (significand, Some(exponent)),
            None => (unsigned, None),
        };
        let exponent: i32 = match exponent_text {
            Some(text) => text.parse().ok()?,
            None => 0,
        };
        let (integer, fraction) = significand.split_once('.').unwrap_or((significand, ""));
        if integer.is_empty() && fraction.is_empty() {
            return None;
        }
        if !integer
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
        {
            return None;
        }
        // A digit written after the point is a digit divided by a power of ten, so the
        // whole significand becomes an integer by moving the exponent down by the count.
        let scale = i32::try_from(fraction.len()).ok()?;
        let digits: Vec<u8> = integer.bytes().chain(fraction.bytes()).collect();
        Self::normalized(negative, digits, exponent.checked_sub(scale)?)
    }

    /// Strip the zeros that carry no value, so equality is over the number and not over
    /// the way it was written.
    fn normalized(negative: bool, digits: Vec<u8>, exponent: i32) -> Option<Self> {
        let mut digits = digits;
        let mut exponent = exponent;
        let leading = digits
            .iter()
            .position(|digit| *digit != b'0')
            .unwrap_or(digits.len());
        digits.drain(..leading);
        while digits.last() == Some(&b'0') {
            digits.pop();
            // A trailing zero removed from the digits is a power of ten added back to the
            // exponent, which is why this is not a saturating or wrapping count: on
            // overflow the value can no longer be stated, and `None` refuses.
            exponent = exponent.checked_add(1)?;
        }
        if digits.is_empty() {
            // Every spelling of zero is one value. Keeping the sign or the exponent here
            // would make `-0.0`, `0e10` and `0` three unequal zeros.
            return Some(Self {
                negative: false,
                digits,
                exponent: 0,
            });
        }
        Some(Self {
            negative,
            digits,
            exponent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the sibling rule depends on: spelling is not value.
    #[test]
    fn one_number_written_many_ways_is_one_value() {
        for group in [
            vec!["100", "1e2", "100.0", "1.0e2", "0.1e3", "10.0e1"],
            vec!["0", "-0", "0.0", "0.000", "0e10", "-0.0e-5"],
            vec!["1.5", "1.50", "15e-1", "0.015e2"],
            vec!["-2.5e-3", "-0.0025", "-25e-4"],
        ] {
            let first = DecimalToken::parse(group[0]).expect("a number");
            for spelling in &group {
                assert_eq!(
                    DecimalToken::parse(spelling).expect("a number"),
                    first,
                    "{spelling} is the same value as {}",
                    group[0],
                );
            }
        }
    }

    /// Without this the control above holds for a parser that returns one constant.
    #[test]
    fn numbers_that_differ_are_not_equal() {
        for (left, right) in [
            ("1", "-1"),
            ("100", "1000"),
            ("1e2", "1e3"),
            ("0.1", "0.2"),
            ("1.0000000000000000001", "1"),
            ("0.12345678901234567890123", "0.12345678901234568"),
            ("1234567890123456789.5", "1.2345678901234568e18"),
        ] {
            assert_ne!(
                DecimalToken::parse(left).expect("a number"),
                DecimalToken::parse(right).expect("a number"),
                "{left} and {right} are different numbers",
            );
        }
    }

    /// Seventeen significant digits are as exactly comparable as one. The whole point of
    /// not going through `f64` is that width is not a limit here.
    #[test]
    fn a_wide_significand_is_compared_digit_for_digit() {
        assert_eq!(
            DecimalToken::parse("0.30000000000000004").expect("a number"),
            DecimalToken::parse("30000000000000004e-17").expect("a number"),
        );
        assert_ne!(
            DecimalToken::parse("0.30000000000000004").expect("a number"),
            DecimalToken::parse("0.30000000000000005").expect("a number"),
        );
    }

    #[test]
    fn what_is_not_a_number_is_none_and_never_a_value() {
        for text in [
            "", "-", ".", "e5", "1.2.3", "1e", "1e2e3", "0x10", "1_000", "nan",
        ] {
            assert_eq!(DecimalToken::parse(text), None, "{text}");
        }
    }

    /// An exponent that cannot be stated exactly is `None`, not a saturated value that
    /// would compare equal to some other number.
    #[test]
    fn an_unstateable_exponent_is_none() {
        assert_eq!(DecimalToken::parse("1e99999999999999999999"), None);
        assert_eq!(
            DecimalToken::parse(&format!("1.5e{}", i32::MIN)),
            None,
            "moving the point past the exponent floor must not wrap",
        );
        assert_eq!(
            DecimalToken::parse(&format!("1{}e{}", "0".repeat(2), i32::MAX)),
            None,
            "normalizing trailing zeros must not wrap the exponent",
        );
    }
}
