//! RFC 3339 UTC timestamp parsing and freshness checking (MCP_RE_SPEC §5 / ADR-006,
//! and the `verify_request` order §9 step 9).
//!
//! **NOT the live freshness gate.** Under ADR-MCPRE-050 the RFC 9421 + RFC 9530 HTTP
//! evidence carrier is the sole carrier, and its `created`/`expires` are sf-integers
//! in the `Signature-Input` header — parsed and bounded by
//! `mcp_re_http_profile::verify`, which is what every served request goes through.
//! Nothing on that path calls this module. It is retained as the parser for the
//! RFC 3339 timestamps that appear in evidence ARTIFACTS (manifests, pins, retained
//! records), and re-exported for embedders; describing it as the gate would send a
//! reader looking for the enforcement in the wrong crate.
//!
//! Core MUST stay pure and deterministic: it does NOT read the system clock.
//! Freshness is evaluated against a `now_unix` value supplied by the caller, so
//! every check is reproducible and testable.
//!
//! ## Timestamp grammar (strict)
//!
//! [`parse_rfc3339_utc`] accepts only the strict RFC 3339 UTC form
//! `YYYY-MM-DDTHH:MM:SSZ`, optionally with a fractional-seconds part
//! (`.sss`, one or more digits) immediately before the `Z`:
//! `YYYY-MM-DDTHH:MM:SS.sssZ`.
//!
//! - **Fractional seconds are accepted and TRUNCATED** (floored) to whole
//!   seconds — Unix-second resolution is all freshness needs. They are not
//!   rounded.
//! - The zone designator MUST be the literal `Z` (UTC). Any numeric offset
//!   (`+01:00`, `-05:00`, `+00:00`) or a lowercase `z` is rejected.
//! - The date/time separator MUST be the uppercase `T`.
//! - Any other deviation (wrong field widths, out-of-range fields, trailing
//!   junk, missing components) is rejected.
//!
//! ## Failure mapping — fail closed
//!
//! A malformed timestamp maps to [`McpReError::ExpiredRequest`]. Rationale: if a
//! timestamp cannot be parsed, freshness cannot be established, and the only
//! safe verdict is to treat the request as outside its freshness window (fail
//! closed) rather than inventing a value or admitting the request. This mapping
//! is deliberate and is asserted by the tests.

use crate::error::McpReError;

// ADR-MCPRE-059 Phase 2. Absent from every production build: the import is
// feature-gated and each specification rides a `cfg_attr` that expands to nothing
// unless `--features verify` is on.
#[cfg(feature = "verify")]
use verus_builtin_macros::{proof, verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

/// Days in each month for a common (non-leap) year, January-indexed at 0.
#[cfg_attr(feature = "verify", verus_verify)]
pub(crate) const DAYS_IN_MONTH: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Returns `true` if `year` is a Gregorian leap year.
#[cfg_attr(feature = "verify", verus_verify)]
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Parse exactly `n` ASCII digits at `bytes[start..start+n]` into an `i64`.
///
/// Returns `None` if any of the `n` bytes is missing or is not an ASCII digit.
// ADR-MCPRE-059 ASM-0001 — the one part of this proof the verifier does not check.
// The bound is what a caller relies on: `n` ASCII digits cannot denote a value of
// more than `n` digits. It is assumed rather than proved
// because attribute-style Verus cannot state a loop invariant over the iteration
// count, and stating it in a `verus!{}` block would put the prover's crates in the
// production dependency graph. Independently exercised by this module's tests.
#[cfg_attr(feature = "verify", verus_verify(external_body))]
#[cfg_attr(feature = "verify", verus_spec(out =>
    requires
        n <= 4,
        start + n <= usize::MAX,
    ensures
        out matches Some(v) ==> 0 <= v && v <= 9999,
))]
fn parse_fixed_digits(bytes: &[u8], start: usize, n: usize) -> Option<i64> {
    // Every operation here is TOTAL in Rust, which matters more in this function than
    // anywhere else in the module: `external_body` means Verus checks the caller against
    // the contract and never looks inside, so the prover's totality result stops at this
    // boundary. Two consecutive `get`s rather than `get(start..start + n)`, because the
    // addition in that range is itself a partial operation on `usize`; and checked
    // accumulation rather than `value * 10 + d`, so a width the precondition does not
    // permit fails closed instead of overflowing. What remains assumed is ASM-0001's
    // arithmetic claim — that n digits denote at most n digits — and nothing else.
    let field = bytes.get(start..)?.get(..n)?;
    let mut value: i64 = 0;
    for b in field {
        let digit = char::from(*b).to_digit(10)?;
        value = value.checked_mul(10)?.checked_add(i64::from(digit))?;
    }
    Some(value)
}

/// Convert a Gregorian `(year, month, day)` to days since the Unix epoch
/// (1970-01-01), using Howard Hinnant's `days_from_civil` algorithm.
///
/// `month` is 1..=12 and `day` is 1..=31; both are assumed already validated by
/// the caller. The algorithm is exact for all years and handles leap years and
/// the 400-year Gregorian cycle correctly.
#[cfg_attr(feature = "verify", verus_spec(days =>
    requires
        0 <= year, year <= 9999,
        1 <= month, month <= 12,
        1 <= day, day <= 31,
    ensures
        -719528 <= days, days <= 2932896,
))]
// The era arithmetic is bounded by this function's OWN verified precondition — year in
// [0, 9999], month in [1, 12], day in [1, 31] — and Verus checks the whole body against
// it, overflow included, in the `verify` lane that gates every change to this crate. The
// allowance is therefore not a promise to remember something: it names a stronger checker
// that measures the same region, so arithmetic added here later is proved or the lane
// goes red. Evidence: verus://core/time/parse_rfc3339_utc_total_and_bounded.
#[allow(clippy::arithmetic_side_effects)]
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // Shift the year so that March is the first month: this places the leap day
    // at the end of the (shifted) year, simplifying the era arithmetic.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parse a strict RFC 3339 UTC timestamp into Unix seconds.
///
/// Accepts `YYYY-MM-DDTHH:MM:SSZ` and the fractional form
/// `YYYY-MM-DDTHH:MM:SS.sssZ` (fractional seconds are truncated to whole
/// seconds). The zone MUST be `Z`; numeric offsets are rejected. Any malformed
/// value maps to [`McpReError::ExpiredRequest`] (fail closed — see module docs).
///
/// # Examples
///
/// `1970-01-01T00:00:00Z` parses to `0`.
// ADR-MCPRE-059 Phase 2 theorem. Two properties, both about untrusted input:
//
//   * the function is TOTAL on it — no index is out of bounds and no arithmetic
//     overflows, for any byte string whatsoever, so a hostile timestamp in an
//     evidence artifact cannot panic the parser;
//   * every admitted value lies inside the parser's ADMITTED four-digit civil range
//     (THM-0002 states it exactly; `boundary_*` below pins both ends).
//
// Totality is the stronger of the two here: it is a property of ALL inputs, which
// no finite test suite establishes.
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures
        out matches Ok(v) ==> -62167219200 <= v && v <= 253402300799,
))]
// TOTALITY IS PROVED HERE, not assumed. Verus checks this body for arbitrary input: the
// fixed-position reads are bounded by the `len() < 20` refusal above them, the two tail
// slices by the same length, the month table by the `1..=12` range check, and the final
// seconds arithmetic by the validated calendar fields. That is the property THM-0002
// states, and it is re-established by the `verify` lane on every change — which is what
// makes a function-scoped allowance safe on a function this long: an unproved partial
// operation added inside it fails the prover, not merely a reviewer's attention.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn parse_rfc3339_utc(s: &str) -> Result<i64, McpReError> {
    let bytes = s.as_bytes();

    // Fixed prefix layout: "YYYY-MM-DDTHH:MM:SS" is exactly 19 bytes, followed
    // by an optional ".sss" fraction and a mandatory trailing "Z".
    // Minimum total length is 20 ("...SSZ").
    if bytes.len() < 20 {
        return Err(McpReError::ExpiredRequest);
    }

    // Structural separators at their fixed positions.
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(McpReError::ExpiredRequest);
    }

    let year = parse_fixed_digits(bytes, 0, 4);
    let month = parse_fixed_digits(bytes, 5, 2);
    let day = parse_fixed_digits(bytes, 8, 2);
    let hour = parse_fixed_digits(bytes, 11, 2);
    let minute = parse_fixed_digits(bytes, 14, 2);
    let second = parse_fixed_digits(bytes, 17, 2);

    let (year, month, day, hour, minute, second) = match (year, month, day, hour, minute, second) {
        (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) => (y, mo, d, h, mi, se),
        _ => return Err(McpReError::ExpiredRequest),
    };

    // Validate the tail after the seconds field: either a bare "Z", or a
    // fractional part ".<digits>" followed by "Z".
    let tail = &bytes[19..bytes.len()];
    let fraction_ok = if tail == b"Z" {
        true
    } else if tail.first() == Some(&b'.') {
        // At least one fractional digit, then a trailing 'Z'.
        let frac = &tail[1..tail.len()];
        match frac.split_last() {
            Some((last, digits)) if *last == b'Z' && !digits.is_empty() => {
                digits.iter().all(|b| b.is_ascii_digit())
            }
            _ => false,
        }
    } else {
        false
    };
    if !fraction_ok {
        return Err(McpReError::ExpiredRequest);
    }

    // Range-validate the calendar/clock fields. Leap seconds (second == 60) are
    // NOT accepted — Unix time has no representation for them.
    if !(1..=12).contains(&month) {
        return Err(McpReError::ExpiredRequest);
    }
    let mut max_day = DAYS_IN_MONTH[(month - 1) as usize] as i64;
    if month == 2 && is_leap_year(year) {
        max_day = 29;
    }
    // Supplies the verifier with the one fact it cannot read off the table itself:
    // no month is longer than 31 days, which is what bounds `days_from_civil`.
    #[cfg(feature = "verify")]
    proof! {
        broadcast use vstd::array::group_array_axioms;
        crate::verus_proofs::lemma_days_in_month_bounded((month - 1) as int);
    }
    if day < 1 || day > max_day {
        return Err(McpReError::ExpiredRequest);
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(McpReError::ExpiredRequest);
    }

    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Convert days-since-Unix-epoch to a Gregorian `(year, month, day)`, using
/// Howard Hinnant's `civil_from_days` — the exact inverse of [`days_from_civil`].
// NOT part of the Verus cone — this is the formatting inverse, and it carries its bound in
// Rust rather than in a proof. The bound is the argument's provenance: the sole caller
// passes `unix.div_euclid(86_400)`, so `z` lies in +/-1.07e14 for EVERY `i64` and each
// subsequent quantity is bounded by the one before it — `era` by z/146_097 to +/-7.3e8,
// `doe` to [0, 146096] by construction, `yoe` to [0, 399], `doy` to [0, 365], `mp` to
// [0, 11]. Nothing here approaches `i64`'s range from any input whatsoever, which
// `civil_from_days_is_total_at_the_i64_extremes` pins at both ends.
#[allow(clippy::arithmetic_side_effects)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format Unix seconds (UTC) as the strict RFC 3339 form MCP-RE uses
/// (`YYYY-MM-DDTHH:MM:SSZ`) — the inverse of [`parse_rfc3339_utc`] for whole
/// seconds. Used by verifiers/servers to stamp `verified_at` / `issued_at` from
/// a caller-supplied `now_unix` (core never reads the system clock itself).
// `div_euclid`/`rem_euclid` by the non-zero constant 86_400 are total on `i64` (the one
// panicking division, `i64::MIN / -1`, needs a negative divisor), and they are what bounds
// [`civil_from_days`] — see its note. `secs` is in [0, 86399] by `rem_euclid`, so the three
// clock divisions below cannot overflow either.
#[allow(clippy::arithmetic_side_effects)]
pub fn unix_to_rfc3339_utc(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339_utc;
    use crate::error::McpReError;

    #[test]
    fn epoch_zero_parses_to_zero() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Ok(0));
    }

    /// The LOWEST instant the grammar admits, at its exact Unix second.
    ///
    /// RFC 3339 defines the era as 0000AD through 9999AD, and the four-digit year field
    /// admits `"0000"`, so this end is reachable rather than theoretical. It is the exact
    /// lower bound of the `parse_rfc3339_utc` postcondition, and pinning it here is what
    /// makes that bound a measured claim rather than a remembered one.
    #[test]
    fn boundary_lowest_admitted_instant() {
        assert_eq!(
            parse_rfc3339_utc("0000-01-01T00:00:00Z"),
            Ok(-62167219200),
            "0000-01-01T00:00:00Z is the era's first instant"
        );
    }

    /// The HIGHEST instant the grammar admits, at its exact Unix second.
    ///
    /// The four-digit year caps the era at 9999, and seconds stop at 59 because leap
    /// seconds are refused — so this is the maximum value the parser can return, and the
    /// exact upper bound of its postcondition.
    ///
    /// The bound used to be `253402387199`, one day higher, which denotes an instant in
    /// year 10000 that no accepted timestamp can produce. The postcondition was true but
    /// looser than the claim it carried; tightening it was MCPRE-129's disposition on
    /// THM-0002, and this control is what stops the slack returning unnoticed.
    #[test]
    fn boundary_highest_admitted_instant() {
        assert_eq!(
            parse_rfc3339_utc("9999-12-31T23:59:59Z"),
            Ok(253402300799),
            "9999-12-31T23:59:59Z is the last instant the four-digit grammar admits"
        );
    }

    /// A year outside the four-digit era is not admitted at all, so nothing above the
    /// bound is reachable by widening the year field.
    #[test]
    fn boundary_a_five_digit_year_is_refused() {
        assert!(parse_rfc3339_utc("10000-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn one_second_past_epoch() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:01Z"), Ok(1));
    }

    #[test]
    fn known_2026_epoch() {
        // 2026-05-28T20:00:00Z. Days from 1970-01-01 to 2026-05-28:
        //   1970..=2025 = 56 years; leap years in [1970, 2025] are
        //   1972,76,80,84,88,92,96,2000,04,08,12,16,20,24 = 14 leap years.
        //   => 56*365 + 14 = 20440 + 14 = 20454 days to 2026-01-01.
        //   2026 day-of-year for May 28 (2026 not leap):
        //   Jan31+Feb28+Mar31+Apr30 = 120, +28 -1 = 147 days into the year.
        //   total days = 20454 + 147 = 20601.
        //   seconds = 20601*86400 + 20*3600 = 1_779_926_400 + 72_000.
        let expected = 20_601i64 * 86_400 + 20 * 3_600;
        assert_eq!(parse_rfc3339_utc("2026-05-28T20:00:00Z"), Ok(expected));
        assert_eq!(expected, 1_779_998_400);
    }

    #[test]
    fn leap_day_2024_parses() {
        // 2024-02-29 exists (2024 is a leap year).
        assert!(parse_rfc3339_utc("2024-02-29T00:00:00Z").is_ok());
        // 2023-02-29 does NOT exist (2023 not a leap year).
        assert_eq!(
            parse_rfc3339_utc("2023-02-29T00:00:00Z"),
            Err(McpReError::ExpiredRequest)
        );
    }

    #[test]
    fn fractional_seconds_are_truncated() {
        let whole = parse_rfc3339_utc("2026-05-28T20:00:00Z").expect("whole parses");
        let frac = parse_rfc3339_utc("2026-05-28T20:00:00.999Z").expect("fraction parses");
        assert_eq!(whole, frac, "fractional seconds truncate, never round up");

        let frac_long =
            parse_rfc3339_utc("2026-05-28T20:00:00.123456789Z").expect("long fraction parses");
        assert_eq!(whole, frac_long);
    }

    #[test]
    fn fractional_dot_without_digits_is_rejected() {
        assert_eq!(
            parse_rfc3339_utc("2026-05-28T20:00:00.Z"),
            Err(McpReError::ExpiredRequest)
        );
    }

    #[test]
    fn out_of_range_month_rejected() {
        assert_eq!(
            parse_rfc3339_utc("2026-13-01T00:00:00Z"),
            Err(McpReError::ExpiredRequest)
        );
    }

    #[test]
    fn out_of_range_day_and_time_rejected() {
        assert_eq!(
            parse_rfc3339_utc("2026-04-31T00:00:00Z"),
            Err(McpReError::ExpiredRequest)
        );
        assert_eq!(
            parse_rfc3339_utc("2026-01-01T24:00:00Z"),
            Err(McpReError::ExpiredRequest)
        );
        assert_eq!(
            parse_rfc3339_utc("2026-01-01T00:60:00Z"),
            Err(McpReError::ExpiredRequest)
        );
        // Leap second (60) is rejected — Unix time cannot represent it.
        assert_eq!(
            parse_rfc3339_utc("2026-01-01T00:00:60Z"),
            Err(McpReError::ExpiredRequest)
        );
    }

    #[test]
    fn numeric_offset_rejected() {
        assert_eq!(
            parse_rfc3339_utc("2026-05-28T20:00:00+01:00"),
            Err(McpReError::ExpiredRequest)
        );
        assert_eq!(
            parse_rfc3339_utc("2026-05-28T20:00:00+00:00"),
            Err(McpReError::ExpiredRequest)
        );
        // Lowercase zone designator is not the strict 'Z'.
        assert_eq!(
            parse_rfc3339_utc("2026-05-28T20:00:00z"),
            Err(McpReError::ExpiredRequest)
        );
    }

    #[test]
    fn garbage_and_wrong_separators_rejected() {
        assert_eq!(parse_rfc3339_utc(""), Err(McpReError::ExpiredRequest));
        assert_eq!(
            parse_rfc3339_utc("not-a-date"),
            Err(McpReError::ExpiredRequest)
        );
        assert_eq!(
            parse_rfc3339_utc("2026-05-28 20:00:00Z"),
            Err(McpReError::ExpiredRequest)
        );
        assert_eq!(
            parse_rfc3339_utc("2026/05/28T20:00:00Z"),
            Err(McpReError::ExpiredRequest)
        );
        // Trailing junk after Z.
        assert_eq!(
            parse_rfc3339_utc("2026-05-28T20:00:00Zextra"),
            Err(McpReError::ExpiredRequest)
        );
        // Non-digit in a numeric field.
        assert_eq!(
            parse_rfc3339_utc("2026-0X-28T20:00:00Z"),
            Err(McpReError::ExpiredRequest)
        );
    }

    /// The formatting inverse is TOTAL on `i64`, including both extremes.
    ///
    /// `unix_to_rfc3339_utc` and `civil_from_days` are the two functions in this module
    /// that the Verus cone does not reach, and their arithmetic is justified by an
    /// argument about bounds rather than by a proof. This control is what makes that
    /// argument measured: the extremes are exactly where a bound argument fails, and a
    /// panic here would mean the reasoning in those two comments is wrong.
    ///
    /// It deliberately asserts nothing about the TEXT produced outside the era the
    /// grammar admits. Outside it, the year field exceeds four digits and
    /// `parse_rfc3339_utc` will not read the result back — the round trip is a property
    /// of the admitted range, which the boundary controls above pin.
    #[test]
    fn civil_from_days_is_total_at_the_i64_extremes() {
        for unix in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX] {
            let _ = super::unix_to_rfc3339_utc(unix);
        }
    }

    /// The round trip holds across the whole admitted era, at both of its ends.
    #[test]
    fn admitted_era_round_trips_through_the_formatter() {
        for (unix, text) in [
            (-62167219200, "0000-01-01T00:00:00Z"),
            (0, "1970-01-01T00:00:00Z"),
            (253402300799, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(super::unix_to_rfc3339_utc(unix), text);
            assert_eq!(parse_rfc3339_utc(text), Ok(unix));
        }
    }

    /// `parse_fixed_digits` refuses every width the parser does not use, rather than
    /// overflowing into one.
    ///
    /// The body is `external_body` to Verus, so the prover checks the CALLER against
    /// ASM-0001 and never looks inside. These are the checks that stand in its place: a
    /// start past the end, a width past the end, and a width wide enough that an
    /// unchecked accumulator would leave `i64`.
    #[test]
    fn fixed_digit_fields_are_total_outside_the_parser_widths() {
        let digits = b"12345678901234567890123456789012345";
        assert_eq!(super::parse_fixed_digits(digits, 100, 2), None);
        assert_eq!(super::parse_fixed_digits(digits, 30, 10), None);
        assert_eq!(super::parse_fixed_digits(digits, 0, 35), None);
        assert_eq!(super::parse_fixed_digits(digits, 0, 4), Some(1234));
        assert_eq!(super::parse_fixed_digits(b"00", 0, 2), Some(0));
        assert_eq!(super::parse_fixed_digits(b"1x", 0, 2), None);
    }
}
