//! RFC 3339 UTC timestamp parsing and freshness checking (MCP_RE_SPEC §5 / ADR-006,
//! and the `verify_request` order §9 step 9).
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

/// Days in each month for a common (non-leap) year, January-indexed at 0.
const DAYS_IN_MONTH: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Returns `true` if `year` is a Gregorian leap year.
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Parse exactly `n` ASCII digits at `bytes[start..start+n]` into an `i64`.
///
/// Returns `None` if any of the `n` bytes is missing or is not an ASCII digit.
fn parse_fixed_digits(bytes: &[u8], start: usize, n: usize) -> Option<i64> {
    if start + n > bytes.len() {
        return None;
    }
    let mut value: i64 = 0;
    for &b in &bytes[start..start + n] {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(b - b'0');
    }
    Some(value)
}

/// Convert a Gregorian `(year, month, day)` to days since the Unix epoch
/// (1970-01-01), using Howard Hinnant's `days_from_civil` algorithm.
///
/// `month` is 1..=12 and `day` is 1..=31; both are assumed already validated by
/// the caller. The algorithm is exact for all years and handles leap years and
/// the 400-year Gregorian cycle correctly.
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
    let tail = &bytes[19..];
    let fraction_ok = if tail == b"Z" {
        true
    } else if tail.first() == Some(&b'.') {
        // At least one fractional digit, then a trailing 'Z'.
        let frac = &tail[1..];
        match frac.split_last() {
            Some((&b'Z', digits)) if !digits.is_empty() => {
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
    let mut max_day = i64::from(DAYS_IN_MONTH[(month - 1) as usize]);
    if month == 2 && is_leap_year(year) {
        max_day = 29;
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

/// Check that `now_unix` falls inside the freshness window for a request
/// (MCP_RE_SPEC §5, §9 step 9).
///
/// With a symmetric `max_clock_skew_secs`, the valid window is
/// `[issued_at − skew, expires_at + skew]` (both bounds inclusive). The function
/// returns:
///
/// - [`McpReError::ExpiredRequest`] if either timestamp is malformed (delegated
///   to [`parse_rfc3339_utc`]'s fail-closed mapping),
/// - [`McpReError::ExpiredRequest`] if `expires_at < issued_at` (a nonsensical
///   window),
/// - [`McpReError::ExpiredRequest`] if `now_unix < issued_at − skew`
///   (future-dated beyond skew) or `now_unix > expires_at + skew` (stale),
/// - `Ok(())` otherwise.
///
/// `max_clock_skew_secs` is expected to be non-negative; a negative value simply
/// tightens the window (subtracting from `expires_at`, adding to `issued_at`),
/// which can only reject more, never admit more — still fail-closed.
pub fn check_freshness(
    issued_at: &str,
    expires_at: &str,
    now_unix: i64,
    max_clock_skew_secs: i64,
) -> Result<(), McpReError> {
    let issued = parse_rfc3339_utc(issued_at)?;
    let expires = parse_rfc3339_utc(expires_at)?;

    // A window whose end precedes its start is nonsensical -> fail closed.
    if expires < issued {
        return Err(McpReError::ExpiredRequest);
    }

    let lower = issued.saturating_sub(max_clock_skew_secs);
    let upper = expires.saturating_add(max_clock_skew_secs);

    if now_unix < lower || now_unix > upper {
        return Err(McpReError::ExpiredRequest);
    }
    Ok(())
}

/// Convert days-since-Unix-epoch to a Gregorian `(year, month, day)`, using
/// Howard Hinnant's `civil_from_days` — the exact inverse of [`days_from_civil`].
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
    use super::check_freshness;
    use super::parse_rfc3339_utc;
    use crate::error::McpReError;

    #[test]
    fn epoch_zero_parses_to_zero() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Ok(0));
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
        assert_eq!(parse_rfc3339_utc("not-a-date"), Err(McpReError::ExpiredRequest));
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

    // ---- freshness ----

    const ISSUED: &str = "2026-05-28T20:00:00Z"; // 1_779_998_400
    const EXPIRES: &str = "2026-05-28T20:05:00Z"; // +300s
    const ISSUED_EPOCH: i64 = 1_779_998_400;
    const EXPIRES_EPOCH: i64 = 1_779_998_400 + 300;

    #[test]
    fn now_inside_window_is_ok() {
        assert_eq!(
            check_freshness(ISSUED, EXPIRES, ISSUED_EPOCH + 150, 30),
            Ok(())
        );
    }

    #[test]
    fn now_at_exact_issued_and_expires_is_ok() {
        // Window is inclusive at both ends even with zero skew.
        assert_eq!(check_freshness(ISSUED, EXPIRES, ISSUED_EPOCH, 0), Ok(()));
        assert_eq!(check_freshness(ISSUED, EXPIRES, EXPIRES_EPOCH, 0), Ok(()));
    }

    #[test]
    fn now_past_expires_plus_skew_is_expired() {
        let skew = 30;
        // Exactly at expires + skew is inclusive -> Ok.
        assert_eq!(
            check_freshness(ISSUED, EXPIRES, EXPIRES_EPOCH + skew, skew),
            Ok(())
        );
        // One second beyond -> expired.
        assert_eq!(
            check_freshness(ISSUED, EXPIRES, EXPIRES_EPOCH + skew + 1, skew),
            Err(McpReError::ExpiredRequest)
        );
    }

    #[test]
    fn now_before_issued_minus_skew_is_expired() {
        let skew = 30;
        // Exactly at issued - skew is inclusive -> Ok.
        assert_eq!(
            check_freshness(ISSUED, EXPIRES, ISSUED_EPOCH - skew, skew),
            Ok(())
        );
        // One second before -> future-dated beyond skew -> expired.
        assert_eq!(
            check_freshness(ISSUED, EXPIRES, ISSUED_EPOCH - skew - 1, skew),
            Err(McpReError::ExpiredRequest)
        );
    }

    #[test]
    fn expires_before_issued_is_expired() {
        // Nonsensical window: expires precedes issued.
        assert_eq!(
            check_freshness(EXPIRES, ISSUED, ISSUED_EPOCH, 30),
            Err(McpReError::ExpiredRequest)
        );
    }

    #[test]
    fn malformed_timestamp_in_freshness_is_expired() {
        assert_eq!(
            check_freshness("garbage", EXPIRES, ISSUED_EPOCH, 30),
            Err(McpReError::ExpiredRequest)
        );
        assert_eq!(
            check_freshness(ISSUED, "garbage", ISSUED_EPOCH, 30),
            Err(McpReError::ExpiredRequest)
        );
    }
}
