// SPDX-License-Identifier: Apache-2.0
//! The FORMATTING inverse: Unix seconds back to the strict RFC 3339 UTC form.
//!
//! Separated from the parser because the two carry their totality differently, and the
//! difference matters to a reader. [`super::parse_rfc3339_utc`] is inside the Verus cone —
//! THM-0002 proves it total on arbitrary bytes, and the lane re-establishes that on every
//! change. Nothing here is. These two functions carry their bounds in Rust, as an argument
//! about the range their arguments can occupy, and the module's own controls pin that
//! argument at both `i64` extremes (`docs/dev/partial-operations.md`, class C).
//!
//! The inverse is exact only across the era the grammar admits. Outside it the year field
//! exceeds four digits and the parser will not read the result back — a property of the
//! admitted range, which the parser's boundary controls pin.

/// Convert days-since-Unix-epoch to a Gregorian `(year, month, day)`, using
/// Howard Hinnant's `civil_from_days` — the exact inverse of [`days_from_civil`].
// Class C, outside the Verus cone. The bound is the argument's provenance: the sole caller
// passes `unix.div_euclid(86_400)`, so `z` lies within +/-1.07e14 for EVERY `i64`, and each
// quantity after it is bounded by the one before — `era` to +/-7.3e8, `doe` to [0, 146096],
// `yoe` to [0, 399], `doy` to [0, 365], `mp` to [0, 11]. Pinned at both ends by
// `civil_from_days_is_total_at_the_i64_extremes`.
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
// Class C: `div_euclid`/`rem_euclid` by the non-zero constant 86_400 are total on `i64`
// (the one panicking division needs a negative divisor), and they are what bounds
// [`civil_from_days`]. `secs` is in [0, 86399], so the clock divisions are total too.
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
