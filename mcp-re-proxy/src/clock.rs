// SPDX-License-Identifier: Apache-2.0
//! Wall-clock acquisition for the proxy — the one place the OS clock enters.
//!
//! Reading the host clock is an authority, not a composition step: the value it
//! returns is trusted, and no proof in this codebase covers whether it is right. It
//! therefore has an owner of its own rather than living beside the code that wires the
//! runtime together, so that the modules needing the current time depend on a clock
//! rather than on a composition root.
//!
//! This module is named by `boundary.clock` in
//! `verification/policy/trust-boundaries.toml`. Keeping it small is the point: the
//! declared boundary is exactly as wide as the code that exercises the authority.
//!
//! Time is read here and passed DOWN as a value. Callers that receive a `now: i64`
//! parameter are consumers, not acquirers, and must not reach back here to re-read it
//! mid-decision — two readings inside one decision are two different instants.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// The current time as whole Unix seconds (UTC).
///
/// A clock reading before the Unix epoch is clamped to `0` rather than reported as an
/// error, and that clamp is load-bearing in two opposite directions:
///
/// * For per-request freshness the clamp fails CLOSED. Every signature then fails its
///   freshness check instead of a stale one being admitted.
/// * For a boot-time refusal it does NOT. A comparison against a clock reading zero
///   declares every client CRL fresh, which is why
///   [`crate::startup_plan::host_clock_is_faulted`] treats `0` as the sentinel for a
///   broken host clock and startup refuses rather than warns when the reading is the
///   reference time for such a check.
///
/// A caller that needs one instant across several comparisons reads once and passes the
/// value, rather than calling this repeatedly.
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whole seconds since the epoch at 2020-01-01T00:00:00Z. Any host this test runs
    /// on reads later than that, so a reading below it means the conversion is wrong
    /// rather than that the clock is merely skewed.
    const YEAR_2020: i64 = 1_577_836_800;

    #[test]
    fn reads_a_plausible_present_instant() {
        assert!(
            now_unix() > YEAR_2020,
            "expected a post-2020 reading, got {}",
            now_unix()
        );
    }

    #[test]
    fn does_not_run_backwards_between_reads() {
        let first = now_unix();
        let second = now_unix();
        assert!(second >= first, "{second} preceded {first}");
    }

    #[test]
    fn a_sane_host_clock_is_not_diagnosed_as_faulted() {
        // The clamp contract, from the consuming side: `host_clock_is_faulted` exists to
        // catch the `0` this function produces for a pre-epoch error, so a working host
        // must not trip it — otherwise startup would refuse on every boot.
        assert!(!crate::startup_plan::host_clock_is_faulted(now_unix()));
    }
}
