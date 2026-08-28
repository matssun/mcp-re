// SPDX-License-Identifier: Apache-2.0
//! WHICH trust-propagation window a deployment may use (ADR-MCPS-021).
//!
//! Separate from the cache that HONOURS a window. `trust_cache` implements *cached active
//! trust expires after `T`*; this module owns the two rules ADR-MCPS-021 states ABOUT `T`:
//! that a window longer than five minutes is a long revocation exposure and should be
//! flagged, and that a request must use the strictest applicable one.
//!
//! # Neither rule is wired, and they are unwired for different reasons
//!
//! This is the honest state of the module and it is written here rather than discovered by
//! the next reader:
//!
//! * [`t_exceeds_recommended_max`] has **no caller**. The advisory exists and nothing
//!   consults it, so no deployment is warned about a long window. What the operator IS told
//!   is the actual window, on the tier's `startup_audit_line`; what is missing is the
//!   annotation that it is longer than recommended.
//! * [`strictest_applicable_t`] has **no input**. The deployment surface carries no
//!   per-sensitivity-class window, so `class_windows` is always empty and the function
//!   would be the identity.
//!
//! Both are retained rather than deleted, and deliberately so: they are ADR-MCPS-021
//! behaviours that were never connected, not values that stopped being needed. Deleting
//! them would erase the only record in the tree that the requirements exist, and a
//! zero-caller count is evidence about the WIRING, not about the rule.

/// The maximum recommended trust-propagation window (seconds). ADR-MCPS-021 warns
/// when a configured `T` exceeds 5 minutes (a long revocation exposure window);
/// strict/production mode MAY cap `T` at this value unless explicitly overridden.
///
/// **NOT WIRED.** Nothing on the startup path consults it, so no deployment is warned
/// about a long window today. Retained deliberately rather than deleted: this is an
/// ADR-MCPS-021 behaviour that has never been connected, not a value that stopped being
/// needed, and deleting it would erase the only record that the advisory exists. What the
/// operator IS told is the actual window, on the tier's `startup_audit_line`; what is
/// missing is the annotation that the window is longer than recommended.
#[allow(dead_code)]
pub(super) const RECOMMENDED_MAX_T_SECS: i64 = 300;

/// Whether a configured `T` exceeds the recommended maximum (→ the proxy warns;
/// strict mode MAY cap). A non-positive `T` (live-check / no caching) never warns.
///
/// **NOT WIRED** — see [`RECOMMENDED_MAX_T_SECS`]. Its own tests pin the predicate; what
/// no test can pin is a caller that does not exist.
#[allow(dead_code)]
pub(super) fn t_exceeds_recommended_max(t_secs: i64) -> bool {
    t_secs > RECOMMENDED_MAX_T_SECS
}

/// Select the **strictest applicable** trust-propagation window (ADR-MCPS-021:
/// "a request MUST use the strictest applicable `T`").
///
/// Starts from the global `default_t_secs` and takes the minimum over any stricter
/// per-sensitivity-class windows that apply to the request (admin, financial
/// mutation, production infra, high-risk tools). Negative class windows are
/// ignored (malformed config never widens the window); the default is clamped to
/// non-negative. The result is the smallest — i.e. the tightest revocation
/// exposure — of the applicable windows.
///
/// **NOT WIRED, and for a different reason from the two above.** Those are an advisory with
/// no caller; this is a capability with no INPUT — the deployment surface has no
/// per-sensitivity-class window to pass, so `class_windows` is always empty and the
/// function would be the identity. Retained because the ADR-MCPS-021 requirement it
/// implements ("a request MUST use the strictest applicable `T`") is real and unchanged;
/// what is absent is the configuration that would give it something to be strict about.
#[allow(dead_code)]
pub(super) fn strictest_applicable_t(default_t_secs: i64, class_windows: &[i64]) -> i64 {
    class_windows
        .iter()
        .copied()
        .filter(|t| *t >= 0)
        .fold(default_t_secs.max(0), |acc, t| acc.min(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strictest_applicable_t_picks_the_tightest_window() {
        // No class overrides → the global default.
        assert_eq!(strictest_applicable_t(60, &[]), 60);
        // A stricter class window wins (smaller = tighter exposure).
        assert_eq!(strictest_applicable_t(60, &[10]), 10);
        // The strictest of several applicable classes wins.
        assert_eq!(strictest_applicable_t(60, &[30, 5, 45]), 5);
        // A looser class window never widens past the default.
        assert_eq!(strictest_applicable_t(60, &[120]), 60);
        // Negative (malformed) class windows are ignored, not treated as 0.
        assert_eq!(strictest_applicable_t(60, &[-1, 20]), 20);
    }

    #[test]
    fn t_exceeds_recommended_max_flags_long_windows() {
        assert!(!t_exceeds_recommended_max(RECOMMENDED_MAX_T_SECS));
        assert!(t_exceeds_recommended_max(RECOMMENDED_MAX_T_SECS + 1));
        assert!(!t_exceeds_recommended_max(0), "no caching never warns");
        assert!(!t_exceeds_recommended_max(
            super::super::trust_cache::DEFAULT_T_SECS
        ));
    }
}
