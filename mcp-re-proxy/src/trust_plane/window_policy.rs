// SPDX-License-Identifier: Apache-2.0
//! WHICH trust-propagation window a deployment may use (ADR-MCPS-021).
//!
//! Separate from the cache that HONOURS a window. `trust_cache` implements *cached active
//! trust expires after `T`*; this module owns the two rules ADR-MCPS-021 states ABOUT `T`:
//! that a window longer than five minutes is a long revocation exposure and should be
//! flagged, and that a request must use the strictest applicable one.
//!
//! # One rule is wired; the other has no input
//!
//! * [`t_exceeds_recommended_max`] backs [`long_window_advisory`], which the startup path
//!   appends to the tier's `startup_audit_line`, so a window past the recommended maximum
//!   is flagged on the same line that states the window. The window is only flagged, never
//!   capped.
//! * [`strictest_applicable_t`] has **no input**, and after ADR-MCPRE-067 Phase 6 the type
//!   system says so: [`ApplicableClassWindows`] has one production constructor and it is
//!   empty, so the rule is the identity BY TYPE. Two things would have to arrive before it
//!   is wired — a producer that classifies a request into sensitivity classes, and a
//!   deployment input that states a window per class. Adding the second alone would be
//!   fabricating configuration to activate dormant code.
//!
//! It is retained rather than deleted: it is an ADR-MCPS-021 behaviour that was never
//! connected, not a value that stopped being needed. Deleting it would erase the only
//! record in the tree that the requirement exists, and a zero-caller count is evidence
//! about the WIRING, not about the rule.

/// The maximum recommended trust-propagation window (seconds). ADR-MCPS-021 warns
/// when a configured `T` exceeds 5 minutes (a long revocation exposure window);
/// strict/production mode MAY cap `T` at this value unless explicitly overridden.
///
/// [`long_window_advisory`] appends the advisory to the tier's startup line; the window is
/// flagged, not capped.
pub(super) const RECOMMENDED_MAX_T_SECS: i64 = 300;

/// Whether a configured `T` exceeds the recommended maximum (→ the proxy warns;
/// strict mode MAY cap). A non-positive `T` (live-check / no caching) never warns.
pub(super) fn t_exceeds_recommended_max(t_secs: i64) -> bool {
    t_secs > RECOMMENDED_MAX_T_SECS
}

/// The startup-line qualifier for a tier whose window exceeds the recommended maximum, with
/// a leading space so it appends to the tier line. `Live` has no window and never warns.
pub(super) fn long_window_advisory(tier: &crate::RevocationTier) -> Option<String> {
    let t_secs = match tier {
        crate::RevocationTier::Live => return None,
        crate::RevocationTier::BoundedCache { t_secs } | crate::RevocationTier::Push { t_secs } => {
            *t_secs
        }
    };
    t_exceeds_recommended_max(t_secs).then(|| {
        format!(
            " window-advisory=\"T {t_secs}s exceeds the ADR-MCPS-021 recommended maximum {RECOMMENDED_MAX_T_SECS}s: a long revocation exposure window\""
        )
    })
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
/// **NOT WIRED.** The window advisory is wired; this is a capability with no INPUT. What it is missing is named by
/// [`ApplicableClassWindows`], which production can only construct empty — so this function
/// is the identity in production BY TYPE rather than by a comment saying so.
#[allow(dead_code)]
pub(super) fn strictest_applicable_t(
    default_t_secs: i64,
    applicable: &ApplicableClassWindows,
) -> i64 {
    applicable
        .windows()
        .iter()
        .copied()
        .filter(|t| *t >= 0)
        .fold(default_t_secs.max(0), |acc, t| acc.min(t))
}

/// The per-sensitivity-class windows that apply to ONE request.
///
/// **This type has no production producer, and that absence is its content.**
/// ADR-MCPS-021 requires a request to use the strictest applicable `T`, and the windows
/// that would make one applicable do not exist anywhere in this tree: nothing classifies a
/// request into a sensitivity class — not the authorization layer, which decides scopes and
/// actions and never a propagation window — and no deployment input names a per-class one.
///
/// It is a type rather than a `&[i64]` parameter for exactly that reason. A slice is a
/// shape any caller can invent, so the old signature read as though the input existed and
/// merely happened to be empty; [`Self::none_apply`] is the only inhabitant production can
/// build, so the compiler now records WHICH input is missing.
///
/// **What would have to arrive before this is wired**, and it is two things rather than one:
/// a producer that classifies a request into sensitivity classes, and a deployment surface
/// that states a window per class. Adding the second alone — a map from an invented class
/// name to a number — would be fabricating configuration to activate dormant code, which
/// is what this type exists to prevent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ApplicableClassWindows {
    /// Empty under every production path.
    windows: Vec<i64>,
}

impl ApplicableClassWindows {
    /// No class window applies — the only value production can name today.
    #[allow(dead_code)]
    pub(super) fn none_apply() -> Self {
        ApplicableClassWindows::default()
    }

    /// The windows, for the selector above.
    fn windows(&self) -> &[i64] {
        &self.windows
    }

    /// A set of applicable windows, for the tests that pin the selection rule.
    ///
    /// `#[cfg(test)]`, so it compiles to nothing in production: the rule stays testable
    /// without giving production a way to state an input it has no producer for.
    #[cfg(test)]
    fn applying(windows: &[i64]) -> Self {
        ApplicableClassWindows {
            windows: windows.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strictest_applicable_t_picks_the_tightest_window() {
        let applying = ApplicableClassWindows::applying;
        // A stricter class window wins (smaller = tighter exposure).
        assert_eq!(strictest_applicable_t(60, &applying(&[10])), 10);
        // The strictest of several applicable classes wins.
        assert_eq!(strictest_applicable_t(60, &applying(&[30, 5, 45])), 5);
        // A looser class window never widens past the default.
        assert_eq!(strictest_applicable_t(60, &applying(&[120])), 60);
        // Negative (malformed) class windows are ignored, not treated as 0.
        assert_eq!(strictest_applicable_t(60, &applying(&[-1, 20])), 20);
    }

    /// The production input, and the whole of it: no class window applies, so the rule is
    /// the identity. This is the honest statement of the missing capability — not that the
    /// rule is wrong, but that nothing can yet give it something to be strict about.
    #[test]
    fn the_only_input_production_can_build_makes_the_rule_the_identity() {
        let production = ApplicableClassWindows::none_apply();
        assert_eq!(production, ApplicableClassWindows::applying(&[]));
        for default_t in [0, 30, 60, 3600] {
            assert_eq!(strictest_applicable_t(default_t, &production), default_t);
        }
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

    #[test]
    fn long_window_advisory_flags_a_window_past_the_recommended_maximum() {
        use crate::RevocationTier::{BoundedCache, Live, Push};
        assert_eq!(
            long_window_advisory(&BoundedCache {
                t_secs: RECOMMENDED_MAX_T_SECS
            }),
            None
        );
        let long = long_window_advisory(&BoundedCache { t_secs: 86400 }).expect("flagged");
        assert!(long.contains("86400s") && long.contains("300s"));
        assert!(long_window_advisory(&Push {
            t_secs: RECOMMENDED_MAX_T_SECS + 1
        })
        .is_some());
        assert_eq!(long_window_advisory(&Live), None);
    }
}
