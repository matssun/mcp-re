// SPDX-License-Identifier: Apache-2.0
//! The deployment's accepted temporal uncertainty, as one owned fact.
//!
//! `--max-clock-skew` is not an operational parameter: two independent security mechanisms
//! are defined in terms of it, and they must agree.
//!
//! ```text
//!                     one resolved skew
//!                            |
//!                 +----------+----------+
//!                 v                     v
//!     RFC 9421 acceptance         replay retention
//!     (created/expires window)    (retain_until horizon)
//! ```
//!
//! Before this owner both consumers read the raw `i64` out of the request — the verifier
//! policy in the composition root, the replay tier through two more hops — so nothing made
//! them agree except that they happened to read the same field. The residue guard that
//! bounds the value said so in its own refusal text: *"it is the tolerance applied to every
//! verified request AND the replay retain_until"*. A rule that has to name two consumers is
//! describing a fact with no owner.
//!
//! **One stored value, two derived projections.** The retention horizon is not a second
//! field that happens to be equal today; it is computed from the same skew, so the two
//! cannot drift apart by editing one of them.
//!
//! The invariant worth stating is the RELATION, not the equality:
//!
//! > The replay retention horizon is never shorter than the window within which the
//! > verifier may still accept the request it stands for.
//!
//! Today the two coincide exactly. That is this deployment's policy, not the security
//! requirement: a later `retention = window + propagation_margin` would keep the invariant
//! while breaking the equality, which is why the test pins `>=` and records that equality
//! is the current policy rather than the claim.

use crate::deployment_request::DeploymentRequest;

/// The accepted temporal uncertainty, and what each mechanism derives from it.
///
/// The representation is private to this module and [`classify_and_validate`] is the only
/// producer, so possessing one IS the statement that the skew is within the §5.1 bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessWindow {
    max_clock_skew_secs: i64,
}

impl FreshnessWindow {
    /// The only public constructor, and it performs the check.
    ///
    /// `None` outside the §5.1 bound: construction itself validates, so possessing a
    /// `FreshnessWindow` means the skew was bounded no matter which crate built it. That is
    /// what lets this be public without weakening the seal — an embedding binary or an
    /// integration test gets the same guarantee the classifier gets, rather than a way
    /// around it.
    pub fn new(max_clock_skew_secs: i64) -> Option<Self> {
        (0..=mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND)
            .contains(&max_clock_skew_secs)
            .then_some(Self {
                max_clock_skew_secs,
            })
    }

    /// The skew the RFC 9421 verifier applies to `created` and `expires` (§5.1).
    pub fn verifier_skew_secs(&self) -> i64 {
        self.max_clock_skew_secs
    }

    /// How long a replay record for a request expiring at `expires_at_unix` must be kept.
    ///
    /// Derived, never stored: the horizon exists so that a nonce cannot be replayed while
    /// the verifier would still accept the request carrying it, which is a statement about
    /// the verifier's window and therefore about the same skew.
    pub fn replay_retain_until(&self, expires_at_unix: i64) -> i64 {
        expires_at_unix.saturating_add(self.max_clock_skew_secs)
    }

    /// The last instant the verifier may still accept a request that expires at
    /// `expires_at_unix`.
    ///
    /// The upper edge of the acceptance window, named so the relation between the two
    /// projections is assertable rather than implied by both calling `saturating_add`.
    pub fn verifier_accepts_until(&self, expires_at_unix: i64) -> i64 {
        expires_at_unix.saturating_add(self.max_clock_skew_secs)
    }
}

/// Bound the skew and resolve the fact.
///
/// The guard moved here from the validation residue: the residue is where rules with no
/// owner live, and this one now has one. Outside the §5.1 bound there is no coherent
/// window, so the value gates construction rather than being reported beside a usable one.
pub fn classify_and_validate(config: &DeploymentRequest) -> (Option<FreshnessWindow>, Vec<String>) {
    let Some(window) = FreshnessWindow::new(config.max_clock_skew) else {
        return (
            None,
            vec![format!(
                "--max-clock-skew must be 0..={} seconds (§5.1 bounded skew), got {}: it is the \
                 tolerance applied to every verified request AND the replay retain_until, so \
                 outside this range the freshness gate stops bounding anything",
                mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND,
                config.max_clock_skew
            )],
        );
    };
    (Some(window), Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(secs: i64) -> Option<FreshnessWindow> {
        let mut config = crate::config_state::test_support::legal_config();
        config.max_clock_skew = secs;
        classify_and_validate(&config).0
    }

    /// THE invariant, stated as the relation rather than as today's equality.
    ///
    /// A replay record that expires before the verifier stops accepting the request it
    /// stands for leaves a window in which the nonce is forgotten and the request is still
    /// admissible — which is the replay hole the horizon exists to close. Equality is the
    /// current policy; `>=` is the requirement, and a later
    /// `retention = window + propagation_margin` must keep this passing.
    #[test]
    fn retention_never_ends_before_the_verifier_stops_accepting() {
        let w = window(300).expect("a bounded skew resolves");
        for expires in [0_i64, 1, 1_000, 1_787_000_000, i64::MAX - 1] {
            assert!(
                w.replay_retain_until(expires) >= w.verifier_accepts_until(expires),
                "retention {} < acceptance {} at expires={expires}",
                w.replay_retain_until(expires),
                w.verifier_accepts_until(expires)
            );
        }
    }

    /// Both projections come from one stored value, so they cannot be edited apart.
    #[test]
    fn the_two_projections_are_derived_from_the_same_skew() {
        let w = window(45).expect("a bounded skew resolves");
        assert_eq!(w.verifier_skew_secs(), 45);
        assert_eq!(w.replay_retain_until(1_000), 1_045);
        assert_eq!(w.verifier_accepts_until(1_000), 1_045);
    }

    /// The horizon saturates rather than wrapping: a wrapped horizon is a retain_until in
    /// the past, which forgets the nonce immediately.
    #[test]
    fn an_overflowing_expiry_saturates_rather_than_wrapping() {
        let w = window(300).expect("a bounded skew resolves");
        assert_eq!(w.replay_retain_until(i64::MAX), i64::MAX);
    }

    /// The public constructor carries the same guard, so no crate can build an unbounded
    /// window by going around the classifier.
    #[test]
    fn the_public_constructor_validates_too() {
        assert!(FreshnessWindow::new(-1).is_none());
        assert!(FreshnessWindow::new(
            mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND + 1
        )
        .is_none());
        assert_eq!(
            FreshnessWindow::new(30)
                .expect("30s is bounded")
                .verifier_skew_secs(),
            30
        );
    }

    /// Outside §5.1 there is no window, so none is constructed.
    #[test]
    fn a_skew_outside_the_bound_resolves_no_window() {
        assert!(window(-1).is_none(), "a negative skew bounds nothing");
        assert!(
            window(mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND + 1).is_none(),
            "past the ceiling the freshness gate stops bounding anything"
        );
        assert!(
            window(0).is_some(),
            "zero skew is the strictest legal window"
        );
    }
}
