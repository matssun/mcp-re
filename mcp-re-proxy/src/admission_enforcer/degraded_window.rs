// SPDX-License-Identifier: Apache-2.0
//! How long a replica may serve on last-known state while the authority is unreachable.
//!
//! One question, and the clock that answers it. Separate from the gate because the gate's
//! job is to decide ONE call against the authority's statement, while this decides whether
//! the deployment is still entitled to act without one — a fact about the replica's recent
//! history, not about any request.
//!
//! # What P has to bound, and what it must not
//!
//! R7-C093. The revocation channel IS the store, so during a store outage the assertion
//! issuer never learns of a revocation and keeps minting assertions with a current `iat`.
//! Bound the presented assertion's freshness and a caller that simply keeps fetching new
//! ones is served for the whole outage, however long, while the operator has been told
//! degraded serving is bounded by P. What makes that a true statement about the deployment
//! is bounding ELAPSED TIME SINCE THE LAST SUCCESSFUL READ, which nothing the caller does
//! can move.

use mcp_re_http_profile::AdmissionPolicy;

use std::sync::atomic::{AtomicI64, Ordering};

/// The last instant the authoritative source ANSWERED, and the rule over it.
#[derive(Debug)]
pub(super) struct DegradedWindow {
    /// Unix seconds, or `i64::MIN` for "never".
    last_read: AtomicI64,
}

impl DegradedWindow {
    /// A window nobody has earned yet.
    ///
    /// `i64::MIN` until the first successful read: a replica that has never reached the
    /// authority has no last-known state to serve on, so it fails closed rather than
    /// treating its own startup as a confirmation. There is deliberately no constructor
    /// taking an instant — one would let a caller hand a fresh replica a window it never
    /// earned, which is the whole property.
    pub(super) fn unearned() -> Self {
        DegradedWindow {
            last_read: AtomicI64::new(i64::MIN),
        }
    }

    /// Note that the authoritative source answered at `now`.
    ///
    /// A definitive negative counts: the authority ANSWERED, which is what P measures.
    /// `fetch_max` rather than `store`, so an out-of-order read cannot re-open a window a
    /// later one closed.
    pub(super) fn record_read(&self, now: i64) {
        self.last_read.fetch_max(now, Ordering::Relaxed);
    }

    /// Has the authority been unreachable for longer than P (+ skew)?
    ///
    /// True also when it has never been reachable, and whenever degraded mode is not
    /// enabled at all — in both cases there is no window to be inside of.
    pub(super) fn exhausted(&self, policy: &AdmissionPolicy, now: i64) -> bool {
        if !policy.allow_degraded_mode {
            return true;
        }
        let last = self.last_read.load(Ordering::Relaxed);
        if last == i64::MIN {
            return true;
        }
        now.saturating_sub(last)
            > policy
                .degraded_propagation_bound
                .saturating_add(policy.max_clock_skew)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(bound: i64, skew: i64, allow_degraded: bool) -> AdmissionPolicy {
        AdmissionPolicy {
            max_assertion_age: 300,
            max_clock_skew: skew,
            degraded_propagation_bound: bound,
            allow_degraded_mode: allow_degraded,
        }
    }

    /// A replica that has never reached the authority has no last-known state to serve on,
    /// so startup is not a confirmation.
    #[test]
    fn a_replica_that_never_reached_the_authority_has_no_window() {
        assert!(DegradedWindow::unearned().exhausted(&policy(60, 5, true), 1_000));
    }

    /// R7-C093: the degraded window is elapsed OUTAGE time, not assertion freshness.
    /// Nothing the caller can do moves this clock.
    #[test]
    fn the_degraded_window_closes_p_after_the_last_successful_read() {
        let window = DegradedWindow::unearned();
        window.record_read(1_000);
        let p = policy(60, 5, true);

        assert!(
            !window.exhausted(&p, 1_060),
            "inside P + skew the last-known state is still usable"
        );
        assert!(
            !window.exhausted(&p, 1_065),
            "the skew allowance is on the same clock"
        );
        assert!(
            window.exhausted(&p, 1_066),
            "past P + skew an unreachable authority fails closed, however fresh the \
             assertion the caller presents"
        );
    }

    /// The clock only moves forward: a stale read cannot re-open a window a later one
    /// closed.
    #[test]
    fn an_out_of_order_read_does_not_rewind_the_window() {
        let window = DegradedWindow::unearned();
        window.record_read(2_000);
        window.record_read(1_000);
        assert!(!window.exhausted(&policy(60, 0, true), 2_050));
    }

    /// Degraded mode is opt-in; without it an unreachable authority fails closed at once,
    /// whatever was last read.
    #[test]
    fn without_the_opt_in_there_is_no_window_at_all() {
        let window = DegradedWindow::unearned();
        window.record_read(1_000);
        assert!(window.exhausted(&policy(3_600, 30, false), 1_001));
    }
}
