// SPDX-License-Identifier: Apache-2.0
//! How long a replica may serve on last-known state while the authority is unreachable.
//!
//! One question, and the clock that answers it. Separate from the gate because the gate's
//! job is to decide ONE call against the authority's statement, while this decides whether
//! the deployment is still entitled to act without one — a fact about the replica's recent
//! history, not about any request.
//!
//! # One window per replica, deliberately
//!
//! The window is replica-wide: ANY answer from the authority, for any workload, restarts it.
//! That is the declared P bound, and it is a choice. A replica whose store is reachable for
//! some workloads and not for another keeps its window open for the unreachable one. A
//! per-workload timer is the alternative that would be wrong: it would give every workload
//! this replica has not yet seen a fresh window to start in during one outage, so the time the
//! deployment may act without confirmation would grow with the number of distinct workloads
//! that arrive, not with how long the authority has been unreachable.
//!
//! What can refresh it is bounded the other way: only a lookup issued for a request whose
//! assertion was authenticated against the configured authority and the verifier-resolved
//! presenter. A caller who has proved nothing cannot hold the window open by sending requests
//! that cause reads.
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
//!
//! # Why the clock is MONOTONIC and not the wall clock
//!
//! "How long has the authority been unreachable" is elapsed time. It is not comparable to
//! any peer's clock and nothing about it needs wall time — so it is measured on
//! [`std::time::Instant`], which is immune to a step in either direction.
//!
//! Over unix seconds it was not. The reading was kept with a `fetch_max`, which is right for
//! CONCURRENCY — two in-flight reads completing out of order must not let the earlier one
//! re-open a window the later closed — and has no defence against a clock fault: an NTP step
//! or a VM jump FORWARD writes a future instant, the max then refuses every later corrected
//! reading, and the deployment serves degraded for the whole length of the excursion while
//! the operator has been told P bounds it. A monotonic reading makes the ratchet, the
//! excursion and the reordering ambiguity stop existing rather than be adjudicated: a later
//! reading is later because time passed.
//!
//! The wall clock stays where a peer's clock matters — the assertion-freshness and
//! record-currentness comparisons inside `check_admission`, which are about agreement with
//! another party and cannot be monotonic.

use mcp_re_http_profile::AdmissionPolicy;

use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

/// The last instant the authoritative source ANSWERED, and the rule over it.
#[derive(Debug)]
pub(super) struct DegradedWindow {
    /// `None` until the authority has answered once. A `Mutex` rather than an atomic
    /// because `Instant` is not one; the critical section is a compare-and-store over a
    /// `Copy` value and runs once per authoritative READ, never per admission decision and
    /// never while anything is awaited.
    ///
    /// Poison is recovered rather than propagated, for the reason the neighbouring admission
    /// source states: a panic elsewhere must not convert every later admission into a
    /// refusal for the process lifetime. Nothing behind this lock admits anybody — it holds
    /// one `Instant`, and the fail-closed decision is taken from what the guard holds either
    /// way.
    last_read: Mutex<Option<Instant>>,
}

impl DegradedWindow {
    /// A window nobody has earned yet.
    ///
    /// `None` until the first successful read: a replica that has never reached the
    /// authority has no last-known state to serve on, so it fails closed rather than
    /// treating its own startup as a confirmation. There is deliberately no constructor
    /// taking an instant — one would let a caller hand a fresh replica a window it never
    /// earned, which is the whole property.
    pub(super) fn unearned() -> Self {
        DegradedWindow {
            last_read: Mutex::new(None),
        }
    }

    /// Note that the authoritative source answered at `at`.
    ///
    /// A definitive negative counts: the authority ANSWERED, which is what P measures.
    /// The stored reading only moves FORWARD, so two reads completing out of order cannot
    /// let the earlier one re-open a window the later one closed — the same property
    /// `fetch_max` gave, now over a clock that cannot step.
    pub(super) fn record_read(&self, at: Instant) {
        let mut last = self
            .last_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_none_or(|previous| at > previous) {
            *last = Some(at);
        }
    }

    /// Has the authority been unreachable for longer than P?
    ///
    /// True also when it has never been reachable, and whenever degraded mode is not
    /// enabled at all — in both cases there is no window to be inside of.
    ///
    /// Judged at the instant of the decision, read here, so no caller can judge the window
    /// against an earlier reading.
    pub(super) fn exhausted(&self, policy: &AdmissionPolicy) -> bool {
        self.exhausted_at(policy, Instant::now())
    }

    fn exhausted_at(&self, policy: &AdmissionPolicy, now: Instant) -> bool {
        if !policy.allow_degraded_mode {
            return true;
        }
        let Some(last) = *self
            .last_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        else {
            // Never reached: no last-known state to serve on, and this arm is the only
            // thing that says so. Typing the reading as `Option<Instant>` leaves no sentinel
            // instant for the comparison below to mistake for a window, hence the `let-else`.
            return true;
        };
        let Some(window) = window_of(policy) else {
            // A bound that is not positive is no window at all, at every elapsed time.
            return true;
        };
        now.saturating_duration_since(last) > window
    }
}

/// P, as a duration.
///
/// # `max_clock_skew` is NOT added, and on this clock it must not be
///
/// A skew allowance exists because two parties' WALL clocks disagree, and the amount they
/// may disagree by is what it names. This measurement is one machine's own elapsed time
/// between two of its own readings: there is no second party, so there is nothing to
/// tolerate. Adding it made the true bound `P + skew` while the operator was told degraded
/// serving is bounded by P — wider than advertised, in the direction that serves longer.
/// The window is now exactly what `--admission-degraded-bound-secs` says.
///
/// `max_clock_skew` keeps its whole meaning where a peer's clock is actually involved: the
/// assertion-freshness and record-currentness comparisons inside `check_admission`.
///
/// The policy carries seconds as `i64` because that is the wire vocabulary. A non-positive
/// bound is `None`, no window at all rather than an enormous or a zero-length one, so a
/// nonsense configuration cannot widen anything, no arithmetic wraps, and no elapsed time —
/// zero included — is inside it.
fn window_of(policy: &AdmissionPolicy) -> Option<Duration> {
    u64::try_from(policy.degraded_propagation_bound)
        .ok()
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
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

    /// One base, and every reading derived from it — so the controls state a DURATION and
    /// nothing has to inject a clock.
    fn base() -> Instant {
        Instant::now()
    }

    fn after(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    /// A replica that has never reached the authority has no last-known state to serve on,
    /// so startup is not a confirmation.
    #[test]
    fn a_replica_that_never_reached_the_authority_has_no_window() {
        assert!(DegradedWindow::unearned().exhausted_at(&policy(60, 5, true), base()));
    }

    /// A bound that is not positive is no window: not even at the instant of the last read.
    #[test]
    fn a_non_positive_bound_is_no_window_even_at_zero_elapsed_time() {
        let t0 = base();
        let window = DegradedWindow::unearned();
        window.record_read(t0);
        for bound in [0, -1, i64::MIN] {
            assert!(
                window.exhausted_at(&policy(bound, 5, true), t0),
                "a bound of {bound} must leave no window open at zero elapsed time"
            );
        }
    }

    /// An unbounded window does not entitle a replica that never earned one.
    ///
    /// `--admission-degraded-bound-secs` takes any positive `i64`, `i64::MAX` included, so
    /// this configuration is reachable from the command line. It is the corner where a
    /// never-read replica is most at risk of reading as INSIDE its window: the bound is
    /// larger than any elapsed measurement can be.
    ///
    /// The `Option<Instant>` is what makes the answer structural — there is no sentinel that
    /// arithmetic could carry into the comparison — so this control is a regression guard on
    /// the configuration rather than the evidence for a deletable check. The check is not
    /// deletable: removing the `let-else` does not compile.
    #[test]
    fn an_unbounded_window_does_not_make_an_unearned_one_open() {
        assert!(
            DegradedWindow::unearned().exhausted_at(&policy(i64::MAX, 60, true), base()),
            "no bound, however large, entitles a replica that never reached the authority"
        );
    }

    /// R7-C093: the degraded window is elapsed OUTAGE time, not assertion freshness.
    /// Nothing the caller can do moves this clock.
    #[test]
    fn the_degraded_window_closes_exactly_p_after_the_last_successful_read() {
        let t0 = base();
        let window = DegradedWindow::unearned();
        window.record_read(t0);
        let p = policy(60, 5, true);

        assert!(
            !window.exhausted_at(&p, after(t0, 60)),
            "at exactly P the last-known state is still usable"
        );
        assert!(
            window.exhausted_at(&p, after(t0, 61)),
            "past P an unreachable authority fails closed, however fresh the \
             assertion the caller presents"
        );
    }

    /// The reading only moves forward: a stale read cannot re-open a window a later one
    /// closed.
    ///
    /// The same proposition the wall-clock form held, and the same fixture shape — what
    /// changes is that "later" is now a fact about elapsed time rather than about two
    /// numbers a clock step could invert.
    #[test]
    fn an_out_of_order_read_does_not_rewind_the_window() {
        let t0 = base();
        let window = DegradedWindow::unearned();
        window.record_read(after(t0, 1_000));
        window.record_read(t0);
        assert!(!window.exhausted_at(&policy(60, 0, true), after(t0, 1_050)));
    }

    /// A clock STEP moves nothing, which is the whole reason for the monotonic reading.
    ///
    /// The wall-clock form kept the maximum unix second it had seen. A forward NTP step or
    /// a VM jump wrote a future instant, and every later corrected reading was then refused
    /// — so the elapsed measurement stayed small for the whole excursion and the window
    /// never closed. There is no value here a step can write: the policy's wall-clock
    /// fields are read, and the reading they are compared against is not.
    #[test]
    fn a_wall_clock_excursion_cannot_widen_the_window() {
        let t0 = base();
        let window = DegradedWindow::unearned();
        window.record_read(t0);
        // A policy whose skew allowance is enormous — the wall-clock vocabulary at its most
        // permissive — still does not make the elapsed measurement anything but elapsed.
        let p = policy(60, 5, true);
        assert!(window.exhausted_at(&p, after(t0, 61)));
        assert!(
            window.exhausted_at(&p, after(t0, 86_400)),
            "a day of outage is a day of outage whatever the wall clock did"
        );
    }

    /// The skew allowance does not widen this window, and could not mean anything if it did.
    ///
    /// Skew names how far two parties' WALL clocks may disagree. This is one machine's own
    /// elapsed time between two of its own readings, so there is no second party to tolerate
    /// — and adding the allowance made the true bound `P + skew` while the operator was told
    /// P. An enormous skew must therefore change nothing here.
    #[test]
    fn the_skew_allowance_does_not_widen_the_outage_window() {
        let t0 = base();
        let window = DegradedWindow::unearned();
        window.record_read(t0);
        assert!(
            window.exhausted_at(&policy(60, 86_400, true), after(t0, 61)),
            "a day of skew tolerance must not buy a second of degraded serving"
        );
        assert_eq!(
            window_of(&policy(60, 86_400, true)),
            window_of(&policy(60, 0, true))
        );
    }

    /// Degraded mode is opt-in; without it an unreachable authority fails closed at once,
    /// whatever was last read.
    #[test]
    fn without_the_opt_in_there_is_no_window_at_all() {
        let t0 = base();
        let window = DegradedWindow::unearned();
        window.record_read(t0);
        assert!(window.exhausted_at(&policy(3_600, 30, false), after(t0, 1)));
    }

    /// A configuration the wire vocabulary admits and a `Duration` does not: there is no
    /// window rather than an enormous one, so a nonsense bound cannot widen anything.
    #[test]
    fn a_negative_bound_is_no_window_rather_than_a_long_one() {
        let t0 = base();
        let window = DegradedWindow::unearned();
        window.record_read(t0);
        assert_eq!(window_of(&policy(-1, 0, true)), None);
        assert!(window.exhausted_at(&policy(-1, 0, true), after(t0, 1)));
    }

    /// The window owns its judging instant: a lookup that took time cannot be judged
    /// against a reading from before it.
    #[test]
    fn the_window_is_judged_at_the_instant_of_the_call() {
        let window = DegradedWindow::unearned();
        let read = Instant::now()
            .checked_sub(Duration::from_secs(2))
            .expect("the monotonic clock has run for two seconds");
        window.record_read(read);
        assert!(window.exhausted(&policy(1, 0, true)));
        assert!(!window.exhausted_at(&policy(1, 0, true), read));
    }
}
