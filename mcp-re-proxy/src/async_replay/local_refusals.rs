// SPDX-License-Identifier: Apache-2.0
//! When the reference L2 says no instead of recording.
//!
//! Three refusals, and every one of them is [`ReplayStoreError::Unavailable`] rather than
//! `Fresh`. That is not caution: an UNRECORDED nonce can be replayed, so admitting a
//! request whose nonce this store could not retain is the one unsafe option available. The
//! refusals differ in what they say about the deployment, not in how safe they are.
//!
//! | refusal | what it means |
//! |---|---|
//! | stale `retain_until` | the entry would be dropped by the next prune, so recording it would report `Fresh` for a replayable nonce |
//! | over fair share | ONE signer is holding more than its share of a store under pressure |
//! | over the ceiling | the store is full |
//!
//! The middle one is what keeps the last one off everyone else. The ceiling alone is a
//! global resource one signer can exhaust, and exhausting it answers
//! `replay_cache_unavailable` to every OTHER signer on the replica.
//!
//! The stale check is judged against the CALLER''s `now` — the same reading the freshness
//! gate used — as the five sibling stores do. The store''s own clock is the PRUNE anchor
//! and only that: pruning must not be driven by a caller-supplied value, and staleness must
//! not be judged against a clock the verifier never saw, or a deployment whose verifier runs
//! elsewhere would have every entry refused, which is an outage rather than a guard.

use crate::shared_replay::ReplayStoreError;

use super::bounds::per_actor_budget;
use super::bounds::under_pressure;
use super::retained_set::RetainedSet;

/// MCPS-08: an already-past `retain_until` is refused BEFORE recording, at the store layer,
/// rather than relying solely on the upstream freshness step having run first.
///
/// Recording it would write an entry the next prune drops, making the nonce replayable
/// while this call reported `Fresh`. Every other store in the tree refuses it here; this one
/// is the DEFAULT, so its being the exception was the wrong way round.
pub(super) fn refuse_stale_retain_until(
    retain_until: i64,
    now_unix: i64,
) -> Result<(), ReplayStoreError> {
    if crate::shared_replay::is_stale_pre_store(retain_until, now_unix) {
        return Err(ReplayStoreError::Unavailable {
            details: "replay retain_until is already past; refusing to record a nonce \
                      that would not be retained"
                .to_string(),
        });
    }
    Ok(())
}

/// Under pressure, refuse the actor already holding more than its share.
///
/// Refusing the greedy signer HERE is what keeps the refusal from landing on every
/// OTHER signer at the ceiling below. Still `Unavailable` and never `Fresh`: an
/// unrecorded nonce can be replayed, so refusing is the only safe answer either way.
pub(super) fn refuse_over_fair_share(
    state: &RetainedSet,
    actor: &str,
    max_entries: usize,
) -> Result<(), ReplayStoreError> {
    if under_pressure(state.seen.len(), max_entries) {
        let budget = per_actor_budget(max_entries, state.per_actor.len());
        let held = state.per_actor.get(actor).copied().unwrap_or(0);
        if held >= budget {
            // No diagnostic HERE. This runs under the caller's guard, and the operator
            // line belongs outside it: see `super::budget_report`. The caller catches
            // this refusal, drops the lock, and reports.
            return Err(ReplayStoreError::Unavailable {
                details: format!(
                    "in-memory async replay store: actor holds {held} of its {budget} \
                         retained-entry budget while the store is at {} of {} entries",
                    state.seen.len(),
                    max_entries
                ),
            });
        }
    }
    Ok(())
}

/// The fail-closed ceiling: refuse rather than grow without bound.
///
/// Admitting a request whose nonce is not retained would be the one unsafe option,
/// since an unrecorded nonce can be replayed — so this is `Unavailable`, never `Fresh`.
pub(super) fn refuse_over_ceiling(
    state: &RetainedSet,
    max_entries: usize,
) -> Result<(), ReplayStoreError> {
    if state.seen.len() >= max_entries {
        return Err(ReplayStoreError::Unavailable {
            details: format!(
                "in-memory async replay store is at its {} entry ceiling",
                max_entries
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(entries: &[(&str, usize)]) -> RetainedSet {
        let mut s = RetainedSet::default();
        for (actor, n) in entries {
            for i in 0..*n {
                s.record(&format!("{actor}-{i}"), actor, 1_000);
            }
        }
        s
    }

    fn is_unavailable(r: Result<(), ReplayStoreError>) -> bool {
        matches!(r, Err(ReplayStoreError::Unavailable { .. }))
    }

    /// A `retain_until` at or before `now` is refused as Unavailable; one past it is admitted.
    #[test]
    fn a_retain_until_at_or_before_now_is_refused() {
        assert!(is_unavailable(refuse_stale_retain_until(100, 100)));
        assert!(is_unavailable(refuse_stale_retain_until(99, 100)));
        assert!(refuse_stale_retain_until(101, 100).is_ok());
    }

    /// Under pressure an actor holding its whole budget is refused, at the `held == budget`
    /// boundary, while an actor under it is admitted.
    #[test]
    fn an_actor_at_its_fair_share_is_refused_under_pressure() {
        let mut s = filled(&[("a", 3), ("b", 5)]);
        assert_eq!(per_actor_budget(10, 2), 4);
        assert!(refuse_over_fair_share(&s, "a", 10).is_ok());
        assert!(is_unavailable(refuse_over_fair_share(&s, "b", 10)));
        s.record("a-3", "a", 1_000);
        assert!(is_unavailable(refuse_over_fair_share(&s, "a", 10)));
    }

    /// Below the pressure threshold the fair share does not apply.
    #[test]
    fn the_fair_share_does_not_apply_below_pressure() {
        let mut s = filled(&[("a", 6), ("b", 1)]);
        assert!(refuse_over_fair_share(&s, "a", 10).is_ok());
        s.record("b-1", "b", 1_000);
        assert!(is_unavailable(refuse_over_fair_share(&s, "a", 10)));
    }

    /// The ceiling admits one below `max_entries` and refuses at it.
    #[test]
    fn the_ceiling_refuses_at_max_entries_and_admits_one_below() {
        let mut s = filled(&[("a", 3)]);
        assert!(refuse_over_ceiling(&s, 4).is_ok());
        s.record("a-3", "a", 1_000);
        assert!(is_unavailable(refuse_over_ceiling(&s, 4)));
    }
}
