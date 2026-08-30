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
            // The wire token is frozen and says only `replay_cache_unavailable`,
            // which is also what a genuine backend outage says. Without this line
            // an operator paging on that token investigates store health while the
            // real cause is one signature-valid peer over its quota — the very
            // mechanism this budget added, otherwise unobservable.
            eprintln!(
                "mcp-re-proxy: replay budget refusal (NOT a store outage): actor \
                     holds {held} of its {budget} entries with the store at {} of {}; \
                     actor={actor}",
                state.seen.len(),
                max_entries
            );
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
