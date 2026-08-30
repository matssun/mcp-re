// SPDX-License-Identifier: Apache-2.0
//! The DEFAULT-BUILD authoritative L2: retained nonces, their expiry, and whose share of
//! the store they occupy.
//!
//! A REAL store rather than a test mock. Its atomic op is a short critical section with no
//! I/O, so it satisfies the async contract without ever blocking a runtime worker, and
//! cloning shares the same state — one store can back several per-core tiers and model
//! cross-core racing within one process.
//!
//! Three bounds, and they are not the same bound:
//!
//!   * **expiry** — entries stop being retained and are evicted on a bounded cadence;
//!   * **the ceiling** — past it the store REFUSES rather than growing, because an
//!     unrecorded nonce can be replayed, so `Unavailable` is the only safe answer;
//!   * **the per-actor share** — evaluated only under pressure, so one signature-valid
//!     peer streaming distinct fresh nonces cannot answer `replay_cache_unavailable` to
//!     every OTHER signer on the replica.
//!
//! Two clocks appear here and they are deliberately different. Staleness is judged against
//! the CALLER's `now` — the same reading the freshness gate used — while eviction is
//! anchored to the store's OWN clock. Pruning against a caller-supplied `retain_until`
//! would over-evict still-live entries and reopen a replay window; judging staleness
//! against a clock the verifier never saw would refuse every entry on a deployment whose
//! verifier runs elsewhere, which is an outage rather than a guard.

use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::ReplayDecision;

use crate::shared_replay::ReplayStoreError;

use super::bounds::ASYNC_MAX_ENTRIES;
use super::local_refusals::refuse_over_ceiling;
use super::local_refusals::refuse_over_fair_share;
use super::local_refusals::refuse_stale_retain_until;
use super::retained_set::system_clock;
use super::retained_set::RetainedSet;
use super::retained_set::UnixClock;

use super::AsyncAtomicReplayStore;
use super::ReplayDecisionFuture;
use super::ReplayInsert;

/// A REAL in-memory async [`AsyncAtomicReplayStore`] reference (the async analogue of
/// [`crate::shared_replay::InMemoryAtomicReplayStore`] — not a test mock). Cloning
/// shares the same underlying state, so one store can back several per-core tiers and
/// model cross-core / cross-replica racing within one process. The atomic op is a
/// short critical section (no real I/O), so it never blocks a runtime worker.
#[derive(Clone)]
pub struct InMemoryAsyncAtomicReplayStore {
    inner: std::sync::Arc<Mutex<RetainedSet>>,
    /// The store's OWN clock, used to anchor the inline prune. Shared with clones so
    /// every handle onto the same state evicts against the same notion of now.
    clock: Arc<UnixClock>,
    max_entries: usize,
}

impl Default for InMemoryAsyncAtomicReplayStore {
    fn default() -> Self {
        InMemoryAsyncAtomicReplayStore {
            inner: std::sync::Arc::new(Mutex::new(RetainedSet::default())),
            clock: Arc::new(system_clock()),
            max_entries: ASYNC_MAX_ENTRIES,
        }
    }
}

impl InMemoryAsyncAtomicReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the fail-closed entry ceiling (tests, and bounded embedders).
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Inject a fixed clock so the inline-prune anchor is deterministic in tests.
    #[cfg(test)]
    pub(crate) fn with_clock(mut self, clock: UnixClock) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Entries currently charged to `actor`. A poisoned lock reports 0 for the same
    /// reason [`Self::len`] does — this is an inspection aid, not a decision.
    #[cfg(test)]
    fn held_by(&self, actor: &str) -> usize {
        self.inner
            .lock()
            .map(|s| s.per_actor.get(actor).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// Number of retained entries (test/inspection aid). A poisoned lock reports 0
    /// rather than panicking — this is an inspection aid, not a decision.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|s| s.seen.len()).unwrap_or(0)
    }

    /// Whether the store retains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The synchronous core of the atomic op: insert-if-absent under the lock.
    /// Exactly one caller among many racing on the same key observes it absent
    /// (`Fresh`); the rest see `Replay`.
    fn insert_locked(
        &self,
        key: &str,
        actor: &str,
        retain_until: i64,
        now_unix: i64,
    ) -> Result<ReplayDecision, ReplayStoreError> {
        refuse_stale_retain_until(retain_until, now_unix)?;
        // A poisoned mutex is an OPERATIONAL failure — fail closed on the frozen
        // `mcp-re.replay_cache_unavailable` token, never a panic. Panicking here bricks
        // the replica for its lifetime (poison is sticky) and the fault never reaches
        // the audit stream as a reason, which is exactly what the sync twin refuses to
        // do.
        let mut state = self
            .inner
            .lock()
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("in-memory async replay store lock poisoned: {e}"),
            })?;
        if state.seen.contains_key(key) {
            return Ok(ReplayDecision::Replay);
        }

        state.prune_if_due(&(self.clock));
        refuse_over_fair_share(&state, actor, self.max_entries)?;
        refuse_over_ceiling(&state, self.max_entries)?;
        state.record(key, actor, retain_until);
        Ok(ReplayDecision::Fresh)
    }
}

impl AsyncAtomicReplayStore for InMemoryAsyncAtomicReplayStore {
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a> {
        // The decision is a lock-guarded insert, wrapped in a ready future so it
        // satisfies the async contract without ever blocking a runtime worker.
        Box::pin(async move {
            self.insert_locked(
                insert.key,
                insert.actor,
                insert.expires_at_unix,
                insert.now_unix,
            )
        })
    }
}

// Everything below is test code.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_replay::bounds::ASYNC_PRUNE_EVERY_N_INSERTS;
    use crate::shared_replay::ReplayStoreError;
    use mcp_re_core::ReplayCacheError;
    use mcp_re_core::ReplayDurabilityClass;

    /// Every entry in these tests is charged to one signer; the per-actor budget has its
    /// own test next door.
    const TEST_ACTOR: &str = "did:example:test-signer";
    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Runtime::new().expect("rt").block_on(f)
    }

    #[test]
    fn in_memory_store_is_fresh_then_replay_and_single_process() {
        let store = InMemoryAsyncAtomicReplayStore::new();
        block(async {
            assert_eq!(
                store
                    .atomic_insert_if_absent(ReplayInsert::new("nonce-1", TEST_ACTOR, 100, 0))
                    .await
                    .unwrap(),
                ReplayDecision::Fresh
            );
            assert_eq!(
                store
                    .atomic_insert_if_absent(ReplayInsert::new("nonce-1", TEST_ACTOR, 100, 0))
                    .await
                    .unwrap(),
                ReplayDecision::Replay
            );
        });
        assert_eq!(
            store.durability_class(),
            ReplayDurabilityClass::SingleProcessReference
        );
    }

    #[test]
    fn the_async_store_evicts_entries_past_their_retain_until() {
        // Every accepted request adds an entry, and a signature-valid peer can stream
        // distinct fresh nonces at will — so without eviction the set grows with total
        // request volume rather than with the freshness window.
        let now = Arc::new(Mutex::new(1_000i64));
        let n = Arc::clone(&now);
        let store = InMemoryAsyncAtomicReplayStore::new()
            .with_clock(Box::new(move || *n.lock().expect("clock")));

        block(async {
            // A prune runs on the 64th insert; the first 63 all retain-until 1_500.
            for i in 0..(ASYNC_PRUNE_EVERY_N_INSERTS - 1) {
                store
                    .atomic_insert_if_absent(ReplayInsert::new(
                        &format!("nonce-{i}"),
                        TEST_ACTOR,
                        1_500,
                        0,
                    ))
                    .await
                    .unwrap();
            }
            assert_eq!(store.len() as u64, ASYNC_PRUNE_EVERY_N_INSERTS - 1);

            // Move the clock past their retain-until; the next insert triggers the
            // cadence and evicts them.
            *now.lock().expect("clock") = 2_000;
            store
                .atomic_insert_if_absent(ReplayInsert::new("nonce-live", TEST_ACTOR, 9_000, 0))
                .await
                .unwrap();
            assert_eq!(store.len(), 1, "only the still-live entry survives");
        });
    }

    #[test]
    fn the_async_store_refuses_rather_than_growing_past_its_ceiling() {
        // Within one freshness window a peer can present more distinct fresh nonces
        // than the prune cadence drains. Refusing is the only safe answer: admitting a
        // request whose nonce is not retained would let it be replayed.
        let store = InMemoryAsyncAtomicReplayStore::new()
            .with_max_entries(3)
            .with_clock(Box::new(|| 1_000));
        block(async {
            for i in 0..3 {
                assert_eq!(
                    store
                        .atomic_insert_if_absent(ReplayInsert::new(
                            &format!("nonce-{i}"),
                            TEST_ACTOR,
                            9_000,
                            0
                        ))
                        .await
                        .unwrap(),
                    ReplayDecision::Fresh
                );
            }
            let refused = store
                .atomic_insert_if_absent(ReplayInsert::new("nonce-over", TEST_ACTOR, 9_000, 0))
                .await;
            assert!(
                matches!(refused, Err(ReplayStoreError::Unavailable { .. })),
                "past the ceiling the store must refuse, got {refused:?}"
            );
            // Fail CLOSED: it maps to the frozen unavailable token, never an allow.
            assert_eq!(
                ReplayCacheError::from(refused.unwrap_err()).to_mcp_re_error(),
                mcp_re_core::McpReError::ReplayCacheUnavailable
            );
            assert_eq!(store.len(), 3, "the refused entry was not recorded");

            // A known replay is still reported as one at the ceiling: refusing to GROW
            // must not turn a known replay into an unknown.
            assert_eq!(
                store
                    .atomic_insert_if_absent(ReplayInsert::new("nonce-0", TEST_ACTOR, 9_000, 0))
                    .await
                    .unwrap(),
                ReplayDecision::Replay
            );
        });
    }

    /// R6-C058: the entry ceiling is a SHARED resource, so exhausting it must not be
    /// something one signer can do to everybody else. A signature-valid peer streaming
    /// distinct fresh nonces used to fill all `max_entries` and every OTHER signer then
    /// got `mcp-re.replay_cache_unavailable` — one actor taking the replay tier down.
    #[test]
    fn one_actor_cannot_spend_the_whole_ceiling_and_deny_another() {
        // max_entries 10 ⇒ reserve 2, pressure at 8, solo budget 8.
        let store = InMemoryAsyncAtomicReplayStore::new()
            .with_max_entries(10)
            .with_clock(Box::new(|| 1_000));
        const GREEDY: &str = "did:example:greedy";
        const QUIET: &str = "did:example:quiet";

        block(async {
            // The greedy signer streams distinct fresh nonces until it is refused.
            let mut admitted = 0usize;
            for i in 0..20 {
                let key = format!("greedy-nonce-{i}");
                match store
                    .atomic_insert_if_absent(ReplayInsert::new(&key, GREEDY, 9_000, 0))
                    .await
                {
                    Ok(ReplayDecision::Fresh) => admitted += 1,
                    Err(ReplayStoreError::Unavailable { .. }) => break,
                    other => panic!("unexpected decision {other:?}"),
                }
            }
            assert_eq!(
                admitted, 8,
                "one actor must stop at its budget, not at the global ceiling"
            );
            assert_eq!(store.held_by(GREEDY), 8);
            assert!(
                store.len() < 10,
                "the reserve must still be free, got {} of 10 entries",
                store.len()
            );

            // THE PROPERTY: a signer that has sent nothing is still served while the
            // greedy one is refused. Before the budget existed this was the request
            // that failed.
            assert_eq!(
                store
                    .atomic_insert_if_absent(ReplayInsert::new("quiet-nonce-0", QUIET, 9_000, 0))
                    .await
                    .expect("the quiet actor must still be admitted"),
                ReplayDecision::Fresh
            );

            // And the greedy one stays refused — fail closed on the frozen token, never
            // an allow, because an unrecorded nonce can be replayed.
            let refused = store
                .atomic_insert_if_absent(ReplayInsert::new("greedy-nonce-99", GREEDY, 9_000, 0))
                .await
                .expect_err("over budget");
            assert_eq!(
                ReplayCacheError::from(refused).to_mcp_re_error(),
                mcp_re_core::McpReError::ReplayCacheUnavailable
            );

            // A known replay is still reported as one while over budget: refusing to
            // GROW must not turn a known replay into an unknown.
            assert_eq!(
                store
                    .atomic_insert_if_absent(ReplayInsert::new("greedy-nonce-0", GREEDY, 9_000, 0))
                    .await
                    .unwrap(),
                ReplayDecision::Replay
            );
        });
    }

    /// The charge is released with the entry it accounts for — otherwise a busy actor
    /// would be permanently penalised for traffic that has long since expired, and the
    /// budget would become a slow leak rather than a bound.
    #[test]
    fn pruning_releases_the_per_actor_charge() {
        let now = Arc::new(Mutex::new(1_000i64));
        let n = Arc::clone(&now);
        let store = InMemoryAsyncAtomicReplayStore::new()
            .with_clock(Box::new(move || *n.lock().expect("clock")));
        const ACTOR: &str = "did:example:busy";

        block(async {
            for i in 0..(ASYNC_PRUNE_EVERY_N_INSERTS - 1) {
                store
                    .atomic_insert_if_absent(ReplayInsert::new(
                        &format!("nonce-{i}"),
                        ACTOR,
                        1_500,
                        0,
                    ))
                    .await
                    .unwrap();
            }
            assert_eq!(store.held_by(ACTOR) as u64, ASYNC_PRUNE_EVERY_N_INSERTS - 1);

            // Past their retain-until, the next insert triggers the prune cadence.
            *now.lock().expect("clock") = 2_000;
            store
                .atomic_insert_if_absent(ReplayInsert::new("nonce-live", ACTOR, 9_000, 0))
                .await
                .unwrap();
            assert_eq!(
                store.held_by(ACTOR),
                1,
                "only the still-live entry is still charged"
            );
        });
    }

    /// MCPS-08: an already-past `retain_until` is refused BEFORE recording. Every
    /// sibling store does this; the DEFAULT store was the exception, so it would have
    /// recorded a nonce the next prune drops and reported `Fresh` for it.
    #[test]
    fn an_already_stale_retain_until_is_refused_pre_store() {
        let store = InMemoryAsyncAtomicReplayStore::new();
        block(async {
            let err = store
                .atomic_insert_if_absent(ReplayInsert::new("stale", TEST_ACTOR, 100, 100))
                .await
                .expect_err("retain_until == now is not retained");
            assert!(matches!(err, ReplayStoreError::Unavailable { .. }));
            assert!(store
                .atomic_insert_if_absent(ReplayInsert::new("stale", TEST_ACTOR, 99, 100))
                .await
                .is_err());
            // One second of retention IS retention.
            assert_eq!(
                store
                    .atomic_insert_if_absent(ReplayInsert::new("live", TEST_ACTOR, 101, 100))
                    .await
                    .expect("a future retain_until records"),
                ReplayDecision::Fresh
            );
        });
    }
}
