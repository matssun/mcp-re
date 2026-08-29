// SPDX-License-Identifier: Apache-2.0
//! A per-core L1 fast-reject cache in front of the shared authoritative L2 — **defined,
//! and DORMANT.**
//!
//! # Its dormancy is the first thing to know about it
//!
//! Nothing in the shipped deployment constructs one. `app.rs` wires the L2 store directly
//! on every backend, there is no configuration surface that selects an L1, no theorem,
//! specification or security-boundary document claims one is in force, and the only
//! constructions in the tree are in `async_replay_test`. So the two-tier architecture is
//! not what runs today, and every request pays a full L2 round trip.
//!
//! **That is a dormancy, not a wiring defect.** The census asked the question mechanically
//! (MCPRE-175, campaign section C): no live guarantee rests on it. The L1 is a LATENCY
//! optimization with no security consequence in either direction — see the invariant below
//! — so an unwired L1 costs throughput and claims nothing. An SLO claim resting on
//! "per-core L1 fast-reject" would be unbacked, and none is made.
//!
//! Wiring it is not a one-line change and is deliberately not done here: the L1 is per-core
//! state, and one `HttpProfileProxy` is shared by every core.
//!
//! # L1-never-Fresh, the load-bearing invariant
//!
//! On `atomic_insert_if_absent` the L1 is consulted FIRST; a hit returns `Replay`
//! immediately with no L2 round-trip. On a miss the authoritative L2 is awaited — and ONLY
//! L2 can return `Fresh`. Whatever L2 answers for a key, the key is now present in L2, so
//! it is recorded in L1 to fast-reject future duplicates.
//!
//! Because the L1 lookup can only ever yield `Replay` or a miss, the L1 can NEVER
//! manufacture a `Fresh`. That is enforced BY CONSTRUCTION — [`L1FastRejectStore::l1_lookup`]
//! returns a type that cannot express `Fresh` — and by test. Eviction is likewise always
//! safe: an evicted key costs an authoritative L2 round-trip next time, never a false
//! `Fresh`. On an L2 error nothing is recorded, because the key''s presence is unknown.

use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Mutex;

use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;

use super::AsyncAtomicReplayStore;
use super::ReplayDecisionFuture;
use super::ReplayInsert;

/// A bounded, insertion-ordered set of keys the L1 knows are PRESENT in L2 (known
/// replays). Bounded so a per-core L1 cannot grow without bound; eviction is FIFO and
/// always safe — an evicted key simply costs an authoritative L2 round-trip next time,
/// never a false `Fresh`.
struct BoundedKeySet {
    set: HashSet<String>,
    order: VecDeque<String>,
    cap: usize,
}

impl BoundedKeySet {
    fn new(cap: usize) -> Self {
        BoundedKeySet {
            set: HashSet::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    fn contains(&self, key: &str) -> bool {
        self.set.contains(key)
    }

    fn insert(&mut self, key: &str) {
        if self.set.contains(key) {
            return;
        }
        while self.order.len() >= self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            } else {
                break;
            }
        }
        self.set.insert(key.to_string());
        self.order.push_back(key.to_string());
    }
}

/// Default per-core L1 capacity (known-replay keys). Bounds L1 memory per core; the
/// exact value is not correctness-relevant (L2 is authoritative on any L1 miss).
pub const DEFAULT_L1_CAPACITY: usize = 65_536;

/// A PER-CORE L1 fast-reject cache in front of a shared authoritative L2.
///
/// **L1-never-Fresh (the load-bearing invariant):** on `atomic_insert_if_absent` the
/// L1 is consulted FIRST; a hit returns `Replay` immediately (fast-reject, no L2
/// round-trip). On a miss the authoritative L2 is awaited — and ONLY L2 can return
/// `Fresh`. Whatever L2 returns for a key (`Fresh` because this caller won, or
/// `Replay`), the key is now present in L2, so it is recorded in L1 to fast-reject
/// future duplicates. Because the L1 lookup can only ever yield `Replay` or "miss",
/// the L1 can NEVER manufacture a `Fresh` — it is a pure latency optimization.
/// **Not on the shipped serving path.** `app.rs` wires the L2 store directly, with no
/// L1 wrapper, on every backend — so the two-tier architecture the module header
/// describes is not what runs today, and every request pays a full L2 round trip. The
/// type is exercised only by `async_replay_test`. There is no security consequence
/// (the L1 can only fast-REJECT and never manufactures `Fresh`), but an SLO claim
/// resting on "per-core L1 fast-reject" would be unbacked. Wiring it needs per-core
/// state, and one `HttpProfileProxy` is shared by every core.
pub struct L1FastRejectStore<L2> {
    l2: L2,
    l1: Mutex<BoundedKeySet>,
}

impl<L2: AsyncAtomicReplayStore> L1FastRejectStore<L2> {
    /// Wrap `l2` with a per-core L1 of the default capacity.
    pub fn new(l2: L2) -> Self {
        Self::with_capacity(l2, DEFAULT_L1_CAPACITY)
    }

    /// Wrap `l2` with a per-core L1 of `capacity` known-replay keys.
    pub fn with_capacity(l2: L2, capacity: usize) -> Self {
        L1FastRejectStore {
            l2,
            l1: Mutex::new(BoundedKeySet::new(capacity)),
        }
    }

    /// L1 lookup — returns `Some(Replay)` on a hit, `None` on a miss. The return type
    /// deliberately CANNOT express `Fresh`: this is the type-level half of the
    /// L1-never-Fresh guarantee.
    fn l1_lookup(&self, key: &str) -> Option<ReplayDecision> {
        if self.l1.lock().expect("l1 lock").contains(key) {
            Some(ReplayDecision::Replay)
        } else {
            None
        }
    }

    fn l1_record(&self, key: &str) {
        self.l1.lock().expect("l1 lock").insert(key);
    }
}

impl<L2: AsyncAtomicReplayStore> AsyncAtomicReplayStore for L1FastRejectStore<L2> {
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a> {
        Box::pin(async move {
            // L1 fast-reject: a known replay never touches L2 (and never yields Fresh).
            if let Some(replay) = self.l1_lookup(insert.key) {
                return Ok(replay);
            }
            // Authoritative L2 — the ONLY source of Fresh. On any decision the key is
            // now present in L2, so cache it in L1 for future fast-reject. On an L2
            // error, fail closed and record NOTHING (the key's presence is unknown).
            let decision = self.l2.atomic_insert_if_absent(insert).await?;
            self.l1_record(insert.key);
            Ok(decision)
        })
    }

    fn durability_class(&self) -> ReplayDurabilityClass {
        // The L1 is a per-core optimization with no durability of its own — the tier
        // is exactly as durable as its authoritative L2.
        self.l2.durability_class()
    }
}

// Everything below is test code.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_replay::InMemoryAsyncAtomicReplayStore;

    /// The L1 budgets nothing, so the actor is only there to build a legal insert.
    const TEST_ACTOR: &str = "did:example:test-signer";
    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Runtime::new().expect("rt").block_on(f)
    }

    #[test]
    fn l1_fast_reject_never_fresh_and_evicts_fifo() {
        // Capacity 2 so a third distinct key forces FIFO eviction of the oldest.
        let l1 = L1FastRejectStore::with_capacity(InMemoryAsyncAtomicReplayStore::new(), 2);
        block(async {
            // First sight is authoritative Fresh (from L2); the repeat is an L1 hit.
            assert_eq!(
                l1.atomic_insert_if_absent(ReplayInsert::new("a", TEST_ACTOR, 100, 0))
                    .await
                    .unwrap(),
                ReplayDecision::Fresh
            );
            assert_eq!(
                l1.atomic_insert_if_absent(ReplayInsert::new("a", TEST_ACTOR, 100, 0))
                    .await
                    .unwrap(),
                ReplayDecision::Replay
            );
            // Fill past capacity: 'a' is evicted from L1, but L2 still remembers it,
            // so a re-check is Replay (never a false Fresh — the load-bearing invariant).
            assert_eq!(
                l1.atomic_insert_if_absent(ReplayInsert::new("b", TEST_ACTOR, 100, 0))
                    .await
                    .unwrap(),
                ReplayDecision::Fresh
            );
            assert_eq!(
                l1.atomic_insert_if_absent(ReplayInsert::new("c", TEST_ACTOR, 100, 0))
                    .await
                    .unwrap(),
                ReplayDecision::Fresh
            );
            assert_eq!(
                l1.atomic_insert_if_absent(ReplayInsert::new("a", TEST_ACTOR, 100, 0))
                    .await
                    .unwrap(),
                ReplayDecision::Replay
            );
        });
        assert_eq!(
            l1.durability_class(),
            ReplayDurabilityClass::SingleProcessReference
        );
    }
}
