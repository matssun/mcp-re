// MCPRE-117 (ADR-MCPRE-051 §4, Phase 2) — async authoritative replay tier seam.
//
// The named CI release gate "§4 replay race" runs this module. Its three requirement
// controls drive the L2 seam itself: an L2 outage fails closed with clean recovery,
// many concurrent handles on one shared L2 admit EXACTLY ONE `Fresh` under
// concurrency, and distinct keys are each Fresh once.
//
// The L2 behind them is `InMemoryAsyncAtomicReplayStore` inside `DurableL2`, which
// declares the durability class `replay_plane::materialized::assert_durable` ACCEPTS.
// The insert semantics are the reference store's, so nothing here is a claim about a
// live backend: concrete async Redis and etcd stores implement the same
// `AsyncAtomicReplayStore` contract and their cross-replica proofs are
// `replay_race_harness_test.rs`, in the skip-when-absent infra lane. Nothing in this
// file is cross-replica.
//
// Two further controls have the per-core L1 as their SUBJECT — it fast-rejects a known
// replay without consulting the L2 again, and its FIFO eviction never manufactures a
// `Fresh`. `L1FastRejectStore` is dormant: nothing in the shipped deployment
// constructs one.

#![cfg(feature = "async_serve")]

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;

use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_replay::L1FastRejectStore;
use mcp_re_proxy::async_replay::ReplayDecisionFuture;
use mcp_re_proxy::async_replay::ReplayInsert;
use mcp_re_proxy::shared_replay::ReplayStoreError;

/// Every entry in this file is charged to one signer; the per-actor budget is
/// exercised by its own test in `async_replay.rs`.
const TEST_ACTOR: &str = "did:example:test-signer";

/// A multi-thread runtime for the concurrency tests.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("runtime")
}

// --- test L2 doubles (both are REAL stores over the in-memory reference) -------

/// An L2 that counts how many times it is consulted (to prove the L1 fast-reject
/// short-circuits it).
struct CountingL2 {
    inner: InMemoryAsyncAtomicReplayStore,
    calls: Arc<AtomicUsize>,
}

impl AsyncAtomicReplayStore for CountingL2 {
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.atomic_insert_if_absent(insert)
    }
}

/// The reference L2, declaring the durability posture the production composition ACCEPTS.
///
/// `replay_plane::materialized::assert_durable` refuses any tier whose store declares
/// `SingleProcessReference`, and that is exactly what `InMemoryAsyncAtomicReplayStore`
/// declares (pinned by `in_memory::tests::in_memory_store_is_fresh_then_replay_and_single_process`).
/// Driving a release gate at the bare reference store would measure an arrangement the
/// composition root refuses outright. Only the DECLARATION is the shipped one; the insert
/// semantics are the reference store's, and no claim here reaches a live backend.
///
/// `clone` shares the underlying state, as `InMemoryAsyncAtomicReplayStore`'s own `Arc`
/// does — that is what makes many handles over one store a real contention.
#[derive(Clone)]
struct DurableL2(InMemoryAsyncAtomicReplayStore);

impl AsyncAtomicReplayStore for DurableL2 {
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a> {
        self.0.atomic_insert_if_absent(insert)
    }

    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::Durable
    }
}

/// An L2 whose availability is toggled by `fail`, to prove fail-closed + recovery.
struct FaultInjectingL2 {
    inner: DurableL2,
    fail: Arc<AtomicBool>,
}

impl AsyncAtomicReplayStore for FaultInjectingL2 {
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a> {
        if self.fail.load(Ordering::SeqCst) {
            Box::pin(async {
                Err(ReplayStoreError::Unavailable {
                    details: "injected outage".to_string(),
                })
            })
        } else {
            self.inner.atomic_insert_if_absent(insert)
        }
    }

    fn durability_class(&self) -> ReplayDurabilityClass {
        self.inner.durability_class()
    }
}

// --- tests --------------------------------------------------------------------

#[test]
fn l1_fast_rejects_known_replay_without_consulting_l2_again() {
    rt().block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let l2 = CountingL2 {
            inner: InMemoryAsyncAtomicReplayStore::new(),
            calls: Arc::clone(&calls),
        };
        let tier = L1FastRejectStore::new(l2);

        // First sight of the key: L1 miss ⇒ L2 consulted ⇒ Fresh.
        let first = tier
            .atomic_insert_if_absent(ReplayInsert::new("k", TEST_ACTOR, 100, 0))
            .await
            .expect("ok");
        assert_eq!(
            first,
            ReplayDecision::Fresh,
            "first insert is Fresh (from L2)"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "L2 consulted exactly once");

        // Second sight of the SAME key: L1 fast-rejects ⇒ Replay, L2 NOT consulted.
        let second = tier
            .atomic_insert_if_absent(ReplayInsert::new("k", TEST_ACTOR, 100, 0))
            .await
            .expect("ok");
        assert_eq!(
            second,
            ReplayDecision::Replay,
            "known replay fast-rejected by L1"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "L1 hit did not touch L2");
    });
}

#[test]
fn l1_eviction_never_causes_a_false_fresh() {
    rt().block_on(async {
        // A tiny L1 so we can force eviction of a known key.
        let l2 = InMemoryAsyncAtomicReplayStore::new();
        let tier = L1FastRejectStore::with_capacity(l2, 2);

        assert_eq!(
            tier.atomic_insert_if_absent(ReplayInsert::new("A", TEST_ACTOR, 100, 0))
                .await
                .expect("ok"),
            ReplayDecision::Fresh
        );
        // Insert enough distinct keys to evict "A" from the 2-slot L1.
        for k in ["B", "C", "D"] {
            let _ = tier
                .atomic_insert_if_absent(ReplayInsert::new(k, TEST_ACTOR, 100, 0))
                .await
                .expect("ok");
        }
        // "A" is now evicted from L1, but L2 still holds it — so re-inserting "A" must
        // be a Replay (from L2), NEVER a false Fresh.
        let again = tier
            .atomic_insert_if_absent(ReplayInsert::new("A", TEST_ACTOR, 100, 0))
            .await
            .expect("ok");
        assert_eq!(
            again,
            ReplayDecision::Replay,
            "an L1-evicted known key is still a Replay via L2 — never a false Fresh"
        );
    });
}

#[test]
fn l2_outage_fails_closed_and_recovers_clean() {
    rt().block_on(async {
        let fail = Arc::new(AtomicBool::new(true));
        let tier = FaultInjectingL2 {
            inner: DurableL2(InMemoryAsyncAtomicReplayStore::new()),
            fail: Arc::clone(&fail),
        };

        // During the outage: fail closed (Unavailable), NOT a silent allow.
        let outage = tier
            .atomic_insert_if_absent(ReplayInsert::new("k", TEST_ACTOR, 100, 0))
            .await;
        assert!(
            matches!(outage, Err(ReplayStoreError::Unavailable { .. })),
            "an L2 outage must fail closed, got {outage:?}",
        );

        // The outage recorded nothing, so recovery is clean: the first post-recovery
        // sight of the key is a correct Fresh.
        fail.store(false, Ordering::SeqCst);
        let recovered = tier
            .atomic_insert_if_absent(ReplayInsert::new("k", TEST_ACTOR, 100, 0))
            .await
            .expect("recovered");
        assert_eq!(
            recovered,
            ReplayDecision::Fresh,
            "clean recovery: first sight is Fresh"
        );
        let replay = tier
            .atomic_insert_if_absent(ReplayInsert::new("k", TEST_ACTOR, 100, 0))
            .await
            .expect("ok");
        assert_eq!(replay, ReplayDecision::Replay, "and the next is a Replay");
    });
}

#[test]
fn cross_core_exactly_one_fresh_under_concurrency() {
    rt().block_on(async {
        // One shared authoritative L2, reached through as many handles as there are
        // cores — all sharing its state via the cloned Arc inside InMemoryAsync...,
        // so the contention is real and it is the seam's atomic insert that resolves it.
        let shared_l2 = DurableL2(InMemoryAsyncAtomicReplayStore::new());
        let cores = 4;
        let tiers: Vec<Arc<DurableL2>> = (0..cores).map(|_| Arc::new(shared_l2.clone())).collect();

        // Fire many concurrent inserts of the SAME key across all handles.
        let key = "same-nonce";
        let tasks = 64;
        let mut handles = Vec::new();
        for i in 0..tasks {
            let tier = Arc::clone(&tiers[i % cores]);
            handles.push(tokio::spawn(async move {
                tier.atomic_insert_if_absent(ReplayInsert::new(key, TEST_ACTOR, 100, 0))
                    .await
                    .expect("ok")
            }));
        }
        let mut fresh = 0;
        let mut replay = 0;
        for h in handles {
            match h.await.expect("task") {
                ReplayDecision::Fresh => fresh += 1,
                ReplayDecision::Replay => replay += 1,
            }
        }
        assert_eq!(
            fresh, 1,
            "EXACTLY ONE Fresh across all handles under concurrency"
        );
        assert_eq!(replay, tasks - 1, "every other caller sees Replay");
    });
}

#[test]
fn distinct_keys_are_each_fresh_once() {
    rt().block_on(async {
        let tier = DurableL2(InMemoryAsyncAtomicReplayStore::new());
        // Distinct keys are independent: each is Fresh exactly once, Replay thereafter.
        // Three keys interleaved under one actor — a different proposition from
        // `in_memory::tests::in_memory_store_is_fresh_then_replay_and_single_process`,
        // which presents ONE key twice and says nothing about independence.
        for k in ["a", "b", "c"] {
            assert_eq!(
                tier.atomic_insert_if_absent(ReplayInsert::new(k, TEST_ACTOR, 100, 0))
                    .await
                    .expect("ok"),
                ReplayDecision::Fresh
            );
        }
        for k in ["a", "b", "c"] {
            assert_eq!(
                tier.atomic_insert_if_absent(ReplayInsert::new(k, TEST_ACTOR, 100, 0))
                    .await
                    .expect("ok"),
                ReplayDecision::Replay
            );
        }
    });
}
