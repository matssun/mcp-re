// MCPRE-117 (ADR-MCPRE-051 §4, Phase 2) — async authoritative replay tier seam.
//
// Proves the async replay tier's load-bearing properties on the in-memory reference
// backend (no live infra): the per-core L1 fast-rejects known replays WITHOUT ever
// manufacturing a `Fresh` (Fresh only from a winning L2 insert), L1 eviction is
// always safe, an L2 outage fails closed with clean recovery, and — cross-core — many
// per-core tiers over one shared L2 admit EXACTLY ONE `Fresh` under concurrency.
//
// Concrete async Redis/etcd backends implement the same `AsyncAtomicReplayStore`
// contract; their live cross-replica proofs run in the skip-when-absent infra lane.

#![cfg(feature = "async_serve")]

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::ReplayDecision;

use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_replay::L1FastRejectStore;
use mcp_re_proxy::async_replay::ReplayDecisionFuture;
use mcp_re_proxy::shared_replay::ReplayStoreError;

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
    fn atomic_insert_if_absent<'a>(
        &'a self,
        key: &'a str,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> ReplayDecisionFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.atomic_insert_if_absent(key, expires_at_unix, now_unix)
    }
}

/// An L2 whose availability is toggled by `fail`, to prove fail-closed + recovery.
struct FaultInjectingL2 {
    inner: InMemoryAsyncAtomicReplayStore,
    fail: Arc<AtomicBool>,
}

impl AsyncAtomicReplayStore for FaultInjectingL2 {
    fn atomic_insert_if_absent<'a>(
        &'a self,
        key: &'a str,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> ReplayDecisionFuture<'a> {
        if self.fail.load(Ordering::SeqCst) {
            Box::pin(async {
                Err(ReplayStoreError::Unavailable {
                    details: "injected outage".to_string(),
                })
            })
        } else {
            self.inner.atomic_insert_if_absent(key, expires_at_unix, now_unix)
        }
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
        let first = tier.atomic_insert_if_absent("k", 0, 0).await.expect("ok");
        assert_eq!(first, ReplayDecision::Fresh, "first insert is Fresh (from L2)");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "L2 consulted exactly once");

        // Second sight of the SAME key: L1 fast-rejects ⇒ Replay, L2 NOT consulted.
        let second = tier.atomic_insert_if_absent("k", 0, 0).await.expect("ok");
        assert_eq!(second, ReplayDecision::Replay, "known replay fast-rejected by L1");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "L1 hit did not touch L2");
    });
}

#[test]
fn l1_eviction_never_causes_a_false_fresh() {
    rt().block_on(async {
        // A tiny L1 so we can force eviction of a known key.
        let l2 = InMemoryAsyncAtomicReplayStore::new();
        let tier = L1FastRejectStore::with_capacity(l2, 2);

        assert_eq!(tier.atomic_insert_if_absent("A", 0, 0).await.expect("ok"), ReplayDecision::Fresh);
        // Insert enough distinct keys to evict "A" from the 2-slot L1.
        for k in ["B", "C", "D"] {
            let _ = tier.atomic_insert_if_absent(k, 0, 0).await.expect("ok");
        }
        // "A" is now evicted from L1, but L2 still holds it — so re-inserting "A" must
        // be a Replay (from L2), NEVER a false Fresh.
        let again = tier.atomic_insert_if_absent("A", 0, 0).await.expect("ok");
        assert_eq!(again, ReplayDecision::Replay, "an L1-evicted known key is still a Replay via L2 — never a false Fresh");
    });
}

#[test]
fn l2_outage_fails_closed_and_recovers_clean() {
    rt().block_on(async {
        let fail = Arc::new(AtomicBool::new(true));
        let l2 = FaultInjectingL2 {
            inner: InMemoryAsyncAtomicReplayStore::new(),
            fail: Arc::clone(&fail),
        };
        let tier = L1FastRejectStore::new(l2);

        // During the outage: fail closed (Unavailable), NOT a silent allow.
        let outage = tier.atomic_insert_if_absent("k", 0, 0).await;
        assert!(
            matches!(outage, Err(ReplayStoreError::Unavailable { .. })),
            "an L2 outage must fail closed, got {outage:?}",
        );

        // The outage recorded nothing in L1 (presence unknown), so recovery is clean:
        // the first post-recovery sight of the key is a correct Fresh.
        fail.store(false, Ordering::SeqCst);
        let recovered = tier.atomic_insert_if_absent("k", 0, 0).await.expect("recovered");
        assert_eq!(recovered, ReplayDecision::Fresh, "clean recovery: first sight is Fresh");
        let replay = tier.atomic_insert_if_absent("k", 0, 0).await.expect("ok");
        assert_eq!(replay, ReplayDecision::Replay, "and the next is a Replay");
    });
}

#[test]
fn cross_core_exactly_one_fresh_under_concurrency() {
    rt().block_on(async {
        // One shared authoritative L2; many PER-CORE L1 tiers over it (each a distinct
        // L1, all sharing L2 state via the cloned Arc inside InMemoryAsync...).
        let shared_l2 = InMemoryAsyncAtomicReplayStore::new();
        let cores = 4;
        let tiers: Vec<Arc<L1FastRejectStore<InMemoryAsyncAtomicReplayStore>>> = (0..cores)
            .map(|_| Arc::new(L1FastRejectStore::new(shared_l2.clone())))
            .collect();

        // Fire many concurrent inserts of the SAME key across all per-core tiers.
        let key = "same-nonce";
        let tasks = 64;
        let mut handles = Vec::new();
        for i in 0..tasks {
            let tier = Arc::clone(&tiers[i % cores]);
            handles.push(tokio::spawn(async move {
                tier.atomic_insert_if_absent(key, 0, 0).await.expect("ok")
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
        assert_eq!(fresh, 1, "EXACTLY ONE Fresh across all cores under concurrency");
        assert_eq!(replay, tasks - 1, "every other caller sees Replay");
    });
}

#[test]
fn distinct_keys_are_each_fresh_once() {
    rt().block_on(async {
        let tier = L1FastRejectStore::new(InMemoryAsyncAtomicReplayStore::new());
        // Distinct keys are independent: each is Fresh exactly once, Replay thereafter.
        for k in ["a", "b", "c"] {
            assert_eq!(tier.atomic_insert_if_absent(k, 0, 0).await.expect("ok"), ReplayDecision::Fresh);
        }
        for k in ["a", "b", "c"] {
            assert_eq!(tier.atomic_insert_if_absent(k, 0, 0).await.expect("ok"), ReplayDecision::Replay);
        }
    });
}
