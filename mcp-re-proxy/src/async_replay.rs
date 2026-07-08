//! MCPRE-117 (ADR-MCPRE-051 §4, Phase 2) — the ASYNC authoritative replay tier seam.
//!
//! The async data plane (MCPRE-113) serves on per-core `tokio` runtimes, so the
//! replay check on the request path must NOT block a runtime worker on store I/O.
//! This module defines the async analogue of `shared_replay::AtomicReplayStore`:
//!
//!   * [`AsyncAtomicReplayStore`] — the authoritative L2 contract, one async op
//!     *insert-if-absent-with-TTL* (`atomic_insert_if_absent`). Concrete backends
//!     (async Redis `SET NX PX`, async etcd CAS) implement it without blocking the
//!     request path; the in-memory [`InMemoryAsyncAtomicReplayStore`] is the
//!     default-build reference.
//!   * [`L1FastRejectStore`] — a PER-CORE L1 optimization in front of the shared L2.
//!     It may FAST-REJECT a key it already knows is present (returning `Replay`
//!     without touching L2), but it can NEVER answer `Fresh`: **`Fresh` is only ever
//!     produced by a winning L2 insert.** This "L1-never-Fresh" property is enforced
//!     BY CONSTRUCTION — the L1 lookup returns `Some(Replay)` or `None` (miss ⇒
//!     consult L2), a type that cannot express `Fresh` — and BY TEST.
//!
//! Fail-closed posture (ADR-MCPS-020, unchanged): any L2 operational failure surfaces
//! as [`ReplayStoreError::Unavailable`] ⇒ `mcp-re.replay_cache_unavailable`, never a
//! silent "allow". The L1 is a pure optimization: an L1 miss or eviction only ever
//! costs an authoritative L2 round-trip, never a false `Fresh`.

#![cfg(feature = "async_serve")]

use std::collections::HashSet;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;
use mcp_re_core::ReplayKey;

use crate::shared_replay::composite_replay_key;
use crate::shared_replay::skew_folded_retain_until;
use crate::shared_replay::ReplayStoreError;

/// A boxed, `Send` future returning a replay decision — the object-safe return type
/// of [`AsyncAtomicReplayStore::atomic_insert_if_absent`] (native async-fn-in-trait is
/// not `dyn`-compatible, and the tier is dispatched dynamically over feature-gated
/// backends, so the future is boxed explicitly rather than via `async fn`).
pub type ReplayDecisionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ReplayDecision, ReplayStoreError>> + Send + 'a>>;

/// The ASYNC authoritative (L2) replay store contract — the async analogue of
/// [`crate::shared_replay::AtomicReplayStore`]. One server-side-atomic
/// insert-if-absent-with-TTL, awaited on the request path without blocking a runtime
/// worker.
pub trait AsyncAtomicReplayStore: Send + Sync {
    /// Atomically insert `key` iff absent, with a TTL derived from the skew-folded
    /// `expires_at_unix` relative to the store's OWN clock. `now_unix` is the same
    /// vestigial `0` anchor as the sync contract — a backend that derives a
    /// server-side TTL MUST read its own clock and ignore it (see
    /// [`crate::shared_replay::AtomicReplayStore::insert_if_absent`]).
    ///
    /// `Fresh` iff the key was absent and is now recorded (this caller won the
    /// insert), `Replay` if already present, or [`ReplayStoreError`] on operational
    /// failure (⇒ fail closed). This is the ONLY source of an authoritative `Fresh`.
    fn atomic_insert_if_absent<'a>(
        &'a self,
        key: &'a str,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> ReplayDecisionFuture<'a>;

    /// This store's declared durability class (ADR-MCPS-020). Defaults to the
    /// conservative single-process reference; only a genuinely cross-process backend
    /// overrides it to `Durable`.
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::SingleProcessReference
    }
}

/// A REAL in-memory async [`AsyncAtomicReplayStore`] reference (the async analogue of
/// [`crate::shared_replay::InMemoryAtomicReplayStore`] — not a test mock). Cloning
/// shares the same underlying state, so one store can back several per-core tiers and
/// model cross-core / cross-replica racing within one process. The atomic op is a
/// short critical section (no real I/O), so it never blocks a runtime worker.
#[derive(Clone, Default)]
pub struct InMemoryAsyncAtomicReplayStore {
    inner: std::sync::Arc<Mutex<InMemoryState>>,
}

#[derive(Default)]
struct InMemoryState {
    seen: HashSet<String>,
}

impl InMemoryAsyncAtomicReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The synchronous core of the atomic op: insert-if-absent under the lock.
    /// Exactly one caller among many racing on the same key observes it absent
    /// (`Fresh`); the rest see `Replay`.
    fn insert_locked(&self, key: &str) -> ReplayDecision {
        let mut state = self.inner.lock().expect("replay state lock");
        if state.seen.insert(key.to_string()) {
            ReplayDecision::Fresh
        } else {
            ReplayDecision::Replay
        }
    }
}

impl AsyncAtomicReplayStore for InMemoryAsyncAtomicReplayStore {
    fn atomic_insert_if_absent<'a>(
        &'a self,
        key: &'a str,
        _expires_at_unix: i64,
        _now_unix: i64,
    ) -> ReplayDecisionFuture<'a> {
        // The in-memory reference has no server-side TTL (eviction would be an
        // explicit prune) — the decision is a lock-guarded insert. Wrapped in a
        // ready future so it satisfies the async contract without ever blocking.
        Box::pin(async move { Ok(self.insert_locked(key)) })
    }
}

/// The async replay TIER the proxy's async serving path awaits (ADR-MCPRE-051
/// §4): the async analogue of [`crate::shared_replay::SharedReplayCache`]. Given a
/// `mcp_re_core::ReplayKey` from `verify_request_dispatch_preflight`, it composes
/// the collision-safe composite key and folds the clock skew IDENTICALLY to the
/// sync path (via the shared [`composite_replay_key`] / [`skew_folded_retain_until`]
/// helpers), then AWAITS the authoritative [`AsyncAtomicReplayStore`] insert. The
/// store round-trip is the ONLY awaited I/O on the request path; the returned
/// [`ReplayDecision`] is fed straight into
/// [`mcp_re_core::PreflightVerified::finalize`].
///
/// Fail-closed: any store failure surfaces as [`ReplayCacheError::Unavailable`]
/// ⇒ `mcp-re.replay_cache_unavailable`, never a silent allow (ADR-MCPS-020).
#[derive(Clone)]
pub struct AsyncReplayTier {
    store: Arc<dyn AsyncAtomicReplayStore>,
    max_clock_skew_secs: i64,
}

impl AsyncReplayTier {
    /// Build the tier over `store`, applying the symmetric `max_clock_skew_secs`
    /// to each entry's retain-until (folded into the store TTL) exactly as the
    /// sync `SharedReplayCache` does.
    pub fn new(store: Arc<dyn AsyncAtomicReplayStore>, max_clock_skew_secs: i64) -> Self {
        AsyncReplayTier {
            store,
            max_clock_skew_secs,
        }
    }

    /// This tier's declared durability class — delegated to the backing store, so
    /// a strict/production startup can machine-check the object it actually holds
    /// (never a hardcoded `Durable`).
    pub fn durability_class(&self) -> ReplayDurabilityClass {
        self.store.durability_class()
    }

    /// AWAIT the authoritative atomic insert-if-absent for `key`. Composes the
    /// composite key and folds skew identically to the sync path; maps a store
    /// failure to the fail-closed [`ReplayCacheError::Unavailable`]. The vestigial
    /// `now_unix = 0` anchor is passed through — a store that derives a server-side
    /// TTL reads its OWN clock and ignores it (see [`AsyncAtomicReplayStore`]).
    pub async fn check_and_insert(
        &self,
        key: &ReplayKey,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        let composite = composite_replay_key(&key.signer, &key.audience, &key.nonce);
        let retain_until = skew_folded_retain_until(key.expires_at_unix, self.max_clock_skew_secs);
        self.store
            .atomic_insert_if_absent(&composite, retain_until, 0)
            .await
            .map_err(ReplayCacheError::from)
    }
}

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
    fn atomic_insert_if_absent<'a>(
        &'a self,
        key: &'a str,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> ReplayDecisionFuture<'a> {
        Box::pin(async move {
            // L1 fast-reject: a known replay never touches L2 (and never yields Fresh).
            if let Some(replay) = self.l1_lookup(key) {
                return Ok(replay);
            }
            // Authoritative L2 — the ONLY source of Fresh. On any decision the key is
            // now present in L2, so cache it in L1 for future fast-reject. On an L2
            // error, fail closed and record NOTHING (the key's presence is unknown).
            let decision = self.l2.atomic_insert_if_absent(key, expires_at_unix, now_unix).await?;
            self.l1_record(key);
            Ok(decision)
        })
    }

    fn durability_class(&self) -> ReplayDurabilityClass {
        // The L1 is a per-core optimization with no durability of its own — the tier
        // is exactly as durable as its authoritative L2.
        self.l2.durability_class()
    }
}
