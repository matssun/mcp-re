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
//!     **Defined, not wired**: `app.rs` installs the L2 directly, so this is not what
//!     runs today. See the type's own docs.
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

use std::collections::BTreeMap;
use std::collections::HashMap;
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

/// One insert-if-absent request: the composite key, the actor the entry is BUDGETED
/// against, and the two clock anchors.
///
/// A struct rather than four positional arguments because `key` and `actor` are both
/// `&str`: transposed at a call site they would still compile, and the result is a
/// store that budgets every entry against a nonce — which is to say, against nothing.
#[derive(Clone, Copy, Debug)]
pub struct ReplayInsert<'a> {
    /// The collision-safe composite key the tier composed (signer|audience|nonce).
    pub key: &'a str,
    /// The RESOLVED signer this entry is charged to. Retention is a shared resource,
    /// so every entry has to name who is holding it; see [`AsyncReplayTier`] for what
    /// the charge buys.
    pub actor: &'a str,
    /// The skew-folded retain-until the tier computed.
    pub expires_at_unix: i64,
    /// The same vestigial `0` anchor as the sync contract — a backend that derives a
    /// server-side TTL reads its OWN clock and ignores this.
    pub now_unix: i64,
}

impl<'a> ReplayInsert<'a> {
    /// Build an insert charged to `actor`.
    pub fn new(key: &'a str, actor: &'a str, expires_at_unix: i64, now_unix: i64) -> Self {
        ReplayInsert {
            key,
            actor,
            expires_at_unix,
            now_unix,
        }
    }
}

/// The ASYNC authoritative (L2) replay store contract — the async analogue of
/// [`crate::shared_replay::AtomicReplayStore`]. One server-side-atomic
/// insert-if-absent-with-TTL, awaited on the request path without blocking a runtime
/// worker.
pub trait AsyncAtomicReplayStore: Send + Sync {
    /// Atomically insert `insert.key` iff absent, with a TTL derived from the
    /// skew-folded `insert.expires_at_unix` relative to the store's OWN clock.
    ///
    /// `Fresh` iff the key was absent and is now recorded (this caller won the
    /// insert), `Replay` if already present, or [`ReplayStoreError`] on operational
    /// failure (⇒ fail closed). This is the ONLY source of an authoritative `Fresh`.
    ///
    /// `insert.actor` is the principal the entry is charged to. The per-actor
    /// retention bound is enforced ABOVE this seam, by [`AsyncReplayTier`], so it
    /// applies to every backend; a backend that also bounds a local set of its own may
    /// budget that set per `insert.actor` as well, and one whose retention is a
    /// server-side TTL has no local set to budget.
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a>;

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
#[derive(Clone)]
pub struct InMemoryAsyncAtomicReplayStore {
    inner: std::sync::Arc<Mutex<InMemoryState>>,
    /// The store's OWN clock, used to anchor the inline prune. Shared with clones so
    /// every handle onto the same state evicts against the same notion of now.
    clock: Arc<UnixClock>,
    max_entries: usize,
}

#[derive(Default)]
struct InMemoryState {
    /// composite key -> the retained entry.
    seen: HashMap<String, RetainedEntry>,
    /// `retain_until` -> the keys that stop being retained at that instant.
    ///
    /// Eviction walks only the buckets that have actually expired. Sweeping `seen`
    /// instead is O(max_entries) — a million-entry scan, plus a map lookup per evicted
    /// entry — inside the one mutex every per-core serving runtime shares, in a future
    /// with no await point. At the ceiling that is a global serialization point on the
    /// request path, which is the opposite of what this store claims to be.
    by_expiry: BTreeMap<i64, Vec<String>>,
    /// Admitted inserts since the last prune; drives the eviction cadence.
    inserts_since_prune: u64,
    /// Retained entries per actor. The `Arc<str>` is shared with every entry charged
    /// to that actor, so an actor's name is dropped as soon as its last entry is
    /// pruned — the accounting map cannot outgrow the set it accounts for.
    per_actor: HashMap<Arc<str>, usize>,
}

/// One retained entry: who is holding it.
///
/// The instant it stops being retained is the `by_expiry` bucket it sits in, so it is
/// not repeated here — two copies of an expiry that eviction must agree on is a way for
/// them to disagree.
struct RetainedEntry {
    actor: Arc<str>,
}

/// A unix-seconds clock. Local to this module so the async in-memory store keeps its
/// eviction anchor in the default build — `redis_store`'s twin is feature-gated.
type UnixClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Wall-clock unix seconds; the production anchor for the inline prune.
fn system_clock() -> UnixClock {
    Box::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

/// How often (in admitted inserts) the async in-memory store evicts entries past
/// their retain-until.
///
/// Every accepted request adds one entry, and a signature-valid peer can stream
/// distinct fresh nonces at will, so without eviction the set grows with total
/// request volume rather than with the freshness window. Pruning on every insert
/// would itself be O(n); a small cadence amortises it while keeping the bound tight.
/// Mirrors the file-backed cache's `PRUNE_EVERY_N_INSERTS`.
const ASYNC_PRUNE_EVERY_N_INSERTS: u64 = 64;

/// Fail-closed ceiling on retained entries. Within a single freshness window a
/// pathological peer can present more distinct fresh nonces than the prune cadence
/// drains, so past this the store refuses further inserts with
/// [`ReplayStoreError::Unavailable`] (→ `mcp-re.replay_cache_unavailable`) rather
/// than growing without bound — never a silent allow. Mirrors the file-backed
/// cache's `MAX_ENTRIES`.
const ASYNC_MAX_ENTRIES: usize = 1_000_000;

/// The share of [`ASYNC_MAX_ENTRIES`] no single actor may occupy, as a divisor: the
/// reserve is `max_entries / ASYNC_RESERVE_DIVISOR`.
///
/// The ceiling alone is a global resource one signer can exhaust, and exhausting it
/// answers `mcp-re.replay_cache_unavailable` to EVERY other signer on the replica —
/// a signature-valid peer streaming distinct fresh nonces takes the whole replay tier
/// down with it. Holding a reserve back means the greedy actor hits its own wall while
/// the store still has room for everyone else.
const ASYNC_RESERVE_DIVISOR: usize = 5;

/// The per-actor retention budget, evaluated only when the store is under pressure.
///
/// `actors` is the number of actors currently holding entries. The budget is an equal
/// split of the SPENDABLE capacity — the ceiling minus the reserve — so the sum of
/// every actor's budget is `max_entries - reserve` for any number of actors, and the
/// reserve stays unspendable. That is the property the reserve exists for: an actor
/// holding nothing yet is still admitted while an actor over its share is refused.
///
/// Splitting the FULL ceiling instead would make the reserve reachable the moment a
/// second actor appears — `k` actors at `max/k` sum to exactly `max`, the ceiling is
/// hit, and the next signer is refused by the global bound with the reserve already
/// spent. That is the outage this budget was introduced to prevent, merely needing two
/// actors instead of one.
///
/// Minting identities to shrink everyone's share is not free: `actor` is the PRINCIPAL
/// the verifier resolved — an authenticated delegation credential rooted in a trust
/// anchor, with the keyid deliberately excluded (see [`mcp_re_core::ReplayKey`]), so a
/// subject cannot present as several actors by holding several keys.
///
/// Under pressure this is a fair share, which means an actor holding more than its
/// share is refused while its existing entries drain. That is the intended ordering —
/// the greedy signer stops before the quiet one — and it is bounded by the freshness
/// window, not permanent.
fn per_actor_budget(max_entries: usize, actors: usize) -> usize {
    let reserve = max_entries / ASYNC_RESERVE_DIVISOR;
    let spendable = max_entries.saturating_sub(reserve);
    (spendable / actors.max(1)).max(1)
}

/// Occupancy at which per-actor budgeting starts applying. Below it the store has room
/// for every caller, so budgeting could only refuse a request the store could have
/// served — one busy legitimate signer must not be throttled for being busy.
fn under_pressure(len: usize, max_entries: usize) -> bool {
    len >= max_entries.saturating_sub(max_entries / ASYNC_RESERVE_DIVISOR)
}

impl Default for InMemoryAsyncAtomicReplayStore {
    fn default() -> Self {
        InMemoryAsyncAtomicReplayStore {
            inner: std::sync::Arc::new(Mutex::new(InMemoryState::default())),
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
        // MCPS-08: an already-past `retain_until` is refused BEFORE recording, at the
        // store layer, rather than relying solely on the upstream freshness step
        // having run first. Recording it would write an entry the next prune drops,
        // making the nonce replayable while this call reported `Fresh`. Every other
        // store in the tree refuses it here; this one is the DEFAULT, so its being the
        // exception was the wrong way round.
        // Against the CALLER's `now` — the same clock the freshness gate used — as the
        // five sibling stores do. The store's own clock is the PRUNE anchor and only
        // that: pruning must not be driven by a caller-supplied value, and staleness
        // must not be judged against a clock the verifier never saw. A deployment whose
        // verifier runs on a different clock than this process would otherwise have
        // every entry refused as stale, which is a fail-closed outage rather than a
        // guard.
        if crate::shared_replay::is_stale_pre_store(retain_until, now_unix) {
            return Err(ReplayStoreError::Unavailable {
                details: "replay retain_until is already past; refusing to record a nonce \
                          that would not be retained"
                    .to_string(),
            });
        }
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

        // Opportunistic, bounded-cadence eviction. The anchor is the store's OWN
        // clock — NOT the caller's `retain_until`, which is derived from the request's
        // `expires` and can sit arbitrarily far ahead of real time, so using it would
        // over-evict still-live entries and reopen a replay window.
        state.inserts_since_prune = state.inserts_since_prune.saturating_add(1);
        if state.inserts_since_prune >= ASYNC_PRUNE_EVERY_N_INSERTS {
            state.inserts_since_prune = 0;
            let now = (self.clock)();
            let InMemoryState {
                seen,
                by_expiry,
                per_actor,
                ..
            } = &mut *state;
            // Only the buckets strictly before `now` have stopped being retained.
            // `split_off` leaves those behind and returns the live tail, so the work is
            // proportional to what actually expired — and a prune with nothing to do
            // costs one B-tree descent rather than a full scan.
            let live = by_expiry.split_off(&now);
            let dead = std::mem::replace(by_expiry, live);
            for (_retain_until, keys) in dead {
                for key in keys {
                    // A key can only leave `seen` through this loop, but the guard
                    // keeps the accounting honest if that ever stops being true.
                    let Some(entry) = seen.remove(&key) else {
                        continue;
                    };
                    // The per-actor charge is released with the entry it accounts for,
                    // and the actor's last release drops its name from the map
                    // entirely.
                    if let Some(held) = per_actor.get_mut(&entry.actor) {
                        *held -= 1;
                        if *held == 0 {
                            per_actor.remove(&entry.actor);
                        }
                    }
                }
            }
        }

        // Under pressure, spend what is left of the ceiling on the actors that are not
        // already holding more than their share. Refusing the greedy signer here is
        // what keeps the refusal from landing on every OTHER signer at the ceiling
        // below. Still `Unavailable` and never `Fresh`: an unrecorded nonce can be
        // replayed, so refusing is the only safe answer either way.
        if under_pressure(state.seen.len(), self.max_entries) {
            let budget = per_actor_budget(self.max_entries, state.per_actor.len());
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
                    self.max_entries
                );
                return Err(ReplayStoreError::Unavailable {
                    details: format!(
                        "in-memory async replay store: actor holds {held} of its {budget} \
                         retained-entry budget while the store is at {} of {} entries",
                        state.seen.len(),
                        self.max_entries
                    ),
                });
            }
        }

        // Fail-closed ceiling: refuse rather than grow without bound. Admitting a
        // request whose nonce is not retained would be the one unsafe option, since an
        // unrecorded nonce can be replayed — so this is `Unavailable`, never `Fresh`.
        if state.seen.len() >= self.max_entries {
            return Err(ReplayStoreError::Unavailable {
                details: format!(
                    "in-memory async replay store is at its {} entry ceiling",
                    self.max_entries
                ),
            });
        }

        // One `Arc<str>` per actor, shared by every entry charged to it, so the entry
        // map carries a pointer rather than a copy of the signer id.
        let actor: Arc<str> = match state.per_actor.get_key_value(actor) {
            Some((name, _)) => Arc::clone(name),
            None => Arc::from(actor),
        };
        *state.per_actor.entry(Arc::clone(&actor)).or_insert(0) += 1;
        state
            .by_expiry
            .entry(retain_until)
            .or_default()
            .push(key.to_string());
        state.seen.insert(key.to_string(), RetainedEntry { actor });
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

/// The async replay TIER the proxy's async serving path awaits (ADR-MCPRE-051
/// §4): the async analogue of [`crate::shared_replay::SharedReplayCache`]. Given a
/// `mcp_re_core::ReplayKey` (projected from the RFC 9421 five-tuple via
/// `HttpReplayKey::to_core_replay_key`), it composes the collision-safe composite
/// key and folds the clock skew IDENTICALLY to the sync path (via the shared
/// [`composite_replay_key`] / [`skew_folded_retain_until`] helpers), then AWAITS the
/// authoritative [`AsyncAtomicReplayStore`] insert. The store round-trip is the ONLY
/// awaited I/O on the request path.
///
/// Fail-closed: any store failure surfaces as [`ReplayCacheError::Unavailable`]
/// ⇒ `mcp-re.replay_cache_unavailable`, never a silent allow (ADR-MCPS-020).
#[derive(Clone)]
pub struct AsyncReplayTier {
    store: Arc<dyn AsyncAtomicReplayStore>,
    max_clock_skew_secs: i64,
    /// Shared by every clone, so the per-core tiers of one replica budget against one
    /// account rather than one each.
    ledger: Arc<RetentionLedger>,
}

impl AsyncReplayTier {
    /// Build the tier over `store`, applying the symmetric `max_clock_skew_secs`
    /// to each entry's retain-until (folded into the store TTL) exactly as the
    /// sync `SharedReplayCache` does.
    pub fn new(store: Arc<dyn AsyncAtomicReplayStore>, max_clock_skew_secs: i64) -> Self {
        AsyncReplayTier {
            store,
            max_clock_skew_secs,
            ledger: Arc::new(RetentionLedger::new(ASYNC_MAX_ENTRIES)),
        }
    }

    /// Override the retained-entry ceiling the per-actor budget is computed from
    /// (tests, and bounded embedders). A fresh ledger, so this is only meaningful
    /// before the tier serves anything.
    pub fn with_max_retained_entries(mut self, max_entries: usize) -> Self {
        self.ledger = Arc::new(RetentionLedger::new(max_entries));
        self
    }

    /// This tier's declared durability class — delegated to the backing store, so
    /// a strict/production startup can machine-check the object it actually holds
    /// (never a hardcoded `Durable`).
    pub fn durability_class(&self) -> ReplayDurabilityClass {
        self.store.durability_class()
    }

    /// AWAIT the authoritative atomic insert-if-absent for `key`. Composes the
    /// composite key and folds skew identically to the sync path; maps a store
    /// failure to the fail-closed [`ReplayCacheError::Unavailable`].
    ///
    /// `now_unix` is the instant the VERIFIER used for this request — the same reading
    /// the freshness gate was evaluated against. A store that bounds its own retention
    /// judges an already-past `retain_until` against it (MCPS-08); one that derives a
    /// server-side TTL reads its own clock and ignores it (see
    /// [`AsyncAtomicReplayStore`]). Passing a constant here would silently disable that
    /// guard in the in-memory store, which is the DEFAULT one.
    pub async fn check_and_insert(
        &self,
        key: &ReplayKey,
        now_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        let composite = composite_replay_key(&key.signer, &key.audience, &key.nonce);
        let retain_until = skew_folded_retain_until(key.expires_at_unix, self.max_clock_skew_secs);
        // Charged to the resolved PRINCIPAL, not to the signer slot: the slot carries
        // the keyid so distinct keys can never share a replay key, which would hand a
        // subject one budget per key it holds. Passed explicitly so a store never has
        // to recover it by parsing a key it did not compose.
        //
        // The charge is taken HERE, above the backend seam, so the bound holds for
        // every deployable adapter — see [`RetentionLedger`].
        let charge = Charge::reserve(&self.ledger, &key.principal, now_unix)
            .map_err(ReplayCacheError::from)?;
        let outcome = self
            .store
            .atomic_insert_if_absent(ReplayInsert::new(
                &composite,
                &key.principal,
                retain_until,
                now_unix,
            ))
            .await;
        match outcome {
            // The nonce is retained until `retain_until`, and so is its charge.
            Ok(ReplayDecision::Fresh) => {
                charge.commit(retain_until);
                Ok(ReplayDecision::Fresh)
            }
            // A replay adds no retention (the entry was already there), and a refusal
            // adds none either, so neither may leave the actor charged for one — the
            // charge is handed back when it drops here.
            other => other.map_err(ReplayCacheError::from),
        }
    }
}

/// The per-replica retention account the TIER keeps, so one signature-valid actor
/// cannot exhaust the replay tier whichever backend is configured.
///
/// The backends disagree about where retention lives — a bounded local set for the
/// in-memory reference, a server-side `SET NX PX` TTL for Redis, a lease per key for
/// etcd — and only the first of those has anything of its own to budget. A bound
/// implemented inside a backend therefore governs only the deployments that select
/// that backend. This one sits above the seam: every admitted nonce is charged to the
/// principal the verifier resolved, and an actor already holding more than its share
/// of a tier under pressure is refused before the store is touched.
///
/// The account is per replica, which is what a replica can observe: it bounds the
/// retention THIS node admits, and the shared store's total is that bound times the
/// fleet size. Refusals are [`ReplayStoreError::Unavailable`] and never `Fresh` — an
/// unrecorded nonce can be replayed, so refusing is the only safe answer.
struct RetentionLedger {
    state: Mutex<LedgerState>,
    max_entries: usize,
}

#[derive(Default)]
struct LedgerState {
    /// Entries charged to each actor — committed and outstanding alike. The `Arc<str>`
    /// is shared with every charge against that actor, so its name is dropped as soon
    /// as its last charge is released.
    per_actor: HashMap<Arc<str>, usize>,
    /// `retain_until` -> the actors whose entries stop being retained at that instant.
    /// Only committed charges appear here; walking it evicts exactly what expired.
    by_expiry: BTreeMap<i64, Vec<Arc<str>>>,
    /// Charges for nonces the store admitted.
    committed: usize,
    /// Charges taken for an insert whose outcome is not back yet. Counted against the
    /// ceiling too: without it, every request in flight at the bound would be admitted
    /// on the same free slot.
    outstanding: usize,
    /// Reservations since the last prune; drives the eviction cadence.
    inserts_since_prune: u64,
}

impl RetentionLedger {
    fn new(max_entries: usize) -> Self {
        RetentionLedger {
            state: Mutex::new(LedgerState::default()),
            max_entries: max_entries.max(1),
        }
    }

    /// Charge one prospective entry to `actor`, or refuse fail-closed.
    ///
    /// `now_unix` is the verifier's reading — the same instant the freshness gate used,
    /// and the same timeline the `retain_until` values in `by_expiry` were derived on.
    /// Pruning against a second, independent clock would evict against a different
    /// timeline than the one the entries were recorded on.
    fn reserve(&self, actor: &str, now_unix: i64) -> Result<Arc<str>, ReplayStoreError> {
        // A poisoned mutex is an OPERATIONAL failure — fail closed on the frozen
        // `mcp-re.replay_cache_unavailable` token, never a panic.
        let mut state = self
            .state
            .lock()
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("async replay tier retention ledger lock poisoned: {e}"),
            })?;
        state.inserts_since_prune = state.inserts_since_prune.saturating_add(1);
        if state.inserts_since_prune >= ASYNC_PRUNE_EVERY_N_INSERTS {
            state.inserts_since_prune = 0;
            state.prune(now_unix);
        }

        let held = state.committed.saturating_add(state.outstanding);
        // Under pressure, spend what is left of the ceiling on the actors that are not
        // already holding more than their share. Refusing the greedy signer here is
        // what keeps the refusal from landing on every OTHER signer at the ceiling
        // below.
        if under_pressure(held, self.max_entries) {
            let budget = per_actor_budget(self.max_entries, state.per_actor.len());
            let charged = state.per_actor.get(actor).copied().unwrap_or(0);
            if charged >= budget {
                // The wire token is frozen and says only `replay_cache_unavailable`,
                // which is also what a genuine backend outage says. Without this line
                // an operator paging on that token investigates store health while the
                // real cause is one signature-valid peer over its quota.
                eprintln!(
                    "mcp-re-proxy: replay budget refusal (NOT a store outage): actor holds \
                     {charged} of its {budget} entries with the tier at {held} of {}; \
                     actor={actor}",
                    self.max_entries
                );
                return Err(ReplayStoreError::Unavailable {
                    details: format!(
                        "async replay tier: actor holds {charged} of its {budget} \
                         retained-entry budget while the tier is at {held} of {} entries",
                        self.max_entries
                    ),
                });
            }
        }
        if held >= self.max_entries {
            return Err(ReplayStoreError::Unavailable {
                details: format!(
                    "async replay tier is at its {} retained-entry ceiling",
                    self.max_entries
                ),
            });
        }

        let actor: Arc<str> = match state.per_actor.get_key_value(actor) {
            Some((name, _)) => Arc::clone(name),
            None => Arc::from(actor),
        };
        *state.per_actor.entry(Arc::clone(&actor)).or_insert(0) += 1;
        state.outstanding = state.outstanding.saturating_add(1);
        Ok(actor)
    }

    /// The store admitted the nonce: the reservation becomes a retained charge, released
    /// when `retain_until` passes.
    fn commit(&self, actor: Arc<str>, retain_until: i64) {
        // A poisoned ledger cannot be repaired from here, and the request has already
        // been admitted by the authoritative store. Losing the charge under-counts the
        // actor, which is the direction that cannot refuse a legitimate request.
        if let Ok(mut state) = self.state.lock() {
            state.outstanding = state.outstanding.saturating_sub(1);
            state.committed = state.committed.saturating_add(1);
            state.by_expiry.entry(retain_until).or_default().push(actor);
        }
    }

    /// The store did not admit the nonce (a replay, or an operational failure), so the
    /// reservation retains nothing and is handed back.
    fn release(&self, actor: &Arc<str>) {
        if let Ok(mut state) = self.state.lock() {
            state.outstanding = state.outstanding.saturating_sub(1);
            state.discharge(actor);
        }
    }

    /// Entries currently charged to `actor` (test/inspection aid).
    #[cfg(test)]
    fn held_by(&self, actor: &str) -> usize {
        self.state
            .lock()
            .map(|s| s.per_actor.get(actor).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

/// One reservation, held for as long as its insert is in flight.
///
/// The charge is taken before the store round-trip and settled after it, and the
/// request in between can simply STOP: the serving path awaits the handler inside a
/// hyper service, so a peer that closes its connection (or a deadline that fires) drops
/// the future mid-await. Settling by hand on each exit path would leak a charge on
/// exactly that one, and a charge that is never handed back is permanent — an actor
/// that cancels in flight would walk the tier to its ceiling and fail every signer
/// closed. A guard cannot miss the path it was not written for.
struct Charge {
    ledger: Arc<RetentionLedger>,
    actor: Arc<str>,
    /// Set once the entry the charge accounts for exists, so `Drop` leaves it alone.
    committed: bool,
}

impl Charge {
    /// Charge one prospective entry to `actor`, or refuse fail-closed.
    fn reserve(
        ledger: &Arc<RetentionLedger>,
        actor: &str,
        now_unix: i64,
    ) -> Result<Charge, ReplayStoreError> {
        let actor = ledger.reserve(actor, now_unix)?;
        Ok(Charge {
            ledger: Arc::clone(ledger),
            actor,
            committed: false,
        })
    }

    /// The store admitted the nonce, so the reservation becomes retention that expires
    /// with it rather than with this request.
    fn commit(mut self, retain_until: i64) {
        self.committed = true;
        self.ledger.commit(Arc::clone(&self.actor), retain_until);
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        if !self.committed {
            self.ledger.release(&self.actor);
        }
    }
}

impl LedgerState {
    /// Release the charge for every entry whose retain-until has passed. `split_off`
    /// leaves the expired buckets behind and returns the live tail, so the work is
    /// proportional to what actually expired.
    fn prune(&mut self, now_unix: i64) {
        let live = self.by_expiry.split_off(&now_unix);
        let dead = std::mem::replace(&mut self.by_expiry, live);
        for (_retain_until, actors) in dead {
            for actor in actors {
                self.committed = self.committed.saturating_sub(1);
                self.discharge(&actor);
            }
        }
    }

    /// Drop one charge against `actor`, and the actor's name with its last charge.
    fn discharge(&mut self, actor: &Arc<str>) {
        if let Some(charged) = self.per_actor.get_mut(actor) {
            *charged -= 1;
            if *charged == 0 {
                self.per_actor.remove(actor);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every entry in these tests is charged to one signer; the per-actor budget
    /// has its own test below.
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

    /// The budget tightens as actors appear, and never below one entry.
    #[test]
    fn the_budget_reserves_headroom_and_splits_evenly() {
        // Solo: capped below the ceiling, so a newcomer always has room.
        assert_eq!(per_actor_budget(1_000_000, 1), 800_000);
        // Shared: an equal split of the SPENDABLE capacity, not of the ceiling.
        assert_eq!(per_actor_budget(1_000_000, 2), 400_000);
        assert_eq!(per_actor_budget(1_000_000, 100), 8_000);
        // Never zero — a budget of 0 would refuse every actor and close the tier.
        assert_eq!(per_actor_budget(10, 1_000), 1);
        assert!(under_pressure(800_000, 1_000_000));
        assert!(!under_pressure(799_999, 1_000_000));
    }

    /// The reserve must survive ANY number of actors, which is the whole point of it.
    ///
    /// Splitting the full ceiling makes the reserve reachable as soon as a second actor
    /// appears: `k` budgets of `max/k` sum to exactly `max`, so the store fills, the
    /// global ceiling refuses the next signer, and the outage the budget exists to
    /// prevent needs two actors rather than one.
    #[test]
    fn no_number_of_actors_can_spend_the_reserve() {
        const MAX: usize = 1_000_000;
        let reserve = MAX / ASYNC_RESERVE_DIVISOR;
        for actors in 1..=64usize {
            let total = per_actor_budget(MAX, actors) * actors;
            assert!(
                total <= MAX - reserve,
                "{actors} actors may hold {total} of {MAX}, which leaves \
                 {} against a reserve of {reserve}",
                MAX.saturating_sub(total)
            );
        }
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

    /// A store that declares `Durable` and bounds nothing — the shape of BOTH
    /// deployable backends, whose retention is a server-side TTL (Redis `SET NX PX`)
    /// or a per-key lease (etcd) and which therefore hold no local set to budget.
    #[derive(Default)]
    struct UnboundedDurableStore {
        seen: Mutex<HashSet<String>>,
        /// Round-trips this store was asked for. The bound is only worth having if it
        /// refuses BEFORE the shared store is touched, so the count is the assertion.
        dispatches: std::sync::atomic::AtomicUsize,
    }

    impl UnboundedDurableStore {
        fn dispatches(&self) -> usize {
            self.dispatches.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl AsyncAtomicReplayStore for UnboundedDurableStore {
        fn atomic_insert_if_absent<'a>(
            &'a self,
            insert: ReplayInsert<'a>,
        ) -> ReplayDecisionFuture<'a> {
            Box::pin(async move {
                self.dispatches
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut seen = self.seen.lock().expect("seen");
                Ok(if seen.insert(insert.key.to_string()) {
                    ReplayDecision::Fresh
                } else {
                    ReplayDecision::Replay
                })
            })
        }

        fn durability_class(&self) -> ReplayDurabilityClass {
            ReplayDurabilityClass::Durable
        }
    }

    fn replay_key(actor: &str, nonce: &str, expires_at_unix: i64) -> ReplayKey {
        ReplayKey {
            // The signer slot carries the keyid; the budget is charged to `principal`.
            signer: format!("{actor}#key-1"),
            principal: actor.to_string(),
            audience: "did:example:verifier".to_string(),
            nonce: nonce.to_string(),
            expires_at_unix,
        }
    }

    /// The bound has to hold for the backends a shipped proxy can actually select.
    /// `app.rs` refuses any tier whose store declares `SingleProcessReference`, so a
    /// budget implemented only inside the in-memory store governs no deployment: the
    /// two survivors delegate retention to a server-side TTL and budget nothing.
    #[test]
    fn the_tier_budgets_a_durable_backend_that_budgets_nothing_itself() {
        // max_entries 10 ⇒ reserve 2, pressure at 8, solo budget 8.
        let store = Arc::new(UnboundedDurableStore::default());
        let tier = AsyncReplayTier::new(Arc::clone(&store) as Arc<dyn AsyncAtomicReplayStore>, 0)
            .with_max_retained_entries(10);
        assert_eq!(
            tier.durability_class(),
            ReplayDurabilityClass::Durable,
            "the store under test must be one a production startup accepts"
        );
        const GREEDY: &str = "did:example:greedy";
        const QUIET: &str = "did:example:quiet";

        block(async {
            let mut admitted = 0usize;
            for i in 0..20 {
                match tier
                    .check_and_insert(&replay_key(GREEDY, &format!("greedy-{i}"), 9_000), 1_000)
                    .await
                {
                    Ok(ReplayDecision::Fresh) => admitted += 1,
                    Err(ReplayCacheError::Unavailable { .. }) => break,
                    other => panic!("unexpected decision {other:?}"),
                }
            }
            assert_eq!(
                admitted, 8,
                "one actor must stop at its budget, not at the global ceiling"
            );
            assert_eq!(tier.ledger.held_by(GREEDY), 8);

            // THE PROPERTY: a signer that has sent nothing is still served while the
            // greedy one is refused.
            assert_eq!(
                tier.check_and_insert(&replay_key(QUIET, "quiet-0", 9_000), 1_000)
                    .await
                    .expect("the quiet actor must still be admitted"),
                ReplayDecision::Fresh
            );

            // And the greedy one stays refused — fail closed on the frozen token, never
            // an allow, because an unrecorded nonce can be replayed.
            let before = store.dispatches();
            let refused = tier
                .check_and_insert(&replay_key(GREEDY, "greedy-99", 9_000), 1_000)
                .await
                .expect_err("over budget");
            assert_eq!(
                refused.to_mcp_re_error(),
                mcp_re_core::McpReError::ReplayCacheUnavailable
            );

            // THE MECHANISM: the refusal happens above the backend seam, so the actor
            // over its share cannot spend the shared store's capacity — not even the
            // round-trip. A nonce it re-presents is refused on the same token rather
            // than reported as a replay, which is the direction that is safe: an
            // over-budget actor is denied either way, and asking the store would mean
            // performing the very insert the budget refuses to fund.
            assert!(tier
                .check_and_insert(&replay_key(GREEDY, "greedy-0", 9_000), 1_000)
                .await
                .is_err());
            assert_eq!(
                store.dispatches(),
                before,
                "an over-budget actor must not reach the shared store at all"
            );
        });
    }

    /// A replay retains nothing new, so it must not leave the actor charged for one —
    /// otherwise re-sending one nonce would spend an actor's whole budget.
    #[test]
    fn a_replay_hands_the_charge_back() {
        let tier = AsyncReplayTier::new(Arc::new(UnboundedDurableStore::default()), 0)
            .with_max_retained_entries(10);
        const ACTOR: &str = "did:example:repeater";
        block(async {
            for _ in 0..5 {
                let _ = tier
                    .check_and_insert(&replay_key(ACTOR, "one-nonce", 9_000), 1_000)
                    .await;
            }
            assert_eq!(
                tier.ledger.held_by(ACTOR),
                1,
                "one retained nonce is one charge, however often it is presented"
            );
        });
    }

    /// A store whose insert never completes — the shape of a wedged backend, and the
    /// case where the caller stops waiting.
    struct NeverAnsweringStore;

    impl AsyncAtomicReplayStore for NeverAnsweringStore {
        fn atomic_insert_if_absent<'a>(
            &'a self,
            _insert: ReplayInsert<'a>,
        ) -> ReplayDecisionFuture<'a> {
            Box::pin(std::future::pending())
        }

        fn durability_class(&self) -> ReplayDurabilityClass {
            ReplayDurabilityClass::Durable
        }
    }

    /// A request that is abandoned mid-insert must hand its charge back. The serving
    /// path awaits the handler inside a hyper service, so a peer that closes its
    /// connection drops the future while the store round-trip is outstanding — and a
    /// charge that is never handed back is permanent, so an actor cancelling in flight
    /// would walk the tier to its ceiling and fail every signer closed.
    #[test]
    fn an_abandoned_insert_does_not_leak_its_charge() {
        let tier =
            AsyncReplayTier::new(Arc::new(NeverAnsweringStore), 0).with_max_retained_entries(10);
        const ACTOR: &str = "did:example:quitter";
        block(async {
            for i in 0..50 {
                let key = replay_key(ACTOR, &format!("nonce-{i}"), 9_000);
                // Give it a chance to reserve and reach the store, then walk away.
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(1),
                        tier.check_and_insert(&key, 1_000)
                    )
                    .await
                    .is_err(),
                    "the store under test never answers"
                );
            }
            assert_eq!(
                tier.ledger.held_by(ACTOR),
                0,
                "an abandoned request retains nothing, so it must hold no charge"
            );
            // And the tier is still able to serve: a leak of 50 against a ceiling of 10
            // would have closed it for everyone.
            assert!(tokio::time::timeout(
                std::time::Duration::from_millis(1),
                tier.check_and_insert(&replay_key("did:example:other", "n", 9_000), 1_000)
            )
            .await
            .is_err());
        });
    }

    /// The charge is released with the retention it accounts for, so a busy actor is
    /// not permanently penalised for traffic that has long since expired.
    #[test]
    fn the_tier_releases_charges_once_their_retention_expires() {
        let tier = AsyncReplayTier::new(Arc::new(UnboundedDurableStore::default()), 0)
            .with_max_retained_entries(10_000);
        const ACTOR: &str = "did:example:busy";
        block(async {
            // A prune runs on the 64th reservation; the first 63 retain until 1_500.
            for i in 0..(ASYNC_PRUNE_EVERY_N_INSERTS - 1) {
                tier.check_and_insert(&replay_key(ACTOR, &format!("nonce-{i}"), 1_500), 1_000)
                    .await
                    .unwrap();
            }
            assert_eq!(
                tier.ledger.held_by(ACTOR) as u64,
                ASYNC_PRUNE_EVERY_N_INSERTS - 1
            );

            // Past their retain-until, the next reservation triggers the cadence.
            tier.check_and_insert(&replay_key(ACTOR, "nonce-live", 9_000), 2_000)
                .await
                .unwrap();
            assert_eq!(
                tier.ledger.held_by(ACTOR),
                1,
                "only the still-live entry is still charged"
            );
        });
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
