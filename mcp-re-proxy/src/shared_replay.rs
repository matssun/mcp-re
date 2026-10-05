//! SHARED, server-side-ATOMIC replay cache for HORIZONTALLY-SCALED replay safety
//! (issue #3837).
//!
//! A node-local cache cannot prevent cross-node replays: each proxy process sees only
//! its own state, so a nonce admitted on one node is unknown to every other. This module
//! puts the store behind the same `mcp_re_core::ReplayCache` trait so that multiple proxy
//! processes / hosts share one replay-state store and a nonce accepted on one node is
//! rejected as a replay on every other node. It is the only shape a replay state takes.
//!
//! ## Layering — backend-agnostic core + opt-in backend adapter
//!
//! The shared-cache SEMANTICS are factored out of any specific backend:
//!   * [`AtomicReplayStore`] is the minimal shared primitive — a single
//!     server-side-atomic *insert-if-absent-with-TTL* op. Any shared store
//!     (Redis, a SQL row with a unique key, a consensus KV, …) can implement it.
//!   * [`SharedReplayCache`] holds a `Box<dyn AtomicReplayStore>` and impls
//!     `mcp_re_core::ReplayCache`. It builds a collision-safe composite key from
//!     `(signer, audience, nonce)`, retains each entry for the deployment's
//!     [`FreshnessWindow`], delegates atomicity to the store, and FAILS
//!     CLOSED on any store error (→ `mcp-re.replay_cache_unavailable`).
//!   * [`InMemoryAtomicReplayStore`] is a REAL reference store (an
//!     `Arc<Mutex<…>>`) — like `InMemoryReplayCache`, not a test mock. Because it
//!     is shared by `Arc`, the SAME store can back two `SharedReplayCache`
//!     instances, modelling two proxy nodes against one shared backend; that is
//!     the default-build, Bazel-tested path that proves cross-node rejection.
//!
//! Backends in tree:
//!   * [`InMemoryAtomicReplayStore`] (THIS module) — the default-build reference
//!     store. It is a single-process store and does NOT, on its own, give
//!     horizontally-scaled replay safety across SEPARATE proxy processes/hosts;
//!     it proves the cross-instance property only within one process (two
//!     `SharedReplayCache` over one cloned `Arc`).
//!
//! The cross-process replay backends are asynchronous: `async_redis_store` and
//! `async_etcd_store` (inline code, NOT intra-doc links — each module is compiled only
//! under its own non-default feature and is absent from the default-feature doc build)
//! serve the [`AsyncReplayTier`](crate::async_replay::AsyncReplayTier) the serving path
//! awaits, and do not implement this module's synchronous [`AtomicReplayStore`].
//!
//! The DEFAULT build ships ONLY the in-memory reference store and gains ZERO new
//! dependencies, so the default build does NOT provide cross-process replay safety —
//! that "MUST NOT be claimed" caveat is scoped to the default build.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::sha256_hash_id;
use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;

use crate::config_state::FreshnessWindow;

/// An operational failure of an [`AtomicReplayStore`] (the shared backend could
/// not be reached or did not answer).
///
/// Mapped to [`ReplayCacheError::Unavailable`] via the `From` impl below, which
/// in turn maps to `mcp-re.replay_cache_unavailable` — so a backend failure FAILS
/// CLOSED and never falls back to "allow".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayStoreError {
    /// The shared store could not be reached or otherwise failed the op.
    #[error("shared replay store unavailable: {details}")]
    Unavailable {
        /// Human-readable diagnostic; never part of any wire token.
        details: String,
    },
}

impl From<ReplayStoreError> for ReplayCacheError {
    fn from(err: ReplayStoreError) -> ReplayCacheError {
        match err {
            ReplayStoreError::Unavailable { details } => ReplayCacheError::Unavailable { details },
        }
    }
}

/// MCPS-08 defensive pre-store guard: `true` when the remaining window
/// `retain_until - now` is NON-POSITIVE (the skew-folded retain-until is at or
/// before `now`), i.e. the request is ALREADY STALE and MUST be rejected BEFORE
/// the shared store is consulted, fail closed — never recorded and reported
/// `Fresh`.
///
/// Pure (no clock, no I/O) so the boundary is unit-testable. Every store passes
/// its OWN clock's `now`, so the layer enforces the ADR's explicit pre-store
/// rejection of a non-positive TTL defensively, instead of depending SOLELY on the
/// upstream `mcp-re-core` freshness step running before replay.
pub(crate) fn is_stale_pre_store(retain_until_unix: i64, now_unix: i64) -> bool {
    retain_until_unix.saturating_sub(now_unix) <= 0
}

/// Build the COLLISION-SAFE composite replay key for the `(signer, audience,
/// nonce)` triple (ADR-MCPRE-051 §4 replay key).
///
/// Naive concatenation aliases distinct tuples (`("a","bc",…)` and `("ab","c",…)`
/// would collide), so each field is length-prefixed in BYTES (`<len>:<field>`) —
/// making the preimage injective regardless of field content — then hashed with
/// `mcp_re_core::sha256_hash_id` to a fixed, opaque, store-safe key.
///
/// This is the SINGLE source of the replay key formula: both the synchronous
/// [`SharedReplayCache`] and the async replay tier
/// ([`crate::async_replay`]) compose keys through THIS function, so a nonce
/// inserted via the sync path is recognised as a replay via the async path and
/// vice versa (cross-path coherence is a correctness requirement, not an accident
/// of two matching literals).
pub(crate) fn composite_replay_key(signer: &str, audience: &str, nonce: &str) -> String {
    let preimage = format!(
        "{}:{}|{}:{}|{}:{}",
        signer.len(),
        signer,
        audience.len(),
        audience,
        nonce.len(),
        nonce,
    );
    sha256_hash_id(preimage.as_bytes())
}

/// The minimal SHARED, server-side-ATOMIC primitive a [`SharedReplayCache`] needs
/// from any backing store.
///
/// A single op — *insert this key if absent, with a server-side TTL* — carries
/// all the atomicity the cache requires: the absent-check and the insert MUST
/// happen as one atomic step in the store (e.g. Redis `SET key v NX PX ttl`), so
/// two nodes racing on the same nonce cannot both observe it absent. The store
/// owns expiry via the TTL; there is no separate prune step (contrast the
/// in-process caches' explicit `prune`).
///
/// `&self` (not `&mut self`): a shared store is consulted concurrently by many
/// callers, so implementations use interior synchronization / a connection pool.
pub trait AtomicReplayStore {
    /// Atomically insert `key` iff it is absent, with a TTL derived from
    /// `expires_at_unix` (already the skew-folded `retain_until = expires_at +
    /// skew`, mirroring `InMemoryReplayCache`) relative to the CURRENT time.
    ///
    /// The trait carries no clock: every implementor reads its OWN clock for
    /// "now", refuses a retain-until at or before it, and derives any server-side
    /// TTL (e.g. Redis `PX`) from it. Clamp any derived duration to non-negative.
    ///
    /// Returns [`ReplayDecision::Fresh`] if the key was absent and is now
    /// recorded, [`ReplayDecision::Replay`] if it was already present, or
    /// [`ReplayStoreError`] on an operational failure (→ fail closed).
    fn insert_if_absent(
        &self,
        key: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayStoreError>;

    /// This store's self-declared [`ReplayDurabilityClass`] (issue #78,
    /// ADR-MCPS-020). A [`SharedReplayCache`] DELEGATES its own
    /// `durability_class()` to this, so the durability declaration is anchored to
    /// the store that actually persists nonces, NOT hardcoded on the cache wrapper.
    ///
    /// The default is the conservative
    /// [`ReplayDurabilityClass::SingleProcessReference`] (fail closed): a store that
    /// does not explicitly override this — including any future backend that forgets
    /// to — is treated as the non-durable, single-process reference and can never
    /// silently pass a strict/production durability gate. Only a genuinely durable
    /// / cross-process store (the Redis and etcd backends) overrides this to honestly
    /// return [`ReplayDurabilityClass::Durable`]. This is a PURE, type-level
    /// capability (no IO, no async) — safe to keep `mcp-re-core` pure
    /// (ADR-MCPS-011/012) since it only returns the pure `mcp-re-core` enum.
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::SingleProcessReference
    }
}

/// A [`ReplayCache`] backed by a shared [`AtomicReplayStore`], giving
/// horizontally-scaled replay safety: a nonce accepted on one node is rejected on
/// every node sharing the store.
///
/// `check_and_insert` derives each entry's retain-until from the deployment's
/// [`FreshnessWindow`] — the projection the async tier folds through, so the two paths
/// retain a nonce for exactly as long as the verifier may still accept its request —
/// builds a collision-safe composite key from `(signer, audience, nonce)`, and delegates
/// the atomic check-and-insert to the store. Any store error fails closed.
pub struct SharedReplayCache {
    store: Box<dyn AtomicReplayStore + Send + Sync>,
    freshness: FreshnessWindow,
}

impl SharedReplayCache {
    /// Build a shared cache over `store`, retaining each entry for as long as `freshness`
    /// says the verifier may accept its request.
    ///
    /// The window, not a skew: a [`FreshnessWindow`] is bounded at construction, so a
    /// negative skew — which would retain an entry for less time than its request stays
    /// acceptable — is not a value this constructor can be handed.
    pub fn new(
        store: Box<dyn AtomicReplayStore + Send + Sync>,
        freshness: FreshnessWindow,
    ) -> Self {
        SharedReplayCache { store, freshness }
    }

    /// Build a COLLISION-SAFE composite key for the `(signer, audience, nonce)`
    /// triple. Delegates to the shared [`composite_replay_key`] so the sync and
    /// async replay paths key identically (cross-path coherence).
    fn composite_key(signer: &str, audience: &str, nonce: &str) -> String {
        composite_replay_key(signer, audience, nonce)
    }
}

impl ReplayCache for SharedReplayCache {
    fn check_and_insert(
        &self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        let key = SharedReplayCache::composite_key(signer, audience, nonce);
        // The retain-until instant is the window's, handed to the store as an absolute
        // instant. The pure ReplayCache trait carries NO clock: each store derives "now"
        // and its TTL from its OWN clock (the proxy's impure edge). The decision
        // (Fresh/Replay) does NOT depend on the TTL value; only eviction timing does.
        let retain_until = self.freshness.replay_retain_until(expires_at_unix);
        Ok(self.store.insert_if_absent(&key, retain_until)?)
    }

    /// DELEGATES to the backing [`AtomicReplayStore`]'s own
    /// [`durability_class`](AtomicReplayStore::durability_class) (issue #78,
    /// ADR-MCPS-020) — the wrapper does NOT hardcode `Durable`.
    ///
    /// A `SharedReplayCache` is only as durable as the store behind it: backed by a
    /// genuinely durable / cross-process store (Redis, etcd) it reports
    /// [`ReplayDurabilityClass::Durable`]; backed by the single-process
    /// [`InMemoryAtomicReplayStore`] reference it reports the conservative
    /// [`ReplayDurabilityClass::SingleProcessReference`] (the store's default), so an
    /// in-process-only shared cache can NOT masquerade as durable and CANNOT clear
    /// the strict object-level durability gate. The strength of any horizontal claim
    /// beyond mere durability is asserted separately by the configured
    /// `ReplayDurabilityTier`.
    fn durability_class(&self) -> ReplayDurabilityClass {
        self.store.durability_class()
    }
}

/// A REAL, shared in-memory [`AtomicReplayStore`] reference implementation (NOT a
/// test mock — the in-memory analogue of `InMemoryReplayCache`, usable wherever a
/// single multi-threaded process wants a shared store without an external
/// service).
///
/// State is an `Arc<Mutex<BTreeMap<key, retain_until>>>`, so CLONING the store
/// shares the SAME underlying map. That is what lets two [`SharedReplayCache`]
/// instances model two proxy nodes over one shared backend: insert via one,
/// replay-rejected via the other. The mutex makes the absent-check + insert
/// atomic, mirroring the server-side atomicity a real backend (Redis `SET NX`)
/// provides.
///
/// There is no background clock: an entry is a replay until [`prune`](InMemoryAtomicReplayStore::prune)
/// evicts it (the absolute `retain_until` carried per entry is the eviction
/// boundary).
/// Fail-closed ceiling on retained entries in the in-memory reference store
/// (finding #140). Unlike a durable/cross-process backend (Redis/etcd) this store
/// has no server-side TTL and no production prune scheduler, so without a cap a
/// peer streaming distinct fresh nonces grows it without bound. At the ceiling
/// `insert_if_absent` fails closed (Unavailable) rather than allow or grow
/// unbounded; an explicit `prune` drains the backlog as entries expire.
const MAX_ATOMIC_STORE_ENTRIES: usize = 1_000_000;

/// How often the in-memory shared store evicts expired entries inline.
///
/// Bounded cadence rather than every insert: the sweep is O(n) over the map, and the
/// ceiling only needs headroom to reappear, not to be exact.
const PRUNE_EVERY_N_INSERTS: usize = 64;

/// Wall-clock Unix seconds anchoring the pre-store staleness guard and the inline
/// eviction.
///
/// An unreadable or pre-epoch clock reads as `i64::MAX`, so every insert is
/// refused pre-store (Unavailable) rather than admitted against a bogus "now".
fn wall_clock_unix() -> i64 {
    unix_seconds(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH))
}

/// Whole Unix seconds of a clock reading; a reading before the epoch, or one that
/// does not fit `i64`, is `i64::MAX`.
fn unix_seconds(since_epoch: Result<std::time::Duration, std::time::SystemTimeError>) -> i64 {
    since_epoch.map_or(i64::MAX, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[derive(Clone)]
pub struct InMemoryAtomicReplayStore {
    /// `composite_key -> retain_until` (absolute Unix seconds).
    seen: Arc<Mutex<BTreeMap<String, i64>>>,
    /// Inserts since the last inline eviction pass, under the same lock as `seen`.
    /// Clones share it, because they share the map.
    inserts_since_prune: Arc<Mutex<usize>>,
    /// Fail-closed entry ceiling (defaults to [`MAX_ATOMIC_STORE_ENTRIES`]). Held
    /// as a field so tests can exercise the ceiling cheaply; production always
    /// uses the default.
    max_entries: usize,
    /// The anchor of the pre-store staleness guard and the inline sweep. Shared with
    /// clones, so every handle onto the same map judges against the same notion of
    /// now.
    clock: UnixClock,
}

/// A unix-seconds clock, behind an `Arc` because the store is cloned to share state.
type UnixClock = Arc<dyn Fn() -> i64 + Send + Sync>;

impl Default for InMemoryAtomicReplayStore {
    fn default() -> Self {
        InMemoryAtomicReplayStore::new()
    }
}

impl InMemoryAtomicReplayStore {
    /// Construct an empty shared store. Clone it to share the SAME state.
    pub fn new() -> Self {
        InMemoryAtomicReplayStore {
            seen: Arc::new(Mutex::new(BTreeMap::new())),
            inserts_since_prune: Arc::new(Mutex::new(0)),
            max_entries: MAX_ATOMIC_STORE_ENTRIES,
            clock: Arc::new(wall_clock_unix),
        }
    }

    /// Test-only: override the fail-closed entry ceiling so the ceiling path can
    /// be exercised without inserting [`MAX_ATOMIC_STORE_ENTRIES`] entries.
    #[cfg(test)]
    fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Test-only: inject a fixed clock so the inline sweep's boundary is observable
    /// without racing the wall clock.
    #[cfg(test)]
    fn with_clock(mut self, clock: UnixClock) -> Self {
        self.clock = clock;
        self
    }

    /// Evict every entry whose `retain_until < now_unix` (an explicit prune; this
    /// reference store has no background clock). After eviction the key is
    /// [`ReplayDecision::Fresh`] again — safe, because past its retain-until the
    /// nonce can no longer pass the freshness window.
    pub fn prune(&self, now_unix: i64) {
        if let Ok(mut map) = self.seen.lock() {
            map.retain(|_, &mut retain_until| retain_until >= now_unix);
        }
    }

    /// Number of live entries (test/inspection aid). A poisoned lock counts as 0.
    pub fn len(&self) -> usize {
        self.seen.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Whether the store holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AtomicReplayStore for InMemoryAtomicReplayStore {
    fn insert_if_absent(
        &self,
        key: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayStoreError> {
        let now = (self.clock)();
        // MCPS-08 defensive pre-store rejection: an already-stale request (a
        // non-positive remaining window against this store's own clock) is rejected
        // fail-closed BEFORE the store is consulted, never recorded and reported
        // `Fresh`. It enforces the contract at this layer rather than relying solely
        // on the upstream `mcp-re-core` freshness step running before replay.
        if is_stale_pre_store(expires_at_unix, now) {
            return Err(ReplayStoreError::Unavailable {
                details: format!(
                    "replay request already stale: retain_until ({expires_at_unix}) \
                     is at or before now ({now}) — rejected pre-store (MCPS-08, \
                     fail closed) rather than recorded as Fresh"
                ),
            });
        }
        // A poisoned mutex is an operational failure → fail closed (Unavailable),
        // never a silent "allow".
        let mut map = self
            .seen
            .lock()
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("shared store mutex poisoned: {e}"),
            })?;
        if map.contains_key(key) {
            return Ok(ReplayDecision::Replay);
        }
        // INLINE EVICTION, on a bounded cadence, anchored on the store's own `now`.
        //
        // The ceiling below is fail-closed, but nothing scheduled a prune: `prune` is
        // an explicit method no production caller invokes, so once the map filled the
        // store returned `Unavailable` for every subsequent nonce FOREVER — a
        // permanent brick, not a backpressure window, because the expired entries that
        // would have made room were never removed. Evicting here is what makes the
        // ceiling a bound rather than a terminal state.
        //
        // The boundary is `>=`, the same one [`Self::prune`] and every other store in
        // the tree apply: an entry is KEPT through its `retain_until` and dropped only
        // strictly past it. Both directions are safe — past `retain_until` the nonce
        // can no longer pass the freshness window — but one store applying two
        // boundaries would put its two code paths a second apart.
        if let Ok(mut since) = self.inserts_since_prune.lock() {
            *since = since.saturating_add(1);
            if *since >= PRUNE_EVERY_N_INSERTS {
                *since = 0;
                map.retain(|_, &mut until| until >= now);
            }
        }
        // Fail-closed ceiling (finding #140): this reference store has no
        // server-side TTL, so past the ceiling it refuses with Unavailable
        // (→ `mcp-re.replay_cache_unavailable`, fail closed) rather than grow
        // unbounded — never a silent "allow". (A genuinely durable/cross-process
        // backend — Redis/etcd — instead self-evicts via a server-side TTL and is
        // exempt.)
        if map.len() >= self.max_entries {
            return Err(ReplayStoreError::Unavailable {
                details: format!(
                    "in-memory shared replay store at capacity ({} entries); refusing further nonces until expired entries are pruned",
                    self.max_entries
                ),
            });
        }
        // `expires_at_unix` is the already-skew-folded retain-until instant.
        map.insert(key.to_string(), expires_at_unix);
        Ok(ReplayDecision::Fresh)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::Mutex;

    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    use super::is_stale_pre_store;
    use super::unix_seconds;
    use super::AtomicReplayStore;
    use super::InMemoryAtomicReplayStore;
    use super::ReplayStoreError;
    use super::SharedReplayCache;
    use super::PRUNE_EVERY_N_INSERTS;

    /// The ceiling must be a BACKPRESSURE window, not a terminal state. Without an
    /// inline sweep nothing ever removed an expired entry — `prune` is an explicit
    /// method no production caller invokes — so once the map filled, every subsequent
    /// nonce got `Unavailable` for the life of the process.
    #[test]
    fn a_full_store_recovers_once_its_entries_expire() {
        const FILLED_AT: i64 = 1_000;
        const LATER: i64 = 2_000;
        let now = Arc::new(AtomicI64::new(FILLED_AT));
        let clock = Arc::clone(&now);
        let store = InMemoryAtomicReplayStore::new()
            .with_max_entries(4)
            .with_clock(Arc::new(move || clock.load(Ordering::SeqCst)));
        // Fill it with entries that are live when recorded, then let the store's own
        // clock pass their retain-until so the sweep can reclaim them.
        for i in 0..4 {
            store
                .insert_if_absent(&format!("k{i}"), FILLED_AT + 1)
                .expect("fills");
        }
        assert!(
            store.insert_if_absent("overflow", LATER + 1).is_err(),
            "the ceiling refuses before the sweep has run"
        );
        now.store(LATER, Ordering::SeqCst);
        // The sweep runs on a bounded cadence, so drive enough attempts to reach it.
        // Every attempt before the pass is refused; none ever admits a replay.
        let mut admitted = None;
        for i in 0..PRUNE_EVERY_N_INSERTS * 2 {
            if let Ok(decision) = store.insert_if_absent(&format!("later{i}"), LATER + 1) {
                admitted = Some(decision);
                break;
            }
        }
        assert_eq!(
            admitted,
            Some(ReplayDecision::Fresh),
            "expired entries must be reclaimed so the store recovers"
        );
    }
    /// One store, one eviction boundary. The explicit `prune` keeps an entry through
    /// its `retain_until` (`>=`), and the inline sweep — the path production actually
    /// takes, since nothing calls `prune` — must agree, or the two code paths of one
    /// store drop an entry a second apart while a doc elsewhere asserts they were
    /// unified.
    #[test]
    fn the_inline_sweep_uses_the_same_boundary_as_the_explicit_prune() {
        const NOW: i64 = 1_000;
        let now = Arc::new(AtomicI64::new(NOW - 1));
        let clock = Arc::clone(&now);
        let store = InMemoryAtomicReplayStore::new()
            .with_clock(Arc::new(move || clock.load(Ordering::SeqCst)));
        // Retained until exactly `NOW` — the instant the two boundaries disagree on.
        for i in 0..PRUNE_EVERY_N_INSERTS - 1 {
            store
                .insert_if_absent(&format!("boundary{i}"), NOW)
                .expect("records");
        }
        // The clock reaches `NOW`; the next insert is the one that trips the sweep
        // cadence.
        now.store(NOW, Ordering::SeqCst);
        store
            .insert_if_absent("trigger", NOW + 5_000)
            .expect("records");
        assert_eq!(
            store.len(),
            PRUNE_EVERY_N_INSERTS,
            "an entry is kept THROUGH its retain_until on the inline path too"
        );

        // And the explicit prune, on the same store at the same instant, agrees.
        store.prune(NOW);
        assert_eq!(store.len(), PRUNE_EVERY_N_INSERTS);
        // One second past it, both drop the boundary entries.
        store.prune(NOW + 1);
        assert_eq!(store.len(), 1, "only the still-live entry survives");
    }

    use crate::config_state::FreshnessWindow;
    use mcp_re_core::McpReError;
    use mcp_re_core::ReplayCache;
    use mcp_re_core::ReplayCacheError;
    use mcp_re_core::ReplayDecision;
    use mcp_re_core::ReplayDurabilityClass;

    const SIGNER: &str = "did:example:host";
    const AUD: &str = "did:example:verifier";
    const NONCE: &str = "nonce-aaaaaaaaaaaaaaaaaaaaaa";
    const EXPIRES: i64 = 1_779_998_700;
    const SKEW: i64 = 30;
    /// The fixture clock: ten minutes before `EXPIRES`, so every fixture request is live.
    const FIXTURE_NOW: i64 = EXPIRES - 600;

    /// The deployment window every fixture cache retains under.
    fn window() -> FreshnessWindow {
        FreshnessWindow::new(SKEW).expect("SKEW is inside the verifier's bound")
    }

    /// An in-memory store whose clock reads [`FIXTURE_NOW`].
    fn fixture_store() -> InMemoryAtomicReplayStore {
        InMemoryAtomicReplayStore::new().with_clock(Arc::new(|| FIXTURE_NOW))
    }

    /// A store whose every call is an operational failure — exercises the
    /// fail-closed mapping (the in-memory reference store has no failure path
    /// short of a poisoned mutex).
    struct AlwaysUnavailableStore;

    impl AtomicReplayStore for AlwaysUnavailableStore {
        fn insert_if_absent(
            &self,
            _key: &str,
            _expires_at_unix: i64,
        ) -> Result<ReplayDecision, ReplayStoreError> {
            Err(ReplayStoreError::Unavailable {
                details: "shared backend unreachable".to_string(),
            })
        }
    }

    /// A test double modelling a genuinely durable / cross-process backend (Redis
    /// or etcd in production): it OVERRIDES `durability_class()` to `Durable`. It
    /// exists only to prove the SharedReplayCache DELEGATES its declared class to
    /// the backing store (a real durable store ⇒ the cache declares Durable),
    /// without compiling a feature-gated Redis/etcd backend into the default build.
    #[derive(Clone, Default)]
    struct DurableModelStore {
        seen: Arc<Mutex<BTreeMap<String, i64>>>,
    }

    impl AtomicReplayStore for DurableModelStore {
        fn insert_if_absent(
            &self,
            key: &str,
            expires_at_unix: i64,
        ) -> Result<ReplayDecision, ReplayStoreError> {
            let mut map = self
                .seen
                .lock()
                .map_err(|e| ReplayStoreError::Unavailable {
                    details: format!("durable model store poisoned: {e}"),
                })?;
            if map.contains_key(key) {
                return Ok(ReplayDecision::Replay);
            }
            map.insert(key.to_string(), expires_at_unix);
            Ok(ReplayDecision::Fresh)
        }

        fn durability_class(&self) -> ReplayDurabilityClass {
            ReplayDurabilityClass::Durable
        }
    }

    #[test]
    fn durability_class_delegates_to_backing_store() {
        // #78 (ADR-MCPS-020): a SharedReplayCache is only as durable as the store
        // behind it — its durability_class DELEGATES to the backing store's, it does
        // NOT hardcode Durable.

        // Over the SINGLE-PROCESS in-memory reference store (which does NOT override
        // the conservative default), the cache must declare SingleProcessReference,
        // so it canNOT masquerade as durable nor clear the strict object-level gate.
        let in_memory = SharedReplayCache::new(Box::new(fixture_store()), window());
        assert_eq!(
            in_memory.durability_class(),
            ReplayDurabilityClass::SingleProcessReference,
            "an in-memory-backed shared cache is single-process, not durable"
        );
        assert!(in_memory.is_single_process_reference());

        // Over a genuinely durable / cross-process store (Redis/etcd in production,
        // modelled here by a store that overrides to Durable), the cache declares
        // Durable — proving the delegation, not a hardcode.
        let durable = SharedReplayCache::new(Box::new(DurableModelStore::default()), window());
        assert_eq!(
            durable.durability_class(),
            ReplayDurabilityClass::Durable,
            "a durable-store-backed shared cache must declare Durable"
        );
        assert!(!durable.is_single_process_reference());
    }

    #[test]
    fn fresh_then_replay_single_instance() {
        let store = fixture_store();
        let cache = SharedReplayCache::new(Box::new(store), window());
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
    }

    /// The load-bearing cross-node proof: two SEPARATE `SharedReplayCache`
    /// instances over the SAME shared store (cloned `Arc`, modelling two proxy
    /// nodes). A nonce inserted via node A is rejected as a replay via node B —
    /// the property the single-node file cache cannot provide.
    #[test]
    fn cross_instance_insert_via_a_is_replay_via_b() {
        let store = fixture_store();
        // Clone shares the SAME underlying map (Arc<Mutex<..>>).
        let node_a = SharedReplayCache::new(Box::new(store.clone()), window());
        let node_b = SharedReplayCache::new(Box::new(store.clone()), window());

        assert_eq!(
            node_a.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh),
            "first sight on node A is fresh"
        );
        assert_eq!(
            node_b.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay),
            "node B must reject a nonce first seen on node A — shared replay state"
        );
        // The store really holds the single shared entry.
        assert_eq!(store.len(), 1);
    }

    /// Key-collision safety: changing ONLY the signer, ONLY the audience, or ONLY
    /// the nonce yields independent entries. The crafted inputs would ALIAS under
    /// naive concatenation (`signer + audience + nonce`): `("ab","c", n)` and
    /// `("a","bc", n)` both concatenate to `"abc" + n`. The length-prefixed key
    /// keeps them distinct.
    #[test]
    fn distinct_tuples_do_not_alias() {
        let store = fixture_store();
        let cache = SharedReplayCache::new(Box::new(store), window());

        // Would collide under naive concat: signer|audience boundary moved.
        assert_eq!(
            cache.check_and_insert("ab", "c", NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert("a", "bc", NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh),
            "moving the signer/audience boundary must NOT alias to a replay"
        );
        // Same nonce, different signer → independent.
        assert_eq!(
            cache.check_and_insert("other-host", AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        // Same nonce, different audience → independent.
        assert_eq!(
            cache.check_and_insert(SIGNER, "other-aud", NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        // Same signer/audience, different nonce → independent.
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, "nonce-bbbbbbbbbbbbbbbbbbbbbb", EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        // And each of the above is now a replay on a second sight.
        assert_eq!(
            cache.check_and_insert("ab", "c", NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
        assert_eq!(
            cache.check_and_insert("a", "bc", NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
    }

    /// Skew handling matches `InMemoryReplayCache` semantics: the stored
    /// retain-until is `expires_at + max_clock_skew`, and pruning strictly past it
    /// readmits the nonce while pruning AT it keeps it. The same tuple is driven
    /// through the core cache and every decision must agree.
    #[test]
    fn skew_folded_into_retain_until_matches_in_memory_semantics() {
        let store = fixture_store();
        let shared = SharedReplayCache::new(Box::new(store.clone()), window());
        let core = mcp_re_core::InMemoryReplayCache::new(SKEW);
        let retain_until = EXPIRES + SKEW;
        assert_eq!(
            shared.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            core.check_and_insert(SIGNER, AUD, NONCE, EXPIRES)
        );
        // Pruning AT retain_until keeps the entry (retain_until >= now).
        store.prune(retain_until);
        core.prune(retain_until);
        let at_boundary = shared.check_and_insert(SIGNER, AUD, NONCE, EXPIRES);
        assert_eq!(
            at_boundary,
            core.check_and_insert(SIGNER, AUD, NONCE, EXPIRES)
        );
        assert_eq!(
            at_boundary,
            Ok(ReplayDecision::Replay),
            "entry is live through its skew-extended retain-until"
        );
        // Pruning strictly past retain_until evicts → fresh again.
        store.prune(retain_until + 1);
        core.prune(retain_until + 1);
        let past_boundary = shared.check_and_insert(SIGNER, AUD, NONCE, EXPIRES);
        assert_eq!(
            past_boundary,
            core.check_and_insert(SIGNER, AUD, NONCE, EXPIRES)
        );
        assert_eq!(
            past_boundary,
            Ok(ReplayDecision::Fresh),
            "past retain-until the nonce is readmitted (it can no longer pass freshness)"
        );
    }

    /// Finding #140 fail-closed ceiling: the in-memory reference store has no
    /// server-side TTL and no production prune scheduler, so a peer streaming
    /// distinct fresh nonces would grow it without bound. At the ceiling
    /// `insert_if_absent` must FAIL CLOSED (Unavailable), never admit the entry or
    /// grow past the cap. A `prune` then drains the backlog and readmits capacity.
    #[test]
    fn ceiling_fails_closed_when_full() {
        let cap = 4;
        let store = InMemoryAtomicReplayStore::new()
            .with_max_entries(cap)
            .with_clock(Arc::new(|| 1_000));
        // Fill to capacity (long-lived entries so prune cannot reclaim).
        for i in 0..cap as i64 {
            assert_eq!(
                store.insert_if_absent(&format!("k{i}"), 1_000_000),
                Ok(ReplayDecision::Fresh)
            );
        }
        // One more distinct key must be refused, not admitted.
        let err = store
            .insert_if_absent("overflow", 1_000_000)
            .expect_err("at capacity the store must fail closed, never grow unbounded");
        assert!(matches!(err, ReplayStoreError::Unavailable { .. }));
        assert_eq!(
            store.len(),
            cap,
            "the refused key must NOT have been admitted"
        );

        // Pruning past every entry's retain-until drains the backlog and frees
        // capacity again (the ceiling is a backstop, not a permanent wedge).
        store.prune(2_000_000);
        assert_eq!(store.len(), 0);
        assert_eq!(
            store.insert_if_absent("after-drain", 1_000_000),
            Ok(ReplayDecision::Fresh)
        );
    }

    /// A store error fails closed: `ReplayCacheError::Unavailable`, which maps to
    /// `McpReError::ReplayCacheUnavailable` — never "allow".
    #[test]
    fn store_error_fails_closed_as_unavailable() {
        let cache = SharedReplayCache::new(Box::new(AlwaysUnavailableStore), window());
        let err = cache
            .check_and_insert(SIGNER, AUD, NONCE, EXPIRES)
            .expect_err("an unavailable store must surface an error, never allow");
        assert!(matches!(err, ReplayCacheError::Unavailable { .. }));
        assert_eq!(err.to_mcp_re_error(), McpReError::ReplayCacheUnavailable);
        assert_eq!(McpReError::from(err), McpReError::ReplayCacheUnavailable);
    }

    /// The `From<ReplayStoreError>` bridge preserves the diagnostic and lands on
    /// the fail-closed `Unavailable` variant.
    #[test]
    fn store_error_converts_to_cache_unavailable() {
        let store_err = ReplayStoreError::Unavailable {
            details: "conn refused".to_string(),
        };
        let cache_err: ReplayCacheError = store_err.into();
        match cache_err {
            ReplayCacheError::Unavailable { details } => assert_eq!(details, "conn refused"),
        }
    }

    /// MCPS-08 regression (finding #142) — PURE proof of the pre-store staleness
    /// boundary. A non-positive remaining window (`retain_until <= now`) is flagged
    /// stale (→ reject); a strictly-positive window is admitted. At this clock-free
    /// layer the guard takes the store's own clock reading as `now`.
    #[test]
    fn nonpositive_window_is_flagged_stale_pre_store() {
        assert!(
            is_stale_pre_store(1_000, 1_000),
            "exactly-now is non-positive → reject"
        );
        assert!(
            is_stale_pre_store(900, 1_000),
            "already-past is non-positive → reject"
        );
        assert!(
            !is_stale_pre_store(1_001, 1_000),
            "a positive window is admitted"
        );
        // Against an epoch-anchored `now`: a real future retain-until is a huge
        // positive window (NOT stale); a non-positive absolute retain-until IS stale.
        assert!(
            !is_stale_pre_store(EXPIRES + SKEW, 0),
            "future retain-until is not stale"
        );
        assert!(
            is_stale_pre_store(0, 0),
            "retain-until at the epoch is stale"
        );
        assert!(
            is_stale_pre_store(-5, 0),
            "a negative absolute retain-until is stale"
        );
    }

    /// MCPS-08 regression (finding #142) — WIRING proof through the real in-memory
    /// store, default features. An already-stale request (a retain-until at or
    /// before the store's own clock) is REJECTED fail-closed PRE-STORE and is NOT recorded: the store
    /// stays empty and a subsequent valid request for the SAME key is still `Fresh`
    /// (the stale attempt left no `Replay`-causing entry). WITHOUT the guard the
    /// store would `insert` the entry and return `Fresh`, recording an already-
    /// expired sighting.
    #[test]
    fn already_stale_request_rejected_pre_store_not_recorded_as_fresh() {
        let store = fixture_store();
        // retain_until at/before the store's clock.
        let err = store
            .insert_if_absent("k", FIXTURE_NOW)
            .expect_err("an already-stale request must be rejected, never admitted as Fresh");
        assert!(
            matches!(err, ReplayStoreError::Unavailable { .. }),
            "a stale pre-store rejection must fail closed as Unavailable"
        );
        // It was NOT recorded: the store is empty and a later valid request is Fresh.
        assert!(
            store.is_empty(),
            "a rejected stale request must leave NO entry behind"
        );
        assert_eq!(
            store.insert_if_absent("k", EXPIRES + SKEW),
            Ok(ReplayDecision::Fresh),
            "the key was never recorded, so a valid request is still Fresh"
        );
    }

    /// MCPS-08 regression (finding #142) — same guard surfaced through the full
    /// `SharedReplayCache` path, default features: a stale request fails closed as
    /// `ReplayCacheError::Unavailable` → `McpReError::ReplayCacheUnavailable` (never
    /// `Fresh`, never "allow"). The cache folds skew into `retain_until =
    /// expires_at + skew`, so to drive a stale retain-until we pass an `expires_at`
    /// that nets to the store's clock after skew.
    #[test]
    fn stale_request_via_shared_cache_fails_closed() {
        let store = fixture_store();
        let cache = SharedReplayCache::new(Box::new(store.clone()), window());
        // retain_until = expires_at + SKEW = FIXTURE_NOW → non-positive window → stale.
        let err = cache
            .check_and_insert(SIGNER, AUD, NONCE, FIXTURE_NOW - SKEW)
            .expect_err("a stale request must fail closed, never be admitted as Fresh");
        assert!(matches!(err, ReplayCacheError::Unavailable { .. }));
        assert_eq!(McpReError::from(err), McpReError::ReplayCacheUnavailable);
        assert!(
            store.is_empty(),
            "the stale request must not have been recorded"
        );
    }

    /// A retain-until at or before the store's own clock is refused pre-store; one
    /// second after it is admitted.
    #[test]
    fn a_retain_until_at_or_before_the_stores_clock_is_refused_pre_store() {
        let store = InMemoryAtomicReplayStore::new().with_clock(Arc::new(|| 1_000));
        assert!(matches!(
            store.insert_if_absent("k", 1_000),
            Err(ReplayStoreError::Unavailable { .. })
        ));
        assert!(store.is_empty());
        assert_eq!(
            store.insert_if_absent("k", 1_001),
            Ok(ReplayDecision::Fresh)
        );
    }

    /// A pre-epoch clock reads as `i64::MAX`, so every insert is refused rather
    /// than judged against the epoch.
    #[test]
    fn a_pre_epoch_clock_refuses_every_insert_rather_than_reading_as_the_epoch() {
        let pre_epoch = UNIX_EPOCH.duration_since(UNIX_EPOCH + Duration::from_secs(1));
        assert!(pre_epoch.is_err());
        assert_eq!(unix_seconds(pre_epoch), i64::MAX);
        let store = InMemoryAtomicReplayStore::new().with_clock(Arc::new(|| {
            unix_seconds(UNIX_EPOCH.duration_since(UNIX_EPOCH + Duration::from_secs(1)))
        }));
        assert!(matches!(
            store.insert_if_absent("k", EXPIRES + SKEW),
            Err(ReplayStoreError::Unavailable { .. })
        ));
        assert!(store.is_empty());
    }
}
