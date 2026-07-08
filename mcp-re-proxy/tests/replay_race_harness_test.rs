//! MCPRE-109 (ADR-MCPRE-051 §4) — replay race harness: the authoritative
//! replay tier admits EXACTLY ONE `Fresh` under true concurrency.
//!
//! ADR-MCPRE-051 §4 makes replay a globally coherent admission decision: a
//! request is dispatchable *only* if its replay key is **atomically inserted**
//! into the authoritative replay tier ([`AtomicReplayStore`]). The load-bearing
//! property, on every release, is:
//!
//! > N concurrent submissions of the SAME signed request (same replay key),
//! > across cores and across replicas, yield EXACTLY ONE `Fresh` and N−1
//! > `Replay` — and if the store is unavailable, ZERO `Fresh` (fail closed).
//!
//! This harness proves that property deterministically. Determinism comes from a
//! [`Barrier`] that releases all racing threads at once (maximising real
//! contention) followed by an EXACT count assertion — the atomic
//! insert-if-absent contract makes "exactly one `Fresh`" hold regardless of
//! thread interleaving, so there is no timing/sleep assertion to be flaky.
//!
//! Layering (ADR-MCPRE-051 §4): `Fresh` is only ever the result of a successful
//! L2 atomic insert, so the race is proven at the [`AtomicReplayStore`] tier —
//! the sole authority. The [`SharedReplayCache`] wrapper adds only pure,
//! deterministic skew-folding + composite-key construction over that tier; its
//! correctness and cross-replica coherence are covered single-threaded here
//! (`shared_cache_*`). The full-stack variant that drives N cores through one
//! shared serving `Proxy` arrives with the async data plane + `Proxy: Send +
//! Sync` (ADR-MCPRE-051 Phase 1/2, MCPRE-111); until the serving path is
//! shareable across threads, the authoritative tier IS the concurrency boundary
//! and is where this gate belongs.
//!
//! Backends: the default build races the in-tree reference
//! [`InMemoryAtomicReplayStore`] (an `Arc<Mutex<…>>`, a real store — not a mock),
//! so this runs on every `bazel test //...` with no live infra. The Redis and
//! etcd backends race the SAME harness on the live store when their feature is
//! compiled and their endpoint env var is set (skip-when-absent, hard-fail under
//! `MCP_RE_REQUIRE_LIVE_INFRA`), mirroring `redis_replay_e2e_test.rs`.

use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use mcp_re_proxy::AtomicReplayStore;
use mcp_re_proxy::InMemoryAtomicReplayStore;
use mcp_re_proxy::ReplayStoreError;
use mcp_re_proxy::SharedReplayCache;

use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayDecision;

/// A retain-until far in the future so the store's defensive pre-store staleness
/// guard (`is_stale_pre_store`, MCPS-08) never rejects the submission before the
/// race — the vestigial `now_unix = 0` the trait passes means the guard reduces
/// to "reject a non-positive ABSOLUTE retain-until", so any large positive value
/// is admissible and the ONLY thing that decides Fresh/Replay is the atomic
/// insert.
const FAR_FUTURE_RETAIN_UNTIL: i64 = 4_000_000_000;

/// How many threads pile onto the one replay key per race round.
const RACE_WIDTH: usize = 64;

/// How many independent race rounds (each a fresh key) every test runs, so the
/// "exactly one Fresh" property is exercised across many distinct races rather
/// than a single lucky interleaving.
const RACE_ROUNDS: usize = 50;

/// Tally of the verdicts returned by one race round.
#[derive(Debug, Default, PartialEq, Eq)]
struct RaceTally {
    fresh: usize,
    replay: usize,
    unavailable: usize,
}

/// Fire `RACE_WIDTH` threads that all submit the SAME `key` to `store` at once
/// (barrier-released), then tally the verdicts. `store` is the shared
/// authoritative tier — every thread holds an `Arc` clone of the one store, so
/// the insert-if-absent races for real.
fn race_one_key(store: &Arc<dyn AtomicReplayStore + Send + Sync>, key: &str) -> RaceTally {
    let barrier = Arc::new(Barrier::new(RACE_WIDTH));
    let handles: Vec<_> = (0..RACE_WIDTH)
        .map(|_| {
            let store = Arc::clone(store);
            let barrier = Arc::clone(&barrier);
            let key = key.to_string();
            thread::spawn(move || {
                // Every thread parks here; the last arrival releases them all
                // simultaneously into the atomic insert — maximum contention.
                barrier.wait();
                store.insert_if_absent(&key, FAR_FUTURE_RETAIN_UNTIL, 0)
            })
        })
        .collect();

    let mut tally = RaceTally::default();
    for handle in handles {
        match handle.join().expect("race thread panicked") {
            Ok(ReplayDecision::Fresh) => tally.fresh += 1,
            Ok(ReplayDecision::Replay) => tally.replay += 1,
            Err(ReplayStoreError::Unavailable { .. }) => tally.unavailable += 1,
        }
    }
    tally
}

/// A composite-shaped replay key for round `round`. The store treats the key as
/// opaque; the only invariant the race depends on is that every thread in a
/// round submits the IDENTICAL key and distinct rounds use distinct keys.
fn round_key(round: usize) -> String {
    format!("did:example:agent\u{1f}did:example:server\u{1f}nonce-{round}")
}

/// Drive `RACE_ROUNDS` independent race rounds against `store` and assert EXACTLY
/// ONE `Fresh` + `RACE_WIDTH - 1` `Replay` + ZERO `Unavailable` every round. This
/// is the cross-core property: many threads (cores) racing one replay key on one
/// shared authoritative tier admit the request exactly once.
fn assert_exactly_one_fresh_per_round(store: Arc<dyn AtomicReplayStore + Send + Sync>) {
    for round in 0..RACE_ROUNDS {
        let tally = race_one_key(&store, &round_key(round));
        assert_eq!(
            tally,
            RaceTally {
                fresh: 1,
                replay: RACE_WIDTH - 1,
                unavailable: 0,
            },
            "round {round}: {RACE_WIDTH}-way race must admit exactly one Fresh",
        );
    }
}

// ---------------------------------------------------------------------------
// Default build — in-memory reference authoritative tier (always runs)
// ---------------------------------------------------------------------------

/// Cross-core: `RACE_WIDTH` threads racing ONE replay key on ONE shared store
/// yield exactly one `Fresh`, `RACE_WIDTH - 1` `Replay`. Repeated over many
/// rounds so no single interleaving carries the proof.
#[test]
fn cross_core_same_key_admits_exactly_one_fresh_in_memory() {
    let store: Arc<dyn AtomicReplayStore + Send + Sync> =
        Arc::new(InMemoryAtomicReplayStore::new());
    assert_exactly_one_fresh_per_round(store);
}

/// Cross-replica: two (or more) logical replicas backed by ONE shared store race
/// the same key. `InMemoryAtomicReplayStore` clones share the SAME `Arc<Mutex<…>>`
/// state, so cloning the store per replica models a fleet over one backend
/// exactly as `SharedReplayCache` replicas do. Exactly one `Fresh` still holds.
#[test]
fn cross_replica_shared_store_admits_exactly_one_fresh_in_memory() {
    // One backend; each race thread is a distinct replica holding its own clone
    // of the shared store (same underlying `Arc<Mutex<…>>` state) — the topology
    // of a horizontally-scaled fleet against a single authoritative tier.
    // Wrapper-level cross-replica agreement over this same backend is asserted
    // deterministically in `shared_cache_cross_replica_admit_via_a_is_replay_via_b`.
    let backend = InMemoryAtomicReplayStore::new();
    let store: Arc<dyn AtomicReplayStore + Send + Sync> = Arc::new(backend);
    assert_exactly_one_fresh_per_round(store);
}

/// Fail-closed: when the authoritative tier is unavailable, a concurrent race
/// produces ZERO `Fresh` — uncertainty is never freshness (ADR-MCPRE-051 §4,
/// `Unavailable` fails closed). Every thread must get `Unavailable`, none admitted.
#[test]
fn store_unavailable_admits_zero_fresh_fail_closed() {
    /// An authoritative tier that is always down — every insert fails closed.
    struct AlwaysUnavailableStore;
    impl AtomicReplayStore for AlwaysUnavailableStore {
        fn insert_if_absent(
            &self,
            _key: &str,
            _expires_at_unix: i64,
            _now_unix: i64,
        ) -> Result<ReplayDecision, ReplayStoreError> {
            Err(ReplayStoreError::Unavailable {
                details: "authoritative replay tier down".to_string(),
            })
        }
    }

    let store: Arc<dyn AtomicReplayStore + Send + Sync> = Arc::new(AlwaysUnavailableStore);
    for round in 0..RACE_ROUNDS {
        let tally = race_one_key(&store, &round_key(round));
        assert_eq!(tally.fresh, 0, "round {round}: an unavailable tier must admit ZERO Fresh");
        assert_eq!(
            tally.unavailable, RACE_WIDTH,
            "round {round}: every submission must fail closed as Unavailable",
        );
    }
}

// ---------------------------------------------------------------------------
// SharedReplayCache wrapper coherence (single-threaded, deterministic)
// ---------------------------------------------------------------------------

/// The `SharedReplayCache` composite-key + skew-folding path admits the first
/// submission of a `(signer, audience, nonce)` and rejects the second — the
/// pure wrapper over the authoritative tier the race exercises concurrently.
#[test]
fn shared_cache_first_is_fresh_then_replay() {
    let mut cache = SharedReplayCache::new(Box::new(InMemoryAtomicReplayStore::new()), 30);
    assert_eq!(
        cache.check_and_insert("did:example:agent", "did:example:server", "nonce-1", 1_000),
        Ok(ReplayDecision::Fresh),
    );
    assert_eq!(
        cache.check_and_insert("did:example:agent", "did:example:server", "nonce-1", 1_000),
        Ok(ReplayDecision::Replay),
    );
    // A different nonce is independently Fresh.
    assert_eq!(
        cache.check_and_insert("did:example:agent", "did:example:server", "nonce-2", 1_000),
        Ok(ReplayDecision::Fresh),
    );
}

/// Cross-replica coherence at the wrapper level: two `SharedReplayCache`
/// replicas over ONE shared backend — a nonce admitted (`Fresh`) via replica A
/// is `Replay` via replica B, because the authoritative tier is shared. This is
/// the store-shared analogue of the fleet Redis proof (MCPS-81), on the default
/// in-memory backend.
#[test]
fn shared_cache_cross_replica_admit_via_a_is_replay_via_b() {
    let backend = InMemoryAtomicReplayStore::new();
    let mut replica_a = SharedReplayCache::new(Box::new(backend.clone()), 30);
    let mut replica_b = SharedReplayCache::new(Box::new(backend.clone()), 30);

    assert_eq!(
        replica_a.check_and_insert("did:example:agent", "did:example:server", "nonce-x", 1_000),
        Ok(ReplayDecision::Fresh),
        "replica A admits the fresh nonce",
    );
    assert_eq!(
        replica_b.check_and_insert("did:example:agent", "did:example:server", "nonce-x", 1_000),
        Ok(ReplayDecision::Replay),
        "replica B rejects it as a replay — the authoritative tier is shared",
    );
}

// ---------------------------------------------------------------------------
// Live-infra lanes — Redis / etcd race the SAME harness (skip-when-absent)
// ---------------------------------------------------------------------------

/// CI opt-in: when `MCP_RE_REQUIRE_LIVE_INFRA` is set to any non-empty value, a
/// missing backend endpoint HARD-FAILS instead of skipping, so the live lane
/// cannot be silently scored green.
fn require_live_infra() -> bool {
    std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty())
}

#[cfg(feature = "redis_replay")]
#[test]
fn cross_core_same_key_admits_exactly_one_fresh_redis() {
    use mcp_re_proxy::RedisAtomicReplayStore;

    let url = std::env::var("MCP_RE_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    let Some(url) = url else {
        if require_live_infra() {
            panic!(
                "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable; \
                 the replay-race Redis lane cannot be scored as passing without a live store"
            );
        }
        eprintln!("skipping replay-race Redis lane: MCP_RE_TEST_REDIS_URL unset");
        return;
    };
    let store = RedisAtomicReplayStore::connect(&url).expect("connect Redis replay store");
    let store: Arc<dyn AtomicReplayStore + Send + Sync> = Arc::new(store);
    assert_exactly_one_fresh_per_round(store);
}

#[cfg(feature = "cpstore_etcd")]
#[test]
fn cross_core_same_key_admits_exactly_one_fresh_etcd() {
    use mcp_re_proxy::EtcdAtomicReplayStore;

    let endpoint = std::env::var("MCP_RE_TEST_ETCD_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    let Some(endpoint) = endpoint else {
        if require_live_infra() {
            panic!(
                "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_ETCD_URL is unavailable; \
                 the replay-race etcd lane cannot be scored as passing without a live store"
            );
        }
        eprintln!("skipping replay-race etcd lane: MCP_RE_TEST_ETCD_URL unset");
        return;
    };
    let store = EtcdAtomicReplayStore::connect(&endpoint);
    let store: Arc<dyn AtomicReplayStore + Send + Sync> = Arc::new(store);
    assert_exactly_one_fresh_per_round(store);
}
