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
//! (`shared_cache_*`). The full-stack variant — N concurrent submissions of the
//! SAME signed RFC 9421 request through ONE shared serving `HttpProfileProxy`
//! (MCPRE-117 AC) — lives in the `http_profile_full_stack` module at the bottom
//! of this file, over the in-memory reference tier and over each live store.
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

/// Every entry in this file is charged to one signer; the per-actor budget is
/// exercised by its own test in `async_replay.rs`.
///
/// Gated on the exact union of its two uses — the async Redis and async etcd race
/// lanes. Gating it on `async_serve` alone left it unused under that feature by
/// itself, a combination neither CI clippy lane builds (they run default and
/// all-features, never this one in between).
#[cfg(all(
    feature = "async_serve",
    any(feature = "redis_replay", feature = "cpstore_etcd")
))]
const TEST_ACTOR: &str = "did:example:test-signer";

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

/// A per-invocation-unique salt (process id + wall-clock nanos, read ONCE by the
/// caller) so a LIVE race test's keys never collide with another test's or a prior
/// run's on a SHARED persistent store. Every live lane needs this: the fixed
/// `round_key`s are stored with a far-future TTL, so a second lane — or a second
/// run against the same store — would see all `Replay` (zero `Fresh`) and fail on
/// a store that is behaving correctly. The caller reads the salt ONCE and reuses it
/// for every round, so all threads in a round still submit the IDENTICAL key (the
/// race invariant holds).
#[cfg(any(feature = "redis_replay", feature = "cpstore_etcd"))]
fn unique_salt(tag: &str) -> String {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{tag}-{}-{nanos}", std::process::id())
}

/// A `round_key` namespaced by a per-test `salt` (see [`unique_salt`]).
#[cfg(any(feature = "redis_replay", feature = "cpstore_etcd"))]
fn salted_round_key(salt: &str, round: usize) -> String {
    format!("did:example:agent\u{1f}did:example:server\u{1f}nonce-{salt}-{round}")
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

/// [`assert_exactly_one_fresh_per_round`] over keys namespaced by `salt` — the
/// form every LIVE lane must use, since a live store outlives the test process.
#[cfg(any(feature = "redis_replay", feature = "cpstore_etcd"))]
fn assert_exactly_one_fresh_per_round_salted(
    store: Arc<dyn AtomicReplayStore + Send + Sync>,
    salt: &str,
) {
    for round in 0..RACE_ROUNDS {
        let tally = race_one_key(&store, &salted_round_key(salt, round));
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
        assert_eq!(
            tally.fresh, 0,
            "round {round}: an unavailable tier must admit ZERO Fresh"
        );
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
    let cache = SharedReplayCache::new(Box::new(InMemoryAtomicReplayStore::new()), 30);
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
    let replica_a = SharedReplayCache::new(Box::new(backend.clone()), 30);
    let replica_b = SharedReplayCache::new(Box::new(backend.clone()), 30);

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
#[cfg(any(feature = "redis_replay", feature = "cpstore_etcd"))]
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
    assert_exactly_one_fresh_per_round_salted(store, &unique_salt("redis-sync"));
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
    assert_exactly_one_fresh_per_round_salted(store, &unique_salt("etcd-sync"));
}

/// ASYNC Redis lane (ADR-MCPRE-051 §4): the async authoritative tier
/// (`RedisAsyncAtomicReplayStore`, `SET NX PX` over the tokio async client) admits
/// EXACTLY ONE `Fresh` under a concurrent race — the same load-bearing property as
/// the sync lane, proven on the async client the per-core data plane awaits.
/// Skip-when-absent (hard-fail under `MCP_RE_REQUIRE_LIVE_INFRA`).
#[cfg(all(feature = "async_serve", feature = "redis_replay"))]
#[test]
fn cross_core_same_key_admits_exactly_one_fresh_redis_async() {
    use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
    use mcp_re_proxy::async_replay::ReplayInsert;
    use mcp_re_proxy::RedisAsyncAtomicReplayStore;

    let url = std::env::var("MCP_RE_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    let Some(url) = url else {
        if require_live_infra() {
            panic!(
                "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable; \
                 the async replay-race Redis lane cannot be scored as passing without a live store"
            );
        }
        eprintln!("skipping async replay-race Redis lane: MCP_RE_TEST_REDIS_URL unset");
        return;
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let store = Arc::new(
            RedisAsyncAtomicReplayStore::connect(&url)
                .await
                .expect("connect async Redis replay store"),
        );
        // Salt read ONCE so this lane's keys are disjoint from the sync Redis lane's
        // (which shares this live store and runs first) — else every insert here is a
        // Replay of a key the sync lane already left behind (zero Fresh).
        let salt = unique_salt("redis-async");
        for round in 0..RACE_ROUNDS {
            let key = salted_round_key(&salt, round);
            let tasks = RACE_WIDTH;
            let mut handles = Vec::new();
            for _ in 0..tasks {
                let store = Arc::clone(&store);
                let key = key.clone();
                handles.push(tokio::spawn(async move {
                    store
                        .atomic_insert_if_absent(ReplayInsert::new(
                            &key,
                            TEST_ACTOR,
                            FAR_FUTURE_RETAIN_UNTIL,
                            0,
                        ))
                        .await
                }));
            }
            let mut fresh = 0usize;
            for handle in handles {
                if let Ok(ReplayDecision::Fresh) = handle.await.expect("task") {
                    fresh += 1;
                }
            }
            assert_eq!(
                fresh, 1,
                "round {round}: async Redis {RACE_WIDTH}-way race must admit exactly one Fresh"
            );
        }
    });
}

/// ASYNC etcd lane (ADR-MCPRE-051 §4): the CP/linearizable async authoritative tier
/// (`EtcdAsyncAtomicReplayStore`, a `compare { CREATE_REVISION == 0 }` txn over the
/// v3 JSON gateway, AWAITED off the per-core runtime) admits EXACTLY ONE `Fresh`
/// under a concurrent race — the async analogue of the sync etcd lane above, on the
/// async client the per-core data plane awaits. Skip-when-absent (hard-fail under
/// `MCP_RE_REQUIRE_LIVE_INFRA`).
#[cfg(all(feature = "async_serve", feature = "cpstore_etcd"))]
#[test]
fn cross_core_same_key_admits_exactly_one_fresh_etcd_async() {
    use mcp_re_proxy::async_etcd_store::EtcdAsyncAtomicReplayStore;
    use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
    use mcp_re_proxy::async_replay::ReplayInsert;

    let endpoint = std::env::var("MCP_RE_TEST_ETCD_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    let Some(endpoint) = endpoint else {
        if require_live_infra() {
            panic!(
                "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_ETCD_URL is unavailable; \
                 the async replay-race etcd lane cannot be scored as passing without a live store"
            );
        }
        eprintln!("skipping async replay-race etcd lane: MCP_RE_TEST_ETCD_URL unset");
        return;
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        // `connect` is infallible (it only records the endpoint); a wrong/unreachable
        // gateway surfaces as a per-request `Unavailable`, i.e. ZERO Fresh — never a
        // false Fresh — which the exact count below would catch.
        let store = Arc::new(EtcdAsyncAtomicReplayStore::connect(&endpoint));
        // Salt read ONCE so this lane's keys are disjoint from the sync etcd lane's
        // on this shared live store (see the Redis lane above).
        let salt = unique_salt("etcd-async");
        for round in 0..RACE_ROUNDS {
            let key = salted_round_key(&salt, round);
            let tasks = RACE_WIDTH;
            let mut handles = Vec::new();
            for _ in 0..tasks {
                let store = Arc::clone(&store);
                let key = key.clone();
                handles.push(tokio::spawn(async move {
                    store
                        .atomic_insert_if_absent(ReplayInsert::new(
                            &key,
                            TEST_ACTOR,
                            FAR_FUTURE_RETAIN_UNTIL,
                            0,
                        ))
                        .await
                }));
            }
            let mut fresh = 0usize;
            for handle in handles {
                if let Ok(ReplayDecision::Fresh) = handle.await.expect("task") {
                    fresh += 1;
                }
            }
            assert_eq!(
                fresh, 1,
                "round {round}: async etcd {RACE_WIDTH}-way race must admit exactly one Fresh"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Full-stack serving path — N concurrent submissions through ONE shared PEP
// ---------------------------------------------------------------------------
//
// MCPRE-117 AC. The lanes above prove the property at the authoritative tier;
// these prove it end to end on the production serving PEP (`HttpProfileProxy`,
// ADR-MCPRE-050 sole carrier): N tasks submit the SAME signed RFC 9421 request
// to ONE shared proxy and EXACTLY ONE is served (200) while the rest are
// replay-rejected (409). The store behind the tier is the cross-replica
// coherence boundary, so wiring a live networked store (Redis/etcd) makes this
// "cross-replica through the full serving path"; `two_replicas_*` wires two
// independent proxies over ONE live store to state that directly.
#[cfg(feature = "async_serve")]
mod http_profile_full_stack {
    use std::sync::Arc;

    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::issue_delegation_credential;
    use mcp_re_http_profile::sign_request_full;
    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::ArtifactBinding;
    use mcp_re_http_profile::ArtifactType;
    use mcp_re_http_profile::AudienceTuple;
    use mcp_re_http_profile::CustodyConfig;
    use mcp_re_http_profile::DelegatedSigningCustody;
    use mcp_re_http_profile::DelegationClaims;
    use mcp_re_http_profile::DelegationHeader;
    use mcp_re_http_profile::HttpRequest;
    use mcp_re_http_profile::HttpRequestEvidenceBlock;
    use mcp_re_http_profile::ResolvedActor;
    use mcp_re_http_profile::ResolverOutcome;
    use mcp_re_http_profile::SignerSlot;
    use mcp_re_http_profile::PROFILE_TAG;

    use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
    use mcp_re_proxy::async_replay::AsyncReplayTier;
    use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
    use mcp_re_proxy::async_serve::ServedHttpRequest;
    use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
    use mcp_re_proxy::ActorResolver;
    use mcp_re_proxy::DelegatedRotor;
    use mcp_re_proxy::DelegatedServerSigner;
    use mcp_re_proxy::HttpProfileProxy;

    const CLIENT_SEED: [u8; 32] = [11u8; 32];
    const ROOT_SEED: [u8; 32] = [33u8; 32];
    const TARGET: &str = "https://mcp.example.com/mcp?route=a";
    const ACCESS_TOKEN: &str = "access-token-xyz";
    const CLIENT_KEY_ID: &str = "client-key-1";
    const ROOT_KID: &str = "root-kid";
    const VERIFIER_AUD: &str = "verifier-1";

    /// How many concurrent submissions of the one nonce each round fires.
    const TASKS: usize = 64;
    /// Independent rounds (each a fresh nonce) per lane, so "exactly one 200"
    /// is exercised across many races rather than one lucky interleaving. Fewer
    /// rounds than the store-tier lanes: every submission here also costs a
    /// signature verify + a delegated response signing, and the store tier —
    /// where the atomicity actually lives — is already raced 50× above.
    const ROUNDS: usize = 10;

    fn client_key() -> SigningKey {
        SigningKey::from_seed_bytes(&CLIENT_SEED)
    }
    fn root_key() -> SigningKey {
        SigningKey::from_seed_bytes(&ROOT_SEED)
    }
    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: VERIFIER_AUD.into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        }
    }

    /// The serving clock. A LIVE replay store derives each key's TTL from the
    /// REAL wall clock, so a frozen fixture timestamp would make every insert
    /// look long-expired and admit nothing — these lanes run on real time and
    /// read it ONCE per test so the whole race shares one `now`.
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    }

    /// The client key resolves for the Request slot and the ROOT key for the
    /// Response slot — the delegated key is authorized by its credential.
    fn actor_resolver() -> ActorResolver {
        Box::new(move |key_id: &str, slot: SignerSlot| {
            let (role, key) = match (key_id, slot) {
                (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key().public_key()),
                (ROOT_KID, SignerSlot::Response) => ("server", root_key().public_key()),
                _ => return ResolverOutcome::NotTrusted,
            };
            ResolverOutcome::Resolved(Box::new(ResolvedActor {
                identity: ActorIdentity {
                    role: role.into(),
                    trust_domain: "example.com".into(),
                    subject: format!("did:example:{role}"),
                    keyid: key_id.into(),
                },
                verification_key: key,
                slot,
            }))
        })
    }

    fn custody_cfg() -> CustodyConfig {
        CustodyConfig {
            issuer_kid: ROOT_KID.into(),
            iss: "did:example:server".into(),
            profile: PROFILE_TAG.into(),
            aud: VERIFIER_AUD.into(),
            audience_hash: VERIFIER_AUD.into(),
            trust_epoch: "epoch-1".into(),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            ttl: 300,
            overlap: 60,
        }
    }

    /// A delegated-signing PEP over `store` as its authoritative async replay
    /// tier, with its first delegated key already published. `seed_base`
    /// distinguishes the delegated key material of independent replicas.
    fn proxy_over(
        store: Arc<dyn AsyncAtomicReplayStore>,
        seed_base: u8,
        now: i64,
    ) -> HttpProfileProxy {
        let signer = Arc::new(DelegatedServerSigner::new());
        let root = root_key();
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(issue_delegation_credential(&root, h, c))
        };
        let mut n = seed_base;
        let factory = move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        };
        let mut rotor = DelegatedRotor::new(
            DelegatedSigningCustody::new(custody_cfg(), issue, factory),
            Arc::clone(&signer),
        );
        rotor.rotate(now).expect("issue the first delegated key");
        let inner = Box::new(|_forwarded: &[u8]| -> Vec<u8> {
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
        });
        HttpProfileProxy::new_delegated(
            actor_resolver(),
            audience(),
            AsyncReplayTier::new(
                store,
                mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
            ),
            ProxyDispatchConfig {
                fleet_strict: false,
                tier: None,
            },
            inner,
            300,
            signer,
        )
    }

    /// A client-signed RFC 9421 + RFC 9530 request carrying `nonce`.
    fn signed_request(nonce: &str, now: i64) -> HttpRequest {
        let block = HttpRequestEvidenceBlock {
            profile: PROFILE_TAG.into(),
            audience: audience(),
            artifact_bindings: vec![ArtifactBinding::opaque_digest(
                ArtifactType::OauthDpop,
                ACCESS_TOKEN.as_bytes(),
            )],
            continuation: None,
            admission: None,
            admission_assertion: None,
        };
        let mut req = HttpRequest {
            method: "POST".into(),
            target_uri: TARGET.into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
            ],
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
                .to_vec(),
        };
        sign_request_full(
            &mut req,
            &block,
            &client_key(),
            CLIENT_KEY_ID,
            now - 60,
            now + 240,
            nonce,
        )
        .expect("client signs the RFC 9421 request");
        req
    }

    fn served(req: &HttpRequest) -> ServedHttpRequest {
        ServedHttpRequest {
            method: req.method.clone(),
            target_uri: req.target_uri.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
            peer: None,
            assertion: None,
        }
    }

    /// A per-invocation-unique nonce prefix so a LIVE store never sees this
    /// process's nonces collide with another lane's or a prior run's (the
    /// live stores outlive the test process; a collision would show up as
    /// ZERO 200s, not as a false pass).
    fn unique_prefix(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        format!("{tag}-{}-{nanos}", std::process::id())
    }

    #[cfg(any(feature = "redis_replay", feature = "cpstore_etcd"))]
    fn require_live_infra() -> bool {
        std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.trim().is_empty())
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// Fire `TASKS` concurrent submissions of the SAME signed request at ONE
    /// shared PEP and assert the end-to-end property: exactly one 200 and
    /// `TASKS - 1` replay rejections (409).
    async fn assert_exactly_one_served(proxy: Arc<HttpProfileProxy>, nonce: &str, now: i64) {
        let req = Arc::new(signed_request(nonce, now));
        let mut handles = Vec::new();
        for _ in 0..TASKS {
            let proxy = Arc::clone(&proxy);
            let req = Arc::clone(&req);
            handles.push(tokio::spawn(async move {
                proxy.handle(served(&req), now).await.status
            }));
        }
        let mut ok = 0usize;
        let mut replay = 0usize;
        for handle in handles {
            match handle.await.expect("task") {
                200 => ok += 1,
                409 => replay += 1,
                other => panic!("unexpected status {other} from the serving path"),
            }
        }
        assert_eq!(
            ok, 1,
            "nonce {nonce}: a {TASKS}-way race through one shared PEP must serve EXACTLY one"
        );
        assert_eq!(
            replay,
            TASKS - 1,
            "nonce {nonce}: every loser must be a 409 replay rejection"
        );
    }

    /// In-memory reference tier — always on, no live infra.
    #[test]
    fn serving_path_admits_exactly_one_in_memory() {
        rt().block_on(async {
            let now = now();
            let store = Arc::new(InMemoryAsyncAtomicReplayStore::new());
            let proxy = Arc::new(proxy_over(store, 100, now));
            let prefix = unique_prefix("mem");
            for round in 0..ROUNDS {
                assert_exactly_one_served(Arc::clone(&proxy), &format!("{prefix}-{round}"), now)
                    .await;
            }
        });
    }

    /// LIVE Redis async tier through the full serving path: the cross-replica
    /// coherence boundary is a real networked store (MCPRE-117 AC).
    /// Skip-when-absent; hard-fail under `MCP_RE_REQUIRE_LIVE_INFRA`.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn serving_path_admits_exactly_one_over_live_redis() {
        use mcp_re_proxy::RedisAsyncAtomicReplayStore;

        let Some(url) = live_url("MCP_RE_TEST_REDIS_URL", "Redis") else {
            return;
        };
        rt().block_on(async {
            let now = now();
            let store = Arc::new(
                RedisAsyncAtomicReplayStore::connect(&url)
                    .await
                    .expect("connect the async Redis replay store"),
            );
            let proxy = Arc::new(proxy_over(store, 100, now));
            let prefix = unique_prefix("redis");
            for round in 0..ROUNDS {
                assert_exactly_one_served(Arc::clone(&proxy), &format!("{prefix}-{round}"), now)
                    .await;
            }
        });
    }

    /// TWO independent PEPs over ONE live Redis store: a nonce served by
    /// replica A is replay-rejected by replica B — cross-replica coherence
    /// stated through the full serving path, not at the store tier.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn two_replicas_share_one_live_redis_admission() {
        use mcp_re_proxy::RedisAsyncAtomicReplayStore;

        let Some(url) = live_url("MCP_RE_TEST_REDIS_URL", "Redis") else {
            return;
        };
        rt().block_on(async {
            let now = now();
            let store = Arc::new(
                RedisAsyncAtomicReplayStore::connect(&url)
                    .await
                    .expect("connect the async Redis replay store"),
            );
            // Distinct PEP instances (distinct delegated key material) sharing
            // ONE authoritative tier — the fleet shape.
            let a = proxy_over(store.clone(), 100, now);
            let b = proxy_over(store, 200, now);

            let prefix = unique_prefix("fleet");
            let req = signed_request(&format!("{prefix}-cross"), now);
            assert_eq!(
                a.handle(served(&req), now).await.status,
                200,
                "replica A serves it"
            );
            assert_eq!(
                b.handle(served(&req), now).await.status,
                409,
                "replica B replay-rejects a nonce replica A already admitted"
            );

            // Control: a nonce no replica has seen is admitted on B.
            let fresh = signed_request(&format!("{prefix}-fresh"), now);
            assert_eq!(
                b.handle(served(&fresh), now).await.status,
                200,
                "a distinct nonce is still admitted on replica B"
            );
        });
    }

    /// LIVE etcd (CP/linearizable) async tier through the full serving path.
    /// Skip-when-absent; hard-fail under `MCP_RE_REQUIRE_LIVE_INFRA`.
    #[cfg(feature = "cpstore_etcd")]
    #[test]
    fn serving_path_admits_exactly_one_over_live_etcd() {
        use mcp_re_proxy::async_etcd_store::EtcdAsyncAtomicReplayStore;

        let Some(endpoint) = live_url("MCP_RE_TEST_ETCD_URL", "etcd") else {
            return;
        };
        rt().block_on(async {
            let now = now();
            let store = Arc::new(EtcdAsyncAtomicReplayStore::connect(&endpoint));
            let proxy = Arc::new(proxy_over(store, 100, now));
            let prefix = unique_prefix("etcd");
            for round in 0..ROUNDS {
                assert_exactly_one_served(Arc::clone(&proxy), &format!("{prefix}-{round}"), now)
                    .await;
            }
        });
    }

    /// Read a live-store endpoint from `var`, or decide how to skip: silently
    /// when live infra is optional, by panic when it is required (so an absent
    /// store can never be scored as a pass).
    #[cfg(any(feature = "redis_replay", feature = "cpstore_etcd"))]
    fn live_url(var: &str, what: &str) -> Option<String> {
        match std::env::var(var).ok().filter(|u| !u.trim().is_empty()) {
            Some(url) => Some(url),
            None => {
                assert!(
                    !require_live_infra(),
                    "MCP_RE_REQUIRE_LIVE_INFRA is set but {var} is unavailable; the \
                     full-serving-path {what} race cannot be scored as passing without a live store"
                );
                eprintln!("skipping the full-serving-path {what} race: {var} unset");
                None
            }
        }
    }
}
