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

/// ASYNC Redis lane (ADR-MCPRE-051 §4): the async authoritative tier
/// (`RedisAsyncAtomicReplayStore`, `SET NX PX` over the tokio async client) admits
/// EXACTLY ONE `Fresh` under a concurrent race — the same load-bearing property as
/// the sync lane, proven on the async client the per-core data plane awaits.
/// Skip-when-absent (hard-fail under `MCP_RE_REQUIRE_LIVE_INFRA`).
#[cfg(all(feature = "async_serve", feature = "redis_replay"))]
#[test]
fn cross_core_same_key_admits_exactly_one_fresh_redis_async() {
    use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
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
        for round in 0..RACE_ROUNDS {
            let key = round_key(round);
            let tasks = RACE_WIDTH;
            let mut handles = Vec::new();
            for _ in 0..tasks {
                let store = Arc::clone(&store);
                let key = key.clone();
                handles.push(tokio::spawn(async move {
                    store
                        .atomic_insert_if_absent(&key, FAR_FUTURE_RETAIN_UNTIL, 0)
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
        for round in 0..RACE_ROUNDS {
            let key = round_key(round);
            let tasks = RACE_WIDTH;
            let mut handles = Vec::new();
            for _ in 0..tasks {
                let store = Arc::clone(&store);
                let key = key.clone();
                handles.push(tokio::spawn(async move {
                    store
                        .atomic_insert_if_absent(&key, FAR_FUTURE_RETAIN_UNTIL, 0)
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
// Full-stack async serving path — N cores through ONE shared `Proxy`
// ---------------------------------------------------------------------------
//
// The variant the module doc above deferred to "when the serving path is
// shareable across threads" (ADR-MCPRE-051 Phase 1/2, MCPRE-111): now that the
// `Proxy` is `Send + Sync` and `Proxy::handle_with_transport_async` awaits the
// authoritative async replay tier (ADR-MCPRE-051 §4), this drives N concurrent
// submissions of the SAME signed request through ONE shared async `Proxy` and
// asserts the end-to-end property — EXACTLY ONE `Fresh` (a verifiable signed
// response) and N−1 `Replay` (a fail-closed JSON-RPC error). This is the proof
// that the async serving path is a genuine async data plane over the coherent
// replay tier, not an async transport wrapped around a synchronous replay core.
#[cfg(feature = "async_serve")]
mod full_stack_async {
    use std::sync::Arc;

    use mcp_re_core::request_hash;
    use mcp_re_core::request_signing_preimage;
    use mcp_re_core::verify_response;
    use mcp_re_core::InMemoryTrustResolver;
    use mcp_re_core::SigningKey;
    use mcp_re_core::REQUEST_META_KEY;
    use mcp_re_core::SIG_ALG_ED25519;
    use mcp_re_core::VERSION_DRAFT_01;

    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper::Uri;
    use hyper_util::rt::TokioExecutor;
    use hyper_util::rt::TokioIo;
    use hyper_util::server::conn::auto;
    use tokio::net::TcpListener;

    use mcp_re_proxy::async_inner::AsyncInnerServer;
    use mcp_re_proxy::async_inner::InnerResponseFuture;
    use mcp_re_proxy::async_replay::AsyncReplayTier;
    use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
    use mcp_re_proxy::http_inner::HttpInnerPool;
    use mcp_re_proxy::Proxy;

    use serde_json::json;
    use serde_json::Value;

    /// A minimal async inner that returns a fixed valid JSON-RPC result — the async
    /// analogue of the sync echo inner. Proves the async serving path awaits the
    /// async inner seam end to end.
    struct EchoAsyncInner;

    impl AsyncInnerServer for EchoAsyncInner {
        fn dispatch<'a>(&'a self, _request: &'a [u8]) -> InnerResponseFuture<'a> {
            Box::pin(async move {
                serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": REQUEST_ID, "result": {} }))
                    .expect("serialize inner result")
            })
        }
    }

    const SIGNER: &str = "did:example:agent-1";
    const SIGNER_KEY_ID: &str = "key-1";
    const SERVER: &str = "did:example:server-1";
    const SERVER_KEY_ID: &str = "server-key-1";
    const AUDIENCE: &str = "did:example:server-1";
    const ON_BEHALF_OF: &str = "did:example:user-1";
    const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
    const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
    const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
    const SKEW: i64 = 300;
    const REQUEST_ID: &str = "req-async-race-1";

    fn signer_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[1u8; 32])
    }
    fn server_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[2u8; 32])
    }
    fn now() -> i64 {
        mcp_re_core::parse_rfc3339_utc(ISSUED_AT).expect("parse issued_at") + 60
    }
    fn inbound_resolver() -> InMemoryTrustResolver {
        let mut r = InMemoryTrustResolver::new();
        r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
        r
    }
    fn server_resolver() -> InMemoryTrustResolver {
        let mut r = InMemoryTrustResolver::new();
        r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
        r
    }

    fn signed_request(nonce: &str) -> Vec<u8> {
        let mut request = json!({
            "id": REQUEST_ID,
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": { "text": "hello" },
                "_meta": {
                    REQUEST_META_KEY: {
                        "version": VERSION_DRAFT_01,
                        "signer": SIGNER,
                        "on_behalf_of": ON_BEHALF_OF,
                        "audience": AUDIENCE,
                        "authorization_hash": AUTH_HASH,
                        "nonce": nonce,
                        "issued_at": ISSUED_AT,
                        "expires_at": EXPIRES_AT,
                        "signature": { "alg": SIG_ALG_ED25519, "key_id": SIGNER_KEY_ID },
                    }
                }
            }
        });
        let preimage = request_signing_preimage(&request).expect("request preimage");
        let signature = signer_key().sign(&preimage);
        request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] =
            Value::String(signature);
        serde_json::to_vec(&request).expect("serialize signed request")
    }

    fn expected_request_hash(nonce: &str) -> String {
        let bytes = signed_request(nonce);
        let value: Value = serde_json::from_slice(&bytes).expect("parse signed request");
        request_hash(&value).expect("request_hash")
    }

    fn async_proxy(tier: AsyncReplayTier) -> Proxy {
        Proxy::new(
            server_key(),
            SERVER,
            SERVER_KEY_ID,
            Box::new(inbound_resolver()),
            AUDIENCE,
            SKEW,
        )
        .with_async_replay_tier(tier)
        .with_async_inner(Box::new(EchoAsyncInner))
    }

    /// Spawn an in-process HTTP inner backend that records the last forwarded body
    /// and replies with a fixed JSON-RPC result. Returns its address.
    async fn spawn_http_inner(
        seen: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind inner");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                let seen = std::sync::Arc::clone(&seen);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let seen = std::sync::Arc::clone(&seen);
                        async move {
                            use http_body_util::BodyExt;
                            let body = req.into_body().collect().await.map(|c| c.to_bytes());
                            if let Ok(bytes) = body {
                                *seen.lock().expect("seen") = bytes.to_vec();
                            }
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                br#"{"jsonrpc":"2.0","id":"req-async-race-1","result":{"ok":true}}"#,
                            ))))
                        }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        addr
    }

    /// End-to-end assembly: the async `Proxy` verifies + replay-admits a signed
    /// request, forwards it over the REAL `HttpInnerPool` to a stateless HTTP inner
    /// backend, and signs the backend's result — the client verifies the response.
    /// Also proves the forwarded body carries the proxy-authored verified context
    /// (the inner received a stripped + context-injected request, not the raw
    /// envelope). This is the whole async data plane minus the TLS ingress (which
    /// async_fleet_test / async_serve_parity_test cover).
    #[test]
    fn async_proxy_signs_response_from_real_http_inner() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let addr = spawn_http_inner(std::sync::Arc::clone(&seen)).await;
            let backend: Uri = format!("http://{addr}/mcp").parse().expect("uri");
            let pool = HttpInnerPool::new(vec![backend], Duration::from_secs(5)).expect("pool");

            let tier = AsyncReplayTier::new(
                std::sync::Arc::new(InMemoryAsyncAtomicReplayStore::new()),
                SKEW,
            );
            let proxy = Proxy::new(
                server_key(),
                SERVER,
                SERVER_KEY_ID,
                Box::new(inbound_resolver()),
                AUDIENCE,
                SKEW,
            )
            .with_async_replay_tier(tier)
            .with_async_inner(Box::new(pool));

            let nonce = "nonce-async-http-e2e-1";
            let out = proxy
                .handle_with_transport_async(&signed_request(nonce), now(), None, None)
                .await;

            // The client verifies the signed, request-bound response — proving the
            // response was built from the real HTTP inner round-trip and signed.
            verify_response(&out, &server_resolver(), &expected_request_hash(nonce))
                .expect("the async proxy must sign a verifiable response from the HTTP inner");

            // The inner backend received the proxy-authored forwarded request (the
            // verified-context block is injected; the external request envelope is
            // stripped).
            let forwarded: Value =
                serde_json::from_slice(&seen.lock().expect("seen")).expect("forwarded json");
            assert!(
                forwarded["params"]["_meta"]
                    .get("se.syncom/mcp-re.verified")
                    .is_some()
                    || forwarded["params"]["_meta"]
                        .as_object()
                        .map(|m| m.keys().any(|k| k.contains("verified")))
                        .unwrap_or(false),
                "the HTTP inner must receive the proxy-authored verified-context request, got {forwarded}"
            );
        });
    }

    /// Drive `TASKS` concurrent submissions of the SAME signed request (`nonce`)
    /// through ONE shared async `Proxy` and assert the end-to-end property: EXACTLY
    /// ONE verifiable signed response (the submission that won the atomic insert) and
    /// the rest fail-closed JSON-RPC errors (`Replay`). The store behind the tier is
    /// the cross-replica coherence boundary, so this is the full-serving-path proof
    /// for whichever L2 the caller wired — the in-memory reference OR a live networked
    /// store (Redis/etcd), which is exactly "cross-replica through the full serving
    /// path" (MCPRE-117 AC).
    async fn assert_fullstack_exactly_one_fresh(proxy: Arc<Proxy>, nonce: &str) {
        const TASKS: usize = 64;
        let bytes = Arc::new(signed_request(nonce));
        let hash = expected_request_hash(nonce);

        // Fire many concurrent submissions of the SAME signed request through the
        // async serving entry point.
        let mut handles = Vec::new();
        for _ in 0..TASKS {
            let proxy = Arc::clone(&proxy);
            let bytes = Arc::clone(&bytes);
            handles.push(tokio::spawn(async move {
                proxy
                    .handle_with_transport_async(bytes.as_slice(), now(), None, None)
                    .await
            }));
        }

        let resolver = server_resolver();
        let mut fresh = 0usize;
        let mut replay = 0usize;
        for handle in handles {
            let out = handle.await.expect("task");
            if verify_response(&out, &resolver, &hash).is_ok() {
                // A verifiable signed response ⇒ this submission won the atomic
                // insert (Fresh) and was dispatched + signed.
                fresh += 1;
            } else {
                // Every non-Fresh submission fails closed with a JSON-RPC error
                // (replay detected), never a second signed response.
                let value: Value = serde_json::from_slice(&out).expect("json error object");
                assert!(
                    value.get("error").is_some(),
                    "a non-Fresh async submission must be a fail-closed JSON-RPC error"
                );
                replay += 1;
            }
        }
        assert_eq!(
            fresh, 1,
            "the async serving path admits EXACTLY ONE Fresh under {TASKS}-way concurrency"
        );
        assert_eq!(
            replay,
            TASKS - 1,
            "every other concurrent submission of the same request is a Replay"
        );
    }

    /// A per-run-unique nonce so a full-serving-path proof over a PERSISTENT live
    /// store is independent of keys any earlier run left behind: a leftover key would
    /// make every submission a `Replay` (zero `Fresh`) and spuriously fail. The
    /// in-memory variant does not need this (its store is fresh per test), but the
    /// networked variants MUST use it.
    #[cfg(any(feature = "redis_replay", feature = "cpstore_etcd"))]
    fn unique_nonce(tag: &str) -> String {
        use std::time::SystemTime;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("nonce-async-fullstack-{tag}-{}-{nanos}", std::process::id())
    }

    #[test]
    fn async_proxy_admits_exactly_one_fresh_under_concurrency() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            // ONE shared async `Proxy` over ONE authoritative async L2, shared by
            // all racing tasks (the real fleet model: `Proxy: Send + Sync`).
            let tier = AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), SKEW);
            assert_fullstack_exactly_one_fresh(
                Arc::new(async_proxy(tier)),
                "nonce-async-fullstack-race-1",
            )
            .await;
        });
    }

    /// LIVE full-serving-path proof over a NETWORKED Redis async L2: the same
    /// exactly-one-Fresh property, now with the coherence boundary at a real Redis
    /// (`SET NX PX`) that a cross-replica fleet actually shares — the async data plane
    /// awaits it inside `handle_with_transport_async`. Skip-when-absent (hard-fail
    /// under `MCP_RE_REQUIRE_LIVE_INFRA`).
    #[cfg(feature = "redis_replay")]
    #[test]
    fn async_proxy_exactly_one_fresh_over_live_redis() {
        use mcp_re_proxy::RedisAsyncAtomicReplayStore;

        let url = std::env::var("MCP_RE_TEST_REDIS_URL")
            .ok()
            .filter(|u| !u.trim().is_empty());
        let Some(url) = url else {
            if super::require_live_infra() {
                panic!(
                    "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable; \
                     the full-serving-path Redis race cannot be scored as passing without a live store"
                );
            }
            eprintln!("skipping full-serving-path Redis race: MCP_RE_TEST_REDIS_URL unset");
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
            let tier = AsyncReplayTier::new(store, SKEW);
            assert_fullstack_exactly_one_fresh(Arc::new(async_proxy(tier)), &unique_nonce("redis"))
                .await;
        });
    }

    /// LIVE full-serving-path proof over a NETWORKED etcd async L2 (the CP /
    /// linearizable backend): the same exactly-one-Fresh property with the coherence
    /// boundary at a real etcd `compare { CREATE_REVISION == 0 }` txn. Skip-when-absent
    /// (hard-fail under `MCP_RE_REQUIRE_LIVE_INFRA`).
    #[cfg(feature = "cpstore_etcd")]
    #[test]
    fn async_proxy_exactly_one_fresh_over_live_etcd() {
        use mcp_re_proxy::async_etcd_store::EtcdAsyncAtomicReplayStore;

        let endpoint = std::env::var("MCP_RE_TEST_ETCD_URL")
            .ok()
            .filter(|u| !u.trim().is_empty());
        let Some(endpoint) = endpoint else {
            if super::require_live_infra() {
                panic!(
                    "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_ETCD_URL is unavailable; \
                     the full-serving-path etcd race cannot be scored as passing without a live store"
                );
            }
            eprintln!("skipping full-serving-path etcd race: MCP_RE_TEST_ETCD_URL unset");
            return;
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let store = Arc::new(EtcdAsyncAtomicReplayStore::connect(&endpoint));
            let tier = AsyncReplayTier::new(store, SKEW);
            assert_fullstack_exactly_one_fresh(Arc::new(async_proxy(tier)), &unique_nonce("etcd"))
                .await;
        });
    }
}
