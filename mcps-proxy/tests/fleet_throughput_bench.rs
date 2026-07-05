//! MCPS-89 (ADR-MCPS-049 W3) — fleet throughput / added-latency benchmark.
//!
//! Measures the ISOLATED policy-enforcement path (verify + shared-replay
//! insert + dispatch to an in-process inner) of `mcps-proxy` replicas sharing one
//! Redis replay store, and reports requests/sec plus p50/p99/max added latency at
//! 1 and N replica counts. The inner server is a near-zero-cost in-process
//! closure, so the measured latency is the PEP overhead itself — dominated at
//! scale by the shared-store round-trip (`SET NX PX`), which is exactly the cost
//! horizontal scaling must amortize.
//!
//! This is a HARNESS, not a pass/fail gate: it asserts only that the run
//! completes, and PRINTS the numbers (which land in the deployment reference,
//! MCPS-87). It is `#[ignore]` so normal `cargo test` never runs it; invoke it
//! explicitly. Redis-gated + skip-when-absent like `fleet_replay_e2e_test.rs`.
//!
//! Run:
//!   MCPS_TEST_REDIS_URL=redis://127.0.0.1:6379 \
//!     cargo test -p mcps-proxy --features redis_replay \
//!     --test fleet_throughput_bench -- --ignored --nocapture
//!
//! Tunables (env): MCPS_BENCH_REQUESTS (default 500), MCPS_BENCH_REPLICAS
//! (default 4 — the high end of the 1..=N sweep).
#![cfg(feature = "redis_replay")]

use std::time::Instant;

use mcps_core::InMemoryTrustResolver;
use mcps_core::SigningKey;
use mcps_host::HostSigner;
use mcps_proxy::Proxy;
use mcps_proxy::RedisAtomicReplayStore;
use mcps_proxy::SharedReplayCache;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const SKEW: i64 = 30;

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}

fn redis_url() -> Option<String> {
    let url = std::env::var("MCPS_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && std::env::var("MCPS_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
        panic!("MCPS_REQUIRE_LIVE_INFRA is set but MCPS_TEST_REDIS_URL is unavailable");
    }
    url
}

fn replica(url: &str) -> Proxy {
    let inner = |request: &[u8]| -> Vec<u8> {
        let id = serde_json::from_slice::<Value>(request)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(Value::Null);
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "content": [ { "type": "text", "text": "ok" } ] }
        }))
        .unwrap()
    };
    let store = RedisAtomicReplayStore::connect(url).expect("connect redis");
    Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_replay_cache(Box::new(SharedReplayCache::new(Box::new(store), SKEW)))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sign(now: i64, nonce: &str) -> Vec<u8> {
    let issued_at = mcps_core::unix_to_rfc3339_utc(now);
    let expires_at = mcps_core::unix_to_rfc3339_utc(now + 3600);
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
        .sign_tool_call(
            &Value::String("bench".to_string()),
            "echo",
            json!({ "text": "hi" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            nonce,
            &issued_at,
            &expires_at,
        )
        .expect("host signs")
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn percentile(sorted_micros: &[u128], p: f64) -> u128 {
    if sorted_micros.is_empty() {
        return 0;
    }
    let idx = ((sorted_micros.len() as f64 - 1.0) * p).round() as usize;
    sorted_micros[idx]
}

/// Drive `requests` fresh (distinct-nonce) requests round-robin across `n`
/// replicas, timing ONLY each `handle()` call, and return (throughput_rps,
/// sorted per-request latencies in micros).
fn measure(url: &str, n: usize, requests: usize) -> (f64, Vec<u128>) {
    let nodes: Vec<Proxy> = (0..n).map(|_| replica(url)).collect();
    let now = now_unix();
    let run_tag = format!("{now}-{n}");

    // Pre-sign everything so signing cost is OUTSIDE the timed region — we measure
    // the PEP path (verify + replay insert + dispatch), not host signing.
    let requests_bytes: Vec<Vec<u8>> = (0..requests)
        .map(|i| sign(now, &format!("bench-{run_tag}-{i}")))
        .collect();

    // Warm up connections / caches (not timed) with DEDICATED nonces so warm-up
    // does not consume a nonce the timed loop would then replay.
    for i in 0..n {
        let warm = sign(now, &format!("warm-{run_tag}-{i}"));
        let _ = nodes[i % n].handle(&warm, now);
    }

    let mut latencies = Vec::with_capacity(requests);
    let wall = Instant::now();
    for (i, req) in requests_bytes.iter().enumerate() {
        let node = &nodes[i % n];
        let t = Instant::now();
        let resp = node.handle(req, now);
        latencies.push(t.elapsed().as_micros());
        debug_assert!(
            serde_json::from_slice::<Value>(&resp)
                .ok()
                .and_then(|v| v.get("error").cloned())
                .is_none(),
            "fresh request unexpectedly rejected during benchmark"
        );
    }
    let total = wall.elapsed().as_secs_f64();
    latencies.sort_unstable();
    (requests as f64 / total, latencies)
}

#[test]
#[ignore = "benchmark harness; needs Redis; run explicitly with --ignored --nocapture"]
fn fleet_throughput_and_added_latency() {
    let Some(url) = redis_url() else {
        eprintln!("SKIP fleet_throughput_and_added_latency: MCPS_TEST_REDIS_URL unset");
        return;
    };
    let requests = env_usize("MCPS_BENCH_REQUESTS", 500);
    let max_replicas = env_usize("MCPS_BENCH_REPLICAS", 4).max(1);

    eprintln!(
        "\nMCPS-89 fleet PEP benchmark — {requests} requests/run, in-process inner, shared Redis"
    );
    eprintln!(
        "{:>9} | {:>10} | {:>9} | {:>9} | {:>9}",
        "replicas", "req/s", "p50 (us)", "p99 (us)", "max (us)"
    );
    eprintln!("{:->9}-+-{:->10}-+-{:->9}-+-{:->9}-+-{:->9}", "", "", "", "", "");
    for n in 1..=max_replicas {
        let (rps, lat) = measure(&url, n, requests);
        eprintln!(
            "{:>9} | {:>10.0} | {:>9} | {:>9} | {:>9}",
            n,
            rps,
            percentile(&lat, 0.50),
            percentile(&lat, 0.99),
            lat.last().copied().unwrap_or(0),
        );
        assert_eq!(lat.len(), requests, "every request must be measured");
    }
    eprintln!(
        "note: round-robin dispatch is single-threaded, so req/s reflects per-request PEP latency, \
         not aggregate fleet capacity; the number to publish is p50/p99 ADDED latency.\n"
    );
}
