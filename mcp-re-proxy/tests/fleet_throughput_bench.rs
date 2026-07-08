//! MCPS-89 (ADR-MCPS-049 W3) — fleet throughput / added-latency benchmark.
//!
//! Measures the ISOLATED policy-enforcement path (verify + shared-replay
//! insert + dispatch to an in-process inner) of `mcp-re-proxy` replicas sharing one
//! authoritative async replay store, and reports requests/sec plus p50/p99/max
//! added latency at 1 and N replica counts. The inner server is a near-zero-cost
//! in-process closure, so the measured latency is the PEP overhead itself.
//!
//! This is a HARNESS, not a pass/fail gate: it asserts only that the run
//! completes, and PRINTS the numbers (which land in the deployment reference,
//! MCPS-87). It is `#[ignore]` so normal `cargo test` never runs it; invoke it
//! explicitly.
//!
//! The shared store is the in-memory async reference (`InMemoryAsyncAtomicReplayStore`):
//! ONE `Arc` is cloned into every replica's `AsyncReplayTier`, so the replicas share
//! one authoritative tier without any live infra (the durable-backend throughput
//! lane lives with the live redis/etcd suites). Each `block_on_handle` drives one
//! request through the async serving path to completion.
//!
//! Run:
//!   cargo test -p mcp-re-proxy \
//!     --test fleet_throughput_bench -- --ignored --nocapture
//!
//! Tunables (env): MCP_RE_BENCH_REQUESTS (default 500), MCP_RE_BENCH_REPLICAS
//! (default 4 — the high end of the 1..=N sweep).

use std::sync::Arc;
use std::time::Instant;

use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_host::HostSigner;
use mcp_re_proxy::async_replay::AsyncAtomicReplayStore;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::test_support::block_on_handle;
use mcp_re_proxy::Proxy;
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

fn replica(store: Arc<dyn AsyncAtomicReplayStore>) -> Proxy {
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
    Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
    )
    .with_async_inner(Box::new(inner))
    .with_async_replay_tier(AsyncReplayTier::new(store, SKEW))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sign(now: i64, nonce: &str) -> Vec<u8> {
    let issued_at = mcp_re_core::unix_to_rfc3339_utc(now);
    let expires_at = mcp_re_core::unix_to_rfc3339_utc(now + 3600);
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
/// replicas, timing ONLY each `block_on_handle()` call, and return (throughput_rps,
/// sorted per-request latencies in micros).
fn measure(n: usize, requests: usize) -> (f64, Vec<u128>) {
    // ONE shared authoritative store, cloned into every replica's async tier.
    let shared: Arc<dyn AsyncAtomicReplayStore> = Arc::new(InMemoryAsyncAtomicReplayStore::new());
    let nodes: Vec<Proxy> = (0..n).map(|_| replica(Arc::clone(&shared))).collect();
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
        let _ = block_on_handle(&nodes[i % n], &warm, now);
    }

    let mut latencies = Vec::with_capacity(requests);
    let wall = Instant::now();
    for (i, req) in requests_bytes.iter().enumerate() {
        let node = &nodes[i % n];
        let t = Instant::now();
        let resp = block_on_handle(node, req, now);
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
#[ignore = "benchmark harness; run explicitly with --ignored --nocapture"]
fn fleet_throughput_and_added_latency() {
    let requests = env_usize("MCP_RE_BENCH_REQUESTS", 500);
    let max_replicas = env_usize("MCP_RE_BENCH_REPLICAS", 4).max(1);

    eprintln!(
        "\nMCPS-89 fleet PEP benchmark — {requests} requests/run, in-process inner, shared async store"
    );
    eprintln!(
        "{:>9} | {:>10} | {:>9} | {:>9} | {:>9}",
        "replicas", "req/s", "p50 (us)", "p99 (us)", "max (us)"
    );
    eprintln!("{:->9}-+-{:->10}-+-{:->9}-+-{:->9}-+-{:->9}", "", "", "", "", "");
    for n in 1..=max_replicas {
        let (rps, lat) = measure(n, requests);
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
