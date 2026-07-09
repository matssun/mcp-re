//! MCPS-80 / MCPS-81 (ADR-MCPS-049 W1, proof (a)) — fleet replay coherence.
//!
//! Stands up a fleet of independent serving `mcp-re-proxy` instances (each its own
//! inner server and its own async replay TIER) that all share ONE authoritative
//! replay store, and proves the load-bearing horizontal-scale property: a request
//! admitted by one replica is replay-REJECTED by any sibling replica, because the
//! `(signer, audience, nonce)` replay key is shared across the fleet. This is the
//! full-stack, serving-proxy analogue of the store-level
//! `shared_cache_cross_replica_admit_via_a_is_replay_via_b` in
//! `replay_race_harness_test.rs`; it is the CI-gated proof that lifts "single-node"
//! from the production claim (ADR-MCPS-049 clause 4).
//!
//! ADR-MCPRE-051 §4 makes the authoritative replay tier ASYNC. The shared store here
//! is the in-memory async reference (`InMemoryAsyncAtomicReplayStore`): a SINGLE
//! `Arc` is cloned into every replica's `AsyncReplayTier`, so the replicas share one
//! authoritative tier exactly as a real fleet shares one Redis/etcd backend — the
//! deterministic, no-live-infra substitute for the durable backend (whose own live
//! lane lives in `redis_replay_e2e_test.rs` / `cpstore_etcd`).

use std::sync::Arc;

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

/// The inbound resolver every replica shares — maps the request SIGNER to its
/// public key so any replica admits the same signature (a prerequisite for the
/// replay check to even be reached on a sibling).
fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}

/// One serving proxy replica over its OWN per-core async replay tier backed by the
/// SAME shared authoritative store. Distinct replicas therefore share replay state
/// through the store while remaining otherwise independent (own inner server) — the
/// fleet topology under test.
fn replica(store: Arc<dyn AsyncAtomicReplayStore>) -> Proxy {
    let inner = |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).unwrap_or(Value::Null);
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "content": [ { "type": "text", "text": "ok" } ] }
        });
        serde_json::to_vec(&response).expect("serialize inner response")
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

/// A fleet of `n` replicas behind a (trivial) round-robin dispatcher — the "≥2
/// proxies behind a load balancer over one shared store" topology of MCPS-80. ONE
/// authoritative store is constructed and a CLONE of its `Arc` is handed to each
/// replica, so a nonce admitted on any replica is a replay on every sibling.
fn fleet(n: usize) -> Vec<Proxy> {
    let shared: Arc<dyn AsyncAtomicReplayStore> = Arc::new(InMemoryAsyncAtomicReplayStore::new());
    (0..n).map(|_| replica(Arc::clone(&shared))).collect()
}

/// Wall-clock-relative signed request. `nonce` is an explicit input, so reusing the
/// returned bytes reuses the nonce (== a replay).
fn signed_request(now: i64, nonce: &str) -> Vec<u8> {
    let issued_at = mcp_re_core::unix_to_rfc3339_utc(now);
    let expires_at = mcp_re_core::unix_to_rfc3339_utc(now + 600);
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
        .sign_tool_call(
            &Value::String("req-fleet".to_string()),
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64
}

fn is_error(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("error").cloned())
        .is_some()
}
fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse response object");
    value["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

/// MCPS-81, proof (a): a nonce admitted on replica A is replay-rejected on replica
/// B — the property that makes horizontal scaling safe.
#[test]
fn admit_on_replica_a_then_replay_rejected_on_replica_b() {
    let now = now_unix();
    // Unique per-run nonce so a rerun within the freshness window does not collide
    // with a still-live key from a previous run.
    let nonce = format!("fleet-admit-a-replay-b-{now}");
    let request = signed_request(now, &nonce);

    let nodes = fleet(2);

    // Replica A admits the fresh request: verified, forwarded, signed response.
    let resp_a = block_on_handle(&nodes[0], &request, now);
    assert!(
        !is_error(&resp_a),
        "replica A must admit the fresh request, got: {}",
        String::from_utf8_lossy(&resp_a)
    );

    // Replica B, sharing the same store, rejects the IDENTICAL bytes as a replay.
    let resp_b = block_on_handle(&nodes[1], &request, now);
    assert_eq!(
        error_message(&resp_b),
        "mcp-re.replay_detected",
        "replica B must replay-reject a nonce first admitted on replica A"
    );
}

/// MCPS-81 symmetry: the fleet has no privileged "first" node — whichever replica
/// admits a nonce first, every OTHER replica rejects the replay. Proves the guard
/// is a shared-state property, not an artifact of node ordering.
#[test]
fn replay_is_rejected_on_every_sibling_regardless_of_admitting_node() {
    let now = now_unix();
    let nodes = fleet(3);

    // Admit on the middle node; both the first and last must then reject the replay.
    let nonce = format!("fleet-admit-middle-{now}");
    let request = signed_request(now, &nonce);
    assert!(
        !is_error(&block_on_handle(&nodes[1], &request, now)),
        "middle replica admits"
    );
    assert_eq!(
        error_message(&block_on_handle(&nodes[0], &request, now)),
        "mcp-re.replay_detected"
    );
    assert_eq!(
        error_message(&block_on_handle(&nodes[2], &request, now)),
        "mcp-re.replay_detected"
    );
}

/// MCPS-80 baseline: DISTINCT nonces are admitted on every replica. Proves the
/// fleet is not blanket-rejecting (which would make the replay proof vacuous) —
/// only genuine replays are stopped, fresh traffic flows on any node.
#[test]
fn distinct_nonces_are_admitted_across_the_fleet() {
    let now = now_unix();
    let nodes = fleet(3);
    // Round-robin distinct requests across the replicas; each is fresh, so each is
    // admitted regardless of which node the "load balancer" picked.
    for i in 0..6 {
        let node = &nodes[i % nodes.len()];
        let request = signed_request(now, &format!("fleet-distinct-{now}-{i}"));
        assert!(
            !is_error(&block_on_handle(node, &request, now)),
            "distinct fresh nonce {i} must be admitted on replica {}",
            i % nodes.len()
        );
    }
}
