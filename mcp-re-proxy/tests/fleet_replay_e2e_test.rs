//! MCPS-80 / MCPS-81 (ADR-MCPS-049 W1, proof (a)) — fleet replay coherence.
//!
//! Stands up a fleet of independent serving `mcp-re-proxy` instances (each its own
//! inner server and its own `SharedReplayCache`) that all share ONE Redis replay
//! store, and proves the load-bearing horizontal-scale property: a request
//! admitted by one replica is replay-REJECTED by any sibling replica, because the
//! `(signer, audience, nonce)` replay key is shared across the fleet. This is the
//! full-stack, serving-proxy analogue of the store-level
//! `cross_node_insert_via_a_is_replay_via_b` in `redis_replay_e2e_test.rs`; it is
//! the CI-gated proof that lifts "single-node" from the production claim
//! (ADR-MCPS-049 clause 4).
//!
//! Feature-gated on `redis_replay` and skipped when `MCP_RE_TEST_REDIS_URL` is
//! unset (hard-failed under `MCP_RE_REQUIRE_LIVE_INFRA`), mirroring
//! `redis_replay_e2e_test.rs`.
#![cfg(feature = "redis_replay")]

use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_host::HostSigner;
use mcp_re_proxy::Proxy;
use mcp_re_proxy::RedisAtomicReplayStore;
use mcp_re_proxy::SharedReplayCache;
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

/// Skip-when-absent gate, identical in spirit to `redis_replay_e2e_test.rs`: no
/// Redis → skip, unless `MCP_RE_REQUIRE_LIVE_INFRA` demands the live lane run.
fn redis_url() -> Option<String> {
    let url = std::env::var("MCP_RE_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && require_live_infra() {
        panic!(
            "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable; \
             the fleet replay lane cannot be skipped under required-live-infra"
        );
    }
    url
}
fn require_live_infra() -> bool {
    std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty())
}

/// One serving proxy replica over its OWN `SharedReplayCache` to the SAME Redis
/// `url`. Distinct replicas therefore share replay state through Redis while
/// remaining otherwise independent (own inner server, own connection) — the fleet
/// topology under test.
fn replica(url: &str) -> Proxy {
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
    let store = RedisAtomicReplayStore::connect(url).expect("connect to MCP_RE_TEST_REDIS_URL Redis");
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

/// A fleet of `n` replicas behind a (trivial) round-robin dispatcher — the "≥2
/// proxies behind a load balancer over one shared store" topology of MCPS-80.
fn fleet(url: &str, n: usize) -> Vec<Proxy> {
    (0..n).map(|_| replica(url)).collect()
}

/// Real-wall-clock-relative signed request. The Redis store derives its `PX` TTL
/// from its OWN system clock and fails closed on a past `retain_until`
/// (`redis_store.rs`), so freshness MUST be anchored to real now — not the fixed
/// 2026 constants the in-process proxy tests use. `nonce` is an explicit input, so
/// reusing the returned bytes reuses the nonce (== a replay).
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
    let Some(url) = redis_url() else {
        eprintln!("SKIP admit_on_replica_a_then_replay_rejected_on_replica_b: MCP_RE_TEST_REDIS_URL unset");
        return;
    };
    let now = now_unix();
    // Unique per-run nonce so a rerun within the freshness window does not collide
    // with a still-live Redis key from a previous run.
    let nonce = format!("fleet-admit-a-replay-b-{now}");
    let request = signed_request(now, &nonce);

    let nodes = fleet(&url, 2);

    // Replica A admits the fresh request: verified, forwarded, signed response.
    let resp_a = nodes[0].handle(&request, now);
    assert!(
        !is_error(&resp_a),
        "replica A must admit the fresh request, got: {}",
        String::from_utf8_lossy(&resp_a)
    );

    // Replica B, sharing the same Redis, rejects the IDENTICAL bytes as a replay.
    let resp_b = nodes[1].handle(&request, now);
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
    let Some(url) = redis_url() else {
        eprintln!("SKIP replay_is_rejected_on_every_sibling_regardless_of_admitting_node: MCP_RE_TEST_REDIS_URL unset");
        return;
    };
    let now = now_unix();
    let nodes = fleet(&url, 3);

    // Admit on the middle node; both the first and last must then reject the replay.
    let nonce = format!("fleet-admit-middle-{now}");
    let request = signed_request(now, &nonce);
    assert!(!is_error(&nodes[1].handle(&request, now)), "middle replica admits");
    assert_eq!(error_message(&nodes[0].handle(&request, now)), "mcp-re.replay_detected");
    assert_eq!(error_message(&nodes[2].handle(&request, now)), "mcp-re.replay_detected");
}

/// MCPS-80 baseline: DISTINCT nonces are admitted on every replica. Proves the
/// fleet is not blanket-rejecting (which would make the replay proof vacuous) —
/// only genuine replays are stopped, fresh traffic flows on any node.
#[test]
fn distinct_nonces_are_admitted_across_the_fleet() {
    let Some(url) = redis_url() else {
        eprintln!("SKIP distinct_nonces_are_admitted_across_the_fleet: MCP_RE_TEST_REDIS_URL unset");
        return;
    };
    let now = now_unix();
    let nodes = fleet(&url, 3);
    // Round-robin distinct requests across the replicas; each is fresh, so each is
    // admitted regardless of which node the "load balancer" picked.
    for i in 0..6 {
        let node = &nodes[i % nodes.len()];
        let request = signed_request(now, &format!("fleet-distinct-{now}-{i}"));
        assert!(
            !is_error(&node.handle(&request, now)),
            "distinct fresh nonce {i} must be admitted on replica {}",
            i % nodes.len()
        );
    }
}
