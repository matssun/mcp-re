//! MCPS-86 (ADR-MCPS-049 W1, proof (b)) — fleet trust/revocation coherence.
//!
//! Proves the load-bearing trust-propagation property for a horizontally-scaled
//! fleet: a revocation applied to the shared trust store takes effect on a SIBLING
//! replica within the stated bound once the trust epoch advances. Two serving
//! `mcp-re-proxy` replicas each run the ADR-021 Push tier (a bounded trust cache +
//! the MCPS-84 Redis trust-epoch source) over a shared trust-epoch key.
//!
//! The test includes the discriminating NEGATIVE control: after the signer is
//! revoked in the shared store but BEFORE the epoch advances, the sibling still
//! admits it (served from its bounded cache within `T` — the honest lag a fleet
//! would otherwise inherit). Only when the epoch advances does the sibling flush
//! and reject. That isolates the epoch push as the mechanism, not incidental cache
//! expiry.
//!
//! redis_replay-gated; skipped when `MCP_RE_TEST_REDIS_URL` is unset (hard-failed
//! under `MCP_RE_REQUIRE_LIVE_INFRA`).
#![cfg(feature = "redis_replay")]

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::SigningKey;
use mcp_re_core::TrustResolver;
use mcp_re_core::TrustResolverError;
use mcp_re_core::VerificationKey;
use mcp_re_host::HostSigner;
use mcp_re_proxy::redis_trust_epoch_source;
use mcp_re_proxy::trust_cache::UnixClock;
use mcp_re_proxy::Proxy;
use mcp_re_proxy::PushInvalidationTrustCache;
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
const T_SECS: i64 = 3600; // large, so ONLY the epoch flush (not T expiry) can evict
const NEG_TTL: i64 = 300;

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}

/// A trust resolver over a SHARED revocation flag: while `revoked` is false it
/// returns the signer's key (trusted); once flipped it returns `Revoked`. Two
/// replicas share one `revoked` flag to model a single shared trust store.
struct SharedRevocableTrust {
    key: VerificationKey,
    revoked: Arc<AtomicBool>,
}
impl TrustResolver for SharedRevocableTrust {
    fn resolve(&self, _signer: &str, _key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(TrustResolverError::Revoked)
        } else {
            Ok(self.key.clone())
        }
    }
}

fn redis_url() -> Option<String> {
    let url = std::env::var("MCP_RE_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
        panic!("MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable");
    }
    url
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn unique_epoch_key() -> String {
    format!(
        "mcp-re:test:fleet:trust:epoch:{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// A serving replica whose inbound trust resolver is a Push-tier cache (bounded
/// `T` + Redis trust-epoch flush) over the shared revocation flag.
fn push_replica(url: &str, epoch_key: &str, revoked: Arc<AtomicBool>) -> Proxy {
    let base = Box::new(SharedRevocableTrust {
        key: signer_key().public_key(),
        revoked,
    });
    let clock: UnixClock = Box::new(now_unix);
    let source = redis_trust_epoch_source(url, epoch_key).expect("connect trust-epoch source");
    let resolver = PushInvalidationTrustCache::new(base, T_SECS, NEG_TTL, clock, Box::new(source));

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
        Box::new(resolver),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
}

fn signed_request(now: i64, nonce: &str) -> Vec<u8> {
    let issued_at = mcp_re_core::unix_to_rfc3339_utc(now);
    let expires_at = mcp_re_core::unix_to_rfc3339_utc(now + 600);
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
        .sign_tool_call(
            &Value::String("req".to_string()),
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

fn is_error(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("error").cloned())
        .is_some()
}

#[test]
fn revocation_takes_effect_on_a_sibling_replica_when_the_epoch_advances() {
    let Some(url) = redis_url() else {
        eprintln!("SKIP revocation_takes_effect_on_a_sibling_replica_when_the_epoch_advances: MCP_RE_TEST_REDIS_URL unset");
        return;
    };
    let epoch_key = unique_epoch_key();
    let mut admin = redis::Client::open(url.as_str())
        .expect("open redis")
        .get_connection()
        .expect("admin conn");
    let _: () = redis::cmd("SET")
        .arg(&epoch_key)
        .arg(1_i64)
        .query(&mut admin)
        .expect("SET epoch=1");

    let revoked = Arc::new(AtomicBool::new(false));
    let node_a = push_replica(&url, &epoch_key, revoked.clone());
    let node_b = push_replica(&url, &epoch_key, revoked.clone());

    let now = now_unix();

    // Both replicas admit the trusted signer (and cache its key in their bounded
    // trust caches).
    assert!(
        !is_error(&node_a.handle(&signed_request(now, "trust-a-1"), now)),
        "replica A must admit the trusted signer"
    );
    assert!(
        !is_error(&node_b.handle(&signed_request(now, "trust-b-1"), now)),
        "replica B must admit the trusted signer (and cache its key)"
    );

    // Revoke the signer in the SHARED trust store, but do NOT yet advance the
    // epoch. NEGATIVE CONTROL: replica B still admits — served from its bounded
    // cache within T. This is exactly the cross-replica lag a fleet would inherit
    // without a push signal.
    revoked.store(true, Ordering::SeqCst);
    assert!(
        !is_error(&node_b.handle(&signed_request(now, "trust-b-2"), now)),
        "before the epoch advance, replica B still serves the cached (now-stale) trust — \
         the bounded-T lag the push signal exists to close"
    );

    // Advance the trust epoch (the operator's fleet-wide invalidation).
    let _: i64 = redis::cmd("INCR")
        .arg(&epoch_key)
        .query(&mut admin)
        .expect("INCR epoch");

    // Replica B's next request flushes its trust cache (epoch advanced), re-resolves
    // against the now-revoked shared store, and REJECTS — the revocation has taken
    // effect on the sibling within the bound (one poll/request).
    assert!(
        is_error(&node_b.handle(&signed_request(now, "trust-b-3"), now)),
        "after the epoch advance, replica B must reject the revoked signer"
    );

    let _: () = redis::cmd("DEL").arg(&epoch_key).query(&mut admin).ok().unwrap_or(());
}
