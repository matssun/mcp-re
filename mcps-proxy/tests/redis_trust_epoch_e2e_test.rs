//! MCPS-84 (ADR-MCPS-049 W2) — live Redis trust-epoch source.
//!
//! Proves the networked half of the trust-epoch invalidation source against a
//! real Redis: a `TrustEpochSource` over a `RedisEpochReader` reads a shared epoch
//! key and emits a coarse `FlushAll` when an operator advances that epoch on a
//! DIFFERENT connection (`INCR`) — the cross-connection propagation a fleet relies
//! on. The epoch→event logic itself (baseline, steady, error→unhealthy,
//! self-healing) is unit-tested without Redis in `src/trust_epoch.rs`; this proves
//! the Redis reader wiring.
//!
//! Feature-gated on `redis_replay`, skipped when `MCPS_TEST_REDIS_URL` is unset
//! (hard-failed under `MCPS_REQUIRE_LIVE_INFRA`), mirroring
//! `redis_replay_e2e_test.rs`.
#![cfg(feature = "redis_replay")]

use mcps_proxy::trust_epoch::redis_trust_epoch_source;
use mcps_proxy::InvalidationChannel;
use mcps_proxy::InvalidationEvent;

fn redis_url() -> Option<String> {
    let url = std::env::var("MCPS_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && std::env::var("MCPS_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
        panic!("MCPS_REQUIRE_LIVE_INFRA is set but MCPS_TEST_REDIS_URL is unavailable");
    }
    url
}

fn unique_epoch_key() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("mcps:test:trust:epoch:{now}")
}

#[test]
fn epoch_advance_on_redis_is_detected_as_flush_all() {
    let Some(url) = redis_url() else {
        eprintln!("SKIP epoch_advance_on_redis_is_detected_as_flush_all: MCPS_TEST_REDIS_URL unset");
        return;
    };
    let key = unique_epoch_key();

    // Admin connection: the "operator" that bumps the trust epoch.
    let mut admin = redis::Client::open(url.as_str())
        .expect("open redis client")
        .get_connection()
        .expect("admin connection");
    // Establish a concrete starting epoch.
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(1_i64)
        .query(&mut admin)
        .expect("SET epoch=1");

    // The source is a SEPARATE connection, as a sibling replica would be.
    let source = redis_trust_epoch_source(&url, &key).expect("connect trust-epoch source");

    // First poll establishes the baseline (epoch=1): no flush.
    assert!(
        source.drain_pending().is_empty(),
        "baseline poll must not flush"
    );
    assert!(source.is_healthy(), "a successful read is healthy");

    // Operator advances the epoch on the admin connection.
    let _: i64 = redis::cmd("INCR")
        .arg(&key)
        .query(&mut admin)
        .expect("INCR epoch -> 2");

    // The source, on its own connection, detects the advance and flushes.
    assert_eq!(
        source.drain_pending(),
        vec![InvalidationEvent::FlushAll],
        "an epoch advance on another connection must surface as FlushAll"
    );
    // Steady epoch: no further flush.
    assert!(
        source.drain_pending().is_empty(),
        "a steady epoch must not flush again"
    );

    // A second advance flushes again.
    let _: i64 = redis::cmd("INCR")
        .arg(&key)
        .query(&mut admin)
        .expect("INCR epoch -> 3");
    assert_eq!(
        source.drain_pending(),
        vec![InvalidationEvent::FlushAll],
        "a second epoch advance must flush again"
    );

    // Cleanup.
    let _: () = redis::cmd("DEL")
        .arg(&key)
        .query(&mut admin)
        .expect("DEL epoch key");
}
