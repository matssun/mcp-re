//! Issue #4028 — live cross-node replay proof against a REAL Redis.
//!
//! This whole file is compiled ONLY under the `redis_replay` feature (the same
//! feature that compiles the [`RedisAtomicReplayStore`]). It is a BLACK-BOX
//! exercise of the public `mcp_re_core::ReplayCache` API over two
//! [`SharedReplayCache`] instances backed by two independent connections to the
//! SAME Redis — modelling two proxy nodes sharing one backend.
//!
//! Redis is not installed in every environment, so the test is gated on the
//! `MCP_RE_TEST_REDIS_URL` env var: when it is unset the test prints a skip notice
//! and returns successfully (it does NOT fail). When it is set (e.g. in a CI job
//! that brings up Redis), it runs the load-bearing assertion: a nonce accepted on
//! node A is rejected as a replay on node B.
#![cfg(feature = "redis_replay")]

use std::time::Duration;
use std::time::Instant;

use mcp_re_proxy::RedisAtomicReplayStore;
use mcp_re_proxy::SharedReplayCache;
use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;

const AUD: &str = "did:example:verifier";

/// A fresh `expires_at` a bounded window into the future from the REAL system
/// clock. The Redis store derives its `PX` TTL from its own wall clock and rejects
/// a past `retain_until` PRE-store (MCPS-08, fail closed), so a FIXED timestamp
/// would make these tests fail on any date past it. Clock-relative keeps them
/// date-independent (the same reason the PTTL / wait-quorum tests below already
/// anchor on the real clock).
fn expires_soon() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64;
    now + 3600
}
const SKEW: i64 = 30;

/// The composite key `SharedReplayCache` derives, recomputed here so the PTTL
/// test can probe the SAME Redis key the cache inserts. Mirrors
/// `SharedReplayCache::composite_key`: length-prefixed `(signer, audience, nonce)`
/// then `sha256_hash_id` (lowercase hex).
fn composite_key(signer: &str, audience: &str, nonce: &str) -> String {
    let preimage = format!(
        "{}:{}|{}:{}|{}:{}",
        signer.len(),
        signer,
        audience.len(),
        audience,
        nonce.len(),
        nonce,
    );
    mcp_re_core::sha256_hash_id(preimage.as_bytes())
}

/// Read the Redis URL the test should run against, or `None` to skip. A real
/// shared backend is not present in every environment.
fn redis_url() -> Option<String> {
    let url = std::env::var("MCP_RE_TEST_REDIS_URL").ok().filter(|u| !u.trim().is_empty());
    if url.is_none() && require_live_infra() {
        panic!(
            "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable \
             — this live e2e MUST run under CI, not skip"
        );
    }
    url
}

/// CI opt-in: when `MCP_RE_REQUIRE_LIVE_INFRA` is set to any non-empty value, a
/// missing-infra SKIP must HARD-FAIL instead of passing, so CI cannot score an
/// unavailable backend as a green test. Unset (local dev) leaves skip behavior
/// unchanged.
fn require_live_infra() -> bool {
    std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty())
}

/// Build a `SharedReplayCache` over a fresh Redis connection to `url`. Each call
/// is an independent "node" (its own connection) sharing the one Redis.
fn node(url: &str) -> SharedReplayCache {
    let store = RedisAtomicReplayStore::connect(url)
        .expect("connect to MCP_RE_TEST_REDIS_URL Redis");
    SharedReplayCache::new(Box::new(store), SKEW)
}

/// The load-bearing cross-node proof: a nonce accepted on node A is rejected as a
/// replay on node B, where A and B are two separate `SharedReplayCache` instances
/// over two separate connections to the SAME Redis. This is the property the
/// single-node file cache cannot provide.
#[test]
fn cross_node_insert_via_a_is_replay_via_b() {
    let Some(url) = redis_url() else {
        eprintln!(
            "SKIP cross_node_insert_via_a_is_replay_via_b: MCP_RE_TEST_REDIS_URL unset \
             (no Redis available in this environment)"
        );
        return;
    };

    // A fixed, unique-per-test signer/nonce (derived from the test name, NOT from
    // a clock or RNG) so reruns target a distinct key space and never collide with
    // a prior run's still-live entry.
    let signer = "did:example:host#cross_node_insert_via_a_is_replay_via_b";
    let nonce = "nonce-4028-cross-node-insert-via-a-is-replay-via-b";

    let mut node_a = node(&url);
    let mut node_b = node(&url);

    assert_eq!(
        node_a.check_and_insert(signer, AUD, nonce, expires_soon()),
        Ok(ReplayDecision::Fresh),
        "first sight on node A must be Fresh"
    );
    assert_eq!(
        node_b.check_and_insert(signer, AUD, nonce, expires_soon()),
        Ok(ReplayDecision::Replay),
        "node B must reject a nonce first seen on node A — shared Redis replay state"
    );
}

/// Single-node fresh-then-replay over the real Redis: the same node sees a nonce
/// once as Fresh and again as Replay.
#[test]
fn single_node_fresh_then_replay() {
    let Some(url) = redis_url() else {
        eprintln!(
            "SKIP single_node_fresh_then_replay: MCP_RE_TEST_REDIS_URL unset \
             (no Redis available in this environment)"
        );
        return;
    };

    let signer = "did:example:host#single_node_fresh_then_replay";
    let nonce = "nonce-4028-single-node-fresh-then-replay";

    let cache = node(&url);
    assert_eq!(
        cache.check_and_insert(signer, AUD, nonce, expires_soon()),
        Ok(ReplayDecision::Fresh),
        "first sight is Fresh"
    );
    assert_eq!(
        cache.check_and_insert(signer, AUD, nonce, expires_soon()),
        Ok(ReplayDecision::Replay),
        "second sight on the same node is a Replay"
    );
}

/// MCPS-090 / H-8 / H-9 — live PTTL confirmation that the inserted key gets a
/// BOUNDED `retain_until - now` window TTL, NOT the `now = 0` absolute-epoch TTL
/// (~1.78e9 s × 1000 ≈ 56 years) that let the keyspace grow without bound.
///
/// We pick an `expires_at` a fixed offset into the future from the REAL system
/// clock so the expected window is well-defined regardless of wall-clock, insert
/// via the cache, then read `PTTL` on the exact key the cache derived. The TTL
/// must be within a small band around `(expires_at + skew - now)`, and MUST be far
/// below the absolute-epoch range. Gated on `MCP_RE_TEST_REDIS_URL` exactly like the
/// other live tests — SKIP is printed and the test passes (never silently a pass
/// of a real assertion) when no Redis is present.
#[test]
fn live_pttl_is_bounded_window_not_absolute_epoch() {
    let Some(url) = redis_url() else {
        eprintln!(
            "SKIP live_pttl_is_bounded_window_not_absolute_epoch: MCP_RE_TEST_REDIS_URL \
             unset (no Redis available in this environment)"
        );
        return;
    };

    let signer = "did:example:host#live_pttl_is_bounded_window_not_absolute_epoch";
    let nonce = "nonce-4028-live-pttl-bounded-window";

    // A window of ~600s from the REAL clock: expires_at = now + 600.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs() as i64;
    let window_secs: i64 = 600;
    let expires_at = now + window_secs;

    let cache = node(&url);
    assert_eq!(
        cache.check_and_insert(signer, AUD, nonce, expires_at),
        Ok(ReplayDecision::Fresh),
        "first sight is Fresh"
    );

    // Probe PTTL on the exact key the cache inserted.
    let key = composite_key(signer, AUD, nonce);
    let client = redis::Client::open(url.as_str()).expect("open redis client");
    let mut conn = client.get_connection().expect("redis connection for PTTL probe");
    let pttl_ms: i64 = redis::cmd("PTTL")
        .arg(&key)
        .query(&mut conn)
        .expect("PTTL query");

    // Expected window in ms is (expires_at + skew - now) * 1000. Allow a generous
    // band for the seconds the op itself took.
    let expected_ms = (window_secs + SKEW) * 1000;
    assert!(
        pttl_ms > 0,
        "key must carry a positive TTL, got PTTL={pttl_ms} (key missing or no expiry)"
    );
    assert!(
        (pttl_ms - expected_ms).abs() < 60_000,
        "PTTL ({pttl_ms} ms) must be ≈ the (expires_at + skew - now) window \
         ({expected_ms} ms), within 60s"
    );
    // The decisive anti-regression bound: the now=0 bug would set PTTL on the
    // order of expires_at * 1000 (~1.78e12 ms). The window is < 0.1% of that.
    let absolute_epoch_ms = expires_at.saturating_mul(1000);
    assert!(
        pttl_ms < absolute_epoch_ms / 1000,
        "PTTL ({pttl_ms} ms) must be vastly below the now=0 absolute-epoch TTL \
         ({absolute_epoch_ms} ms ≈ 56 years)"
    );
}

// ---------------------------------------------------------------------------
// Issue #41 — distributed proof of the ADR-MCPS-020 Amendment-1 WAIT-quorum
// shortfall contract against a REAL primary + replica Redis.
//
// The lane (#39 workflow) provisions a primary on 6379 and a replica on 6380
// (`--replicaof 127.0.0.1 6379`). MCP_RE_TEST_REDIS_URL points at the primary;
// MCP_RE_TEST_REDIS_REPLICA_URL is the replica's own connection, used ONLY to
// drive `REPLICAOF` so the test can induce a real WAIT-quorum shortfall and a
// recovery deterministically (no container stop/start, no blind sleeps).
// ---------------------------------------------------------------------------

/// The replica's admin connection URL, or `None` to skip. Hard-fails under
/// MCP_RE_REQUIRE_LIVE_INFRA so CI cannot score the multi-replica proof as a green
/// skip.
fn replica_admin_url() -> Option<String> {
    let url = std::env::var("MCP_RE_TEST_REDIS_REPLICA_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && require_live_infra() {
        panic!(
            "MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_REPLICA_URL is unavailable \
             — the WAIT-quorum multi-replica proof MUST run under CI, not skip"
        );
    }
    url
}

/// WAIT timeout for the quorum insert: short enough to keep the test snappy, long
/// enough not to flake under CI load (a shortfall costs exactly this once).
const WAIT_TIMEOUT_MS: u64 = 1_500;

/// A `WAIT 1`-quorum node over a fresh primary connection: a fresh insert must be
/// acknowledged by at least one replica within `WAIT_TIMEOUT_MS` or it fails closed.
fn wait_quorum_node(primary_url: &str) -> SharedReplayCache {
    let store = RedisAtomicReplayStore::connect(primary_url)
        .expect("connect to the primary Redis")
        .with_wait_quorum(1, WAIT_TIMEOUT_MS);
    SharedReplayCache::new(Box::new(store), SKEW)
}

fn raw_conn(url: &str) -> redis::Connection {
    redis::Client::open(url)
        .expect("open redis client")
        .get_connection()
        .expect("redis connection")
}

/// `(host, port)` parsed from a `redis://host:port[/db]` URL — the REPLICAOF target.
fn host_port(url: &str) -> (String, u16) {
    let s = url.strip_prefix("redis://").unwrap_or(url);
    let s = s.split('/').next().unwrap_or(s);
    let (host, port) = s.rsplit_once(':').expect("redis url is host:port");
    (host.to_string(), port.parse().expect("redis port is numeric"))
}

/// `connected_slaves:N` from the primary's `INFO replication`, or -1 if absent.
fn primary_connected_slaves(primary: &mut redis::Connection) -> i64 {
    let info: String = redis::cmd("INFO")
        .arg("replication")
        .query(primary)
        .expect("INFO replication on primary");
    info.lines()
        .find_map(|l| l.trim().strip_prefix("connected_slaves:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(-1)
}

/// True when the replica reports it is a slave with its master link up.
fn replica_link_up(replica: &mut redis::Connection) -> bool {
    let info: String = redis::cmd("INFO")
        .arg("replication")
        .query(replica)
        .expect("INFO replication on replica");
    let role_slave = info.lines().any(|l| l.trim() == "role:slave");
    let link_up = info
        .lines()
        .any(|l| l.trim() == "master_link_status:up");
    role_slave && link_up
}

/// Poll `cond` until true or a 20s deadline, then panic — never a blind sleep.
fn poll_until<F: FnMut() -> bool>(what: &str, mut cond: F) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("timed out after 20s waiting for: {what}");
}

/// The Amendment-1 distributed proof: against a real primary+replica Redis, prove
/// (1) a healthy replica-acked WAIT-quorum insert is `Fresh`; (2) detaching the
/// replica induces a genuine WAIT shortfall that fails closed as
/// `ReplayCacheError::Unavailable`, never `Fresh`; (3) a same-nonce retry after the
/// shortfall is NOT `Fresh` (keep-the-nonce); (4) reattaching + resyncing the
/// replica restores `Fresh` for a new nonce.
#[test]
fn wait_quorum_shortfall_and_recovery_against_a_replica() {
    let (Some(primary_url), Some(replica_url)) = (redis_url(), replica_admin_url()) else {
        eprintln!(
            "SKIP wait_quorum_shortfall_and_recovery_against_a_replica: \
             MCP_RE_TEST_REDIS_URL / MCP_RE_TEST_REDIS_REPLICA_URL unset (no replica topology)"
        );
        return;
    };

    let mut primary = raw_conn(&primary_url);
    let mut replica = raw_conn(&replica_url);
    let (master_host, master_port) = host_port(&primary_url);

    struct ReattachOnDrop {
        replica_url: String,
        master_host: String,
        master_port: u16,
    }

    impl Drop for ReattachOnDrop {
        fn drop(&mut self) {
            let Ok(mut conn) = redis::Client::open(self.replica_url.as_str())
                .and_then(|c| c.get_connection())
            else {
                return;
            };
            let _ = redis::cmd("REPLICAOF")
                .arg(self.master_host.as_str())
                .arg(self.master_port)
                .query::<()>(&mut conn);
        }
    }

    let _reattach_guard = ReattachOnDrop {
        replica_url: replica_url.clone(),
        master_host: master_host.clone(),
        master_port,
    };

    // A future expiry so the inserted key carries a real multi-second TTL window
    // and persists across the phases below (a past expiry would clamp to ~1ms and
    // vanish between calls). Test-name-derived signer for a unique key space.
    let signer = "did:example:host#wait_quorum_shortfall_and_recovery";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64;
    let expires_at = now + 600;

    // Ensure a clean starting topology: replica attached + link up + visible.
    let _: () = redis::cmd("REPLICAOF")
        .arg(&master_host)
        .arg(master_port)
        .query(&mut replica)
        .expect("attach replica to primary");
    poll_until("replica master_link_status:up", || replica_link_up(&mut replica));
    poll_until("primary connected_slaves>=1", || {
        primary_connected_slaves(&mut primary) >= 1
    });

    let mut store = wait_quorum_node(&primary_url);

    // (1) Healthy: WAIT 1 is satisfied by the attached replica → Fresh.
    assert_eq!(
        store.check_and_insert(signer, AUD, "nonce-41-healthy", expires_at),
        Ok(ReplayDecision::Fresh),
        "a replica-acked WAIT-quorum insert must be Fresh"
    );

    // (2) Shortfall: detach the replica, confirm the primary sees zero replicas,
    //     then a fresh insert's WAIT 1 cannot be met → fail closed, never Fresh.
    let _: () = redis::cmd("REPLICAOF")
        .arg("NO")
        .arg("ONE")
        .query(&mut replica)
        .expect("detach replica (REPLICAOF NO ONE)");
    poll_until("primary connected_slaves==0", || {
        primary_connected_slaves(&mut primary) == 0
    });

    let shortfall = store.check_and_insert(signer, AUD, "nonce-41-shortfall", expires_at);
    assert!(
        matches!(shortfall, Err(ReplayCacheError::Unavailable { .. })),
        "a WAIT-quorum shortfall must fail closed as ReplayCacheError::Unavailable, got {shortfall:?}"
    );
    assert_ne!(
        shortfall,
        Ok(ReplayDecision::Fresh),
        "a WAIT-quorum shortfall must NEVER be reported as Fresh"
    );

    // (3) Same-nonce retry after the shortfall: the SET NX landed on the primary,
    //     so the nonce is burned — the retry must NOT be Fresh (Replay or another
    //     fail-closed are both acceptable per Amendment 1; Fresh is not).
    let retry = store.check_and_insert(signer, AUD, "nonce-41-shortfall", expires_at);
    assert_ne!(
        retry,
        Ok(ReplayDecision::Fresh),
        "the same nonce after a shortfall must not be retryable as Fresh (keep-the-nonce contract); got {retry:?}"
    );

    // (4) Recovery: reattach + resync the replica, then a NEW nonce is Fresh again.
    let _: () = redis::cmd("REPLICAOF")
        .arg(&master_host)
        .arg(master_port)
        .query(&mut replica)
        .expect("reattach replica to primary");
    poll_until("replica link up after reattach", || replica_link_up(&mut replica));
    poll_until("primary connected_slaves>=1 after reattach", || {
        primary_connected_slaves(&mut primary) >= 1
    });
    assert_eq!(
        store.check_and_insert(signer, AUD, "nonce-41-recovered", expires_at),
        Ok(ReplayDecision::Fresh),
        "after replica reattach + resync, a fresh nonce must be Fresh again"
    );

    // Cleanup: leave the topology attached for any subsequent test in the lane.
}
