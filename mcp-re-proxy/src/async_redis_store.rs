//! MCPRE-117 (ADR-MCPRE-051 §4, Phase 2) — the ASYNC Redis authoritative replay
//! backend.
//!
//! The async analogue of [`crate::redis_store::RedisAtomicReplayStore`]: the same
//! server-side-atomic `SET key 1 NX PX <ttl_ms>`, but issued through the tokio
//! ASYNC redis client so the insert is AWAITED on the per-core request path and
//! never blocks a runtime worker (ADR-MCPRE-051 §4 — "the per-core Redis/etcd
//! clients are async and pipelined"). It implements
//! [`AsyncAtomicReplayStore`](crate::async_replay::AsyncAtomicReplayStore), so an
//! [`AsyncReplayTier`](crate::async_replay::AsyncReplayTier) over it gives the
//! async serving path a genuinely durable, cross-process authoritative tier.
//!
//! Connection handling uses redis's auto-reconnecting, cloneable
//! [`ConnectionManager`]: each op clones the manager (cheap, shares one
//! multiplexed connection) and awaits the command. Unlike the sync store this does
//! NOT reconnect-and-retry a failed `SET NX`: a transient error surfaces as
//! [`ReplayStoreError::Unavailable`] (fail closed), which is always safe and
//! sidesteps the `SET NX` non-idempotency-under-retry subtlety (sync store audit
//! #97) — an outage is NEVER a fresh nonce.
//!
//! The `REDIS_WAIT_QUORUM` tier (ADR-MCPS-020) is carried here too: a store built by
//! [`connect_with_wait_quorum`](RedisAsyncAtomicReplayStore::connect_with_wait_quorum)
//! with `Some((quorum, timeout_ms))` pipelines `WAIT <quorum> <timeout_ms>` behind the
//! `SET NX PX` and an ack shortfall fails closed, through the same pure decision helper
//! as the sync backend. The tier is a construction parameter, so no store exists in a
//! weaker tier than the one it was connected with.
//!
//! TTL derivation and the MCPS-08 pre-store staleness guard reuse the SAME pure
//! helpers as the sync backend ([`compute_ttl_ms`] / [`is_stale_pre_store`](crate::shared_replay::is_stale_pre_store)),
//! reading the store's own clock, so the `PX` window is the intended
//! `retain_until - now` and an already-stale request is rejected before Redis is
//! touched.
//!
//! **The server must not be allowed to drop a nonce before its TTL.** "Key present"
//! is the whole replay signal here, so an admitted nonce that leaves the keyspace
//! early is `Fresh` again for the remainder of its freshness window — a replay
//! bypass, on every replica, produced by capacity pressure rather than by an attack.
//! Every replay key carries a `PX` TTL, which makes it a preferred victim under the
//! `volatile-*` policies and an ordinary one under `allkeys-*`. So the connect path
//! ASSERTS `maxmemory-policy noeviction` and fails closed otherwise, including when
//! the server will not answer `CONFIG GET`: an unverifiable eviction policy is not a
//! guarantee, and a startup refusal is recoverable where a silent replay window is
//! not.

use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;
use redis::aio::ConnectionManager;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::async_replay::AsyncAtomicReplayStore;
use crate::async_replay::ReplayDecisionFuture;
use crate::async_replay::ReplayInsert;
use crate::redis_store::classify_wait_acks;
use crate::redis_store::compute_ttl_ms;
use crate::redis_store::system_clock;
use crate::redis_store::UnixClock;
use crate::redis_store::WaitQuorum;
use crate::shared_replay::is_stale_pre_store;
use crate::shared_replay::ReplayStoreError;

/// A durable, cross-process ASYNC authoritative replay store backed by Redis
/// `SET NX PX`. Cloning is NOT exposed — one store owns one
/// [`ConnectionManager`]; the manager is cloned internally per op.
pub struct RedisAsyncAtomicReplayStore {
    /// A POOL of auto-reconnecting multiplexed connections, one picked per op.
    ///
    /// One connection has a finite round-trip rate, and every request costs two ops
    /// (`SET NX PX`, then `WAIT`). Over loopback that rate is far above the serving
    /// path's, so a pool buys NOTHING measurable there — swept 1, 2, 4, 8 and 16
    /// against a Docker Redis and throughput was flat at ~13k either way. It is kept
    /// for the deployment this store is actually for: with Redis a network hop away at
    /// even 0.5 ms, a single connection ceilings at ~2k ops/s — about 1k requests/s —
    /// regardless of cores, and that is a bound no amount of serving parallelism can
    /// cross.
    ///
    /// So this is headroom for remote Redis, not a fix for any locally measured
    /// ceiling. The ~13k seen on loopback is something else and remains unattributed.
    pool: Vec<ConnectionManager>,
    /// Round-robin cursor. `Relaxed` is right: this only has to spread load, and a
    /// racing pair landing on the same connection costs nothing but a shared socket for
    /// one op. Correctness never depends on which connection an op takes.
    next: AtomicUsize,
    /// The store's own clock (the proxy's impure edge), read once per op for both
    /// the staleness guard and the TTL window.
    clock: UnixClock,
    /// `Some` for the `REDIS_WAIT_QUORUM` tier: `WAIT` for `quorum` replica acks within
    /// `timeout_ms` and fail closed on a shortfall (ADR-MCPS-020). `None` = plain
    /// `SET NX PX`, no replica wait.
    wait_quorum: Option<WaitQuorum>,
}

/// Headroom added to a declared `WAIT` timeout when sizing the client-side response
/// timeout, so the SERVER's timeout is the one that decides and the client only cuts
/// in on a genuinely wedged connection.
const WAIT_RESPONSE_HEADROOM_MS: u64 = 2_000;

/// Per-op response bound for tiers that issue no `WAIT`.
const OP_RESPONSE_TIMEOUT_MS: u64 = 500;

/// Bound on each connection attempt.
const CONNECT_TIMEOUT_MS: u64 = 1_000;

/// The shared retention authority: whether an instance promises to keep a key. The
/// decision serves both redis-backed stores, so it lives beside neither store's error
/// type — this module supplies the replay tier's consequence and wraps the detail.
pub(crate) mod retention_promise;

use self::retention_promise::retention_verdict;

/// Whether a server reporting `policy` can be trusted to retain a replay record for its
/// full TTL, as this tier's error. `None` means the policy could not be read at all.
fn eviction_policy_verdict(policy: Option<&str>) -> Result<(), ReplayStoreError> {
    retention_verdict(policy, &retention_promise::REPLAY).map_err(|details| {
        ReplayStoreError::Unavailable {
            details: format!("redis replay store refused: {details}"),
        }
    })
}

impl RedisAsyncAtomicReplayStore {
    /// Connect to `url` (e.g. `redis://host:port`) with the production system
    /// clock. Fails closed ([`ReplayStoreError::Unavailable`]) if the client
    /// cannot be opened or the initial async connection cannot be established.
    pub async fn connect(url: &str) -> Result<Self, ReplayStoreError> {
        Self::connect_with(url, system_clock()).await
    }

    /// Connect with an injected clock (deterministic tests reuse the sync store's
    /// clock-injection pattern).
    pub async fn connect_with(url: &str, clock: UnixClock) -> Result<Self, ReplayStoreError> {
        Self::connect_with_wait_quorum(url, clock, None).await
    }

    /// Connect in the tier `wait_quorum` declares (`(quorum, timeout_ms)`, as
    /// `ReplayDurabilityTier::wait_quorum_params` projects it); `None` is the plain
    /// tier. The response timeout is sized from the same value — see
    /// [`response_timeout_for`](Self::response_timeout_for).
    pub async fn connect_with_wait_quorum(
        url: &str,
        clock: UnixClock,
        wait_quorum: Option<(u32, u64)>,
    ) -> Result<Self, ReplayStoreError> {
        Self::connect_pooled(url, clock, wait_quorum, Self::DEFAULT_POOL_SIZE).await
    }

    /// As [`connect_with_wait_quorum`](Self::connect_with_wait_quorum) with an
    /// explicit pool size. A size of 0 is treated as 1 — a store with no connection
    /// could not serve at all, and failing closed at startup on an arithmetic edge is
    /// worse than the single connection this used to have.
    pub async fn connect_pooled(
        url: &str,
        clock: UnixClock,
        wait_quorum: Option<(u32, u64)>,
        pool_size: usize,
    ) -> Result<Self, ReplayStoreError> {
        let client = redis::Client::open(url).map_err(|e| ReplayStoreError::Unavailable {
            details: format!("open redis client: {e}"),
        })?;
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_millis(CONNECT_TIMEOUT_MS)))
            .set_response_timeout(Some(Self::response_timeout_for(wait_quorum)));
        let mut pool = Vec::with_capacity(pool_size.max(1));
        for _ in 0..pool_size.max(1) {
            let conn = client
                .get_connection_manager_with_config(config.clone())
                .await
                .map_err(|e| ReplayStoreError::Unavailable {
                    details: format!("connect redis async: {e}"),
                })?;
            pool.push(conn);
        }
        // Asked ONCE rather than per connection: every connection in the pool addresses
        // the same server, so an eviction policy is a property of that server and asking
        // n times would only add n-1 round trips to startup.
        Self::assert_no_eviction(&mut pool[0]).await?;
        Ok(RedisAsyncAtomicReplayStore {
            pool,
            next: AtomicUsize::new(0),
            clock,
            wait_quorum: wait_quorum.map(|(quorum, timeout_ms)| WaitQuorum { quorum, timeout_ms }),
        })
    }

    /// The connection this op will use. Round-robin over the pool.
    fn checkout(&self) -> ConnectionManager {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        self.pool[i].clone()
    }

    /// How many connections the store opens when the caller does not say.
    ///
    /// Each request costs two Redis round trips, and one connection sustains roughly
    /// 29k ops/s, so a pool of this size puts the replay path an order of magnitude
    /// above the proxy's own measured per-request CPU cost — far enough that the next
    /// ceiling is something else, which is the point.
    pub const DEFAULT_POOL_SIZE: usize = 8;

    /// Refuse to serve on a Redis that may drop a replay record before its TTL.
    ///
    /// Asked once, at connect, because it is a property of the server rather than of
    /// a request — and asked at all because nothing on the insert path can detect an
    /// eviction after the fact: the next `SET NX` on an evicted key simply succeeds,
    /// which is indistinguishable from a nonce that was never presented.
    async fn assert_no_eviction(conn: &mut ConnectionManager) -> Result<(), ReplayStoreError> {
        eviction_policy_verdict(retention_promise::read_policy(conn).await.as_deref())
    }

    /// The client-side response bound the connection manager runs under.
    ///
    /// Tiers without `WAIT` get [`OP_RESPONSE_TIMEOUT_MS`]. `WAIT <quorum> <timeout_ms>`
    /// is an ordinary command, so a declared timeout longer than the op bound could never
    /// elapse: the bound must exceed it, with headroom for the round trip itself.
    fn response_timeout_for(wait_quorum: Option<(u32, u64)>) -> Duration {
        Duration::from_millis(
            wait_quorum.map_or(OP_RESPONSE_TIMEOUT_MS, |(_, timeout_ms)| {
                timeout_ms.saturating_add(WAIT_RESPONSE_HEADROOM_MS)
            }),
        )
    }
}

impl AsyncAtomicReplayStore for RedisAsyncAtomicReplayStore {
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a> {
        // Retention here is a Redis-side `SET NX PX` TTL, not a bounded local set, so
        // there is no local ceiling to split: `insert.actor` is budgeted above this
        // seam by `AsyncReplayTier`, which is what makes the bound apply to this
        // backend at all.
        //
        // Caller-side work only — no I/O — so this separates our own cost from the round
        // trips below. The three spans together split the replay call into "before the
        // wire", "the SET", and "the WAIT".
        let _t_prep = crate::stage_timers::Timed::start(crate::stage_timers::Stage::ReplayPrep);
        let expires_at_unix = insert.expires_at_unix;
        let key = insert.key.to_string();
        let mut conn = self.checkout();
        let wait_quorum = self.wait_quorum;
        // Read the store's OWN clock once (ignore the trait's vestigial 0), and reuse
        // it for both the staleness guard and the TTL window.
        let now = (self.clock)();
        drop(_t_prep);
        Box::pin(async move {
            // MCPS-08 pre-store staleness guard: an already-stale request (a
            // non-positive remaining window) is rejected fail-closed BEFORE Redis is
            // touched — never recorded and reported Fresh.
            if is_stale_pre_store(expires_at_unix, now) {
                return Err(ReplayStoreError::Unavailable {
                    details: format!(
                        "replay request already stale: retain_until ({expires_at_unix}) is at \
                         or before now ({now}) — rejected pre-store (MCPS-08, fail closed)"
                    ),
                });
            }
            let ttl_ms = compute_ttl_ms(expires_at_unix, now);

            // Single atomic op: SET key 1 NX PX <ttl_ms>. Some(_) => the key was absent
            // and is now set (this caller won) => Fresh; None => NX found it present =>
            // Replay. ANY error fails closed (Unavailable) with no retry, so an outage is
            // never a fresh nonce.
            let mut set = redis::cmd("SET");
            set.arg(&key).arg(1).arg("NX").arg("PX").arg(ttl_ms);
            let Some(WaitQuorum { quorum, timeout_ms }) = wait_quorum else {
                let t_set =
                    crate::stage_timers::Timed::start(crate::stage_timers::Stage::ReplaySet);
                let result: Result<Option<String>, redis::RedisError> =
                    set.query_async(&mut conn).await;
                drop(t_set);
                return match result {
                    Ok(Some(_)) => Ok(ReplayDecision::Fresh),
                    Ok(None) => Ok(ReplayDecision::Replay),
                    Err(e) => Err(ReplayStoreError::Unavailable {
                        details: format!("redis async SET NX failed: {e}"),
                    }),
                };
            };
            // REDIS_WAIT_QUORUM: the SET and the WAIT are ONE pipelined request, written
            // and answered on one multiplexed connection, so a manager reconnect cannot
            // land the WAIT on a fresh connection and report acks for a write it never
            // measured. `WAIT` returns the ack count reached within the timeout (a
            // timeout is a partial count, not an error). A Replay under this tier also
            // carries the WAIT and discards its count.
            let t_wait = crate::stage_timers::Timed::start(crate::stage_timers::Stage::ReplayWait);
            let result: Result<(Option<String>, i64), redis::RedisError> = redis::pipe()
                .add_command(set)
                .cmd("WAIT")
                .arg(quorum)
                .arg(timeout_ms)
                .query_async(&mut conn)
                .await;
            drop(t_wait);
            match result {
                Ok((Some(_), acked)) => classify_wait_acks(acked, quorum, timeout_ms),
                Ok((None, _)) => Ok(ReplayDecision::Replay),
                Err(e) => Err(ReplayStoreError::Unavailable {
                    details: format!("redis async SET+WAIT failed: {e}"),
                }),
            }
        })
    }

    /// A genuinely cross-process durable backend (ADR-MCPS-020).
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::Durable
    }
}

#[cfg(test)]
mod tests {
    //! The eviction-policy assertion. "Key present" is the entire replay signal, so a
    //! server that may drop a live nonce is a replay bypass rather than an outage —
    //! and it is invisible on the insert path, because a `SET NX` on an evicted key
    //! succeeds exactly as it would for a nonce never seen before. The store therefore
    //! has to refuse at connect, which is what these drive against a scripted server.

    use super::retention_promise::config_get_value;
    use super::retention_promise::scripted_server::redis_reporting;
    use super::retention_promise::MAXMEMORY_POLICY_PARAM;
    use super::*;

    fn bulk(text: &str) -> redis::Value {
        redis::Value::BulkString(text.as_bytes().to_vec())
    }

    #[test]
    fn the_policy_is_read_out_of_either_protocols_reply() {
        let resp2 = redis::Value::Array(vec![bulk(MAXMEMORY_POLICY_PARAM), bulk("noeviction")]);
        assert_eq!(
            config_get_value(&resp2, MAXMEMORY_POLICY_PARAM).as_deref(),
            Some("noeviction")
        );
        let resp3 = redis::Value::Map(vec![(bulk(MAXMEMORY_POLICY_PARAM), bulk("volatile-lru"))]);
        assert_eq!(
            config_get_value(&resp3, MAXMEMORY_POLICY_PARAM).as_deref(),
            Some("volatile-lru")
        );
        // A server that answers something else (an empty reply for an unknown
        // parameter, an error, a renamed CONFIG) leaves the policy unread.
        assert_eq!(
            config_get_value(&redis::Value::Array(vec![]), MAXMEMORY_POLICY_PARAM),
            None
        );
        assert_eq!(
            config_get_value(&redis::Value::Nil, MAXMEMORY_POLICY_PARAM),
            None
        );
    }

    #[test]
    fn every_evicting_policy_is_refused_and_so_is_an_unreadable_one() {
        assert!(eviction_policy_verdict(Some("noeviction")).is_ok());
        assert!(
            eviction_policy_verdict(Some("NOEVICTION")).is_ok(),
            "the reply is a server string, not a token this code chose"
        );
        // `volatile-*` is not the safer half: every replay key carries a PX TTL, so
        // they are the PREFERRED victims there.
        for policy in [
            "volatile-lru",
            "volatile-lfu",
            "volatile-ttl",
            "volatile-random",
            "allkeys-lru",
            "allkeys-lfu",
            "allkeys-random",
        ] {
            let err = eviction_policy_verdict(Some(policy))
                .expect_err("an evicting policy silently re-opens replay");
            let ReplayStoreError::Unavailable { details } = err;
            assert!(details.contains(policy), "the refusal must name the policy");
        }
        assert!(
            eviction_policy_verdict(None).is_err(),
            "an unverifiable policy is not evidence of a safe one"
        );
    }

    #[tokio::test]
    async fn a_store_refuses_to_connect_to_an_evicting_redis() {
        let url = redis_reporting("volatile-lru").await;
        let err = RedisAsyncAtomicReplayStore::connect(&url)
            .await
            .err()
            .expect("a Redis that evicts live nonces must not back the replay tier");
        let ReplayStoreError::Unavailable { details } = err;
        assert!(
            details.contains(MAXMEMORY_POLICY_PARAM) && details.contains("volatile-lru"),
            "the refusal must say which policy it read, got: {details}"
        );
    }

    #[tokio::test]
    async fn a_noeviction_redis_is_accepted() {
        // The refusal above must be the policy, not the scripted server: the identical
        // connect against a server reporting `noeviction` has to succeed, or the test
        // above proves nothing.
        let url = redis_reporting("noeviction").await;
        let store = RedisAsyncAtomicReplayStore::connect(&url)
            .await
            .expect("noeviction is the supported configuration");
        assert_eq!(store.durability_class(), ReplayDurabilityClass::Durable);
    }

    use super::retention_promise::scripted_server::serve;
    use super::retention_promise::scripted_server::Script;

    fn set_script(reply: &str) -> Script {
        Script {
            policy: Some("noeviction".into()),
            recorded: vec!["SET".into()],
            reply: reply.into(),
        }
    }

    async fn insert_at(
        store: &RedisAsyncAtomicReplayStore,
        expires: i64,
    ) -> Result<ReplayDecision, ReplayStoreError> {
        store
            .atomic_insert_if_absent(ReplayInsert::new("k", "actor", expires, 0))
            .await
    }

    #[tokio::test]
    async fn a_fresh_insert_sends_the_clock_derived_window() {
        let (url, seen) = serve(set_script("+OK\r\n")).await;
        let store = RedisAsyncAtomicReplayStore::connect_with(&url, Box::new(|| 1_000))
            .await
            .expect("connect");
        assert_eq!(insert_at(&store, 1_600).await, Ok(ReplayDecision::Fresh));
        let recorded = seen.lock().expect("commands").clone();
        assert_eq!(recorded, vec![vec!["SET", "k", "1", "NX", "PX", "600000"]]);
    }

    #[tokio::test]
    async fn an_existing_key_is_a_replay() {
        let (url, _seen) = serve(set_script("$-1\r\n")).await;
        let store = RedisAsyncAtomicReplayStore::connect_with(&url, Box::new(|| 1_000))
            .await
            .expect("connect");
        assert_eq!(insert_at(&store, 1_600).await, Ok(ReplayDecision::Replay));
    }

    #[tokio::test]
    async fn a_set_error_fails_closed() {
        let (url, _seen) = serve(set_script("-ERR boom\r\n")).await;
        let store = RedisAsyncAtomicReplayStore::connect_with(&url, Box::new(|| 1_000))
            .await
            .expect("connect");
        assert!(matches!(
            insert_at(&store, 1_600).await,
            Err(ReplayStoreError::Unavailable { .. })
        ));
    }

    #[tokio::test]
    async fn a_stale_window_never_reaches_redis() {
        let (url, seen) = serve(set_script("+OK\r\n")).await;
        let store = RedisAsyncAtomicReplayStore::connect_with(&url, Box::new(|| 1_000))
            .await
            .expect("connect");
        for expires in [1_000, 999] {
            assert!(matches!(
                insert_at(&store, expires).await,
                Err(ReplayStoreError::Unavailable { .. })
            ));
        }
        assert!(seen.lock().expect("commands").is_empty());
        assert_eq!(insert_at(&store, 1_600).await, Ok(ReplayDecision::Fresh));
        assert_eq!(seen.lock().expect("commands").len(), 1);
    }

    #[tokio::test]
    async fn a_declared_quorum_is_enforced_by_the_store_it_was_connected_with() {
        let script = |reply: &str| Script {
            policy: Some("noeviction".into()),
            recorded: vec!["WAIT".into()],
            reply: reply.into(),
        };
        let (url, seen) = serve(script(":1\r\n")).await;
        let store = RedisAsyncAtomicReplayStore::connect_with_wait_quorum(
            &url,
            Box::new(|| 1_000),
            Some((2, 100)),
        )
        .await
        .expect("connect");
        assert!(matches!(
            insert_at(&store, 1_600).await,
            Err(ReplayStoreError::Unavailable { .. })
        ));
        assert_eq!(
            seen.lock().expect("commands").clone(),
            vec![vec!["WAIT", "2", "100"]]
        );
        let (url, _seen) = serve(script(":2\r\n")).await;
        let store = RedisAsyncAtomicReplayStore::connect_with_wait_quorum(
            &url,
            Box::new(|| 1_000),
            Some((2, 100)),
        )
        .await
        .expect("connect");
        assert_eq!(insert_at(&store, 1_600).await, Ok(ReplayDecision::Fresh));
    }

    #[test]
    fn every_tier_has_an_owned_round_trip_bound() {
        assert_eq!(
            RedisAsyncAtomicReplayStore::response_timeout_for(None),
            Duration::from_millis(OP_RESPONSE_TIMEOUT_MS)
        );
        assert_eq!(
            RedisAsyncAtomicReplayStore::response_timeout_for(Some((2, 2000))),
            Duration::from_millis(4000)
        );
    }

    #[tokio::test]
    async fn a_black_holed_set_fails_closed_within_the_owned_bound() {
        let (url, _seen) = serve(set_script("")).await;
        let store = RedisAsyncAtomicReplayStore::connect_with(&url, Box::new(|| 1_000))
            .await
            .expect("connect");
        let outcome = tokio::time::timeout(Duration::from_secs(5), insert_at(&store, 1_600)).await;
        assert!(matches!(
            outcome,
            Ok(Err(ReplayStoreError::Unavailable { .. }))
        ));
    }

    #[tokio::test]
    async fn a_stalled_connect_is_refused_not_hung() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("redis://{}", listener.local_addr().expect("addr"));
        let holder = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let outcome = tokio::time::timeout(
            Duration::from_secs(60),
            RedisAsyncAtomicReplayStore::connect(&url),
        )
        .await;
        holder.abort();
        assert!(matches!(
            outcome,
            Ok(Err(ReplayStoreError::Unavailable { .. }))
        ));
    }

    #[tokio::test]
    async fn a_credentialled_url_never_reaches_a_refusal() {
        const PASSWORD: &str = "S3cretPW-XYZ";
        for url in [
            format!("redis://proxyuser:{PASSWORD}@127.0.0.1:6379/?protocol=bogus"),
            format!("redis://proxyuser:{PASSWORD}@127.0.0.1:1"),
        ] {
            let err = RedisAsyncAtomicReplayStore::connect(&url)
                .await
                .err()
                .expect("an unusable endpoint must refuse");
            let ReplayStoreError::Unavailable { details } = err;
            assert!(!details.contains(PASSWORD), "password leaked: {details}");
            assert!(!details.contains(&url), "url leaked: {details}");
        }
    }
}
