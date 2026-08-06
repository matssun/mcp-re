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
//! The `REDIS_WAIT_QUORUM` tier (ADR-MCPS-020) is carried here too: with
//! [`with_wait_quorum`](RedisAsyncAtomicReplayStore::with_wait_quorum) a fresh
//! insert is followed by `WAIT <quorum> <timeout_ms>` and an ack shortfall fails
//! closed, through the same pure decision helper as the sync backend. Without it the
//! store is the plain `REDIS_ASYNC` path, so the tier a deployment DECLARES must be
//! applied when the store is built (see `app.rs`) or the stronger guarantee would be
//! audited but not enforced.
//!
//! TTL derivation and the MCPS-08 pre-store staleness guard reuse the SAME pure
//! helpers as the sync backend ([`compute_ttl_ms`] / [`is_nonpositive_ttl`]),
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
use crate::redis_store::is_nonpositive_ttl;
use crate::redis_store::system_clock;
use crate::redis_store::UnixClock;
use crate::redis_store::WaitQuorum;
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
    /// `Some` for the `REDIS_WAIT_QUORUM` tier — after a fresh insert, `WAIT` for
    /// `quorum` replica acks within `timeout_ms` and fail closed on a shortfall
    /// (ADR-MCPS-020). `None` = `REDIS_ASYNC` / `SINGLE_STORE_FAIL_CLOSED`: plain
    /// `SET NX PX`, no replica wait.
    wait_quorum: Option<WaitQuorum>,
}

/// Headroom added to a declared `WAIT` timeout when sizing the client-side response
/// timeout, so the SERVER's timeout is the one that decides and the client only cuts
/// in on a genuinely wedged connection.
const WAIT_RESPONSE_HEADROOM_MS: u64 = 2_000;

/// The Redis parameter that decides whether an admitted nonce survives to its TTL.
const MAXMEMORY_POLICY_PARAM: &str = "maxmemory-policy";

/// The only `maxmemory-policy` under which Redis never removes a key it was asked to
/// hold for `PX` milliseconds. Every other policy — `allkeys-*` and, because every
/// replay key carries a TTL, `volatile-*` — can evict a live nonce at `maxmemory`.
const REQUIRED_MAXMEMORY_POLICY: &str = "noeviction";

/// Pull the single value out of a `CONFIG GET <param>` reply.
///
/// RESP2 answers with a flat array (`[param, value]`) and RESP3 with a map, and the
/// connection's protocol is a URL detail nothing here controls — so both are read, and
/// anything else yields `None`, which the caller treats as an unverified policy.
fn config_get_value(reply: &redis::Value, param: &str) -> Option<String> {
    fn as_text(value: &redis::Value) -> Option<String> {
        match value {
            redis::Value::BulkString(bytes) => String::from_utf8(bytes.clone()).ok(),
            redis::Value::SimpleString(text) => Some(text.clone()),
            _ => None,
        }
    }
    match reply {
        redis::Value::Map(pairs) => pairs
            .iter()
            .find(|(name, _)| as_text(name).as_deref() == Some(param))
            .and_then(|(_, value)| as_text(value)),
        redis::Value::Array(items) => items
            .chunks_exact(2)
            .find(|pair| as_text(&pair[0]).as_deref() == Some(param))
            .and_then(|pair| as_text(&pair[1])),
        _ => None,
    }
}

/// Whether a server reporting `policy` can be trusted to retain a replay record for
/// its full TTL. `None` means the policy could not be read at all.
///
/// Fail closed either way: an evicting policy silently re-opens replay inside a
/// nonce's own freshness window, and a policy nobody can read is not evidence that it
/// is safe.
fn eviction_policy_verdict(policy: Option<&str>) -> Result<(), ReplayStoreError> {
    match policy {
        Some(policy)
            if policy
                .trim()
                .eq_ignore_ascii_case(REQUIRED_MAXMEMORY_POLICY) =>
        {
            Ok(())
        }
        Some(policy) => Err(ReplayStoreError::Unavailable {
            details: format!(
                "redis replay store refused: {MAXMEMORY_POLICY_PARAM} is {policy:?}, which \
                 evicts keys at maxmemory. Every replay record carries a PX TTL, so an evicted \
                 nonce reads as Fresh again for the rest of its freshness window on every \
                 replica — a replay bypass with no error and no audit reason. Set \
                 {MAXMEMORY_POLICY_PARAM} to {REQUIRED_MAXMEMORY_POLICY} on the replay \
                 instance (give other keyspaces their own instance if they need eviction)."
            ),
        }),
        None => Err(ReplayStoreError::Unavailable {
            details: format!(
                "redis replay store refused: could not read {MAXMEMORY_POLICY_PARAM} (CONFIG GET \
                 unavailable or unparseable). This tier's replay guarantee is exactly the \
                 server's promise to keep a key for its PX TTL, and an unverifiable eviction \
                 policy is not that promise. Permit CONFIG GET for the proxy's Redis user, or \
                 point --replay-redis-url at an instance where it is readable."
            ),
        }),
    }
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
        Self::connect_with_wait_timeout(url, clock, None).await
    }

    /// Connect with the connection manager's response timeout sized for a declared
    /// `WAIT` timeout — see [`response_timeout_for`](Self::response_timeout_for).
    ///
    /// `None` keeps the library default, which is correct for the tiers that issue no
    /// `WAIT`.
    pub async fn connect_with_wait_timeout(
        url: &str,
        clock: UnixClock,
        wait_timeout_ms: Option<u64>,
    ) -> Result<Self, ReplayStoreError> {
        Self::connect_pooled(url, clock, wait_timeout_ms, Self::DEFAULT_POOL_SIZE).await
    }

    /// As [`connect_with_wait_timeout`](Self::connect_with_wait_timeout) with an
    /// explicit pool size. A size of 0 is treated as 1 — a store with no connection
    /// could not serve at all, and failing closed at startup on an arithmetic edge is
    /// worse than the single connection this used to have.
    pub async fn connect_pooled(
        url: &str,
        clock: UnixClock,
        wait_timeout_ms: Option<u64>,
        pool_size: usize,
    ) -> Result<Self, ReplayStoreError> {
        let client = redis::Client::open(url).map_err(|e| ReplayStoreError::Unavailable {
            details: format!("open redis client: {e}"),
        })?;
        let config = match wait_timeout_ms {
            Some(timeout_ms) => redis::aio::ConnectionManagerConfig::new()
                .set_response_timeout(Some(Self::response_timeout_for(timeout_ms))),
            None => redis::aio::ConnectionManagerConfig::new(),
        };
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
            wait_quorum: None,
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
        let reply: Option<redis::Value> = redis::cmd("CONFIG")
            .arg("GET")
            .arg(MAXMEMORY_POLICY_PARAM)
            .query_async(conn)
            .await
            .ok();
        let policy = reply
            .as_ref()
            .and_then(|reply| config_get_value(reply, MAXMEMORY_POLICY_PARAM));
        eviction_policy_verdict(policy.as_deref())
    }

    /// Enable the `REDIS_WAIT_QUORUM` tier (ADR-MCPS-020): after each fresh insert,
    /// issue `WAIT <quorum> <timeout_ms>` and fail closed unless at least `quorum`
    /// replicas acknowledge within the timeout. Without this the store is the
    /// `REDIS_ASYNC` / `SINGLE_STORE_FAIL_CLOSED` plain `SET NX PX` path, whose
    /// weaker guarantee a failover can lose.
    pub fn with_wait_quorum(mut self, quorum: u32, timeout_ms: u64) -> Self {
        self.wait_quorum = Some(WaitQuorum { quorum, timeout_ms });
        self
    }

    /// The client-side response timeout the connection manager needs so a declared
    /// `WAIT` timeout is the one that actually applies.
    ///
    /// `redis`'s `ConnectionManager` defaults to a 500 ms per-command response
    /// timeout, and `WAIT <quorum> <timeout_ms>` is an ordinary command — so the
    /// shipped `redis-wait-quorum:2:2000` tier could never wait 2000 ms: any replica
    /// ack slower than 500 ms aborted the command CLIENT-side and failed the request
    /// closed. The deployment declared a durability tier it was not running, and the
    /// symptom (spurious `replay_cache_unavailable` under replica lag) looks like a
    /// Redis problem rather than a client bound.
    ///
    /// The bound must be strictly larger than the declared `WAIT` timeout, with
    /// headroom for the round trip itself.
    fn response_timeout_for(timeout_ms: u64) -> Duration {
        Duration::from_millis(timeout_ms.saturating_add(WAIT_RESPONSE_HEADROOM_MS))
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
            if is_nonpositive_ttl(expires_at_unix, now) {
                return Err(ReplayStoreError::Unavailable {
                    details: format!(
                        "replay request already stale: retain_until ({expires_at_unix}) is at \
                         or before now ({now}) — rejected pre-store (MCPS-08, fail closed)"
                    ),
                });
            }
            let ttl_ms = compute_ttl_ms(expires_at_unix, now);

            // Single atomic op: SET key 1 NX PX <ttl_ms>. Some(_) ⇒ the key was absent
            // and is now set (this caller won) ⇒ Fresh; None ⇒ NX found it present ⇒
            // Replay. ANY error fails closed (Unavailable) — no retry, so an outage is
            // never a fresh nonce and the SET-NX non-idempotency-under-retry subtlety
            // cannot arise.
            let t_set = crate::stage_timers::Timed::start(crate::stage_timers::Stage::ReplaySet);
            let result: Result<Option<String>, redis::RedisError> = redis::cmd("SET")
                .arg(&key)
                .arg(1)
                .arg("NX")
                .arg("PX")
                .arg(ttl_ms)
                .query_async(&mut conn)
                .await;
            drop(t_set);
            match result {
                Ok(Some(_)) => match wait_quorum {
                    // REDIS_ASYNC / SINGLE_STORE_FAIL_CLOSED: the primary's ack is the
                    // whole guarantee.
                    None => Ok(ReplayDecision::Fresh),
                    // REDIS_WAIT_QUORUM: the nonce counts as admitted only once it is
                    // replicated, so a failover to a replica cannot resurrect it.
                    // `WAIT` returns the ack count reached within the timeout (a
                    // timeout is a partial count, not an error), and the shortfall
                    // decision is the SAME pure helper the sync store uses. As
                    // everywhere on this path, an error fails closed with no retry —
                    // and here that also avoids the SET+WAIT non-idempotency the sync
                    // store must reason about: a re-run would find the key it just
                    // wrote and report a false `Replay`.
                    Some(WaitQuorum { quorum, timeout_ms }) => {
                        let t_wait = crate::stage_timers::Timed::start(
                            crate::stage_timers::Stage::ReplayWait,
                        );
                        let acked: Result<i64, redis::RedisError> = redis::cmd("WAIT")
                            .arg(quorum)
                            .arg(timeout_ms)
                            .query_async(&mut conn)
                            .await;
                        drop(t_wait);
                        match acked {
                            Ok(acked) => classify_wait_acks(acked, quorum, timeout_ms),
                            Err(e) => Err(ReplayStoreError::Unavailable {
                                details: format!("redis async WAIT failed: {e}"),
                            }),
                        }
                    }
                },
                Ok(None) => Ok(ReplayDecision::Replay),
                Err(e) => Err(ReplayStoreError::Unavailable {
                    details: format!("redis async SET NX failed: {e}"),
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

    use super::*;
    use tokio::io::AsyncBufReadExt;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::io::BufReader;

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

    /// Read one RESP command (an array of bulk strings) from a client.
    async fn read_command<R: tokio::io::AsyncBufRead + Unpin>(
        reader: &mut R,
    ) -> Option<Vec<String>> {
        let mut header = String::new();
        if reader.read_line(&mut header).await.ok()? == 0 {
            return None;
        }
        let argc: usize = header.trim_end().strip_prefix('*')?.parse().ok()?;
        let mut args = Vec::with_capacity(argc);
        for _ in 0..argc {
            let mut len_line = String::new();
            if reader.read_line(&mut len_line).await.ok()? == 0 {
                return None;
            }
            let len: usize = len_line.trim_end().strip_prefix('$')?.parse().ok()?;
            // The trailing CRLF is part of the framing, so read it and drop it.
            let mut buf = vec![0u8; len + 2];
            reader.read_exact(&mut buf).await.ok()?;
            buf.truncate(len);
            args.push(String::from_utf8(buf).ok()?);
        }
        Some(args)
    }

    /// A server that speaks just enough RESP to answer the connect handshake and one
    /// `CONFIG GET maxmemory-policy`, reporting `policy`. Returns its `redis://` URL.
    async fn redis_reporting(policy: &str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let policy = policy.to_string();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let policy = policy.clone();
                tokio::spawn(async move {
                    let (rx, mut tx) = stream.into_split();
                    let mut reader = BufReader::new(rx);
                    while let Some(args) = read_command(&mut reader).await {
                        let reply = match args.first() {
                            Some(cmd) if cmd.eq_ignore_ascii_case("CONFIG") => format!(
                                "*2\r\n${}\r\n{MAXMEMORY_POLICY_PARAM}\r\n${}\r\n{policy}\r\n",
                                MAXMEMORY_POLICY_PARAM.len(),
                                policy.len()
                            ),
                            // Whatever else the client library sends while setting the
                            // connection up.
                            _ => "+OK\r\n".to_string(),
                        };
                        if tx.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        format!("redis://{addr}")
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
}
