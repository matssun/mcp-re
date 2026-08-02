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

use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;
use redis::aio::ConnectionManager;
use std::time::Duration;

use crate::async_replay::AsyncAtomicReplayStore;
use crate::async_replay::ReplayDecisionFuture;
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
    /// Auto-reconnecting, multiplexed async connection. Cloned per op (cheap).
    conn: ConnectionManager,
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
        let client = redis::Client::open(url).map_err(|e| ReplayStoreError::Unavailable {
            details: format!("open redis client: {e}"),
        })?;
        let config = match wait_timeout_ms {
            Some(timeout_ms) => redis::aio::ConnectionManagerConfig::new()
                .set_response_timeout(Some(Self::response_timeout_for(timeout_ms))),
            None => redis::aio::ConnectionManagerConfig::new(),
        };
        let conn = client
            .get_connection_manager_with_config(config)
            .await
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("connect redis async: {e}"),
            })?;
        Ok(RedisAsyncAtomicReplayStore {
            conn,
            clock,
            wait_quorum: None,
        })
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
    fn atomic_insert_if_absent<'a>(
        &'a self,
        key: &'a str,
        expires_at_unix: i64,
        _now_unix: i64,
    ) -> ReplayDecisionFuture<'a> {
        let key = key.to_string();
        let mut conn = self.conn.clone();
        let wait_quorum = self.wait_quorum;
        // Read the store's OWN clock once (ignore the trait's vestigial 0), and reuse
        // it for both the staleness guard and the TTL window.
        let now = (self.clock)();
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
            let result: Result<Option<String>, redis::RedisError> = redis::cmd("SET")
                .arg(&key)
                .arg(1)
                .arg("NX")
                .arg("PX")
                .arg(ttl_ms)
                .query_async(&mut conn)
                .await;
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
                        let acked: Result<i64, redis::RedisError> = redis::cmd("WAIT")
                            .arg(quorum)
                            .arg(timeout_ms)
                            .query_async(&mut conn)
                            .await;
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
