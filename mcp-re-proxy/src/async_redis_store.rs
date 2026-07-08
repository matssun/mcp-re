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
//! TTL derivation and the MCPS-08 pre-store staleness guard reuse the SAME pure
//! helpers as the sync backend ([`compute_ttl_ms`] / [`is_nonpositive_ttl`]),
//! reading the store's own clock, so the `PX` window is the intended
//! `retain_until - now` and an already-stale request is rejected before Redis is
//! touched.

use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;
use redis::aio::ConnectionManager;

use crate::async_replay::AsyncAtomicReplayStore;
use crate::async_replay::ReplayDecisionFuture;
use crate::redis_store::compute_ttl_ms;
use crate::redis_store::is_nonpositive_ttl;
use crate::redis_store::system_clock;
use crate::redis_store::UnixClock;
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
        let client = redis::Client::open(url).map_err(|e| ReplayStoreError::Unavailable {
            details: format!("open redis client: {e}"),
        })?;
        let conn = client
            .get_connection_manager()
            .await
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("connect redis async: {e}"),
            })?;
        Ok(RedisAsyncAtomicReplayStore { conn, clock })
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
                Ok(Some(_)) => Ok(ReplayDecision::Fresh),
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
