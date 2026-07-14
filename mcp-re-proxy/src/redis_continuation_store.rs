// SPDX-License-Identifier: Apache-2.0
//! The Redis-backed MRTR continuation correlation store (ADR-MCPS-047) — the shared
//! tier that carries a multi-round-trip continuation across a replica switch.
//!
//! The async analogue of the design in [`crate::async_redis_store`]: one
//! auto-reconnecting, multiplexed [`ConnectionManager`] cloned per op. The open leg
//! records the retained bases with `SET key <json> PX <ttl_ms>`; the answer leg
//! reads-and-removes them with a single atomic `GETDEL key`, giving one-shot
//! semantics (a continuation can be answered at most once) without a read-then-
//! delete race across replicas. Any transient error fails closed
//! ([`ContinuationStoreError::Unavailable`]): on the answer leg that reads as "no
//! retained continuation" (the pure dispatcher then rejects the binding), and on the
//! open leg it means the reply cannot be honoured cross-replica.

use redis::aio::ConnectionManager;

use crate::continuation_store::AsyncContinuationStore;
use crate::continuation_store::ContinuationFuture;
use crate::continuation_store::ContinuationStoreError;
use crate::continuation_store::RetainedBases;

/// The on-the-wire value: the two retained signature bases, each base64url-encoded
/// and joined with a `.` (base64url alphabet never contains `.`, so the split is
/// unambiguous). The bases are opaque bytes; base64url keeps the Redis value a clean
/// ASCII string. Avoids a serde dependency for one fixed two-field shape.
fn encode_bases(bases: &RetainedBases) -> String {
    format!(
        "{}.{}",
        mcp_re_core::b64url_encode(&bases.previous_request_base),
        mcp_re_core::b64url_encode(&bases.input_required_response_base),
    )
}

/// Inverse of [`encode_bases`]. `None` on a malformed value (wrong field count or
/// an undecodable segment).
fn decode_bases(value: &str) -> Option<RetainedBases> {
    let (p, i) = value.split_once('.')?;
    Some(RetainedBases {
        previous_request_base: mcp_re_core::b64url_decode(p).ok()?,
        input_required_response_base: mcp_re_core::b64url_decode(i).ok()?,
    })
}

/// A durable, cross-process ASYNC continuation store backed by Redis
/// `SET ... PX` + `GETDEL`.
pub struct RedisContinuationStore {
    /// Auto-reconnecting, multiplexed async connection. Cloned per op (cheap).
    conn: ConnectionManager,
}

impl RedisContinuationStore {
    /// Connect to `url` (e.g. `redis://host:port`). Fails closed
    /// ([`ContinuationStoreError::Unavailable`]) if the client cannot be opened or
    /// the initial async connection cannot be established.
    pub async fn connect(url: &str) -> Result<Self, ContinuationStoreError> {
        let client = redis::Client::open(url).map_err(|e| ContinuationStoreError::Unavailable {
            details: format!("open redis client: {e}"),
        })?;
        let conn =
            client
                .get_connection_manager()
                .await
                .map_err(|e| ContinuationStoreError::Unavailable {
                    details: format!("connect redis async: {e}"),
                })?;
        Ok(RedisContinuationStore { conn })
    }
}

impl AsyncContinuationStore for RedisContinuationStore {
    fn store<'a>(
        &'a self,
        key: &'a str,
        bases: &'a RetainedBases,
        ttl_secs: i64,
    ) -> ContinuationFuture<'a, ()> {
        let key = key.to_string();
        let value = encode_bases(bases);
        let mut conn = self.conn.clone();
        // A non-positive TTL would ask Redis for a <=0 PX; clamp to a 1s floor so a
        // degenerate window still records a briefly-live entry rather than erroring.
        let ttl_ms = (ttl_secs.max(1)) * 1000;
        Box::pin(async move {
            let result: Result<(), redis::RedisError> = redis::cmd("SET")
                .arg(&key)
                .arg(value)
                .arg("PX")
                .arg(ttl_ms)
                .query_async(&mut conn)
                .await;
            result.map_err(|e| ContinuationStoreError::Unavailable {
                details: format!("redis SET continuation failed: {e}"),
            })
        })
    }

    fn take<'a>(&'a self, key: &'a str) -> ContinuationFuture<'a, Option<RetainedBases>> {
        let key = key.to_string();
        let mut conn = self.conn.clone();
        Box::pin(async move {
            // GETDEL is atomic read-and-remove (Redis 6.2+): one-shot without a
            // read-then-delete race across replicas.
            let raw: Result<Option<String>, redis::RedisError> =
                redis::cmd("GETDEL").arg(&key).query_async(&mut conn).await;
            let raw = raw.map_err(|e| ContinuationStoreError::Unavailable {
                details: format!("redis GETDEL continuation failed: {e}"),
            })?;
            let Some(value) = raw else {
                return Ok(None);
            };
            decode_bases(&value)
                .map(Some)
                .ok_or_else(|| ContinuationStoreError::Unavailable {
                    details: "malformed continuation value in shared store".to_string(),
                })
        })
    }
}
