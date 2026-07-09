//! MCPRE (ADR-MCPRE-051 §4) — the ASYNC etcd authoritative replay backend.
//!
//! The async analogue of [`crate::etcd_store::EtcdAtomicReplayStore`]: the same
//! CP/linearizable put-if-absent under a bounded lease, but issued over an ASYNC
//! `hyper` client to etcd's v3 JSON gateway so the insert is AWAITED on the
//! per-core request path and never blocks a runtime worker (ADR-MCPRE-051 §4 —
//! "the per-core Redis/etcd clients are async and pipelined"). It implements
//! [`AsyncAtomicReplayStore`](crate::async_replay::AsyncAtomicReplayStore), so an
//! [`AsyncReplayTier`](crate::async_replay::AsyncReplayTier) over it gives the
//! serving path a genuinely durable, LINEARIZABLE cross-process authoritative tier.
//!
//! Protocol (identical wire shape to the sync store, whose PURE helpers are reused
//! verbatim so the two backends cannot drift):
//!   * `POST /v3/lease/grant` mints a lease with a BOUNDED TTL (so a recorded nonce
//!     self-expires at the freshness window even if the proxy dies);
//!   * `POST /v3/kv/txn` with `compare { CREATE_REVISION == 0 }` PUTs the key under
//!     that lease IFF it does not yet exist — etcd linearizes the txn, so two racing
//!     inserts cannot both observe the key absent (exactly one `Fresh`);
//!   * on a non-fresh outcome the just-granted lease is best-effort revoked
//!     (`POST /v3/lease/revoke`) so replays don't accumulate leases; a revoke
//!     failure is harmless (the bounded TTL still reaps it).
//!
//! Fail-closed: ANY transport/status/parse error is
//! [`ReplayStoreError::Unavailable`] — an outage is NEVER a fresh nonce. Unlike a
//! blocking client the round-trips are awaited, so a slow etcd never stalls a
//! per-core worker (the request path is still bounded by the tier's own timeout).

#![cfg(feature = "cpstore_etcd")]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::header;
use hyper::Method;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;

use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;

use crate::async_replay::AsyncAtomicReplayStore;
use crate::async_replay::ReplayDecisionFuture;
use crate::etcd_store::build_lease_grant_body;
use crate::etcd_store::build_txn_body;
use crate::etcd_store::compute_ttl_secs;
use crate::etcd_store::decision_from_txn;
use crate::etcd_store::parse_lease_id;
use crate::etcd_store::system_clock;
use crate::etcd_store::UnixClock;
use crate::shared_replay::ReplayStoreError;

/// A cap on the etcd gateway response body read into memory, so a broken/hostile
/// gateway cannot exhaust the proxy. Generous relative to a lease/txn JSON reply.
const MAX_ETCD_RESPONSE_BYTES: usize = 1024 * 1024;

/// A durable, CP/linearizable ASYNC authoritative replay store over etcd's v3 JSON
/// gateway. Holds one pooled `hyper` client (cheap to clone per op) and the
/// gateway base URL.
pub struct EtcdAsyncAtomicReplayStore {
    client: Client<HttpConnector, Full<Bytes>>,
    /// The etcd JSON-gateway base, e.g. `http://10.0.0.5:2379` (no trailing slash).
    base_url: String,
    /// The store's own clock, read once per op for the lease-TTL arithmetic.
    clock: UnixClock,
}

impl EtcdAsyncAtomicReplayStore {
    /// Build a store over the etcd JSON-gateway `base_url` (e.g.
    /// `http://host:2379`) with the production system clock.
    pub fn connect(base_url: &str) -> Self {
        Self::connect_with(base_url, system_clock())
    }

    /// Build with an injected clock (deterministic tests reuse the sync store's
    /// clock-injection pattern).
    pub fn connect_with(base_url: &str, clock: UnixClock) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        EtcdAsyncAtomicReplayStore {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            clock,
        }
    }

    /// POST `body` as JSON to `path` on the gateway; return the parsed JSON reply.
    /// A non-2xx status, a transport error, an oversize body, or unparseable JSON
    /// all fail closed as [`ReplayStoreError::Unavailable`].
    async fn post(
        client: &Client<HttpConnector, Full<Bytes>>,
        base_url: &str,
        path: &str,
        body: &Value,
    ) -> Result<Value, ReplayStoreError> {
        let url = format!("{base_url}{path}");
        let payload = serde_json::to_vec(body).map_err(|e| ReplayStoreError::Unavailable {
            details: format!("serialize etcd request body: {e}"),
        })?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("build etcd request {url}: {e}"),
            })?;
        let resp = client
            .request(req)
            .await
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("etcd POST {path} failed: {e}"),
            })?;
        if !resp.status().is_success() {
            return Err(ReplayStoreError::Unavailable {
                details: format!("etcd POST {path} returned status {}", resp.status()),
            });
        }
        let collected = http_body_util::Limited::new(resp.into_body(), MAX_ETCD_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|e| ReplayStoreError::Unavailable {
                details: format!("read etcd {path} response: {e}"),
            })?;
        serde_json::from_slice(&collected.to_bytes()).map_err(|e| ReplayStoreError::Unavailable {
            details: format!("parse etcd {path} response JSON: {e}"),
        })
    }
}

impl AsyncAtomicReplayStore for EtcdAsyncAtomicReplayStore {
    fn atomic_insert_if_absent<'a>(
        &'a self,
        key: &'a str,
        expires_at_unix: i64,
        _now_unix: i64,
    ) -> ReplayDecisionFuture<'a> {
        // Read the store's OWN clock once (the trait's vestigial now_unix=0 is
        // ignored), and reuse it for the lease-TTL arithmetic.
        let now = (self.clock)();
        let key_b64 = STANDARD.encode(key.as_bytes());
        // Value is the constant marker "1" (base64), matching the sync store.
        let value_b64 = STANDARD.encode(b"1");
        let client = &self.client;
        let base = self.base_url.as_str();
        Box::pin(async move {
            // Bounded lease TTL (>=1s even for an already-stale request, so a
            // same-instant racing insert still sees the sighting; the pure helper
            // is shared verbatim with the sync backend).
            let ttl_secs = compute_ttl_secs(expires_at_unix, now);
            let lease_resp =
                Self::post(client, base, "/v3/lease/grant", &build_lease_grant_body(ttl_secs))
                    .await?;
            let lease_id = parse_lease_id(&lease_resp)?;

            // Linearizable put-if-absent under the lease.
            let txn_resp =
                Self::post(client, base, "/v3/kv/txn", &build_txn_body(&key_b64, &value_b64, lease_id))
                    .await?;
            let decision = decision_from_txn(&txn_resp);

            // On a non-fresh outcome the key already existed, so THIS lease bound
            // nothing: best-effort revoke it so replays don't accumulate leases.
            // A revoke failure is harmless — the bounded TTL still reaps it — so it
            // is intentionally not propagated.
            if decision != ReplayDecision::Fresh {
                let _ = Self::post(
                    client,
                    base,
                    "/v3/lease/revoke",
                    &serde_json::json!({ "ID": lease_id.to_string() }),
                )
                .await;
            }
            Ok(decision)
        })
    }

    /// A genuinely cross-process, linearizable durable backend (ADR-MCPS-020).
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::Durable
    }
}
