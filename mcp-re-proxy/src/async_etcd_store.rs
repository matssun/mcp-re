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
//!     self-expires at the freshness window even if the proxy dies), granted only when
//!     no live lease already expires at this key's exact instant — keys retained to the
//!     same second share one, so the outstanding-lease count grows with the freshness
//!     window rather than with request volume;
//!   * `POST /v3/kv/txn` with `compare { CREATE_REVISION == 0 }` PUTs the key under
//!     that lease IFF it does not yet exist — etcd linearizes the txn, so two racing
//!     inserts cannot both observe the key absent (exactly one `Fresh`).
//!
//! Fail-closed: ANY transport/status/parse error — including a per-operation TIMEOUT —
//! is [`ReplayStoreError::Unavailable`], and an outage is NEVER a fresh nonce.
//!
//! Awaiting the round-trips means a slow etcd does not block a runtime worker, but that
//! is not the same as bounding it: an awaited future that never completes holds its
//! request (and its in-flight admission slot) forever. This module's doc used to claim
//! "the request path is still bounded by the tier's own timeout" — there is no such
//! timeout. `AsyncReplayTier` has none, and the async serve path bounds the TLS
//! handshake and the body read but awaits the handler unbounded. So a black-holed etcd
//! endpoint (a dropped route, a stateful firewall that discards instead of resetting)
//! parks every request on this store until the peer gives up, and with
//! `--max-in-flight` set that is a way to consume the whole admission budget without
//! sending a single invalid request. The timeout therefore lives HERE, where the
//! round-trip is issued, and applies to every one of the three POSTs.

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
use std::time::Duration;

use mcp_re_core::ReplayDurabilityClass;

use crate::async_replay::AsyncAtomicReplayStore;
use crate::async_replay::ReplayDecisionFuture;
use crate::async_replay::ReplayInsert;
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

/// Default per-operation deadline for one etcd gateway round trip.
///
/// This bounds ONE POST, and `atomic_insert_if_absent` issues two (lease grant, txn) —
/// up to four when a lease it reused turns out to have been revoked and the grant and
/// txn are retried once — so the worst case is ~4x this. Two seconds is generous for a
/// same-cluster etcd serving a lease grant and a single-key txn — the point is not to
/// tune latency but to make an unreachable endpoint fail closed in bounded time instead
/// of parking the request forever.
pub const DEFAULT_ETCD_OP_TIMEOUT: Duration = Duration::from_secs(2);

/// Hard ceiling on a configured per-operation timeout. A deadline long enough to outlive
/// the caller's own patience is indistinguishable from having none, so an absurd value is
/// clamped rather than honoured.
pub const MAX_ETCD_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// A durable, CP/linearizable ASYNC authoritative replay store over etcd's v3 JSON
/// gateway. Holds one pooled `hyper` client (cheap to clone per op) and the
/// gateway base URL.
pub struct EtcdAsyncAtomicReplayStore {
    client: Client<HttpConnector, Full<Bytes>>,
    /// The etcd JSON-gateway base, e.g. `http://10.0.0.5:2379` (no trailing slash).
    base_url: String,
    /// The store's own clock, read once per op for the lease-TTL arithmetic.
    clock: UnixClock,
    /// Deadline applied to EACH gateway round trip. Never `None`: an unbounded
    /// authoritative-store call on the request path is the defect this closes.
    op_timeout: Duration,
    /// `retain_until` -> the lease already granted to expire at that instant.
    ///
    /// A lease per admitted nonce makes the outstanding-lease count grow with REQUEST
    /// VOLUME, and etcd's lessor carries every one of them until it expires. Keys that
    /// stop being retained at the same second want the same expiry, so they can share
    /// one lease: the count then grows with the FRESHNESS WINDOW instead — at most one
    /// lease per second of `max_signature_validity + skew`, whatever the request rate.
    /// Reaching etcd's backend quota raises a NOSPACE alarm that keeps the cluster
    /// read-only until an operator compacts, defragments and disarms it, so the
    /// difference is between a bounded working set and a sticky manual outage chosen
    /// by one signature-valid peer.
    leases: std::sync::Mutex<std::collections::BTreeMap<i64, i64>>,
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
        Self::connect_with_timeout(base_url, clock, DEFAULT_ETCD_OP_TIMEOUT)
    }

    /// Build with an injected clock and an explicit per-operation deadline. A zero
    /// timeout is refused in the only way this signature allows — it is raised to 1ms —
    /// because `timeout(0)` fires before the request is even issued, which would fail
    /// EVERY insert closed and take the whole serving path down. The value is also
    /// clamped to [`MAX_ETCD_OP_TIMEOUT`].
    pub fn connect_with_timeout(base_url: &str, clock: UnixClock, op_timeout: Duration) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        EtcdAsyncAtomicReplayStore {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            clock,
            op_timeout: op_timeout.clamp(Duration::from_millis(1), MAX_ETCD_OP_TIMEOUT),
            leases: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// The per-operation deadline in force.
    pub fn op_timeout(&self) -> Duration {
        self.op_timeout
    }

    /// The lease already granted to expire at `retain_until`, if one is still live.
    ///
    /// Drops every lease whose instant has arrived first: etcd revokes those itself, and
    /// attaching a key to a lease that no longer exists leaves the key unretained — the
    /// direction that re-opens replay. The instant `now` counts as arrived, so the pool
    /// errs towards one extra grant rather than towards one unretained nonce. The map is
    /// bounded by the freshness window in seconds, not by request volume.
    fn pooled_lease(&self, retain_until: i64, now: i64) -> Option<i64> {
        // A poisoned pool is not a reason to fail a request closed: the worst outcome
        // of ignoring it is granting a lease that could have been shared.
        let mut leases = self.leases.lock().ok()?;
        *leases = leases.split_off(&now.saturating_add(1));
        leases.get(&retain_until).copied()
    }

    /// Offer a freshly granted lease for reuse by later nonces retained to the same
    /// instant. Best effort: a lease nobody reuses simply expires on its own TTL.
    fn pool_lease(&self, retain_until: i64, lease_id: i64) {
        if let Ok(mut leases) = self.leases.lock() {
            leases.insert(retain_until, lease_id);
        }
    }

    /// Stop offering `lease_id` for `retain_until` — it did not work, so no further
    /// request may be built on it.
    fn forget_lease(&self, retain_until: i64, lease_id: i64) {
        if let Ok(mut leases) = self.leases.lock() {
            if leases.get(&retain_until) == Some(&lease_id) {
                leases.remove(&retain_until);
            }
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
        op_timeout: Duration,
    ) -> Result<Value, ReplayStoreError> {
        // One deadline over the WHOLE exchange — connect, send, status, and body read.
        // Bounding only the request would leave a gateway that accepts the request and
        // then trickles (or never finishes) the response just as able to park the caller.
        tokio::time::timeout(op_timeout, Self::post_inner(client, base_url, path, body))
            .await
            .unwrap_or_else(|_| {
                Err(ReplayStoreError::Unavailable {
                    details: format!(
                        "etcd POST {path} exceeded the {}ms per-operation deadline; failing \
                         closed (an unreachable authoritative store is never a fresh nonce)",
                        op_timeout.as_millis()
                    ),
                })
            })
    }

    /// The unbounded exchange, wrapped by [`post`](Self::post).
    async fn post_inner(
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
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a> {
        // Retention is an etcd lease TTL, not a bounded local set, so there is no local
        // ceiling to split: `insert.actor` is budgeted above this seam by
        // `AsyncReplayTier`, and the leases themselves are shared per expiry instant
        // (see [`EtcdAsyncAtomicReplayStore::leases`]). Together those decide what one
        // signature-valid peer can make this cluster hold — and holding it to its
        // backend quota raises a NOSPACE alarm that stays raised, read-only, until an
        // operator compacts, defragments and disarms it, taking every co-tenant of that
        // etcd down with the replay tier.
        let (key, expires_at_unix) = (insert.key, insert.expires_at_unix);
        // Read the store's OWN clock once (the trait's vestigial now_unix=0 is
        // ignored), and reuse it for the lease-TTL arithmetic.
        let now = (self.clock)();
        let key_b64 = STANDARD.encode(key.as_bytes());
        // Value is the constant marker "1" (base64), matching the sync store.
        let value_b64 = STANDARD.encode(b"1");
        let client = &self.client;
        let base = self.base_url.as_str();
        let op_timeout = self.op_timeout;
        let store = self;
        Box::pin(async move {
            // MCPS-08 defensive pre-store rejection (#142), the guard the sync sibling
            // `etcd_store` and the Redis backend both enforce and this one skipped.
            //
            // If the (already skew-folded) retain-until is at or before `now`, the request
            // is ALREADY STALE. Without this the store fell through to `compute_ttl_secs`,
            // which CLAMPS a non-positive window up to a minimal 1s lease — so an expired
            // nonce was put-if-absent'd and reported `Fresh`. That is the exact behaviour
            // the guard was added elsewhere to eliminate, and it mattered most here: this
            // is the LINEARIZABLE production backend, the one a deployment selects when it
            // wants the strongest replay guarantee. Enforcing it at this layer means an
            // upstream ordering regression (the `mcp-re-core` freshness step no longer
            // running before replay) cannot admit a stale nonce.
            //
            // Same `now` the lease arithmetic uses, so the guard and the granted lease
            // cannot disagree about when it is.
            if crate::shared_replay::is_stale_pre_store(expires_at_unix, now) {
                return Err(ReplayStoreError::Unavailable {
                    details: format!(
                        "replay request already stale: retain_until ({expires_at_unix}) is at \
                         or before now ({now}) — rejected pre-store (MCPS-08, fail closed) \
                         rather than recorded as Fresh"
                    ),
                });
            }

            // Bounded lease TTL (the pure helper is shared verbatim with the sync
            // backend). Past the guard above the window is strictly positive, so the
            // helper's clamp is no longer load-bearing here.
            let ttl_secs = compute_ttl_secs(expires_at_unix, now);
            // A lease already granted to expire at this exact instant is the same
            // retention this key needs, so it is reused rather than duplicated.
            let (lease_id, reused) = match store.pooled_lease(expires_at_unix, now) {
                Some(pooled) => (pooled, true),
                None => {
                    let granted = parse_lease_id(
                        &Self::post(
                            client,
                            base,
                            "/v3/lease/grant",
                            &build_lease_grant_body(ttl_secs),
                            op_timeout,
                        )
                        .await?,
                    )?;
                    store.pool_lease(expires_at_unix, granted);
                    (granted, false)
                }
            };

            // Linearizable put-if-absent under the lease.
            let mut txn = Self::post(
                client,
                base,
                "/v3/kv/txn",
                &build_txn_body(&key_b64, &value_b64, lease_id),
                op_timeout,
            )
            .await;
            // A pooled lease can be revoked by etcd between the moment it was read and
            // the moment the txn lands (its instant arrives, an operator revokes it),
            // and a put under a lease that no longer exists is refused. That is a stale
            // local optimisation, not an unhealthy store, so it is retried ONCE on a
            // lease this store grants itself. A second failure is the store's answer.
            if txn.is_err() && reused {
                store.forget_lease(expires_at_unix, lease_id);
                let granted = parse_lease_id(
                    &Self::post(
                        client,
                        base,
                        "/v3/lease/grant",
                        &build_lease_grant_body(ttl_secs),
                        op_timeout,
                    )
                    .await?,
                )?;
                store.pool_lease(expires_at_unix, granted);
                txn = Self::post(
                    client,
                    base,
                    "/v3/kv/txn",
                    &build_txn_body(&key_b64, &value_b64, granted),
                    op_timeout,
                )
                .await;
            }
            // A non-fresh outcome leaves this lease holding nothing of THIS request's,
            // and it is not revoked: the lease is offered to every later nonce retained
            // to the same instant, so revoking it would drop keys that belong to other
            // requests a whole freshness window early — a replay hole, not a saving.
            // Nothing accumulates either way, because a lease is granted only when the
            // pool has none for that instant.
            Ok(decision_from_txn(&txn?))
        })
    }

    /// A genuinely cross-process, linearizable durable backend (ADR-MCPS-020).
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::Durable
    }
}

#[cfg(test)]
mod tests {
    //! C027/C031 (the missing MCPS-08 pre-store guard) and C044 (the unbounded round
    //! trip). The store holds a concrete `hyper` client rather than an injectable
    //! transport, so these drive it against real local sockets: the guard is proven by
    //! the store never reaching a socket at all, and the timeout by a listener that
    //! accepts and then says nothing.

    use super::*;

    /// Every entry in these tests is charged to one signer; the per-actor budget
    /// has its own test below.
    const TEST_ACTOR: &str = "did:example:test-signer";
    use crate::async_replay::AsyncAtomicReplayStore;
    use mcp_re_core::ReplayDecision;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    const NOW: i64 = 1_779_998_100;

    fn fixed_clock() -> UnixClock {
        Box::new(|| NOW)
    }

    /// A listener that accepts connections, counts them, and never replies — the
    /// black-holed gateway an operator actually meets (a dropped route, a firewall that
    /// discards rather than resets). Returns its address and the accept counter.
    async fn silent_gateway() -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    // Hold the connection open and answer nothing. Dropping it would
                    // send a FIN and produce a transport error instead of a hang.
                    Ok((stream, _)) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        std::mem::forget(stream);
                    }
                    Err(_) => return,
                }
            }
        });
        (format!("http://{addr}"), accepts)
    }

    #[tokio::test]
    async fn an_already_stale_request_is_rejected_without_touching_etcd() {
        // retain_until == now is a non-positive remaining window. Before the fix,
        // compute_ttl_secs clamped that up to a 1s lease, the key was put-if-absent'd,
        // and the store answered Fresh — an expired nonce admitted by the LINEARIZABLE
        // backend, the one chosen for the strongest guarantee.
        //
        // The store is pointed at a gateway that accepts connections and counts them, so
        // "no etcd call was made" is asserted rather than assumed: with the guard removed
        // this fails on the accept count as well as on the message.
        let (base, accepts) = silent_gateway().await;
        let store = EtcdAsyncAtomicReplayStore::connect_with_timeout(
            &base,
            fixed_clock(),
            Duration::from_millis(150),
        );
        let err = store
            .atomic_insert_if_absent(ReplayInsert::new(
                "did:example:host|aud|nonce",
                TEST_ACTOR,
                NOW,
                0,
            ))
            .await
            .expect_err("an already-stale request must never be admitted as Fresh");
        let ReplayStoreError::Unavailable { details } = err;
        assert!(
            details.contains("already stale") && details.contains("MCPS-08"),
            "expected the pre-store staleness rejection, got: {details}"
        );
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            0,
            "no lease/grant or kv/txn may be issued for an already-stale request — it must \
             be rejected BEFORE touching etcd"
        );
    }

    #[tokio::test]
    async fn a_fresh_window_is_bounded_by_the_per_operation_deadline() {
        // C044: the module doc claimed the request path was "bounded by the tier's own
        // timeout". AsyncReplayTier has none, and the async serve path awaits the handler
        // unbounded — so a gateway that accepts and never answers parked the request (and
        // its in-flight admission slot) indefinitely. This must now fail closed, and
        // promptly.
        let (base, accepts) = silent_gateway().await;
        let store = EtcdAsyncAtomicReplayStore::connect_with_timeout(
            &base,
            fixed_clock(),
            Duration::from_millis(150),
        );
        let started = tokio::time::Instant::now();
        let err = store
            // A comfortably fresh window, so the staleness guard above is not what fires.
            .atomic_insert_if_absent(ReplayInsert::new(
                "did:example:host|aud|nonce-fresh",
                TEST_ACTOR,
                NOW + 300,
                0,
            ))
            .await
            .expect_err("an unanswering gateway must fail closed, not hang");
        let elapsed = started.elapsed();
        let ReplayStoreError::Unavailable { details } = err;
        assert!(
            details.contains("per-operation deadline"),
            "expected the timeout to be the reason, got: {details}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the call must return on its own deadline, took {elapsed:?}"
        );
        assert!(
            accepts.load(Ordering::SeqCst) >= 1,
            "this test must actually have reached the gateway, or it proves nothing about \
             the timeout"
        );
    }

    /// A scripted etcd JSON gateway: answers `/v3/lease/grant` with an incrementing
    /// lease id and `/v3/kv/txn` with a successful compare, counting the calls to each.
    /// Returns its base URL and the two counters (grants, txns).
    async fn counting_gateway() -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let grants = Arc::new(AtomicUsize::new(0));
        let txns = Arc::new(AtomicUsize::new(0));
        let (g, t) = (Arc::clone(&grants), Arc::clone(&txns));
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (g, t) = (Arc::clone(&g), Arc::clone(&t));
                tokio::spawn(async move {
                    let mut seen = Vec::new();
                    let mut buf = [0u8; 1024];
                    loop {
                        let read = match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        seen.extend_from_slice(&buf[..read]);
                        // One request per connection is enough for this store's use;
                        // answer as soon as a whole request has arrived.
                        let text = String::from_utf8_lossy(&seen).to_string();
                        let Some(head_len) = text.find("\r\n\r\n") else {
                            continue;
                        };
                        let body_len: usize = text
                            .to_ascii_lowercase()
                            .split("content-length:")
                            .nth(1)
                            .and_then(|rest| rest.split("\r\n").next())
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if seen.len() < head_len + 4 + body_len {
                            continue;
                        }
                        let body = if text.contains("/v3/lease/grant") {
                            let id = g.fetch_add(1, Ordering::SeqCst) + 1;
                            format!("{{\"ID\":\"{id}\",\"TTL\":\"300\"}}")
                        } else {
                            t.fetch_add(1, Ordering::SeqCst);
                            "{\"succeeded\":true}".to_string()
                        };
                        let reply = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: \
                             {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(reply.as_bytes()).await;
                        let _ = stream.shutdown().await;
                        return;
                    }
                });
            }
        });
        (format!("http://{addr}"), grants, txns)
    }

    /// One lease per admitted nonce makes the outstanding-lease count grow with request
    /// VOLUME: a signature-valid peer streaming distinct nonces accumulates leases and
    /// keys until etcd hits its backend quota, whose NOSPACE alarm holds the cluster
    /// read-only until an operator intervenes by hand. Nonces retained to the same
    /// instant want the same expiry, so they share one lease and the count grows with
    /// the freshness window instead.
    #[tokio::test]
    async fn nonces_retained_to_the_same_instant_share_one_lease() {
        let (base, grants, txns) = counting_gateway().await;
        let store = EtcdAsyncAtomicReplayStore::connect_with(&base, fixed_clock());
        for i in 0..25 {
            assert_eq!(
                store
                    .atomic_insert_if_absent(ReplayInsert::new(
                        &format!("did:example:host|aud|nonce-{i}"),
                        TEST_ACTOR,
                        NOW + 300,
                        0,
                    ))
                    .await
                    .expect("the scripted gateway admits every put"),
                ReplayDecision::Fresh
            );
        }
        assert_eq!(
            txns.load(Ordering::SeqCst),
            25,
            "every nonce still gets its own linearizable put-if-absent"
        );
        assert_eq!(
            grants.load(Ordering::SeqCst),
            1,
            "25 nonces expiring at one instant must not mint 25 leases"
        );

        // A different retain-until is different retention, so it gets its own lease.
        store
            .atomic_insert_if_absent(ReplayInsert::new(
                "did:example:host|aud|later",
                TEST_ACTOR,
                NOW + 600,
                0,
            ))
            .await
            .expect("records");
        assert_eq!(grants.load(Ordering::SeqCst), 2);
    }

    /// The pool holds leases only while they are live: one whose instant has passed has
    /// been revoked by etcd, and attaching a key to it would leave the key unretained.
    #[tokio::test]
    async fn an_expired_lease_is_never_reused() {
        let (base, grants, _txns) = counting_gateway().await;
        let store = EtcdAsyncAtomicReplayStore::connect_with(&base, fixed_clock());
        store
            .atomic_insert_if_absent(ReplayInsert::new("k|a|n1", TEST_ACTOR, NOW + 5, 0))
            .await
            .expect("records");
        assert_eq!(grants.load(Ordering::SeqCst), 1);
        assert_eq!(store.pooled_lease(NOW + 5, NOW), Some(1));
        // Past that instant the lease is gone from etcd, so it is gone from the pool.
        assert_eq!(store.pooled_lease(NOW + 5, NOW + 5), None);
        assert!(
            store.leases.lock().expect("pool").is_empty(),
            "an expired lease must not be kept for reuse"
        );
    }

    #[test]
    fn the_operation_timeout_is_clamped_at_both_ends() {
        // Zero would make timeout() fire before the request is issued, failing EVERY
        // insert closed and taking the serving path down; an absurd value is
        // indistinguishable from no deadline at all.
        let zero = EtcdAsyncAtomicReplayStore::connect_with_timeout(
            "http://127.0.0.1:2379",
            fixed_clock(),
            Duration::ZERO,
        );
        assert_eq!(
            zero.op_timeout(),
            Duration::from_millis(1),
            "zero is raised, not honoured"
        );

        let absurd = EtcdAsyncAtomicReplayStore::connect_with_timeout(
            "http://127.0.0.1:2379",
            fixed_clock(),
            Duration::from_secs(86_400),
        );
        assert_eq!(
            absurd.op_timeout(),
            MAX_ETCD_OP_TIMEOUT,
            "clamped to the ceiling"
        );

        let default = EtcdAsyncAtomicReplayStore::connect("http://127.0.0.1:2379");
        assert_eq!(
            default.op_timeout(),
            DEFAULT_ETCD_OP_TIMEOUT,
            "connect() is bounded too"
        );
    }
}
