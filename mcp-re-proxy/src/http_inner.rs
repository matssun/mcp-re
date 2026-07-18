//! ADR-MCPRE-051 §3 (Phase 3) — the production async inner plane: a per-core
//! pooled `hyper` client to stateless Streamable-HTTP inner MCP backends, with
//! passive health tracking, outlier ejection, per-backend circuit breaking, and
//! health-aware load balancing.
//!
//! This is the [`AsyncInnerServer`] the async serving path awaits instead of the
//! sync stdio subprocess. It replaces "one subprocess, one pipe, Mutex-serialized,
//! one request at a time" with a keep-alive connection pool over a fleet of
//! stateless HTTP inner servers: many requests in flight concurrently, HTTP/1.1
//! keep-alive or HTTP/2 multiplexing, no serial pipe. That is what converts the
//! async front end's concurrency into throughput (ADR-MCPRE-051 §3).
//!
//! ## Wire framing (stateless Streamable HTTP)
//!
//! Each already-verified, stripped, verified-context-injected JSON-RPC request is
//! sent as an HTTP `POST` with a `application/json` body to a configured backend
//! endpoint; the inner server's JSON-RPC response is the `application/json`
//! response body. This is the stateless request/response shape of MCP Streamable
//! HTTP (SSE streaming responses are a later increment).
//!
//! ## Resilience — outlier ejection + circuit breaking + health-aware LB
//!
//! Each backend carries a per-backend circuit breaker (ADR-MCPRE-051 §3
//! "a slow or dead inner backend is ejected and cannot stall the plane"):
//!
//! - **Passive health**: every dispatch outcome (success vs. transport/timeout/
//!   non-2xx/body-cap failure) updates the chosen backend's state. No synthetic
//!   probe traffic in steady state — real requests are the health signal.
//! - **Outlier ejection / breaker OPEN**: `failure_threshold` consecutive failures
//!   trip a backend `Closed → Open`. An Open backend is SKIPPED by load balancing
//!   for `ejection_duration` — it cannot receive traffic, so it cannot stall the
//!   plane or degrade tail latency for other requests.
//! - **Recovery / HALF-OPEN probe**: after `ejection_duration` a single trial
//!   request re-admits the backend (`Open → HalfOpen`); success closes it
//!   (`→ Closed`, full traffic), failure re-opens it for another cooldown. Exactly
//!   one probe is in flight at a time, so a still-dead backend is not stampeded.
//! - **Health-aware balancing**: selection round-robins over `Closed` backends and
//!   never routes to an `Open` one; traffic rebalances onto healthy backends the
//!   moment one is ejected.
//!
//! The state is per-backend atomics on a per-core pool (share-nothing,
//! ADR-MCPRE-051 §1): each core learns and ejects independently with no contended
//! cross-core lock on the hot path.
//!
//! ## Fail-closed
//!
//! `dispatch` NEVER errors (the [`AsyncInnerServer`] contract): a connect/transport
//! failure, a per-request timeout, a non-2xx status, an unreadable body, every
//! backend being ejected (circuit open), OR the pool being saturated at its
//! in-flight bound all yield the synthesized [`inner_unavailable_response`] — a
//! JSON-RPC error the proxy still SIGNS. When all backends are Open the request
//! fails closed WITHOUT dispatching; when the in-flight bound
//! ([`DEFAULT_MAX_IN_FLIGHT`]) is reached, a further request fails closed WITHOUT
//! queuing — bounded backpressure, never an unbounded backlog. A dead, hostile, or
//! overloaded inner fleet can never suppress the signature or cause a silent allow.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::header;
use hyper::Method;
use hyper::Request;
use hyper::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::Semaphore;

use crate::async_inner::inner_unavailable_response;
use crate::async_inner::AsyncInnerServer;
use crate::async_inner::InnerResponseFuture;

/// A cap on the inner response body read into memory, so a hostile/broken backend
/// streaming an unbounded body cannot exhaust the proxy. A response exceeding it
/// fails closed (synthesized inner error). Generous relative to real MCP responses.
const MAX_INNER_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Circuit-breaker state. `Closed` = healthy (takes traffic); `Open` = ejected
/// (skipped by LB until the cooldown elapses); `HalfOpen` = one trial probe in
/// flight after cooldown.
const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

/// Default consecutive-failure threshold that ejects a backend (Envoy-class default).
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 5;
/// Default ejection duration a backend stays Open before a Half-Open probe.
pub const DEFAULT_EJECTION_DURATION: Duration = Duration::from_secs(30);
/// Default cap on concurrent in-flight inner dispatches per pool. Bounds inner-plane
/// concurrency so a saturated or slow inner fleet fails closed with backpressure
/// instead of queuing unboundedly (ADR-MCPRE-051 §3 pool-exhaustion). Generous for a
/// per-core pool to a small stateless backend fleet; override with
/// [`HttpInnerPool::with_max_in_flight`].
pub const DEFAULT_MAX_IN_FLIGHT: usize = 1024;

/// Outlier-ejection / circuit-breaker tuning for the inner pool.
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// Consecutive dispatch failures that trip a healthy backend to Open (ejected).
    pub failure_threshold: u32,
    /// How long an ejected (Open) backend is skipped before a Half-Open trial.
    pub ejection_duration: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        BreakerConfig {
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            ejection_duration: DEFAULT_EJECTION_DURATION,
        }
    }
}

/// Per-backend endpoint + passive health / circuit-breaker state. All fields are
/// lock-free atomics: the hot path reads/updates them without a mutex, and each
/// per-core pool owns its own copy (share-nothing).
struct Backend {
    /// Absolute endpoint URI (e.g. `http://10.0.0.5:8080/mcp`).
    uri: Uri,
    /// Breaker state: `STATE_CLOSED` / `STATE_OPEN` / `STATE_HALF_OPEN`.
    state: AtomicU8,
    /// Consecutive failures since the last success (drives ejection). Only
    /// meaningful while `Closed`.
    consecutive_failures: AtomicU32,
    /// Monotonic nanos since the pool `origin` at which an `Open` backend becomes
    /// eligible for a Half-Open probe. Only meaningful while `Open`.
    reopen_at_nanos: AtomicU64,
    /// Guards the single in-flight Half-Open trial so a recovering backend is
    /// probed by exactly one request at a time (no stampede onto a still-dead host).
    probe_inflight: AtomicBool,
}

impl Backend {
    fn new(uri: Uri) -> Self {
        Backend {
            uri,
            state: AtomicU8::new(STATE_CLOSED),
            consecutive_failures: AtomicU32::new(0),
            reopen_at_nanos: AtomicU64::new(0),
            probe_inflight: AtomicBool::new(false),
        }
    }
}

/// A per-core pooled HTTP client to stateless Streamable-HTTP inner backends, with
/// per-backend outlier ejection + circuit breaking + health-aware load balancing.
///
/// Cloning the underlying `hyper` client is cheap (it shares the connection pool),
/// so `dispatch` clones per call and awaits without holding a lock. Each core owns
/// its own `HttpInnerPool` (share-nothing, ADR-MCPRE-051 §1).
pub struct HttpInnerPool {
    client: Client<HttpConnector, Full<Bytes>>,
    /// The backend fleet with per-backend health. At least one; construction fails
    /// closed on an empty list.
    backends: Vec<Backend>,
    /// Round-robin cursor over `backends`.
    next: AtomicUsize,
    /// Per-request deadline bounding the inner round-trip. On elapse the request
    /// fails closed (a slow backend cannot hold a per-core in-flight slot forever)
    /// and counts as a failure against the backend's breaker.
    request_timeout: Duration,
    /// Outlier-ejection / breaker tuning.
    breaker: BreakerConfig,
    /// Bounded inner-plane concurrency: a dispatch must acquire a permit. When all
    /// permits are held (the inner fleet is saturated / slow), `dispatch` fails
    /// closed IMMEDIATELY with a synthesized inner-unavailable response rather than
    /// queue — so backpressure is bounded and the per-core backlog can never grow
    /// unboundedly (ADR-MCPRE-051 §3).
    in_flight: Arc<Semaphore>,
    /// The permit count `in_flight` was built with (introspection; not on the hot path).
    max_in_flight: usize,
    /// Monotonic clock origin for breaker timing (all `*_nanos` are relative to it).
    origin: Instant,
}

impl HttpInnerPool {
    /// Build a pool over `backends` (non-empty) with a per-request `request_timeout`
    /// and the default breaker tuning. Fails closed if no backend is given.
    pub fn new(backends: Vec<Uri>, request_timeout: Duration) -> Result<Self, String> {
        Self::with_breaker_config(backends, request_timeout, BreakerConfig::default())
    }

    /// Build a pool with explicit outlier-ejection / circuit-breaker tuning (used by
    /// resilience tests that need a low threshold and short cooldown).
    pub fn with_breaker_config(
        backends: Vec<Uri>,
        request_timeout: Duration,
        breaker: BreakerConfig,
    ) -> Result<Self, String> {
        if backends.is_empty() {
            return Err("HttpInnerPool requires at least one inner backend URL".to_string());
        }
        if breaker.failure_threshold == 0 {
            return Err("HttpInnerPool breaker failure_threshold must be > 0".to_string());
        }
        // Pooled, keep-alive client; HTTP/2 is negotiated per connection by the
        // backend. Defaults on idle-timeout / max-idle-per-host are sane for a
        // per-core pool to a small backend fleet.
        let client = Client::builder(TokioExecutor::new()).build_http();
        Ok(HttpInnerPool {
            client,
            backends: backends.into_iter().map(Backend::new).collect(),
            next: AtomicUsize::new(0),
            request_timeout,
            breaker,
            in_flight: Arc::new(Semaphore::new(DEFAULT_MAX_IN_FLIGHT)),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            origin: Instant::now(),
        })
    }

    /// Override the bound on concurrent in-flight inner dispatches (default
    /// [`DEFAULT_MAX_IN_FLIGHT`]). Beyond `n` concurrent dispatches the pool fails
    /// closed immediately rather than queue (ADR-MCPRE-051 §3 pool-exhaustion
    /// backpressure). `n` must be > 0.
    #[must_use]
    pub fn with_max_in_flight(mut self, n: usize) -> Self {
        assert!(n > 0, "HttpInnerPool max_in_flight must be > 0");
        self.in_flight = Arc::new(Semaphore::new(n));
        self.max_in_flight = n;
        self
    }

    /// Build a pool from string URLs (each parsed to a [`Uri`]), so callers (e.g.
    /// the CLI wiring) need not depend on `hyper` types directly. Fails closed with
    /// a precise message on an unparseable or empty URL, or an empty list.
    pub fn from_url_strs(urls: Vec<String>, request_timeout: Duration) -> Result<Self, String> {
        let backends = urls
            .into_iter()
            .map(|u| {
                u.parse::<Uri>()
                    .map_err(|e| format!("invalid inner HTTP backend URL '{u}': {e}"))
            })
            .collect::<Result<Vec<Uri>, String>>()?;
        Self::new(backends, request_timeout)
    }

    /// Number of backends currently ejected (breaker `Open`). Introspection for
    /// tests and, later, metrics; not on the hot path.
    pub fn ejected_backend_count(&self) -> usize {
        self.backends
            .iter()
            .filter(|b| b.state.load(Ordering::Acquire) == STATE_OPEN)
            .count()
    }

    /// The configured maximum concurrent in-flight inner dispatches.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// In-flight permits currently available (`max_in_flight` minus dispatches in
    /// flight). Introspection for tests/metrics; not on the hot path. Zero means the
    /// inner plane is saturated and further dispatches fail closed.
    pub fn in_flight_available(&self) -> usize {
        self.in_flight.available_permits()
    }

    /// Monotonic nanoseconds since the pool's clock origin.
    fn now_nanos(&self) -> u64 {
        self.origin.elapsed().as_nanos() as u64
    }

    /// Health-aware selection. Returns `(index, is_probe)` of a dispatchable backend,
    /// or `None` when every backend is ejected (all Open, cooldown not elapsed) —
    /// the caller then fails closed WITHOUT dispatching.
    ///
    /// Preference order, scanning round-robin from a rotating start so healthy load
    /// spreads evenly:
    ///   1. any `Closed` backend (normal healthy traffic), else
    ///   2. an `Open` backend past its cooldown, claimed as a Half-Open probe, or a
    ///      `HalfOpen` backend with no probe currently in flight.
    fn select_backend(&self, now_nanos: u64) -> Option<(usize, bool)> {
        let n = self.backends.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed) % n;

        // Pass 1: prefer a healthy (Closed) backend.
        for k in 0..n {
            let i = (start + k) % n;
            if self.backends[i].state.load(Ordering::Acquire) == STATE_CLOSED {
                return Some((i, false));
            }
        }

        // Pass 2: no Closed backend — try to claim a single recovery probe.
        for k in 0..n {
            let i = (start + k) % n;
            let b = &self.backends[i];
            match b.state.load(Ordering::Acquire) {
                STATE_OPEN => {
                    if now_nanos >= b.reopen_at_nanos.load(Ordering::Acquire)
                        && b
                            .state
                            .compare_exchange(
                                STATE_OPEN,
                                STATE_HALF_OPEN,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                    {
                        // This thread won the Open→HalfOpen transition; it owns the
                        // trial. (A benign race can admit a second concurrent probe;
                        // both are trial requests, never harmful.)
                        b.probe_inflight.store(true, Ordering::Release);
                        return Some((i, true));
                    }
                }
                STATE_HALF_OPEN => {
                    if b
                        .probe_inflight
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return Some((i, true));
                    }
                }
                _ => {}
            }
        }

        None
    }

    /// Fold one dispatch outcome into the chosen backend's breaker state.
    fn record_outcome(&self, idx: usize, is_probe: bool, ok: bool, now_nanos: u64) {
        let b = &self.backends[idx];
        if ok {
            // Any success (including a Half-Open trial) fully closes the breaker.
            b.consecutive_failures.store(0, Ordering::Release);
            b.state.store(STATE_CLOSED, Ordering::Release);
            b.probe_inflight.store(false, Ordering::Release);
            return;
        }

        let reopen = now_nanos.saturating_add(self.breaker.ejection_duration.as_nanos() as u64);
        if is_probe {
            // A failed recovery trial re-ejects for another full cooldown.
            b.reopen_at_nanos.store(reopen, Ordering::Release);
            b.state.store(STATE_OPEN, Ordering::Release);
            b.probe_inflight.store(false, Ordering::Release);
        } else {
            let fails = b.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
            if fails >= self.breaker.failure_threshold {
                b.reopen_at_nanos.store(reopen, Ordering::Release);
                b.state.store(STATE_OPEN, Ordering::Release);
            }
        }
    }

    /// Issue the HTTP round-trip to `uri`, returning `Ok(bytes)` on a 2xx with a
    /// readable (capped) body, or `Err(())` on any transport error, timeout, non-2xx
    /// status, or over-cap/unreadable body. The caller maps `Err` to the fail-closed
    /// synthesized response and folds the outcome into the breaker.
    async fn round_trip(
        client: &Client<HttpConnector, Full<Bytes>>,
        uri: Uri,
        body: Bytes,
        timeout: Duration,
    ) -> Result<Vec<u8>, ()> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            // MCP Streamable HTTP (2025-06-18 §Sending Messages): a client POST MUST
            // Accept BOTH application/json and text/event-stream — a spec-conformant
            // backend (e.g. FastMCP) rejects a json-only Accept with 406. We forward
            // stateless single request/response, so a JSON body is what we parse; the
            // dual Accept is the required handshake, not an opt-in to streaming.
            //
            // #415 rev 2 §3.4 (MCPRE-423) asked whether to drop text/event-stream
            // here. It stays: narrowing the Accept would break the mandated
            // handshake and earn a 406 from a conformant backend, turning a profile
            // rule into an interop failure. The rule is enforced where it belongs —
            // on the RESPONSE, below and in the profile verifier — so we advertise
            // what the transport requires and accept only what we can evidence.
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Full::new(body))
            .map_err(|_| ())?;

        // Bound the whole round-trip. Timeout OR transport error ⇒ failure.
        let resp = match tokio::time::timeout(timeout, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            _ => return Err(()),
        };

        // A non-2xx inner status is not a valid JSON-RPC response; treat as failure
        // (the proxy signs the synthesized error) rather than sign backend HTML.
        if !resp.status().is_success() {
            return Err(());
        }

        // JSON mode (#415 rev 2 §3.4): if the backend answered with a stream, refuse
        // it HERE rather than let it fail later as a JSON parse error. The outcome
        // is the same fail-closed synthesized response either way, but a backend
        // that streams is a deployment/profile problem, and it should be refused as
        // a stated rule rather than incidentally because SSE framing happens not to
        // parse as JSON.
        let is_json = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            })
            .unwrap_or(false);
        if !is_json {
            return Err(());
        }

        // Read the body, capped. `Limited` fails the collect if the cap is exceeded.
        let limited = http_body_util::Limited::new(resp.into_body(), MAX_INNER_RESPONSE_BYTES);
        match limited.collect().await {
            Ok(collected) => Ok(collected.to_bytes().to_vec()),
            Err(_) => Err(()),
        }
    }
}

impl AsyncInnerServer for HttpInnerPool {
    fn dispatch<'a>(&'a self, request: &'a [u8]) -> InnerResponseFuture<'a> {
        // Own the request bytes + a cheap client clone into the future.
        let body = Bytes::copy_from_slice(request);
        let client = self.client.clone();
        let timeout = self.request_timeout;
        let in_flight = self.in_flight.clone();
        Box::pin(async move {
            // Bounded inner-plane concurrency: take an in-flight permit or fail closed
            // IMMEDIATELY. Saturation ⇒ synthesized inner-unavailable WITHOUT queuing,
            // so a slow/overloaded inner fleet cannot build an unbounded per-core
            // backlog (ADR-MCPRE-051 §3 pool-exhaustion backpressure). The permit is
            // held for the whole round-trip and released on completion.
            let _permit = match in_flight.try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => return inner_unavailable_response(),
            };
            let now = self.now_nanos();
            // Health-aware selection. All backends ejected ⇒ fail closed WITHOUT
            // dispatching and WITHOUT queuing (bounded fail-closed, ADR-MCPRE-051 §3).
            let Some((idx, is_probe)) = self.select_backend(now) else {
                return inner_unavailable_response();
            };
            let uri = self.backends[idx].uri.clone();

            let outcome = Self::round_trip(&client, uri, body, timeout).await;
            let done = self.now_nanos();
            match outcome {
                Ok(bytes) => {
                    self.record_outcome(idx, is_probe, true, done);
                    bytes
                }
                Err(()) => {
                    self.record_outcome(idx, is_probe, false, done);
                    inner_unavailable_response()
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    //! Deterministic breaker state-machine unit tests — no network, no wall-clock
    //! flakiness. Real-backend chaos coverage (ejection under load, rebalancing,
    //! recovery, slow-backend p99 isolation) is in `tests/http_inner_test.rs`.
    use super::*;

    fn uri(n: u16) -> Uri {
        format!("http://127.0.0.1:{n}/mcp").parse().unwrap()
    }

    fn pool(backends: usize, threshold: u32) -> HttpInnerPool {
        let uris = (0..backends).map(|i| uri(9000 + i as u16)).collect();
        HttpInnerPool::with_breaker_config(
            uris,
            Duration::from_secs(1),
            BreakerConfig { failure_threshold: threshold, ejection_duration: Duration::from_secs(30) },
        )
        .expect("pool")
    }

    #[test]
    fn healthy_backend_selected_and_closed_stays_closed_on_success() {
        let p = pool(1, 3);
        let (idx, is_probe) = p.select_backend(0).expect("dispatchable");
        assert_eq!(idx, 0);
        assert!(!is_probe, "a Closed backend is normal traffic, not a probe");
        p.record_outcome(idx, is_probe, true, 0);
        assert_eq!(p.ejected_backend_count(), 0);
    }

    #[test]
    fn consecutive_failures_trip_open_at_threshold() {
        let p = pool(1, 3);
        // Two failures: still Closed (below threshold), still selectable.
        for _ in 0..2 {
            let (idx, probe) = p.select_backend(0).expect("still selectable");
            p.record_outcome(idx, probe, false, 0);
        }
        assert_eq!(p.ejected_backend_count(), 0, "below threshold stays Closed");
        // Third failure trips it Open (ejected).
        let (idx, probe) = p.select_backend(0).expect("still selectable at threshold-1");
        p.record_outcome(idx, probe, false, 0);
        assert_eq!(p.ejected_backend_count(), 1, "threshold consecutive failures eject");
    }

    #[test]
    fn a_success_resets_the_failure_run() {
        let p = pool(1, 3);
        for _ in 0..2 {
            let (i, pr) = p.select_backend(0).unwrap();
            p.record_outcome(i, pr, false, 0);
        }
        let (i, pr) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, true, 0); // success resets the run
        // Two more failures must NOT eject (run restarted at the success).
        for _ in 0..2 {
            let (i, pr) = p.select_backend(0).unwrap();
            p.record_outcome(i, pr, false, 0);
        }
        assert_eq!(p.ejected_backend_count(), 0, "a success clears the consecutive-failure run");
    }

    #[test]
    fn all_open_selection_returns_none_before_cooldown() {
        let p = pool(1, 1); // one failure ejects
        let (i, pr) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0); // now Open with reopen_at = ejection_duration
        // Before cooldown elapses, nothing is dispatchable — caller fails closed.
        assert!(p.select_backend(1).is_none(), "an Open backend is not dispatched to before cooldown");
        assert_eq!(p.ejected_backend_count(), 1);
    }

    #[test]
    fn open_backend_readmitted_as_probe_after_cooldown_then_closes_on_success() {
        let p = pool(1, 1);
        let (i, pr) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0);
        let cooldown = DEFAULT_EJECTION_DURATION.as_nanos() as u64;
        // After the cooldown, selection admits exactly one Half-Open probe.
        let (pi, is_probe) = p.select_backend(cooldown + 1).expect("probe admitted after cooldown");
        assert!(is_probe, "post-cooldown re-admission is a trial probe");
        // A concurrent second request finds the probe in flight and is turned away.
        assert!(p.select_backend(cooldown + 1).is_none(), "only one probe in flight at a time");
        // Probe success fully closes the breaker → back to normal traffic.
        p.record_outcome(pi, is_probe, true, cooldown + 2);
        assert_eq!(p.ejected_backend_count(), 0);
        let (_, back_to_normal) = p.select_backend(cooldown + 3).expect("healthy again");
        assert!(!back_to_normal, "a recovered backend takes normal (non-probe) traffic");
    }

    #[test]
    fn failed_probe_reopens_for_another_cooldown() {
        let p = pool(1, 1);
        let (i, pr) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0);
        let cooldown = DEFAULT_EJECTION_DURATION.as_nanos() as u64;
        let (pi, is_probe) = p.select_backend(cooldown + 1).expect("probe admitted");
        p.record_outcome(pi, is_probe, false, cooldown + 1); // probe fails
        assert_eq!(p.ejected_backend_count(), 1, "a failed probe re-ejects");
        assert!(
            p.select_backend(cooldown + 2).is_none(),
            "re-ejected backend waits a fresh cooldown, not immediately re-probed"
        );
        // Only after ANOTHER full cooldown is it probed again.
        assert!(p.select_backend(2 * cooldown + 3).is_some(), "re-admitted after a second cooldown");
    }

    #[test]
    fn health_aware_lb_skips_open_backend_and_uses_healthy_one() {
        let p = pool(2, 1);
        // Fail backend 0 into Open; leave backend 1 healthy.
        // Force selection onto index 0 first by draining the round-robin cursor.
        // With 2 backends the cursor alternates; eject whichever we hit until one is Open.
        let (i0, pr0) = p.select_backend(0).unwrap();
        p.record_outcome(i0, pr0, false, 0);
        assert_eq!(p.ejected_backend_count(), 1);
        // Every subsequent selection must avoid the Open backend and pick the healthy one.
        for _ in 0..8 {
            let (i, is_probe) = p.select_backend(0).expect("a healthy backend remains");
            assert_ne!(i, i0, "LB must not route to the ejected backend");
            assert!(!is_probe, "the healthy backend is normal traffic");
        }
    }
}
