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
//! The state is per-backend atomics. ONE pool is shared by every core: `app.rs`
//! builds a single [`HttpInnerPool`], boxes it into the single `HttpProfileProxy`,
//! and hands that `Arc` to each per-core handler. Two consequences follow and neither
//! is hidden:
//!
//!   * [`max_in_flight`](HttpInnerPool::with_max_in_flight) is a PROCESS-WIDE bound,
//!     not a per-core one. `app.rs` therefore sizes it at or above the sum of the
//!     per-core admission ceilings, so the security gate — not this pool — is what
//!     sheds load. Otherwise requests that passed every check would be answered with
//!     a signed `inner server unavailable` at a capacity cliff invisible from the
//!     configured flags.
//!   * Circuit-breaker state is global, so one core's observations eject a backend
//!     for all of them. That is the desired direction (a dead backend is dead for
//!     everyone) and it costs an uncontended atomic on the hot path.
//!
//! ## Fail-closed
//!
//! A committed dispatch NEVER errors (the [`AsyncInnerServer`] contract): every failure
//! becomes a [`DispatchedOutcome`] the proxy still SIGNS a reply about. When all backends
//! are Open the request fails closed WITHOUT dispatching; when the in-flight bound
//! ([`DEFAULT_MAX_IN_FLIGHT`]) is reached, a further request fails closed WITHOUT
//! queuing — bounded backpressure, never an unbounded backlog. A dead, hostile, or
//! overloaded inner fleet can never suppress the signature or cause a silent allow.
//!
//! What it no longer does is report all of those as the same thing (ADR-MCPRE-058 §10,
//! ruling D4). The pool is the only component that KNOWS whether bytes left the process,
//! so it is the only one that can classify — and, since #741, the first three are
//! classified BEFORE anything is committed, by taking the capacity rather than reading it:
//!
//! ```text
//! prepare:  no permit / all backends ejected / unbuildable  -> NotAdmitted
//! dispatch: timeout, connect or transport error             -> Indeterminate
//! dispatch: non-2xx, non-JSON, unreadable or over-cap       -> InvalidUpstream
//! dispatch: 2xx with a JSON body                            -> Replied
//! ```
//!
//! A connect error is classified `Indeterminate`, deliberately. hyper does not reliably
//! distinguish "the connection was refused" from "the request was written and the peer
//! went away", so it is not a fact this pool can prove never reached a backend — and past
//! the commitment there is no outcome that claims one.

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

use crate::async_inner::AsyncInnerServer;
use crate::async_inner::DispatchedOutcome;
use crate::async_inner::NotAdmitted;
use crate::async_inner::PreparedInnerDispatch;

mod selection;

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
/// Default cap on concurrent in-flight inner dispatches for the pool. Bounds
/// inner-plane concurrency so a saturated or slow inner fleet fails closed with
/// backpressure instead of queuing unboundedly (ADR-MCPRE-051 §3 pool-exhaustion).
/// A FLOOR, not the operative value: the pool is process-wide, so `app.rs` raises it
/// to the fleet's aggregate admission ceiling when that is larger.
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

/// The pooled HTTP client to stateless Streamable-HTTP inner backends, with
/// per-backend outlier ejection + circuit breaking + health-aware load balancing.
///
/// Cloning the underlying `hyper` client is cheap (it shares the connection pool), so
/// `dispatch` clones per call and awaits without holding a lock. One pool is shared by
/// every core — see the module docs for what that means for `max_in_flight` and for
/// breaker state.
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

    /// Fold one dispatch outcome into the chosen backend's breaker state.
    fn record_outcome(&self, idx: usize, is_probe: bool, ok: bool, now_nanos: u64) {
        // Read through `get`: an outcome that cannot be attributed is one this breaker
        // must not fold into some OTHER backend's state.
        let Some(b) = self.backends.get(idx) else {
            return;
        };
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
            // Saturating: compared only against `failure_threshold`, so the ceiling is
            // the most-ejected end and wrapping is the permissive one — a backend failing
            // without pause would count back through zero and stop tripping the breaker.
            let fails = b
                .consecutive_failures
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(1);
            if fails >= self.breaker.failure_threshold {
                b.reopen_at_nanos.store(reopen, Ordering::Release);
                b.state.store(STATE_OPEN, Ordering::Release);
            }
        }
    }

    /// Build the transport request for `uri`, BEFORE anything is committed.
    ///
    /// Separate from the round trip because its failure is a different fact: a request
    /// that cannot even be constructed was never transmitted, and saying so is only
    /// possible while the caller can still be told nothing happened. It used to live
    /// inside the dispatch, where the honest answer had to be minted on the far side of
    /// the execution threshold.
    fn build_request(uri: Uri, body: Bytes) -> Result<Request<Full<Bytes>>, NotAdmitted> {
        Request::builder()
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
            // Nothing was transmitted, and nothing can be: reported as a pre-commitment
            // refusal, which is what it is.
            .map_err(|_| NotAdmitted("inner request could not be built"))
    }

    /// Issue the HTTP round-trip for an already-built request.
    ///
    /// Returns the classified [`DispatchedOutcome`] rather than `Result<Vec<u8>, ()>`:
    /// this function is the only place that can tell a timeout from a refused connection
    /// from a backend that answered with HTML, and flattening them to one `Err(())` here
    /// is what made the distinction unrecoverable everywhere else.
    ///
    /// Every arm it can reach is compatible with the action having executed. The
    /// unbuildable-request case is NOT among them: it is decided in
    /// [`build_request`](Self::build_request), before commitment.
    async fn round_trip(
        client: &Client<HttpConnector, Full<Bytes>>,
        req: Request<Full<Bytes>>,
        timeout: Duration,
    ) -> DispatchedOutcome {
        // Bound the whole round-trip. Timeout OR transport error ⇒ failure.
        let resp = match tokio::time::timeout(timeout, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            // Both arms are INDETERMINATE, and the timeout is the reason this classification
            // exists: the request went out, the backend may well have executed the tool, and
            // the answer simply never came back. Reporting that as a clean error response is
            // the strongest available signal that nothing happened, which is precisely what
            // is not known.
            Ok(Err(_)) => return DispatchedOutcome::Indeterminate("inner transport error"),
            Err(_) => return DispatchedOutcome::Indeterminate("inner request timed out"),
        };

        // A non-2xx inner status is not a valid JSON-RPC response. The backend DID answer,
        // so this is not indeterminate — it is an unusable answer, and signing backend HTML
        // as an MCP result is not an option either.
        if !resp.status().is_success() {
            return DispatchedOutcome::InvalidUpstream("inner backend returned a non-2xx status");
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
            return DispatchedOutcome::InvalidUpstream(
                "inner backend did not answer application/json",
            );
        }

        // Read the body, capped. `Limited` fails the collect if the cap is exceeded.
        let limited = http_body_util::Limited::new(resp.into_body(), MAX_INNER_RESPONSE_BYTES);
        match limited.collect().await {
            Ok(collected) => DispatchedOutcome::Replied(collected.to_bytes().to_vec()),
            // The backend answered and the answer is unusable — over the cap, or the body
            // stream broke partway. It acted either way.
            Err(_) => {
                DispatchedOutcome::InvalidUpstream("inner response body was unreadable or over cap")
            }
        }
    }
}

/// Releases a claimed recovery probe when the dispatch future is dropped.
///
/// `record_outcome` clears the flag on a completed round trip; this covers the path
/// where there is no outcome at all. Clearing it twice is harmless — the store is
/// idempotent — and clearing it once too few wedges the backend permanently.
struct ProbeGuard<'a> {
    backend: &'a Backend,
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        self.backend
            .probe_inflight
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

impl AsyncInnerServer for HttpInnerPool {
    /// Take the in-flight permit, claim the backend, build the request — transmit nothing.
    ///
    /// Every one of those is a fact about THIS process, and taking them here is what lets
    /// a saturated or fully-ejected fleet be refused as genuinely retry-safe instead of as
    /// an exchange that may have executed.
    ///
    /// This CLAIMS, where its predecessor observed. `admit` read
    /// [`Semaphore::available_permits`] and [`HttpInnerPool::any_dispatchable`] and took
    /// nothing, deliberately: a reservation would have had to be held across the caller's
    /// remaining pre-dispatch stages and released on every refusal path. The prepared
    /// dispatch IS that holding, and its drop IS that release — so the reason not to claim
    /// is gone, and with it the window in which another core took the last permit between
    /// the answer and the acquisition. The recovery probe is claimed here for the same
    /// reason and released the same way: by [`ProbeGuard`], on drop, whether the dispatch
    /// happens or not.
    fn prepare<'a>(&'a self, request: &[u8]) -> Result<PreparedInnerDispatch<'a>, NotAdmitted> {
        // Bounded inner-plane concurrency: take an in-flight permit or fail closed
        // IMMEDIATELY. Saturation ⇒ refusal WITHOUT queuing, so a slow/overloaded inner
        // fleet cannot build an unbounded per-core backlog (ADR-MCPRE-051 §3
        // pool-exhaustion backpressure). The permit is held from here to the end of the
        // round-trip, and released by dropping this value if the dispatch never happens.
        let permit = Arc::clone(&self.in_flight)
            .try_acquire_owned()
            .map_err(|_| NotAdmitted("inner plane is at its in-flight bound"))?;
        // Health-aware selection. All backends ejected ⇒ fail closed WITHOUT dispatching
        // and WITHOUT queuing (bounded fail-closed, ADR-MCPRE-051 §3). The selection
        // yields the backend alongside its index, so neither is looked back up from the
        // other — and, once taken, neither is selected again at the dispatch.
        let Some((idx, is_probe, backend)) = self.select_backend(self.now_nanos()) else {
            return Err(NotAdmitted("every inner backend is ejected"));
        };
        // A claimed recovery probe MUST be released even if this dispatch never happens.
        // `record_outcome` — the only other place that clears the flag — runs after the
        // awaited round trip, so a prepared dispatch that is dropped, or a future hyper
        // drops on a client disconnect or an H2 RST_STREAM, would otherwise leave
        // `probe_inflight` set forever: the backend stays HalfOpen with its single trial
        // slot permanently claimed, never re-probed and never recovered, for the life of
        // the process. The guard releases on drop, and the drop now covers the
        // never-dispatched path too.
        let probe = is_probe.then_some(ProbeGuard { backend });
        let req = Self::build_request(backend.uri.clone(), Bytes::copy_from_slice(request))?;
        let client = self.client.clone();
        let timeout = self.request_timeout;
        Ok(PreparedInnerDispatch::over(move || {
            Box::pin(async move {
                // Moved in, so the permit and the trial slot are held for exactly the
                // round trip and released with this future however it ends.
                let _permit = permit;
                let _probe = probe;
                let _t_inner =
                    crate::stage_timers::Timed::start(crate::stage_timers::Stage::InnerDispatch);
                let outcome = Self::round_trip(&client, req, timeout).await;
                let done = self.now_nanos();
                // The breaker counts "did this backend serve a usable answer", so every
                // non-`Replied` outcome is a failure for its purposes even though the two
                // differ sharply in what they mean for the exchange.
                let healthy = matches!(outcome, DispatchedOutcome::Replied(_));
                self.record_outcome(idx, is_probe, healthy, done);
                outcome
            })
        }))
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
            BreakerConfig {
                failure_threshold: threshold,
                ejection_duration: Duration::from_secs(30),
            },
        )
        .expect("pool")
    }

    /// A pool whose ejected backends become probe-eligible immediately, so `prepare`'s
    /// use of the real monotonic clock still lands past the cooldown.
    fn pool_no_cooldown(backends: usize, threshold: u32) -> HttpInnerPool {
        let uris = (0..backends).map(|i| uri(9100 + i as u16)).collect();
        HttpInnerPool::with_breaker_config(
            uris,
            Duration::from_secs(1),
            BreakerConfig {
                failure_threshold: threshold,
                ejection_duration: Duration::ZERO,
            },
        )
        .expect("pool")
    }

    #[test]
    fn preparing_claims_the_recovery_probe_and_dropping_it_gives_the_probe_back() {
        let p = pool_no_cooldown(1, 1);
        let (i, pr, _) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0); // ejected, reopen_at = now
        assert_eq!(p.ejected_backend_count(), 1);

        // Preparing takes the single trial slot — it does not predict that the slot will
        // still be there at the dispatch. That is the whole change: the capability is
        // held, so no second claimant can win the race in between.
        let prepared = p.prepare(b"{}").expect("a probe-eligible backend prepares");
        assert!(
            p.backends[0].probe_inflight.load(Ordering::Acquire),
            "prepare must claim the Half-Open trial it is about to use"
        );
        assert!(
            p.prepare(b"{}").is_err(),
            "the trial slot is taken, so a second preparation finds nothing to claim"
        );

        // Dropping it gives everything back, with no release call anywhere. This is the
        // rescind path for a refusal taken between prepare and the dispatch.
        drop(prepared);
        assert!(
            !p.backends[0].probe_inflight.load(Ordering::Acquire),
            "a dropped preparation must not leave the trial slot claimed forever"
        );
        assert_eq!(
            p.in_flight_available(),
            p.max_in_flight(),
            "a dropped preparation must give the in-flight permit back"
        );

        // And the probe is still there for the next attempt to claim and recover on.
        let (pi, is_probe, _) = p
            .select_backend(p.now_nanos())
            .expect("the probe survives a preparation that never dispatched");
        assert!(is_probe, "the claim is a Half-Open trial");
        p.record_outcome(pi, is_probe, true, p.now_nanos());
        assert_eq!(p.ejected_backend_count(), 0, "the backend recovered");
    }

    #[test]
    fn preparing_refuses_only_while_every_backend_is_ejected() {
        let p = pool(1, 1); // 30s cooldown: stays ejected for the whole test
        assert!(p.prepare(b"{}").is_ok(), "healthy backend is admissible");
        let (i, pr, _) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0);
        assert!(
            p.prepare(b"{}").is_err(),
            "an Open backend inside its cooldown is not admissible"
        );
    }

    /// The permit is TAKEN at preparation, not read.
    ///
    /// The defect this closes: `admit` answered from `available_permits`, and the permit
    /// was acquired inside the dispatch — so between the two another core could take the
    /// last one, and the exchange discovered it from the far side of the execution
    /// threshold. Exhausting the bound with prepared-but-undispatched capabilities is
    /// exactly that window, and it must now be closed at the pre-commitment refusal.
    #[test]
    fn a_held_preparation_consumes_the_in_flight_bound() {
        let p = pool(1, 1).with_max_in_flight(1);
        let held = p
            .prepare(b"{}")
            .expect("the first preparation takes the permit");
        assert_eq!(p.in_flight_available(), 0);
        assert!(
            p.prepare(b"{}").is_err(),
            "a permit held by a preparation is not available to predict against"
        );
        drop(held);
        assert!(
            p.prepare(b"{}").is_ok(),
            "and it is available again once the preparation is dropped"
        );
    }

    /// Selection is the ONLY reader of dispatchability, and each claim takes one slot.
    ///
    /// This replaces a control over `any_dispatchable`, the read-only twin `admit` used.
    /// The property worth keeping is not that the two agreed — it is that a claim removes
    /// what it claimed, so an ejected fleet past its cooldown offers exactly as many trials
    /// as it has probe-eligible backends, and not one more.
    #[test]
    fn each_probe_claim_takes_a_slot_that_no_second_claim_can_take() {
        let p = pool(2, 1);
        let cooldown = DEFAULT_EJECTION_DURATION.as_nanos() as u64;
        // Eject both backends.
        for _ in 0..2 {
            let (i, pr, _) = p.select_backend(0).unwrap();
            p.record_outcome(i, pr, false, 0);
        }
        assert_eq!(p.ejected_backend_count(), 2);
        assert!(
            p.select_backend(1).is_none(),
            "inside the cooldown nothing is dispatchable"
        );
        let (first, is_probe, _) = p
            .select_backend(cooldown + 1)
            .expect("past the cooldown a probe is available");
        assert!(is_probe);
        let (second, is_probe, _) = p
            .select_backend(cooldown + 1)
            .expect("the OTHER backend is still probe-eligible");
        assert!(is_probe);
        assert_ne!(first, second, "one probe slot per backend, not per call");
        assert!(
            p.select_backend(cooldown + 1).is_none(),
            "both trial slots are claimed, so there is nothing left to take"
        );
    }

    #[test]
    fn healthy_backend_selected_and_closed_stays_closed_on_success() {
        let p = pool(1, 3);
        let (idx, is_probe, _) = p.select_backend(0).expect("dispatchable");
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
            let (idx, probe, _) = p.select_backend(0).expect("still selectable");
            p.record_outcome(idx, probe, false, 0);
        }
        assert_eq!(p.ejected_backend_count(), 0, "below threshold stays Closed");
        // Third failure trips it Open (ejected).
        let (idx, probe, _) = p
            .select_backend(0)
            .expect("still selectable at threshold-1");
        p.record_outcome(idx, probe, false, 0);
        assert_eq!(
            p.ejected_backend_count(),
            1,
            "threshold consecutive failures eject"
        );
    }

    #[test]
    fn a_success_resets_the_failure_run() {
        let p = pool(1, 3);
        for _ in 0..2 {
            let (i, pr, _) = p.select_backend(0).unwrap();
            p.record_outcome(i, pr, false, 0);
        }
        let (i, pr, _) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, true, 0); // success resets the run
                                          // Two more failures must NOT eject (run restarted at the success).
        for _ in 0..2 {
            let (i, pr, _) = p.select_backend(0).unwrap();
            p.record_outcome(i, pr, false, 0);
        }
        assert_eq!(
            p.ejected_backend_count(),
            0,
            "a success clears the consecutive-failure run"
        );
    }

    #[test]
    fn all_open_selection_returns_none_before_cooldown() {
        let p = pool(1, 1); // one failure ejects
        let (i, pr, _) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0); // now Open with reopen_at = ejection_duration
                                           // Before cooldown elapses, nothing is dispatchable — caller fails closed.
        assert!(
            p.select_backend(1).is_none(),
            "an Open backend is not dispatched to before cooldown"
        );
        assert_eq!(p.ejected_backend_count(), 1);
    }

    #[test]
    fn open_backend_readmitted_as_probe_after_cooldown_then_closes_on_success() {
        let p = pool(1, 1);
        let (i, pr, _) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0);
        let cooldown = DEFAULT_EJECTION_DURATION.as_nanos() as u64;
        // After the cooldown, selection admits exactly one Half-Open probe.
        let (pi, is_probe, _) = p
            .select_backend(cooldown + 1)
            .expect("probe admitted after cooldown");
        assert!(is_probe, "post-cooldown re-admission is a trial probe");
        // A concurrent second request finds the probe in flight and is turned away.
        assert!(
            p.select_backend(cooldown + 1).is_none(),
            "only one probe in flight at a time"
        );
        // Probe success fully closes the breaker → back to normal traffic.
        p.record_outcome(pi, is_probe, true, cooldown + 2);
        assert_eq!(p.ejected_backend_count(), 0);
        let (_, back_to_normal, _) = p.select_backend(cooldown + 3).expect("healthy again");
        assert!(
            !back_to_normal,
            "a recovered backend takes normal (non-probe) traffic"
        );
    }

    #[test]
    fn failed_probe_reopens_for_another_cooldown() {
        let p = pool(1, 1);
        let (i, pr, _) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0);
        let cooldown = DEFAULT_EJECTION_DURATION.as_nanos() as u64;
        let (pi, is_probe, _) = p.select_backend(cooldown + 1).expect("probe admitted");
        p.record_outcome(pi, is_probe, false, cooldown + 1); // probe fails
        assert_eq!(p.ejected_backend_count(), 1, "a failed probe re-ejects");
        assert!(
            p.select_backend(cooldown + 2).is_none(),
            "re-ejected backend waits a fresh cooldown, not immediately re-probed"
        );
        // Only after ANOTHER full cooldown is it probed again.
        assert!(
            p.select_backend(2 * cooldown + 3).is_some(),
            "re-admitted after a second cooldown"
        );
    }

    #[test]
    fn health_aware_lb_skips_open_backend_and_uses_healthy_one() {
        let p = pool(2, 1);
        // Fail backend 0 into Open; leave backend 1 healthy.
        // Force selection onto index 0 first by draining the round-robin cursor.
        // With 2 backends the cursor alternates; eject whichever we hit until one is Open.
        let (i0, pr0, _) = p.select_backend(0).unwrap();
        p.record_outcome(i0, pr0, false, 0);
        assert_eq!(p.ejected_backend_count(), 1);
        // Every subsequent selection must avoid the Open backend and pick the healthy one.
        for _ in 0..8 {
            let (i, is_probe, _) = p.select_backend(0).expect("a healthy backend remains");
            assert_ne!(i, i0, "LB must not route to the ejected backend");
            assert!(!is_probe, "the healthy backend is normal traffic");
        }
    }
}
