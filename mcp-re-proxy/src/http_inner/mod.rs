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
//! `dispatch` NEVER errors (the [`AsyncInnerServer`] contract): every failure becomes an
//! [`InnerOutcome`] the proxy still SIGNS a reply about. When all backends are Open the
//! request fails closed WITHOUT dispatching; when the in-flight bound
//! ([`DEFAULT_MAX_IN_FLIGHT`]) is reached, a further request fails closed WITHOUT
//! queuing — bounded backpressure, never an unbounded backlog. A dead, hostile, or
//! overloaded inner fleet can never suppress the signature or cause a silent allow.
//!
//! What it no longer does is report all of those as the same thing (ADR-MCPRE-058 §10,
//! ruling D4). The pool is the only component that KNOWS whether bytes left the process,
//! so it is the only one that can classify:
//!
//! ```text
//! no permit / all backends ejected / unbuildable request  -> NotDispatched
//! timeout, connect or transport error                     -> Indeterminate
//! non-2xx, non-JSON media type, unreadable or over-cap    -> InvalidUpstream
//! 2xx with a JSON body                                    -> Replied
//! ```
//!
//! A connect error is classified `Indeterminate` rather than `NotDispatched`, deliberately.
//! hyper does not reliably distinguish "the connection was refused" from "the request was
//! written and the peer went away", and `NotDispatched` is a claim that the action did not
//! run. Only outcomes this pool can PROVE never reached a backend earn it.

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
use crate::async_inner::InnerOutcome;
use crate::async_inner::InnerResponseFuture;
use crate::async_inner::NotAdmitted;

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

    /// Issue the HTTP round-trip to `uri`.
    ///
    /// Returns the classified [`InnerOutcome`] rather than `Result<Vec<u8>, ()>`: this
    /// function is the only place that can tell a timeout from a refused connection from a
    /// backend that answered with HTML, and flattening them to one `Err(())` here is what
    /// made the distinction unrecoverable everywhere else.
    async fn round_trip(
        client: &Client<HttpConnector, Full<Bytes>>,
        uri: Uri,
        body: Bytes,
        timeout: Duration,
    ) -> InnerOutcome {
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
            .body(Full::new(body));
        let req = match req {
            Ok(req) => req,
            // The request could not even be constructed, so nothing was transmitted.
            Err(_) => return InnerOutcome::NotDispatched("inner request could not be built"),
        };

        // Bound the whole round-trip. Timeout OR transport error ⇒ failure.
        let _t_inner = crate::stage_timers::Timed::start(crate::stage_timers::Stage::InnerDispatch);
        let resp = match tokio::time::timeout(timeout, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            // Both arms are INDETERMINATE, and the timeout is the reason this classification
            // exists: the request went out, the backend may well have executed the tool, and
            // the answer simply never came back. Reporting that as a clean error response is
            // the strongest available signal that nothing happened, which is precisely what
            // is not known.
            Ok(Err(_)) => return InnerOutcome::Indeterminate("inner transport error"),
            Err(_) => return InnerOutcome::Indeterminate("inner request timed out"),
        };

        // A non-2xx inner status is not a valid JSON-RPC response. The backend DID answer,
        // so this is not indeterminate — it is an unusable answer, and signing backend HTML
        // as an MCP result is not an option either.
        if !resp.status().is_success() {
            return InnerOutcome::InvalidUpstream("inner backend returned a non-2xx status");
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
            return InnerOutcome::InvalidUpstream("inner backend did not answer application/json");
        }

        // Read the body, capped. `Limited` fails the collect if the cap is exceeded.
        let limited = http_body_util::Limited::new(resp.into_body(), MAX_INNER_RESPONSE_BYTES);
        match limited.collect().await {
            Ok(collected) => InnerOutcome::Replied(collected.to_bytes().to_vec()),
            // The backend answered and the answer is unusable — over the cap, or the body
            // stream broke partway. It acted either way.
            Err(_) => {
                InnerOutcome::InvalidUpstream("inner response body was unreadable or over cap")
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
    /// The pre-dispatch capacity and health question, answered without transmitting.
    ///
    /// Both conditions are facts about THIS process: how many round trips are already in
    /// flight, and whether the breaker has ejected every backend. Asking them before the
    /// execution threshold is what lets a saturated or fully-ejected fleet be refused as
    /// genuinely retry-safe instead of as an exchange that may have executed.
    ///
    /// Deliberately claims NOTHING — neither the in-flight permit nor a recovery probe.
    /// Both are read-only observations ([`Semaphore::available_permits`] and
    /// [`HttpInnerPool::any_dispatchable`], never `select_backend`, which claims the
    /// Half-Open trial as a side effect of answering). A reservation would have to be
    /// held across the caller's own stages and released on every refusal path, and the
    /// benefit — closing a race whose losing side is resolved pessimistically anyway —
    /// does not pay for that.
    fn admit(&self) -> Result<(), NotAdmitted> {
        if self.in_flight.available_permits() == 0 {
            return Err(NotAdmitted("inner plane is at its in-flight bound"));
        }
        if !self.any_dispatchable(self.now_nanos()) {
            return Err(NotAdmitted("every inner backend is ejected"));
        }
        Ok(())
    }

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
                Err(_) => {
                    return InnerOutcome::NotDispatched("inner plane is at its in-flight bound")
                }
            };
            let now = self.now_nanos();
            // Health-aware selection. All backends ejected ⇒ fail closed WITHOUT
            // dispatching and WITHOUT queuing (bounded fail-closed, ADR-MCPRE-051 §3).
            // The selection yields the backend alongside its index, so neither is looked
            // back up from the other.
            let Some((idx, is_probe, backend)) = self.select_backend(now) else {
                return InnerOutcome::NotDispatched("every inner backend is ejected");
            };
            let uri = backend.uri.clone();

            // A claimed recovery probe MUST be released even if this future never
            // finishes. hyper drops the service future on a client disconnect or an H2
            // RST_STREAM, and `record_outcome` — the only other place that clears the
            // flag — runs after the awaited round trip. A dropped probe therefore left
            // `probe_inflight` set forever: the backend stayed HalfOpen with its single
            // trial slot permanently claimed, so it could never be re-probed and never
            // recovered, for the life of the process. The guard releases on drop.
            let _probe = is_probe.then(|| ProbeGuard { backend });

            let outcome = Self::round_trip(&client, uri, body.clone(), timeout).await;
            let done = self.now_nanos();
            // The breaker counts "did this backend serve a usable answer", so every
            // non-`Replied` outcome is a failure for its purposes even though the three
            // differ sharply in what they mean for the exchange.
            let healthy = matches!(outcome, InnerOutcome::Replied(_));
            self.record_outcome(idx, is_probe, healthy, done);
            outcome
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
            BreakerConfig {
                failure_threshold: threshold,
                ejection_duration: Duration::from_secs(30),
            },
        )
        .expect("pool")
    }

    /// A pool whose ejected backends become probe-eligible immediately, so `admit`'s
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
    fn admit_does_not_claim_the_recovery_probe() {
        let p = pool_no_cooldown(1, 1);
        let (i, pr, _) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0); // ejected, reopen_at = now
        assert_eq!(p.ejected_backend_count(), 1);

        // Asking the capacity question must not consume the single trial slot, so it
        // stays answerable — and stays the SAME answer — however often it is asked.
        for _ in 0..8 {
            assert!(p.admit().is_ok(), "a probe-eligible backend is admissible");
        }
        assert_eq!(
            p.backends[0].state.load(Ordering::Acquire),
            STATE_OPEN,
            "admit must not perform the Open->HalfOpen transition"
        );
        assert!(
            !p.backends[0].probe_inflight.load(Ordering::Acquire),
            "admit must not set probe_inflight; nothing would ever release it"
        );

        // The dispatch that follows is still able to claim the trial and recover.
        let (pi, is_probe, _) = p
            .select_backend(p.now_nanos())
            .expect("the probe is still there for the dispatch to claim");
        assert!(is_probe, "the claim is a Half-Open trial");
        p.record_outcome(pi, is_probe, true, p.now_nanos());
        assert_eq!(p.ejected_backend_count(), 0, "the backend recovered");
    }

    #[test]
    fn admit_refuses_only_while_every_backend_is_ejected() {
        let p = pool(1, 1); // 30s cooldown: stays ejected for the whole test
        assert!(p.admit().is_ok(), "healthy backend is admissible");
        let (i, pr, _) = p.select_backend(0).unwrap();
        p.record_outcome(i, pr, false, 0);
        assert!(
            p.admit().is_err(),
            "an Open backend inside its cooldown is not admissible"
        );
    }

    #[test]
    fn any_dispatchable_agrees_with_selection_without_mutating() {
        let p = pool(2, 1);
        let cooldown = DEFAULT_EJECTION_DURATION.as_nanos() as u64;
        // Eject both backends.
        for _ in 0..2 {
            let (i, pr, _) = p.select_backend(0).unwrap();
            p.record_outcome(i, pr, false, 0);
        }
        assert_eq!(p.ejected_backend_count(), 2);
        assert!(
            !p.any_dispatchable(1),
            "inside the cooldown nothing is dispatchable"
        );
        assert!(
            p.any_dispatchable(cooldown + 1),
            "past the cooldown a probe is available"
        );
        // Repeated reads never change the answer, because they change nothing.
        assert!(p.any_dispatchable(cooldown + 1));
        assert!(p.select_backend(cooldown + 1).is_some());
        // The claim IS visible to the read: one probe slot, now taken by one backend,
        // leaves the other still probe-eligible.
        assert!(p.any_dispatchable(cooldown + 1));
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
