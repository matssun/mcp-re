//! ADR-MCPRE-051 Phase 2 (§1) — OPT-IN async serving path.
//!
//! Replaces the blocking `std::net` accept loop's I/O with `tokio` +
//! `tokio-rustls` + `hyper` (HTTP/1.1 keep-alive + HTTP/2), killing the
//! one-request-per-connection `Connection: close` wire. It is a THIN transport
//! swap: the security core is reused verbatim —
//!
//!   * the rustls [`ServerConfig`] (mTLS verifier + CRL + client-auth) is the
//!     EXACT one the blocking path builds, handed to `tokio-rustls`'s
//!     `TlsAcceptor` unchanged, so the handshake — and every mTLS rejection —
//!     is byte-identical;
//!   * the verified client identity, the per-connection cert-lifetime rejection,
//!     the routing-header hygiene rejection, and the Tier-3 assertion extraction
//!     all go through the SAME `tls` helpers the blocking loop uses
//!     ([`resolve_identity_from_leaf`], [`connection_rejection_for_leaf`],
//!     [`routing_header_rejection`], [`assertion_header`]);
//!   * the request handler is the SAME `Proxy` handler (`Proxy` is `Send + Sync`
//!     since MCPRE-111, which is why this work was blocked on it).
//!
//! Only the I/O framing changes. `ServerLimits` map onto the async stack: the
//! aggregate read deadline (`request_deadline`, the slow-loris defense) bounds the
//! TLS handshake and the per-request body read via `tokio::time::timeout`, the
//! header read is bounded by `hyper`'s HTTP/1 header-read timeout, `max_body_bytes`
//! caps the body via `http_body_util::Limited`, and `max_concurrent_connections`
//! is a fail-closed `Semaphore` (excess connections dropped, never queued).
//!
//! SCOPE (this increment): the async path is opt-in dev scaffolding — a single
//! shared runtime, never a release (ADR-MCPRE-051 §1); per-core runtimes +
//! `SO_REUSEPORT` are MCPRE-113. Online-OCSP revocation on the async path needs the
//! full peer chain and is a tracked follow-up (see [`connection_rejection_for_leaf`]);
//! the default + shared-replay-tier builds have full parity. Precise `write_timeout`
//! mapping onto `hyper` is likewise deferred (the load-bearing slow-loris defense is
//! the READ side, which is mapped).

use std::convert::Infallible;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use http_body_util::Limited;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::rt::TokioTimer;
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::tls::assertion_header;
use crate::tls::connection_rejection_for_leaf;
use crate::tls::resolve_identity_from_leaf;
use crate::tls::routing_header_rejection;
use crate::tls::ServerOptions;
use crate::transport::RequestHeaders;
use crate::transport::TransportIdentity;

/// The per-request handler: verified request bytes + resolved transport identity +
/// the raw Tier-3 ingress-assertion header (when the strategy is LB-assertion), in,
/// signed response bytes out. This is the async mirror of the blocking serve loop's
/// handler; a `Proxy` satisfies it via `handle_with_transport` because `Proxy` is
/// `Send + Sync` (MCPRE-111).
pub trait AsyncRequestHandler:
    Fn(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8> + Send + Sync + 'static
{
}
impl<F> AsyncRequestHandler for F where
    F: Fn(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8> + Send + Sync + 'static
{
}

/// How long an idle accept poll waits before re-checking the shutdown flag, so a
/// shutdown signal is observed promptly even with no pending connection (mirrors
/// the blocking loop's `SHUTDOWN_POLL_INTERVAL`).
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How often the graceful-drain loop re-checks the in-flight-request count while
/// waiting for shutdown to complete (MCPRE-115). Small enough that a clean drain
/// returns promptly after the last request finishes, large enough to not busy-spin.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// RAII counter of requests currently being served on a core (MCPRE-115). Constructed
/// once a request is admitted and about to be processed; the increment/decrement pair
/// is exactly balanced by `Drop`, so the count reflects live in-flight requests on
/// every return path (503 admission rejections are constructed BEFORE this guard and
/// so are never counted — there is nothing to drain for a request that was shed).
struct InFlightGuard(Arc<AtomicUsize>);

impl InFlightGuard {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        InFlightGuard(Arc::clone(counter))
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Run the async accept loop until `shutdown` flips. Each accepted connection is
/// TLS-terminated (`tokio-rustls`) and served over `hyper` (keep-alive + H2). One
/// shared `Proxy` (behind `handler`) serves every connection — the whole point of
/// `Proxy: Send + Sync`.
pub async fn serve<H: AsyncRequestHandler>(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
) {
    let acceptor = TlsAcceptor::from(config);
    let permits = Arc::new(tokio::sync::Semaphore::new(
        options.limits.max_concurrent_connections,
    ));
    // MCPRE-114: per-core bounded ADMISSION control. One in-flight-request semaphore
    // per `serve` loop (i.e. per core), sized to `max_in_flight_requests`; a request
    // that cannot acquire a permit is rejected with 503 before the handler runs
    // (fail-closed backpressure, never unbounded queuing). `None` ⇒ unbounded
    // in-flight (historical behavior). The semaphore is per-core, so the request path
    // stays lock-free ACROSS cores (ADR-MCPRE-051 §1 share-nothing).
    let in_flight = options
        .limits
        .max_in_flight_requests
        .map(|n| Arc::new(tokio::sync::Semaphore::new(n)));

    // MCPRE-115: live count of requests currently BEING SERVED on this core (past
    // admission, in body-read/handler/response). Graceful drain waits for this to
    // reach zero — idle keep-alive connections carry no in-flight request and so do
    // not extend the drain.
    let in_flight_requests = Arc::new(AtomicUsize::new(0));

    while !shutdown.load(Ordering::SeqCst) {
        // Poll-with-timeout so the shutdown flag is observed within one interval
        // even under an idle listener.
        let accepted = tokio::time::timeout(ACCEPT_POLL_INTERVAL, listener.accept()).await;
        let (tcp, _peer) = match accepted {
            Ok(Ok(pair)) => pair,
            // A single rejected/aborted connection must not bring the server down.
            Ok(Err(_)) => continue,
            // Idle poll elapsed: re-check the shutdown guard.
            Err(_) => continue,
        };

        // Fail-closed admission control: at saturation, drop the connection (TCP
        // accepted then closed) rather than queue without bound. Mirrors the
        // blocking loop's `max_concurrent_connections` cap.
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            drop(tcp);
            continue;
        };

        let acceptor = acceptor.clone();
        let options = Arc::clone(&options);
        let handler = Arc::clone(&handler);
        let in_flight = in_flight.clone();
        let in_flight_requests = Arc::clone(&in_flight_requests);
        tokio::spawn(async move {
            let _permit = permit; // released when the connection task ends
            let _ = serve_connection(tcp, acceptor, options, handler, in_flight, in_flight_requests)
                .await;
        });
    }

    // MCPRE-115: bounded graceful drain. The accept loop has stopped (shutdown
    // observed), so no NEW request will be admitted; wait up to `drain_grace` for the
    // requests already in flight to finish. Because each in-flight request is itself
    // bounded by `request_deadline`, `drain_grace >= request_deadline` guarantees a
    // clean, zero-abandoned drain; the grace is the hard ceiling so a wedged request
    // cannot delay process exit past it (bounded exit). When `serve` returns, the
    // caller drops the runtime, aborting any (idle) connection tasks — none of which
    // hold an in-flight request once the count reaches zero.
    let drain_deadline = tokio::time::Instant::now() + options.limits.drain_grace;
    while in_flight_requests.load(Ordering::Acquire) > 0 {
        if tokio::time::Instant::now() >= drain_deadline {
            break;
        }
        tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
    }
}

/// Terminate TLS on one accepted socket and serve HTTP/1.1 keep-alive + HTTP/2 over
/// it. The handshake is bounded by the aggregate `request_deadline` (slow-loris on
/// the handshake read); the peer leaf certificate is captured once (hyper then owns
/// the stream) and drives per-request identity + cert-lifetime decisions.
async fn serve_connection<H: AsyncRequestHandler>(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    in_flight: Option<Arc<tokio::sync::Semaphore>>,
    in_flight_requests: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    // Handshake, bounded by the aggregate read deadline: a peer that never
    // completes the handshake cannot hold the connection task forever. Reading
    // drives the handshake, exactly as the blocking `DeadlineStream` bounds it.
    let tls = match options.limits.request_deadline {
        Some(deadline) => tokio::time::timeout(deadline, acceptor.accept(tcp))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake deadline"))??,
        None => acceptor.accept(tcp).await?,
    };

    // Capture the verified peer leaf DER ONCE (connection-constant). hyper takes
    // ownership of the TLS stream next, so per-request identity/cert-lifetime
    // decisions read this captured leaf via the shared `tls` leaf-DER helpers.
    let leaf_der: Arc<Option<Vec<u8>>> = Arc::new(
        tls.get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| leaf.as_ref().to_vec()),
    );

    // Capture the header-read deadline before `options` moves into the service.
    let header_read_timeout = options.limits.request_deadline.or(options.limits.read_timeout);

    let io = TokioIo::new(tls);
    let service = service_fn(move |req: Request<Incoming>| {
        let options = Arc::clone(&options);
        let handler = Arc::clone(&handler);
        let leaf_der = Arc::clone(&leaf_der);
        let in_flight = in_flight.clone();
        let in_flight_requests = Arc::clone(&in_flight_requests);
        async move {
            handle_request(req, options, handler, leaf_der, in_flight, in_flight_requests).await
        }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    // Bound the HTTP/1 header read so a slow-loris trickling header bytes cannot
    // hold a keep-alive connection between requests (the per-request analogue of
    // the blocking `request_deadline` over the header block).
    if let Some(read_timeout) = header_read_timeout {
        // `header_read_timeout` needs a `Timer` on the connection or hyper panics
        // when it arms the deadline; supply the tokio timer.
        builder.http1().timer(TokioTimer::new()).header_read_timeout(read_timeout);
    }
    // Serve every request on this connection (keep-alive / H2 multiplexed). A
    // connection-level error just ends this task; other connections are unaffected.
    if let Err(_e) = builder.serve_connection(io, service).await {
        return Ok(());
    }
    Ok(())
}

/// Serve one HTTP request: reconstruct the header view, read the body (capped),
/// run the SAME identity/rejection/handler pipeline as the blocking serve loop, and
/// frame the signed response bytes.
async fn handle_request<H: AsyncRequestHandler>(
    req: Request<Incoming>,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    leaf_der: Arc<Option<Vec<u8>>>,
    in_flight: Option<Arc<tokio::sync::Semaphore>>,
    in_flight_requests: Arc<AtomicUsize>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // MCPRE-114: per-core admission control. Acquire an in-flight permit FIRST — if
    // the per-core ceiling is full, reject with 503 fail-closed BEFORE reading the
    // body or reaching the handler (the request never touches the inner server). The
    // owned permit is held for the rest of this request and released on return (RAII),
    // so the ceiling bounds requests actually in flight, never queuing them without
    // bound. `None` ⇒ no ceiling (unbounded in-flight).
    let _admission = match &in_flight {
        Some(semaphore) => match Arc::clone(semaphore).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return Ok(overloaded_response()),
        },
        None => None,
    };

    // MCPRE-115: count this request as in flight for the duration of its processing
    // (body read + handler + response). Constructed AFTER admission so a shed 503 is
    // not counted; dropped on every return path below, so graceful drain sees the
    // count fall to zero exactly when the last request finishes.
    let _in_flight_guard = InFlightGuard::new(&in_flight_requests);

    // A header view with the SAME case-insensitive lookup + duplicate-count
    // semantics the blocking path's `RequestHeaders::parse` produces (used by the
    // reverse-proxy identity provider, the Tier-3 assertion extractor, and the
    // routing-header hygiene guard). Non-UTF-8 header values become empty — treated
    // as absent, i.e. fail closed.
    let headers = RequestHeaders::from_pairs(
        req.headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or(""))),
    );

    // Read the body, capped at `max_body_bytes` and bounded by the aggregate read
    // deadline (slow-loris on a trickled body). Either bound tripping fails closed:
    // the inner server is never reached.
    let max_body = options.limits.max_body_bytes;
    let collect = Limited::new(req.into_body(), max_body).collect();
    let body_bytes = match options.limits.request_deadline {
        Some(deadline) => match tokio::time::timeout(deadline, collect).await {
            Ok(Ok(collected)) => collected.to_bytes(),
            _ => return Ok(fail_closed_response()),
        },
        None => match collect.await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return Ok(fail_closed_response()),
        },
    };

    let leaf = (*leaf_der).as_deref();
    let identity = resolve_identity_from_leaf(leaf, &options, &headers);
    let assertion = assertion_header(&options, &headers);

    // SAME order as the blocking loop: per-connection cert-lifetime rejection, then
    // routing-header hygiene, then (only if admitted) the handler. The inner server
    // is never reached on a rejection.
    let response_bytes = match connection_rejection_for_leaf(leaf, &options, &body_bytes)
        .or_else(|| routing_header_rejection(&headers, &body_bytes))
    {
        Some(error) => error,
        None => handler(&body_bytes, identity, assertion),
    };

    Ok(json_response(response_bytes))
}

/// A JSON response carrying `body` (Content-Length framed by `Full`; hyper handles
/// keep-alive/H2 framing).
fn json_response(body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("static response builds")
}

/// Fail-closed reply when the body exceeds `max_body_bytes` or the read deadline
/// elapses: an empty `413`, the inner server never reached. (No request id is
/// available when the body itself could not be read.)
fn fail_closed_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(413)
        .body(Full::new(Bytes::new()))
        .expect("static response builds")
}

/// MCPRE-114 fail-closed backpressure: an empty `503 Service Unavailable` returned
/// when the per-core in-flight ceiling (`max_in_flight_requests`) is saturated. The
/// body is never read and the handler never runs, so an overloaded core sheds load
/// with a bounded, cheap rejection instead of queuing work without bound.
fn overloaded_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(503)
        .body(Full::new(Bytes::new()))
        .expect("static response builds")
}
