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
use std::future::Future;
use std::pin::Pin;
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
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::tls::assertion_header;
use crate::tls::connection_rejection_for_leaf;
use crate::tls::resolve_identity_from_leaf;
use crate::tls::routing_header_rejection;
use crate::tls::ServerOptions;
use crate::transport::RequestHeaders;
use crate::transport::TransportIdentity;

/// The boxed, `Send` future a handler returns: signed response bytes out. The
/// handler is genuinely ASYNC — the request path AWAITS it — so a real `Proxy`
/// handler can await the authoritative async replay tier (ADR-MCPRE-051 §4)
/// WITHOUT blocking the per-core runtime worker. (A sync `-> Vec<u8>` seam would
/// have forced the replay store I/O to block the worker — an async transport
/// wrapped around a synchronous core; this type makes that impossible.)
pub type HandlerResponseFuture = Pin<Box<dyn Future<Output = ServedHttpResponse> + Send>>;

/// The HTTP request view handed to a serving handler — the RFC 9421 / RFC 9530
/// evidence carrier (ADR-MCPRE-050) needs the full HTTP request, not just the body:
/// the `@method`, the canonical `@target-uri` both sides sign over, and the entire
/// header block (so `Signature`, `Signature-Input`, and `Content-Digest` are
/// covered), plus the resolved transport identity and the optional Tier-3 ingress
/// assertion. Fields are OWNED because the handler's returned future is `'static`
/// (awaited on a spawned connection task, cannot borrow request-scoped data).
pub struct ServedHttpRequest {
    /// The HTTP method (RFC 9421 `@method`).
    pub method: String,
    /// The canonical `@target-uri` both client and server sign over
    /// (deployment-configured via [`ServerOptions`]); an empty string when the
    /// deployment did not configure one (the verifier then fails closed).
    pub target_uri: String,
    /// The full request header block (name, value) — carries the RFC 9421
    /// `Signature`/`Signature-Input` and RFC 9530 `Content-Digest`.
    pub headers: Vec<(String, String)>,
    /// The raw request body bytes.
    pub body: Vec<u8>,
    /// The resolved transport identity (mTLS peer / trusted upstream header).
    pub identity: Option<TransportIdentity>,
    /// The raw Tier-3 ingress-assertion header, when the strategy is LB-assertion.
    pub assertion: Option<String>,
}

/// The signed HTTP response a handler returns: the status, the header block
/// (carrying the RFC 9421 `Signature`/`Signature-Input` and RFC 9530
/// `Content-Digest` the handler emitted), and the body bytes.
pub struct ServedHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ServedHttpResponse {
    /// A JSON body reply with the given status and `content-type: application/json`
    /// — for pre-handler transport rejections that carry no RFC 9421 evidence.
    pub fn json(status: u16, body: Vec<u8>) -> Self {
        ServedHttpResponse {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body,
        }
    }
}

/// The per-request async handler: the full HTTP request view in ([`ServedHttpRequest`]),
/// a future of the signed HTTP response out ([`ServedHttpResponse`], carrying the
/// RFC 9421 response headers). A `Proxy` satisfies it by returning
/// `Box::pin(async move { proxy.handle_http_profile_async(req, ..).await })` —
/// `Proxy` is `Send + Sync` (MCPRE-111), so one `Proxy` per core serves every
/// connection on that core.
pub trait AsyncRequestHandler:
    Fn(ServedHttpRequest) -> HandlerResponseFuture + Send + Sync + 'static
{
}
impl<F> AsyncRequestHandler for F where
    F: Fn(ServedHttpRequest) -> HandlerResponseFuture + Send + Sync + 'static
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
    config: Arc<crate::config_snapshot::ServerConfigSnapshot>,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
) {
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

        // MCPRE-116: read the CURRENT serving config per connection, so a CRL
        // hot-reload that atomically swapped a rebuilt `ServerConfig` into the
        // snapshot is observed by the next handshake — without a restart. Building
        // the acceptor once outside this loop would pin every core to the config
        // captured at startup and make `--client-crl-reload-secs` a no-op. An
        // in-flight handshake keeps serving on the config it captured here.
        let acceptor = TlsAcceptor::from(config.load());
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
    // Read before `options` is moved into the service closure below.
    let stream_ceiling = options.limits.max_in_flight_requests;

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
    // Cap HTTP/2 concurrent streams to the same per-core in-flight ceiling. Without a
    // cap, ONE connection holding a valid client certificate can open unbounded
    // concurrent streams; each is a request that buffers up to `max_body_bytes`, so the
    // in-flight semaphore sheds them with a 503 only AFTER hyper has accepted the
    // stream. Capping at the connection level applies the same bound one layer earlier,
    // at the multiplexer. Left unset when no ceiling is configured (unbounded, the
    // historical behavior).
    if let Some(ceiling) = stream_ceiling {
        builder.http2().max_concurrent_streams(ceiling as u32);
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

    // A header value that is not valid UTF-8 has no lossy rendering this profile can
    // safely use, so the request is refused here — before any view of it is built.
    // See [`malformed_header_response`].
    if req.headers().values().any(|value| value.to_str().is_err()) {
        return Ok(malformed_header_response());
    }

    // A header view with the SAME case-insensitive lookup + duplicate-count
    // semantics the blocking path's `RequestHeaders::parse` produces (used by the
    // reverse-proxy identity provider, the Tier-3 assertion extractor, and the
    // routing-header hygiene guard).
    let headers = RequestHeaders::from_pairs(
        req.headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or(""))),
    );

    // Capture the RFC 9421 request view BEFORE the body is consumed: the `@method`
    // and the full header block (carrying `Signature`/`Signature-Input`/`Content-Digest`)
    // the handler needs to verify the HTTP evidence carrier (ADR-MCPRE-050).
    let method = req.method().as_str().to_owned();
    let header_pairs: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap_or("").to_owned()))
        .collect();

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
    // is never reached on a rejection. The two rejection checks are sync CPU
    // (leaf-cert lifetime + header hygiene); only the admitted handler is AWAITED,
    // and it is the handler that awaits the async replay tier.
    let served = match connection_rejection_for_leaf(leaf, &options, &body_bytes)
        .or_else(|| routing_header_rejection(&headers, &body_bytes))
    {
        // A pre-handler transport rejection carries a JSON error body, no RFC 9421
        // evidence; frame it as a 403 JSON reply.
        Some(error) => ServedHttpResponse::json(403, error),
        None => {
            let served_req = ServedHttpRequest {
                method,
                target_uri: options.target_uri.clone(),
                headers: header_pairs,
                body: body_bytes.to_vec(),
                identity,
                assertion: assertion.map(str::to_string),
            };
            handler(served_req).await
        }
    };

    Ok(served_to_hyper(served))
}

/// Translate the handler's [`ServedHttpResponse`] (status + headers + body) into a
/// hyper response, PRESERVING every signed header (RFC 9421 `Signature`/
/// `Signature-Input`, RFC 9530 `Content-Digest`, `Content-Type`).
fn served_to_hyper(resp: ServedHttpResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(resp.status);
    for (k, v) in &resp.headers {
        builder = builder.header(k, v);
    }
    builder
        .body(Full::new(Bytes::from(resp.body)))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(500)
                .body(Full::new(Bytes::new()))
                .expect("static response builds")
        })
}

/// Fail-closed reply when a header value is not valid UTF-8: an empty `400`, the
/// handler never reached.
///
/// The profile has no lossy rendering of such a value that is safe. Substituting
/// `""` makes a COVERED component resolve to an empty line in the signature base —
/// exactly the "never a blank line, always an error" case `sigbase` refuses to
/// produce — and omitting the header instead hides a duplicate from the
/// exactly-once rules that `sigbase::component_value` and
/// [`crate::transport::RequestHeaders::count`] rely on to fail closed on a
/// duplicated covered field or trust header. One direction fabricates a signable
/// value, the other conceals a duplicate, so the message is refused at the boundary
/// rather than rendered into a view that cannot represent it.
///
/// Nothing conformant is lost: a covered component's value must be an RFC 8941
/// string, and this profile's signature base is UTF-8 by construction.
fn malformed_header_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(400)
        .body(Full::new(Bytes::new()))
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
