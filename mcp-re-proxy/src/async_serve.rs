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
//!     ([`resolve_identity_from_leaf`], [`connection_rejection_for_chain`],
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
//! full peer chain and is a tracked follow-up (see [`connection_rejection_for_chain`]);
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

use crate::communication_assurance::mechanism_verified_credential::accepted_chain_der;
use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;
use crate::communication_assurance::MechanismVerifiedCredentialEvidence;
use crate::tls::assertion_header;
use crate::tls::connection_rejection_for_chain;
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

/// hyper's own floor for `http1::Builder::max_buf_size`; a smaller value panics.
/// `--max-header-bytes` is clamped up to it rather than passed through.
const MIN_HYPER_BUF_BYTES: usize = 8192;

/// How many TLS handshakes may be in progress at once on a core whose handshake
/// signature is produced by a device or a KMS.
///
/// On that path `acceptor.accept` occupies its worker thread for a whole `C_Sign` /
/// `asymmetricSign`, and nothing else on the runtime runs meanwhile: the future does not
/// yield, so the handshake deadline cannot preempt it. `async_fleet` answers this with a
/// small worker pool per core, but a pool is not a bound — a peer needs only as many
/// concurrent connections as there are workers to occupy every one of them, and it needs
/// no client certificate to do it, because TLS 1.3 signs `CertificateVerify` before the
/// client's `Certificate` is ever seen.
///
/// This is the bound. Held strictly below the per-core worker pool, so a core under
/// handshake flood always retains workers for its accept loop, its established
/// connections and its in-flight requests. Raising it re-opens exactly what it closes.
const DELEGATED_TLS_HANDSHAKES_PER_CORE: usize = 2;

/// The per-core ceiling on request-body bytes buffered before verification, expressed as
/// a multiple of `max_body_bytes`.
///
/// The in-flight ceiling bounds request COUNT, and was reasoned about as if that bounded
/// memory. It does not: each admitted slot may buffer a whole `max_body_bytes` body, and
/// the permit is taken before the body is read, so the per-core product is
/// `max_in_flight_requests x max_body_bytes` (256 x 16 MiB = 4 GiB by default) and the
/// fleet product multiplies that by the core count. A peer holding a valid client
/// certificate and NO valid signing key — one that cannot get a single request past the
/// verifier — can drive all of it.
///
/// A multiple of `max_body_bytes` rather than an absolute number, so a deployment that
/// raises the body limit gets a proportional budget and a single maximum-size request is
/// always admissible. Four is enough that ordinary traffic (JSON-RPC bodies orders of
/// magnitude below the cap) never meets it, and small enough that the fleet total scales
/// with cores instead of with cores x 256.
const BUFFERED_BODY_BUDGET_MULTIPLE: usize = 4;

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

/// A per-core ceiling on request-body bytes resident before verification.
///
/// Charged as the body arrives rather than from a declared `Content-Length`, so a
/// chunked or HTTP/2 body with no declared length is bounded by the same budget, and a
/// peer cannot understate what it is about to send.
struct BodyByteBudget {
    ceiling: usize,
    charged: AtomicUsize,
}

impl BodyByteBudget {
    fn new(ceiling: usize) -> Self {
        BodyByteBudget {
            ceiling,
            charged: AtomicUsize::new(0),
        }
    }

    /// Reserve `bytes`, or `None` when the core is already holding its ceiling. The
    /// returned guard releases on every path, including an aborted body read.
    fn charge(self: &Arc<Self>, bytes: usize) -> Option<BodyBytes> {
        let mut current = self.charged.load(Ordering::Acquire);
        loop {
            if current.saturating_add(bytes) > self.ceiling {
                return None;
            }
            match self.charged.compare_exchange_weak(
                current,
                current + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(BodyBytes {
                        budget: Arc::clone(self),
                        bytes,
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }
}

/// Bytes charged against a [`BodyByteBudget`], returned on drop.
struct BodyBytes {
    budget: Arc<BodyByteBudget>,
    bytes: usize,
}

impl BodyBytes {
    /// Fold `other` into this reservation, so a streamed body holds one guard rather
    /// than one per frame.
    fn absorb(&mut self, mut other: BodyBytes) {
        self.bytes += other.bytes;
        // `other`'s bytes are now this guard's; it must not release them twice.
        other.bytes = 0;
    }
}

impl Drop for BodyBytes {
    fn drop(&mut self) {
        self.budget.charged.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Why a request body could not be buffered.
///
/// The two are distinct on the wire because they mean different things to the peer. A
/// body that is too large, unreadable or too slow is that peer's own request being
/// refused (`413`). A body the core has no budget for is the core saying "not now" to a
/// request that may be perfectly well formed (`503`), which is a retry-safe shed.
enum BodyReadError {
    /// The core is already holding its ceiling of pre-verification body bytes.
    BudgetExhausted,
    /// Over `max_body_bytes`, or the connection failed part-way through the body.
    Unreadable,
}

/// Buffer a request body under BOTH the per-request size cap and the core's aggregate
/// byte budget, charging as the bytes arrive.
///
/// Charging per frame rather than from `Content-Length` is what makes the budget hold: a
/// chunked or HTTP/2 body declares no length, and a declared one is the peer's claim
/// about what it is about to send. The returned [`BodyBytes`] holds the whole charge for
/// as long as the caller holds the bytes, and releases it on drop — including on a body
/// read that is abandoned part-way.
async fn collect_body(
    body: Incoming,
    max_body: usize,
    budget: &Arc<BodyByteBudget>,
) -> Result<(Bytes, BodyBytes), BodyReadError> {
    // `Limited` enforces `max_body_bytes` with the same semantics the whole serving path
    // is documented to have; the budget is the aggregate bound layered over it.
    let limited = Limited::new(body, max_body);
    let mut limited = std::pin::pin!(limited);
    // A zero-byte charge always succeeds and gives an empty body a guard to return.
    let mut charge = budget.charge(0).ok_or(BodyReadError::BudgetExhausted)?;
    let mut collected: Vec<u8> = Vec::new();
    while let Some(frame) = limited.frame().await {
        let frame = frame.map_err(|_| BodyReadError::Unreadable)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        // Charged BEFORE the bytes are copied into `collected`, so the ceiling bounds
        // what is resident rather than trailing it by one frame.
        charge.absorb(
            budget
                .charge(data.len())
                .ok_or(BodyReadError::BudgetExhausted)?,
        );
        collected.extend_from_slice(&data);
    }
    Ok((Bytes::from(collected), charge))
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

    // The byte half of admission. `max_in_flight_requests` bounds how many requests a
    // core serves at once; this bounds how much attacker-supplied body they may hold
    // between them, which the count alone never did.
    let body_budget = Arc::new(BodyByteBudget::new(
        options
            .limits
            .max_body_bytes
            .saturating_mul(BUFFERED_BODY_BUDGET_MULTIPLE),
    ));

    // Handshake admission, and ONLY where a handshake can block: on the exported-key
    // path the signature is in-memory and bounding it would cost throughput for nothing.
    let handshakes = options.tls_signing_may_block.then(|| {
        Arc::new(tokio::sync::Semaphore::new(
            DELEGATED_TLS_HANDSHAKES_PER_CORE,
        ))
    });

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
        let body_budget = Arc::clone(&body_budget);
        let handshakes = handshakes.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the connection task ends
            let _ = serve_connection(
                tcp,
                acceptor,
                options,
                handler,
                in_flight,
                in_flight_requests,
                body_budget,
                handshakes,
            )
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

/// Is the received request-target inconsistent with the configured `@target-uri`?
///
/// Returns `Some(received_origin_form)` on a mismatch, `None` when consistent. Compares
/// the ORIGIN FORM (path + query) only: the scheme and authority of the external target
/// are exactly the parts a TLS-terminating proxy cannot observe, which is why the
/// operator asserts the whole URI in the first place. The path is what the ingress
/// routes on and what this process CAN see, so it is the part whose assertion is
/// checkable.
///
/// An empty configured target is not checked here — `config_state::validation::target_uri_violation` refuses it
/// at the validation boundary every config passes through, and the verifier fails closed on
/// a blank covered value.
fn target_uri_mismatch(configured: &str, received: &hyper::Uri) -> Option<String> {
    if configured.is_empty() {
        return None;
    }
    let configured_origin = origin_form_of(configured)?;
    let received_origin = received
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    (configured_origin != received_origin).then_some(received_origin)
}

/// The origin-form (`/path`) of an ABSOLUTE `--target-uri`.
///
/// `None` only for a target with no `://`, which `config_state::validation::target_uri_violation` refuses at the
/// validation boundary — so on the served path this is always `Some`, and the mismatch
/// check is always live. The refusal is at the boundary rather than only in the parser
/// because a `None` here reads as "no mismatch", which would disable this check silently
/// for a config that never met a parser.
fn origin_form_of(absolute: &str) -> Option<String> {
    let authority_start = absolute.find("://")? + 3;
    let authority = &absolute[authority_start..];
    Some(match authority.find('/') {
        Some(offset) => authority[offset..].to_owned(),
        None => "/".to_owned(),
    })
}

/// Terminate TLS on one accepted socket and serve HTTP/1.1 keep-alive + HTTP/2 over
/// it. The handshake is bounded by the aggregate `request_deadline` (slow-loris on
/// the handshake read); the peer leaf certificate is captured once (hyper then owns
/// the stream) and drives per-request identity + cert-lifetime decisions.
// Every argument is a distinct per-connection collaborator captured from the serve
// loop; bundling them into a struct would only rename the same set.
#[allow(clippy::too_many_arguments)]
async fn serve_connection<H: AsyncRequestHandler>(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    in_flight: Option<Arc<tokio::sync::Semaphore>>,
    in_flight_requests: Arc<AtomicUsize>,
    body_budget: Arc<BodyByteBudget>,
    handshakes: Option<Arc<tokio::sync::Semaphore>>,
) -> std::io::Result<()> {
    // Handshake, bounded by the aggregate read deadline: a peer that never
    // completes the handshake cannot hold the connection task forever. Reading
    // drives the handshake, exactly as the blocking `DeadlineStream` bounds it.
    //
    // Under DELEGATED TLS custody the CertificateVerify signature is produced by a
    // blocking KMS round trip or a PKCS#11 `C_Sign` inside rustls' SYNCHRONOUS
    // `Signer::sign`, so this `await` can occupy its worker thread for the whole call
    // and the deadline below cannot preempt it — the future never yields, so the timer
    // never runs. `async_fleet` gives those deployments a multi-worker runtime per
    // core for exactly this reason: the stall then costs one worker rather than the
    // core's accept loop and every other connection on it.
    //
    // The pool is not a bound, though — a peer with no credentials of any kind can open
    // as many connections as there are workers and occupy every one, because TLS 1.3
    // signs CertificateVerify before it has seen the client's Certificate. So on that
    // path the number of handshakes allowed to be signing at once is capped strictly
    // below the pool. Waiting for the cap is safe in a way the signature is not: this
    // await yields, so `request_deadline` really does preempt it, and a connection that
    // cannot get in before the deadline is dropped rather than queued indefinitely.
    let _handshake = match (&handshakes, options.limits.request_deadline) {
        (None, _) => None,
        (Some(semaphore), Some(deadline)) => Some(
            tokio::time::timeout(deadline, Arc::clone(semaphore).acquire_owned())
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "TLS handshake admission deadline",
                    )
                })?
                .map_err(|_| std::io::Error::other("TLS handshake admission closed"))?,
        ),
        (Some(semaphore), None) => Some(
            Arc::clone(semaphore)
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("TLS handshake admission closed"))?,
        ),
    };
    let tls = match options.limits.request_deadline {
        Some(deadline) => tokio::time::timeout(deadline, acceptor.accept(tcp))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake deadline")
            })??,
        None => acceptor.accept(tcp).await?,
    };
    // Released here, not at the end of the connection: the bound is on handshakes in
    // progress, and an established connection costs no further device signatures.
    drop(_handshake);

    // THE ESTABLISHMENT BOUNDARY (ADR-MCPRE-063 Slice 4). `acceptor.accept` has
    // succeeded, so only now can the mechanism be asked which credential it associated
    // with the relationship. Captured ONCE — the credential is connection-constant and
    // hyper takes ownership of the TLS stream next. A refusal becomes an absent
    // credential and the fail-closed core downstream decides it; both refusals are
    // mechanism-boundary inconsistencies unreachable from this position.
    //
    // The whole chain, not just the leaf: the handshake verifier checks revocation to
    // the trust anchor (`RevocationCheckDepth::Chain`), so a per-request check that
    // stopped at the leaf would keep honouring a peer whose INTERMEDIATE was revoked
    // for as long as it held the connection open.
    // THE ESTABLISHMENT BOUNDARY: `accept` succeeded (ADR-MCPRE-064 Slice 1).
    let peer_credential = Arc::new(verified_credential(tls.get_ref().1).ok());

    // Capture the header-read deadline before `options` moves into the service.
    let header_read_timeout = options
        .limits
        .request_deadline
        .or(options.limits.read_timeout);
    // Read before `options` is moved into the service closure below.
    let stream_ceiling = options.limits.max_in_flight_requests;
    let max_header_bytes = options.limits.max_header_bytes;
    let write_timeout = options.limits.write_timeout;
    let max_connection_age = options.limits.max_connection_age;

    let io = TokioIo::new(tls);
    let service = service_fn(move |req: Request<Incoming>| {
        let options = Arc::clone(&options);
        let handler = Arc::clone(&handler);
        let peer_credential = Arc::clone(&peer_credential);
        let in_flight = in_flight.clone();
        let in_flight_requests = Arc::clone(&in_flight_requests);
        let body_budget = Arc::clone(&body_budget);
        async move {
            handle_request(
                req,
                options,
                handler,
                peer_credential,
                in_flight,
                in_flight_requests,
                body_budget,
            )
            .await
        }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    // Bound the HTTP/1 header read so a slow-loris trickling header bytes cannot
    // hold a keep-alive connection between requests (the per-request analogue of
    // the blocking `request_deadline` over the header block).
    if let Some(read_timeout) = header_read_timeout {
        // `header_read_timeout` needs a `Timer` on the connection or hyper panics
        // when it arms the deadline; supply the tokio timer.
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(read_timeout);
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
    // Apply the operator's `--max-header-bytes` on BOTH protocols. It was previously
    // parsed, validated, and then read by nothing on this path, so the only bound was
    // hyper's internal default — an operator tightening the limit got a silent no-op.
    // `max_buf_size` has a hyper-enforced 8 KiB floor, so clamp rather than pass a
    // smaller value straight through and panic.
    builder
        .http1()
        .max_buf_size(max_header_bytes.max(MIN_HYPER_BUF_BYTES));
    builder
        .http2()
        .max_header_list_size(max_header_bytes.min(u32::MAX as usize) as u32);
    // `--write-timeout-secs` is refused at parse time when it is 0, on the stated
    // grounds that it is a slow-loris defence — so it has to actually bound something
    // here. HTTP/2 has no per-write deadline in hyper; the keep-alive PING probe is
    // the equivalent liveness bound, and it closes a connection whose peer has stopped
    // reading. HTTP/1's write side is covered by the connection-age bound below.
    if let Some(write_timeout) = write_timeout {
        builder
            .http2()
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(write_timeout))
            .keep_alive_timeout(write_timeout);
    }
    // Serve every request on this connection (keep-alive / H2 multiplexed). A
    // connection-level error just ends this task; other connections are unaffected.
    //
    // MAX CONNECTION AGE: the peer's certificate was validated — chain, CRL, validity
    // window — at the handshake and is never re-consulted on an established
    // connection. At the age bound the connection is GRACEFULLY shut down: in-flight
    // requests finish and no new ones are accepted, so a peer that never reconnects
    // is not served indefinitely on one admission decision.
    //
    // This bound alone does not force re-verification. A TLS 1.3 peer that resumes
    // presents a PSK and sends no CertificateVerify, so the reconnection re-runs no
    // chain or CRL check. Resumption tickets are bound to the trust-anchor epoch, so
    // an anchor change invalidates them; a CRL reload does not. Per-request
    // revocation is what holds against a revoked-but-resuming peer.
    let conn = builder.serve_connection(io, service);
    tokio::pin!(conn);
    match max_connection_age {
        None => {
            let _ = conn.await;
        }
        Some(age) => {
            let deadline = tokio::time::sleep(age);
            tokio::pin!(deadline);
            let mut draining = false;
            loop {
                tokio::select! {
                    result = conn.as_mut() => {
                        let _ = result;
                        break;
                    }
                    // `draining` disarms this arm after it fires once: the elapsed
                    // sleep is immediately ready forever, so re-selecting it would
                    // spin instead of letting the graceful close complete.
                    _ = &mut deadline, if !draining => {
                        draining = true;
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
        }
    }
    Ok(())
}

/// How often the scheduler-latency probe is sampled, in requests. The probe is itself a
/// spawned task, so sampling every request would measure a runtime perturbed by the
/// measurement; this is rare enough to be free and frequent enough to average out.
const SCHEDULER_PROBE_EVERY_N_REQUESTS: u64 = 500;

/// Serve one HTTP request: reconstruct the header view, read the body (capped),
/// run the SAME identity/rejection/handler pipeline as the blocking serve loop, and
/// frame the signed response bytes.
async fn handle_request<H: AsyncRequestHandler>(
    req: Request<Incoming>,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    peer_credential: Arc<Option<MechanismVerifiedCredentialEvidence>>,
    in_flight: Option<Arc<tokio::sync::Semaphore>>,
    in_flight_requests: Arc<AtomicUsize>,
    body_budget: Arc<BodyByteBudget>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // MCPRE-114: per-core admission control. Acquire an in-flight permit FIRST — if
    // the per-core ceiling is full, reject with 503 fail-closed BEFORE reading the
    // body or reaching the handler (the request never touches the inner server). The
    // owned permit is held for the rest of this request and released on return (RAII),
    // so the ceiling bounds requests actually in flight, never queuing them without
    // bound. `None` ⇒ no ceiling (unbounded in-flight).
    let _timed_total = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Total);
    // Sampled from the serving path so the probe queues behind exactly what a request
    // queues behind; see `probe_scheduler`.
    crate::stage_timers::probe_scheduler(SCHEDULER_PROBE_EVERY_N_REQUESTS);
    let _admission = {
        let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Admission);
        match &in_flight {
            Some(semaphore) => match Arc::clone(semaphore).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => return Ok(overloaded_response()),
            },
            None => None,
        }
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
    // Tier-3 assertion extractor and the routing-header hygiene guard).
    let headers = RequestHeaders::from_pairs(
        req.headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or(""))),
    );

    // Capture the RFC 9421 request view BEFORE the body is consumed: the `@method`
    // and the full header block (carrying `Signature`/`Signature-Input`/`Content-Digest`)
    // the handler needs to verify the HTTP evidence carrier (ADR-MCPRE-050).
    let method = req.method().as_str().to_owned();
    // C008/C045/C046: the covered `@target-uri` is the operator's configured value, not
    // the received line. That substitution IS the ruled reconstruction mechanism — a
    // proxy behind TLS termination cannot see the external target URI, so the operator
    // asserts it (`http-profile-open-questions.md`: "exact reconstruction of the
    // external @target-uri is mandatory; if it cannot be reconstructed, strict
    // verification fails"). What was missing is EXACT. Nothing checked the assertion
    // against reality, so a deployment fanning several ingress paths into one process
    // silently verified signatures over a target the request did not arrive at, and
    // the verifier's `expected_audience.target_uri != request.target_uri` check
    // compared the configured value with itself.
    //
    // Compare the received origin-form against the configured target's, and fail
    // closed on a mismatch. This does not bind the received line INTO the signature
    // (both ends must still agree on one canonical absolute URI); it refuses to serve
    // where the operator's assertion is provably not a reconstruction of this request.
    if let Some(mismatch) = target_uri_mismatch(&options.target_uri, req.uri()) {
        let _ = mismatch;
        return Ok(malformed_header_response());
    }
    let header_pairs: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect();

    // Read the body, capped at `max_body_bytes`, charged against the core's byte budget
    // as it arrives, and bounded by the aggregate read deadline (slow-loris on a
    // trickled body). Any of the three tripping fails closed: the inner server is never
    // reached.
    let max_body = options.limits.max_body_bytes;
    let collect = collect_body(req.into_body(), max_body, &body_budget);
    let (body_bytes, _body_charge) = match options.limits.request_deadline {
        Some(deadline) => match tokio::time::timeout(deadline, collect).await {
            Ok(Ok(collected)) => collected,
            Ok(Err(BodyReadError::BudgetExhausted)) => return Ok(overloaded_response()),
            _ => return Ok(fail_closed_response()),
        },
        None => match collect.await {
            Ok(collected) => collected,
            Err(BodyReadError::BudgetExhausted) => return Ok(overloaded_response()),
            Err(_) => return Ok(fail_closed_response()),
        },
    };

    let chain: Vec<&[u8]> = accepted_chain_der(peer_credential.as_ref().as_ref());
    let leaf = chain.first().copied();
    let identity = resolve_identity_from_leaf(leaf, &options);
    let assertion = assertion_header(&options, &headers);

    // SAME order as the blocking loop: per-connection cert-lifetime rejection, then
    // routing-header hygiene, then (only if admitted) the handler. The inner server
    // is never reached on a rejection. The two rejection checks are sync CPU
    // (leaf-cert lifetime + header hygiene); only the admitted handler is AWAITED,
    // and it is the handler that awaits the async replay tier.
    //
    // The clock is read PER REQUEST, not per connection: the leaf is captured once at
    // handshake, so this is the only point at which a certificate that has since
    // passed `notAfter` can be caught on a connection the peer keeps open.
    let served = match connection_rejection_for_chain(
        &chain,
        &options,
        &body_bytes,
        crate::tls::wall_clock_unix(),
    )
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
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Handler);
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

#[cfg(test)]
mod target_uri_tests {
    use super::*;

    fn uri(value: &str) -> hyper::Uri {
        value.parse().expect("test uri")
    }

    #[test]
    fn a_matching_origin_form_is_consistent() {
        assert_eq!(
            target_uri_mismatch("https://mcp.example.com/mcp?route=a", &uri("/mcp?route=a")),
            None
        );
    }

    /// The finding: an ingress fanning several paths into one process meant the
    /// operator's asserted target was not a reconstruction of the request that
    /// arrived, and nothing noticed.
    #[test]
    fn a_different_received_path_is_refused() {
        assert_eq!(
            target_uri_mismatch(
                "https://mcp.example.com/mcp?route=a",
                &uri("/other?route=a")
            ),
            Some("/other?route=a".to_owned())
        );
    }

    /// The query is part of the request-target and part of the route coordinate, so a
    /// differing query is a differing target — not a detail to normalise away.
    #[test]
    fn a_different_query_is_refused() {
        assert_eq!(
            target_uri_mismatch("https://mcp.example.com/mcp?route=a", &uri("/mcp?route=b")),
            Some("/mcp?route=b".to_owned())
        );
    }

    /// Scheme and authority are exactly what a TLS-terminating proxy cannot observe —
    /// they are why the operator asserts the URI at all — so they are not compared.
    #[test]
    fn the_configured_authority_is_not_compared() {
        assert_eq!(
            target_uri_mismatch("https://external.example.com/mcp", &uri("/mcp")),
            None
        );
    }

    #[test]
    fn a_root_target_matches_a_root_request() {
        assert_eq!(
            target_uri_mismatch("https://mcp.example.com", &uri("/")),
            None
        );
        assert_eq!(
            target_uri_mismatch("https://mcp.example.com/", &uri("/")),
            None
        );
    }

    /// An unset target is not checked here: `--target-uri` is required and non-empty at
    /// parse, and a blank covered value already fails verification closed.
    #[test]
    fn an_empty_configured_target_is_not_checked_here() {
        assert_eq!(target_uri_mismatch("", &uri("/anything")), None);
    }
}

#[cfg(test)]
mod admission_bound_tests {
    use super::*;

    /// R7-C060/C061: the in-flight ceiling bounds request COUNT, not bytes.
    ///
    /// Each admitted slot may buffer a whole `max_body_bytes` body and the permit is
    /// taken before the body is read, so the per-core product was
    /// `max_in_flight_requests x max_body_bytes` (256 x 16 MiB = 4 GiB) and the fleet
    /// product multiplied that by the core count. A peer holding a valid client
    /// certificate and no valid signing key — one that cannot get a single request past
    /// the verifier — could drive all of it. The budget is what turns that into a bound.
    #[test]
    fn the_core_budget_admits_a_maximum_size_body_and_refuses_past_the_ceiling() {
        let max_body = 16 * 1024 * 1024usize;
        let budget = Arc::new(BodyByteBudget::new(
            max_body * BUFFERED_BODY_BUDGET_MULTIPLE,
        ));

        // A single maximum-size request is always admissible: the budget is a multiple
        // of the per-request cap precisely so raising the cap cannot make one legal
        // request unservable.
        let held: Vec<BodyBytes> = (0..BUFFERED_BODY_BUDGET_MULTIPLE)
            .map(|i| {
                budget
                    .charge(max_body)
                    .unwrap_or_else(|| panic!("body {i} within the budget"))
            })
            .collect();

        assert!(
            budget.charge(1).is_none(),
            "the core is at its ceiling: one more byte of attacker-supplied body must \
             be refused, not buffered"
        );

        drop(held);
        assert!(
            budget.charge(max_body).is_some(),
            "the charge is released when the bytes are, so the ceiling is a bound on \
             what is RESIDENT rather than a lifetime quota"
        );
    }

    /// The charge is returned on every path, including a body read abandoned part-way.
    #[test]
    fn an_abandoned_body_read_returns_its_charge() {
        let budget = Arc::new(BodyByteBudget::new(100));
        {
            let mut charge = budget.charge(10).expect("first frame");
            charge.absorb(budget.charge(20).expect("second frame"));
            assert!(budget.charge(71).is_none(), "30 bytes are held");
        }
        assert!(
            budget.charge(100).is_some(),
            "dropping the guard mid-read returns everything it had charged"
        );
    }

    /// Folding frames into one guard must not double-release: the absorbed guard's
    /// bytes belong to the survivor.
    #[test]
    fn absorbing_a_frame_does_not_release_its_bytes_twice() {
        let budget = Arc::new(BodyByteBudget::new(10));
        let mut charge = budget.charge(4).expect("first");
        charge.absorb(budget.charge(6).expect("second"));
        assert!(
            budget.charge(1).is_none(),
            "all ten bytes are held by one guard"
        );
        drop(charge);
        assert!(budget.charge(10).is_some(), "and exactly ten come back");
    }

    /// R7-C022: the handshake bound must stay strictly below the per-core worker pool.
    ///
    /// `async_fleet` gives a delegated-TLS core a small multi-worker runtime
    /// (`DELEGATED_TLS_WORKERS_PER_CORE`, 4) because `acceptor.accept` occupies its
    /// worker for a whole device/KMS signature. A pool is not a bound: a peer with no
    /// credentials needs only as many concurrent connections as there are workers to
    /// occupy every one, since TLS 1.3 signs `CertificateVerify` before the client's
    /// `Certificate` is seen. Raising this to the pool size re-opens exactly that.
    ///
    /// The comparison is against the OTHER CONSTANT, not a copy of its value. This
    /// assertion read `< 4`, which pins the wrong relation: lowering
    /// `DELEGATED_TLS_WORKERS_PER_CORE` to 2 leaves `2 < 4` true and this test green while
    /// the property it exists to protect — a worker left over for the rest of the core —
    /// is violated. A guard on a literal only looks load-bearing.
    #[test]
    fn the_handshake_bound_leaves_workers_for_the_rest_of_the_core() {
        const {
            // A bound of zero would refuse every handshake.
            assert!(DELEGATED_TLS_HANDSHAKES_PER_CORE >= 1);
            // The PROPERTY: a core under a full handshake flood still has a worker for its
            // accept loop, its established connections and its in-flight requests. Stated
            // as the subtraction rather than as an inequality against the pool size,
            // because the leftover worker is the thing that matters — the ordering is just
            // today's way of obtaining it.
            assert!(
                crate::async_fleet::DELEGATED_TLS_WORKERS_PER_CORE
                    .saturating_sub(DELEGATED_TLS_HANDSHAKES_PER_CORE)
                    >= 1
            );
        }
    }
}
