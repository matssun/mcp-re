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
//!     ([`resolve_authenticated_identity`], [`credential_currency_rejection`],
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
//! full peer chain and is a tracked follow-up (see [`credential_currency_rejection`]);
//! the default + shared-replay-tier builds have full parity. Precise `write_timeout`
//! mapping onto `hyper` is likewise deferred (the load-bearing slow-loris defense is
//! the READ side, which is mapped).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::communication_assurance::AuthenticatedChannelPeer;

use crate::tls::ServerOptions;

/// The BYTE half of per-core admission: how much attacker-supplied body this core may hold
/// between its in-flight requests, which the request COUNT alone never bounded.
mod body_budget;

/// What one core admits work against: the four bounds and the live in-flight count.
mod core_admission;

/// One accepted connection: handshake admission and the establishment boundary.
mod connection;

/// The operator's limits, as bounds on the wire.
mod http_limits;

/// One HTTP request over an established connection.
mod request;

/// Reading the inbound message: what it says about itself, then what it carries.
mod inbound;

use body_budget::BUFFERED_BODY_BUDGET_MULTIPLE;
use connection::serve_connection;
use core_admission::CoreAdmission;

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
    /// The peer that authenticated this relationship, with whatever currency assurance the
    /// deployment's controls established (ADR-MCPRE-064 Slices 2-4). `None` under
    /// LB-assertion, where no channel peer is derived at all.
    pub peer: Option<AuthenticatedChannelPeer>,
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
    let connections = Arc::new(tokio::sync::Semaphore::new(
        options.limits.max_concurrent_connections,
    ));
    // Every bound this core admits against, taken once. Per-core, so the request path
    // stays lock-free ACROSS cores (ADR-MCPRE-051 §1 share-nothing).
    let admission = CoreAdmission::for_core(&options);

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
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
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
        let admission = admission.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the connection task ends
            let _ = serve_connection(tcp, acceptor, options, handler, admission).await;
        });
    }

    // The accept loop has stopped, so no NEW request will be admitted. When `serve`
    // returns, the caller drops the runtime, aborting any (idle) connection tasks — none
    // of which hold an in-flight request once the count reaches zero.
    admission.drain(options.limits.drain_grace).await;
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
