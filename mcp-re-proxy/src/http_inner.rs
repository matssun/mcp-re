//! ADR-MCPRE-051 §3 (Phase 3) — the production async inner plane: a per-core
//! pooled `hyper` client to stateless Streamable-HTTP inner MCP backends.
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
//! ## Fail-closed
//!
//! `dispatch` NEVER errors (the [`AsyncInnerServer`] contract): a connect/transport
//! failure, a per-request timeout, a non-2xx status, or an unreadable body all
//! yield the synthesized [`inner_unavailable_response`] — a JSON-RPC error the
//! proxy still SIGNS. A dead or hostile backend can never suppress the signature or
//! cause a silent allow.
//!
//! ## Scope (this increment)
//!
//! Pooled client + round-robin across the configured backends + a per-request
//! timeout + fail-closed. Active health checks, outlier ejection, and circuit
//! breaking are the next increment (a slow/dead backend is today bounded only by
//! the per-request timeout, not yet proactively ejected).


use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

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

use crate::async_inner::inner_unavailable_response;
use crate::async_inner::AsyncInnerServer;
use crate::async_inner::InnerResponseFuture;

/// A cap on the inner response body read into memory, so a hostile/broken backend
/// streaming an unbounded body cannot exhaust the proxy. A response exceeding it
/// fails closed (synthesized inner error). Generous relative to real MCP responses.
const MAX_INNER_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// A per-core pooled HTTP client to stateless Streamable-HTTP inner backends.
///
/// Cloning the underlying `hyper` client is cheap (it shares the connection pool),
/// so `dispatch` clones per call and awaits without holding a lock. Round-robin
/// across `backends` spreads load; each core owns its own `HttpInnerPool`
/// (share-nothing, ADR-MCPRE-051 §1).
pub struct HttpInnerPool {
    client: Client<HttpConnector, Full<Bytes>>,
    /// Absolute backend endpoint URIs (e.g. `http://10.0.0.5:8080/mcp`). At least
    /// one; construction fails closed on an empty list.
    backends: Vec<Uri>,
    /// Round-robin cursor over `backends`.
    next: AtomicUsize,
    /// Per-request deadline bounding the inner round-trip. On elapse the request
    /// fails closed (a slow backend cannot hold a per-core in-flight slot forever).
    request_timeout: Duration,
}

impl HttpInnerPool {
    /// Build a pool over `backends` (non-empty) with a per-request `request_timeout`.
    /// Returns an error string (fail closed at wiring time) if no backend is given.
    pub fn new(backends: Vec<Uri>, request_timeout: Duration) -> Result<Self, String> {
        if backends.is_empty() {
            return Err("HttpInnerPool requires at least one inner backend URL".to_string());
        }
        // Pooled, keep-alive client; HTTP/2 is negotiated per connection by the
        // backend. Defaults on idle-timeout / max-idle-per-host are sane for a
        // per-core pool to a small backend fleet.
        let client = Client::builder(TokioExecutor::new()).build_http();
        Ok(HttpInnerPool {
            client,
            backends,
            next: AtomicUsize::new(0),
            request_timeout,
        })
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

    /// Round-robin the next backend URI (lock-free).
    fn pick_backend(&self) -> Uri {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.backends.len();
        self.backends[i].clone()
    }
}

impl AsyncInnerServer for HttpInnerPool {
    fn dispatch<'a>(&'a self, request: &'a [u8]) -> InnerResponseFuture<'a> {
        // Own the request bytes + a cheap client clone into the 'static future.
        let body = Bytes::copy_from_slice(request);
        let uri = self.pick_backend();
        let client = self.client.clone();
        let timeout = self.request_timeout;
        Box::pin(async move {
            let req = match Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json")
                .body(Full::new(body))
            {
                Ok(req) => req,
                // A malformed backend URI is a wiring error; fail closed.
                Err(_) => return inner_unavailable_response(),
            };

            // Bound the whole round-trip. Timeout OR transport error ⇒ fail closed.
            let resp = match tokio::time::timeout(timeout, client.request(req)).await {
                Ok(Ok(resp)) => resp,
                _ => return inner_unavailable_response(),
            };

            // A non-2xx inner status is not a valid JSON-RPC response; fail closed
            // (the proxy signs the synthesized error) rather than sign backend HTML.
            if !resp.status().is_success() {
                return inner_unavailable_response();
            }

            // Read the body, capped. `Limited` fails the collect if the cap is
            // exceeded ⇒ fail closed.
            let limited = http_body_util::Limited::new(resp.into_body(), MAX_INNER_RESPONSE_BYTES);
            match limited.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(_) => inner_unavailable_response(),
            }
        })
    }
}
