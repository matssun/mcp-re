// SPDX-License-Identifier: Apache-2.0
//! The blocking mTLS + hand-rolled HTTP/1.1 harness — a CONSUMER of the TLS authority.
//!
//! It accepts a TCP connection, drives a `rustls` server handshake to completion, reads
//! one HTTP/1.1 request, calls a handler, and writes one fixed `200 OK` reply. That is the
//! whole capability, and naming it accurately is why it lives here rather than in
//! [`crate::tls`].
//!
//! # NOT an MCP-RE serving path
//!
//! Every reply is framed as a literal `HTTP/1.1 200 OK` with a fixed header set: the
//! handler signature carries no status and no headers, so there is nowhere for them to come
//! from. Under ADR-MCPRE-050 the RFC 9421 `Signature`/`Signature-Input`, the RFC 9530
//! `Content-Digest` and the STATUS LINE are the evidence carrier — so a response written
//! here can never be verified, and a signed 403 rejection receipt would be flattened to a
//! 200. The shipped proxy serves on the async fleet (ADR-MCPRE-051), where
//! `HttpProfileProxy` owns the status and the headers.
//!
//! It is retained, not deleted, because it has consumers: the transport crate's client
//! tests and the demo/PKCS#11 end-to-end tests run against a real mTLS termination, and
//! external embedders reach [`serve`], [`serve_once`] and [`serve_once_with_assertion`]
//! through the crate façade. ADR-MCPRE-061 §2 class 4 — zero PRODUCTION callers is a
//! naming problem, not a deletion argument.
//!
//! # What this module does NOT own
//!
//! It owns no TLS authentication policy. It holds the live [`ServerConnection`], so it is
//! the only place that can turn one into a peer chain — but every decision made from that
//! chain belongs to [`crate::tls`] and is called, not reimplemented:
//! [`resolve_identity_from_leaf`](crate::tls::resolve_identity_from_leaf) for the verified
//! identity, [`cert_lifetime_rejection_for_chain`](crate::tls::cert_lifetime_rejection_for_chain)
//! and (under `online_ocsp`) `ocsp_rejection_for_chain` for the per-request rejection
//! guards, [`routing_header_rejection`](crate::tls::routing_header_rejection) and
//! [`assertion_header`](crate::tls::assertion_header) for the header guards. The adapters
//! in `connection` turn a connection into those inputs; they do not decide anything.
//!
//! This module is the accept policy — one connection ([`serve_once`],
//! [`serve_once_with_assertion`]) or a thread-per-connection loop under a concurrency cap
//! ([`serve`]). Everything after the socket is `connection::serve_one`, once, for all three.

mod connection;
mod deadline_stream;
mod http1;

use std::io;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use rustls::ServerConfig;

use crate::tls::ServerOptions;
use crate::transport::TransportIdentity;

use connection::serve_one;

/// Accept ONE TLS connection, complete the handshake (mTLS — a missing or untrusted client
/// certificate fails here), read one HTTP request body (bounded by `options.limits`),
/// invoke `handler(request_bytes, identity)`, and write the response. Returns the verified
/// client identity that was observed (for test assertions).
///
/// Blocking; the caller owns the accept-loop policy (see [`serve`]).
pub fn serve_once<H>(
    listener: &TcpListener,
    config: Arc<ServerConfig>,
    options: &ServerOptions,
    handler: H,
) -> io::Result<Option<TransportIdentity>>
where
    H: FnOnce(&[u8], Option<TransportIdentity>) -> Vec<u8>,
{
    // Adapt the 2-arg handler to the assertion-aware form (the assertion header is
    // ignored — this entry point predates Tier-3 and stays byte-for-byte for its
    // many callers). The Tier-3 serve path uses [`serve_once_with_assertion`].
    serve_once_with_assertion(
        listener,
        config,
        options,
        |request, identity, _assertion| handler(request, identity),
    )
}

/// As [`serve_once`], but the handler ALSO receives the raw Tier-3 ingress-assertion
/// header value (issue #71) when the `LbAssertion` identity strategy is active. Under any
/// other strategy the third argument is always `None`. This is the entry point an embedder
/// uses so the assertion can reach the proxy's post-verification LB check
/// (`Proxy::with_lb_assertion`); a duplicated assertion header yields `None` (fail closed
/// at the proxy's required-header guard).
pub fn serve_once_with_assertion<H>(
    listener: &TcpListener,
    config: Arc<ServerConfig>,
    options: &ServerOptions,
    handler: H,
) -> io::Result<Option<TransportIdentity>>
where
    H: FnOnce(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8>,
{
    let (tcp, _peer) = listener.accept()?;
    // MCPS-88: a caller may set the LISTENER non-blocking so it can poll for a shutdown
    // signal between connections. Accepted connection sockets inherit O_NONBLOCK on some
    // platforms (BSD/macOS) but not others (Linux), so force this one back to blocking —
    // the bounded read/write phase relies on blocking semantics (plus the socket timeouts
    // applied next). Harmless when the listener is already blocking.
    tcp.set_nonblocking(false)?;
    serve_one(tcp, config, options, handler)
}

/// Accept loop: handle each connection on its own thread (blocking, no async). Each
/// connection runs `handler` once. The number of simultaneously-served connections is
/// capped at `options.limits.max_concurrent_connections`; connections beyond the cap are
/// accepted and immediately dropped (fail closed against connection exhaustion) rather
/// than queued without bound. Runs until `listener` errors.
pub fn serve<H>(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    options: ServerOptions,
    handler: H,
) where
    H: Fn(&[u8], Option<TransportIdentity>) -> Vec<u8> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let options = Arc::new(options);
    let in_flight = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(tcp) = incoming else { continue };
        let max = options.limits.max_concurrent_connections;
        // Reserve a slot; if the server is saturated, drop the connection.
        if in_flight.fetch_add(1, Ordering::AcqRel) >= max {
            in_flight.fetch_sub(1, Ordering::AcqRel);
            drop(tcp); // close immediately — do not serve beyond the cap
            continue;
        }
        let config = Arc::clone(&config);
        let handler = Arc::clone(&handler);
        let options = Arc::clone(&options);
        let in_flight = Arc::clone(&in_flight);
        std::thread::spawn(move || {
            serve_worker(tcp, config, &options, handler.as_ref());
            in_flight.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

/// One worker thread's whole job: serve the connection with the 2-arg handler adapted to
/// the assertion-aware form, and swallow the per-connection error — the accept loop must
/// outlive any one peer.
fn serve_worker<H>(tcp: TcpStream, config: Arc<ServerConfig>, options: &ServerOptions, handler: &H)
where
    H: Fn(&[u8], Option<TransportIdentity>) -> Vec<u8>,
{
    let _ = serve_one(tcp, config, options, |request, identity, _assertion| {
        handler(request, identity)
    });
}
