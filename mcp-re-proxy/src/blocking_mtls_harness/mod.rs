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
//! tests and the demo/PKCS#11 end-to-end tests run against a real mTLS termination through
//! [`serve_once`], which the crate façade exports. ADR-MCPRE-061 §2 class 4 — zero
//! PRODUCTION callers is a naming problem, not a deletion argument.
//!
//! # What this module does NOT own
//!
//! It owns no TLS authentication policy. It holds the live [`ServerConnection`], so it is
//! the only place that can turn one into a peer chain — but every decision made from that
//! chain belongs to [`crate::tls`] and is called, not reimplemented:
//! [`resolve_authenticated_identity`](crate::tls::resolve_authenticated_identity) for the
//! identity the relationship authenticated as, [`cert_lifetime_rejection_for_chain`](crate::tls::cert_lifetime_rejection_for_chain)
//! and (under `online_ocsp`) `ocsp_rejection_for_chain` for the per-request rejection
//! guards, [`routing_header_rejection`](crate::tls::routing_header_rejection) and
//! [`assertion_header`](crate::tls::assertion_header) for the header guards. The adapters
//! in `connection` turn a connection into those inputs; they do not decide anything.
//!
//! This module is the accept policy — one connection, one handler invocation
//! ([`serve_once`]). Everything after the socket is `connection::serve_one`.

mod connection;
mod deadline_stream;
mod http1;
mod http1_framing;

use std::io;
use std::net::TcpListener;
use std::sync::Arc;

use rustls::ServerConfig;

use crate::tls::ServerOptions;

use connection::serve_one;

use crate::communication_assurance::AuthenticatedChannelPeer;

/// Accept ONE TLS connection, complete the handshake (mTLS — a missing or untrusted client
/// certificate fails here), read one HTTP request body (bounded by `options.limits`),
/// invoke `handler(request_bytes, identity)`, and write the response. Returns the verified
/// client identity that was observed (for test assertions).
///
/// Blocking; the caller owns the accept-loop policy.
pub fn serve_once<H>(
    listener: &TcpListener,
    config: Arc<ServerConfig>,
    options: &ServerOptions,
    handler: H,
) -> io::Result<Option<AuthenticatedChannelPeer>>
where
    H: FnOnce(&[u8], Option<AuthenticatedChannelPeer>) -> Vec<u8>,
{
    let (tcp, _peer) = listener.accept()?;
    // MCPS-88: a caller may set the LISTENER non-blocking so it can poll for a shutdown
    // signal between connections. Accepted connection sockets inherit O_NONBLOCK on some
    // platforms (BSD/macOS) but not others (Linux), so force this one back to blocking —
    // the bounded read/write phase relies on blocking semantics (plus the socket timeouts
    // applied next). Harmless when the listener is already blocking.
    tcp.set_nonblocking(false)?;
    serve_one(tcp, config, options, |request, identity, _assertion| {
        handler(request, identity)
    })
}
