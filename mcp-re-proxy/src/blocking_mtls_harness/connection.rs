// SPDX-License-Identifier: Apache-2.0
//! One served connection, and the adapters that feed it — PRIVATE to the harness subtree.
//!
//! Exactly one sequence: handshake, read one request, resolve the identity, apply the
//! authority's guards, write one reply, close. Both entry points in the parent run THIS
//! function, so a guard cannot be present on one blocking path and missing on the other —
//! it used to be written twice, once per entry point.
//!
//! The adapters here turn a live [`ServerConnection`] into the arguments
//! [`crate::tls`] decides from. They own no policy: each one reads the connection and calls
//! the authority.

use std::io;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::StreamOwned;

use crate::tls::assertion_header;
use crate::tls::cert_lifetime_rejection_for_chain;
use crate::tls::routing_header_rejection;
use crate::tls::wall_clock_unix;
use crate::tls::ServerLimits;
use crate::tls::ServerOptions;
use crate::transport::RequestHeaders;
use crate::transport::TransportIdentity;

use super::deadline_stream::DeadlineStream;
use super::http1::read_http_request;
use super::http1::write_http_response;

/// Serve one already-accepted socket to completion.
///
/// Reading the request drives the handshake; an unauthenticated or untrusted client
/// certificate surfaces here as an error (fail closed). The per-request rejection guards
/// run BEFORE the handler, so the inner backend is never reached for a rejected peer.
/// Returns the verified client identity that was observed.
pub(super) fn serve_one<H>(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
    options: &ServerOptions,
    handler: H,
) -> io::Result<Option<TransportIdentity>>
where
    H: FnOnce(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8>,
{
    apply_socket_timeouts(&tcp, &options.limits)?;
    let conn = ServerConnection::new(config).map_err(|e| io::Error::other(e.to_string()))?;
    // AGGREGATE wall-clock deadline over the WHOLE read phase (handshake + header/
    // body), the server-side mirror of mcp-re-transport's `DeadlineStream`
    // (MCPS-094/093): a peer trickling bytes just under `read_timeout` cannot hold
    // this serve thread without bound (slow-loris). Reads go through the wrapper;
    // writes delegate straight to the socket (bounded by `write_timeout`).
    let mut stream = StreamOwned::new(conn, DeadlineStream::new(tcp, &options.limits));

    let request = read_http_request(&mut stream, &options.limits)?;
    let headers = RequestHeaders::parse(&request.header_block);
    let identity = resolve_identity(&stream.conn, options);
    let assertion = assertion_header(options, &headers);
    let response = match connection_rejection(&stream.conn, options, &request.body)
        .or_else(|| routing_header_rejection(&headers, &request.body))
    {
        Some(error) => error,
        None => handler(&request.body, identity.clone(), assertion),
    };
    write_http_response(&mut stream, &response)?;
    // Clean TLS shutdown: send close_notify so the peer does not see an
    // unexpected EOF, then flush it out.
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(identity)
}

/// Apply the configured read/write timeouts to a freshly-accepted socket.
fn apply_socket_timeouts(tcp: &TcpStream, limits: &ServerLimits) -> io::Result<()> {
    tcp.set_read_timeout(limits.read_timeout)?;
    tcp.set_write_timeout(limits.write_timeout)?;
    Ok(())
}

/// The peer certificate chain of an established connection, leaf-first, borrowed from
/// rustls' own storage. An absent peer certificate is an EMPTY chain, passed through
/// rather than short-circuited here, so the no-leaf case is decided once by the
/// fail-closed core in [`crate::tls`] instead of a second time in this module.
fn peer_chain(conn: &ServerConnection) -> Vec<&[u8]> {
    conn.peer_certificates()
        .map(|chain| chain.iter().map(|cert| cert.as_ref()).collect())
        .unwrap_or_default()
}

/// The verified transport identity for one served request. The strategy dispatch, the
/// extraction and the fail-closed `None` are all
/// [`crate::tls::resolve_identity_from_leaf`]'s; this reads the leaf out of the
/// connection and hands it over — the same extractor, and so the same identity, the
/// async fleet resolves from the chain it captured at handshake.
fn resolve_identity(conn: &ServerConnection, options: &ServerOptions) -> Option<TransportIdentity> {
    let chain = peer_chain(conn);
    crate::tls::resolve_identity_from_leaf(chain.first().copied(), options)
}

/// The per-request rejection decision for an established connection: the certificate
/// lifetime/revocation guard, then (under the `online_ocsp` feature) the online OCSP
/// guard. The order and every verdict are [`crate::tls`]'s; this supplies the chain.
/// Returns the first rejection's error bytes, or `None` if the request is admitted.
fn connection_rejection(
    conn: &ServerConnection,
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    let chain = peer_chain(conn);
    if let Some(error) =
        cert_lifetime_rejection_for_chain(&chain, options, request, wall_clock_unix())
    {
        return Some(error);
    }
    #[cfg(feature = "online_ocsp")]
    if let Some(error) = crate::tls::ocsp_rejection_for_chain(&chain, options, request) {
        return Some(error);
    }
    None
}
