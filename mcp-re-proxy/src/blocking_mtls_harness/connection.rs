// SPDX-License-Identifier: Apache-2.0
//! One served connection, and the adapters that feed it — PRIVATE to the harness subtree.
//!
//! Exactly one sequence: handshake, read one request, resolve the identity, apply the
//! authority's guards, write one reply, close. Both entry points in the parent run THIS
//! function, so a guard cannot be present on one blocking path and missing on the other —
//! it used to be written twice, once per entry point.
//!
//! The adapters here turn the relationship's channel-associated credential evidence into
//! the arguments [`crate::tls`] decides from. They own no policy: each one projects the
//! credential and calls the authority. Asking the mechanism WHICH credential it associated
//! is not theirs either — that authority lives in
//! [`crate::communication_assurance::channel_associated_credential::rustls_adapter`], and
//! this module reaches it once, at the point the request read has driven the handshake to
//! completion.

use std::io;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::StreamOwned;

#[cfg(feature = "online_ocsp")]
use crate::communication_assurance::mechanism_verified_credential::accepted_chain_der;
use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;
use crate::communication_assurance::MechanismVerifiedCredentialEvidence;
use crate::tls::assertion_header;
use crate::tls::credential_currency_rejection;
use crate::tls::resolve_authenticated_identity;
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
    // THE ESTABLISHMENT BOUNDARY (ADR-MCPRE-063 Slice 4). The read above is what drove
    // the rustls handshake to completion — a `ServerConnection` exists before that and
    // proves nothing — so this is the first point at which the mechanism can be asked
    // which credential it associated with the relationship. A refusal becomes an absent
    // credential and the fail-closed core downstream decides it, exactly as an absent
    // chain did before.
    let credential = verified_credential(&stream.conn).ok();
    let headers = RequestHeaders::parse(&request.header_block);
    // ADR-MCPRE-064 (#619): the SAME function the async fleet calls, taking the SAME
    // acceptance product. Parity is now one call site rather than two derivations that
    // agree — there is no per-path leaf projection left to drift.
    let identity = resolve_authenticated_identity(credential.as_ref(), options);
    let assertion = assertion_header(options, &headers);
    let response = match connection_rejection(credential.as_ref(), options, &request.body)
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

/// The per-request rejection decision for an established relationship: the certificate
/// lifetime/revocation guard, then (under the `online_ocsp` feature) the online OCSP
/// guard. The order and every verdict are [`crate::tls`]'s; this supplies the chain.
/// Returns the first rejection's error bytes, or `None` if the request is admitted.
fn connection_rejection(
    credential: Option<&MechanismVerifiedCredentialEvidence>,
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    if let Some(error) =
        credential_currency_rejection(credential, options, request, wall_clock_unix())
    {
        return Some(error);
    }
    // The one remaining raw-chain consumer, named rather than hidden: online OCSP has not
    // been migrated and its redesign is a separate slice. The async path does not wire it.
    #[cfg(feature = "online_ocsp")]
    if let Some(error) =
        crate::tls::ocsp_rejection_for_chain(&accepted_chain_der(credential), options, request)
    {
        return Some(error);
    }
    None
}
