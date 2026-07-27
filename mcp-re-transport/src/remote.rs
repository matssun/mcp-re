// SPDX-License-Identifier: Apache-2.0
//! The production `RemoteTransport`: `mcp-re-client-proxy`'s remote-leg seam
//! carried over this crate's verifying mTLS client.
//!
//! `mcp-re-client-proxy` defines the seam (`HttpRequest` in, `HttpResponse` out)
//! and stays pure — it links no TLS stack — so the implementation lives here, in
//! the crate that owns the TLS. Wiring a [`MtlsRemoteTransport`] into a
//! `ClientProxy` gives the client leg of Mode A end-to-end mTLS as a shipped
//! component: the proxy's server certificate and identity are verified against a
//! configured CA before any signed request reaches the wire, a client certificate
//! is presented for the server's own binding check, and the RFC 9421 / RFC 9530
//! evidence survives intact in both directions so the response can be verified
//! bound to the request that produced it.

use std::net::SocketAddr;

use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_proxy::transport::RemoteTransport;
use mcp_re_client_proxy::transport::TransportError as RemoteTransportError;

use crate::MtlsClient;
use crate::TransportError;

/// A [`RemoteTransport`] that sends each signed request over one verifying mTLS
/// connection to a fixed remote address.
///
/// One connection per exchange (single-request-per-connection, matching the
/// proxy's framing). The client is reusable and cheap to clone; the expected
/// server name it verifies against is fixed when the [`MtlsClient`] is built.
#[derive(Debug, Clone)]
pub struct MtlsRemoteTransport {
    client: MtlsClient,
    addr: SocketAddr,
}

impl MtlsRemoteTransport {
    /// Bind a verifying mTLS client to the remote endpoint it dials.
    ///
    /// `addr` is where the connection goes; the identity that must be PROVEN is
    /// the expected server name already configured on `client`, not this address.
    pub fn new(client: MtlsClient, addr: SocketAddr) -> Self {
        MtlsRemoteTransport { client, addr }
    }

    /// The remote address this transport dials.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl RemoteTransport for MtlsRemoteTransport {
    fn round_trip(&self, request: &HttpRequest) -> Result<HttpResponse, RemoteTransportError> {
        let path = origin_form(&request.target_uri).map_err(to_remote_error)?;
        let response = self
            .client
            .round_trip_http(
                self.addr,
                &request.method,
                &path,
                &request.headers,
                &request.body,
            )
            .map_err(to_remote_error)?;
        Ok(HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

/// A transport-level failure, carried to the proxy as a transport failure — never
/// as an MCP-RE verdict. A handshake rejection (an unauthenticated or
/// wrong-identity server) is a failed channel, not a failed signature, and the
/// proxy must not classify it as bad evidence.
fn to_remote_error(error: TransportError) -> RemoteTransportError {
    RemoteTransportError::new(error.to_string())
}

/// The origin-form request target (path + query) for an absolute `@target-uri`.
///
/// The signature covers the ABSOLUTE `@target-uri`; the request line carries the
/// origin form of it. Both sides derive the covered value from their own
/// configuration, so this conversion never feeds the signature base — it only has
/// to route the request at the peer.
fn origin_form(target_uri: &str) -> Result<String, TransportError> {
    let authority_start = target_uri.find("://").map(|i| i + 3).ok_or_else(|| {
        TransportError::InvalidRequest(format!("target-uri is not absolute: {target_uri:?}"))
    })?;
    let authority = &target_uri[authority_start..];
    match authority.find('/') {
        Some(offset) => Ok(authority[offset..].to_string()),
        // An absolute URI with no path component addresses the root.
        None => Ok("/".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_form_keeps_the_path_and_query() {
        assert_eq!(
            origin_form("https://mcp.example.com/mcp?route=a").expect("origin form"),
            "/mcp?route=a"
        );
    }

    #[test]
    fn origin_form_of_a_bare_authority_is_root() {
        assert_eq!(
            origin_form("https://mcp.example.com").expect("origin form"),
            "/"
        );
    }

    #[test]
    fn a_relative_target_uri_fails_closed() {
        assert!(matches!(
            origin_form("/mcp?route=a"),
            Err(TransportError::InvalidRequest(_))
        ));
    }
}
