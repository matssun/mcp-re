//! The concrete remote-leg transport for the client-proxy binary (ADR-MCPS-045
//! Phase 3): a verifying mTLS client to the remote MCP-RE server/proxy.
//!
//! The pure `mcp-re-client-proxy` library abstracts the remote leg behind
//! [`RemoteTransport`] so its security pipeline is testable without real I/O.
//! This adapter binds that trait to [`mcp_re_transport::MtlsClient`] — a single
//! verifying mTLS round-trip per request (the handshake authenticates the remote
//! against the configured server CA + expected name BEFORE the signed body is
//! sent). A connection/handshake failure surfaces as a [`TransportError`], which
//! the proxy treats as ABSENCE of evidence (pre-evidence transport failure),
//! never as bad evidence.

use std::net::SocketAddr;

use mcp_re_client_proxy::RemoteTransport;
use mcp_re_client_proxy::TransportError;
use mcp_re_transport::MtlsClient;

/// A [`RemoteTransport`] that round-trips signed request bytes to `addr` over a
/// verifying mTLS connection.
pub struct MtlsRemoteTransport {
    client: MtlsClient,
    addr: SocketAddr,
}

impl MtlsRemoteTransport {
    /// Wrap a configured [`MtlsClient`] + the remote socket address it dials.
    pub fn new(client: MtlsClient, addr: SocketAddr) -> Self {
        MtlsRemoteTransport { client, addr }
    }
}

impl RemoteTransport for MtlsRemoteTransport {
    fn round_trip(&self, request_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.client
            .round_trip(self.addr, request_bytes)
            .map_err(|e| TransportError::new(format!("mtls round-trip to {}: {e}", self.addr)))
    }
}
