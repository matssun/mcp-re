// SPDX-License-Identifier: Apache-2.0
//! The reusable mTLS client: what it composes, and in what order.
//!
//! One connection per round trip, matching the proxy's single-request-per-connection
//! framing. The ORDER is the security content:
//!
//! 1. the request bytes are built and validated BEFORE a socket is opened — a caller header
//!    that cannot be emitted safely is a local programming error, not something to discover
//!    with a connection already established;
//! 2. the handshake is driven explicitly, so server-authentication failure is
//!    distinguishable from a later IO error and the body is never sent to an unauthenticated
//!    peer;
//! 3. only then are the request head and body written;
//! 4. the response is read under its own aggregate deadline and size cap, and parsed.
//!
//! The handshake gets its own deadline and its own error classification because a stalled
//! handshake and a rejected server certificate arrive as the same `io::Error` and mean
//! entirely different things to an operator.

use std::net::SocketAddr;

use rustls_pki_types::ServerName;

use super::limits::ClientLimits;
use super::request::build_request_head;
use super::response::HttpResponseParts;
use super::tls_config::ClientTlsConfig;
use super::TransportError;

/// A reusable verifying mTLS client bound to an expected server name. Each
/// [`round_trip`](Self::round_trip) opens a fresh connection (single-request-
/// per-connection, matching the proxy), completing the handshake — which
/// authenticates the server against the configured CA and the expected name —
/// before sending the request body.
#[derive(Debug, Clone)]
pub struct MtlsClient {
    pub(super) config: ClientTlsConfig,
    pub(super) server_name: ServerName<'static>,
    pub(super) limits: ClientLimits,
}

impl MtlsClient {
    /// Build a client that will verify the proxy presents a certificate valid
    /// for `expected_server_name` (matched against the certificate's SAN/name by
    /// rustls during the handshake). A wrong-identity server cert is rejected.
    ///
    /// Uses the default [`ClientLimits`] (30s connect/read/write timeouts, 16 MiB
    /// response ceiling). Use [`with_limits`](Self::with_limits) to override.
    pub fn new(
        config: ClientTlsConfig,
        expected_server_name: &str,
    ) -> Result<Self, TransportError> {
        Self::with_limits(config, expected_server_name, ClientLimits::default())
    }

    /// Like [`new`](Self::new) but with explicit connection resource limits
    /// (timeouts + response-size cap).
    pub fn with_limits(
        config: ClientTlsConfig,
        expected_server_name: &str,
        limits: ClientLimits,
    ) -> Result<Self, TransportError> {
        let server_name = ServerName::try_from(expected_server_name.to_string())
            .map_err(|e| TransportError::BadServerName(e.to_string()))?;
        Ok(MtlsClient {
            config,
            server_name,
            limits,
        })
    }

    /// Open one mTLS connection to `addr`, POST `request_body` to `/`, and return
    /// the response BODY bytes.
    ///
    /// A convenience wrapper over [`round_trip_http`](Self::round_trip_http) for
    /// callers that carry no evidence and ignore the status. A client on the
    /// RFC 9421 carrier MUST use `round_trip_http` instead: this signature can
    /// neither send the request `Signature`/`Signature-Input`/`Content-Digest`
    /// nor return the response's, and it discards the status that separates a
    /// success from a signed rejection receipt.
    pub fn round_trip(
        &self,
        addr: SocketAddr,
        request_body: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        self.round_trip_http(addr, "POST", "/", &[], request_body)
            .map(|response| response.body)
    }

    /// Open one mTLS connection to `addr`, send a single HTTP/1.1 request built
    /// from `method`, `path`, `headers` and `body`, and return the whole
    /// [`HttpResponseParts`].
    ///
    /// This is the ADR-MCPRE-050 carrier: `headers` go on the wire verbatim (that
    /// is how `Signature`, `Signature-Input` and `Content-Digest` reach the
    /// server) and the response's status and headers come back intact (that is how
    /// the client verifies the bound response and tells a success from a signed
    /// rejection).
    ///
    /// The handshake authenticates the server BEFORE anything is sent: an
    /// untrusted, wrong-identity, or expired server certificate causes the
    /// handshake to fail and returns `Err(TransportError::Handshake(..))` — the
    /// request never reaches the wire.
    ///
    /// Fails closed on a caller-supplied method/path/header that cannot be emitted
    /// unambiguously ([`TransportError::InvalidRequest`]) and on a peer response
    /// whose framing cannot be read unambiguously
    /// ([`TransportError::MalformedResponse`]).
    pub fn round_trip_http(
        &self,
        addr: SocketAddr,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponseParts, TransportError> {
        // Build (and validate) the request bytes BEFORE opening the connection: a
        // caller header that cannot be emitted safely is a local programming error,
        // not something to discover with a socket already open.
        let request_head = build_request_head(
            method,
            path,
            &server_name_host(&self.server_name),
            headers,
            body.len(),
        )?;
        self.exchange(addr, request_head.as_bytes(), body)
    }
}

/// The host header value for the expected server name.
fn server_name_host(name: &ServerName<'_>) -> String {
    match name {
        ServerName::DnsName(dns) => dns.as_ref().to_string(),
        ServerName::IpAddress(ip) => {
            let addr: std::net::IpAddr = (*ip).into();
            addr.to_string()
        }
        _ => "localhost".to_string(),
    }
}
