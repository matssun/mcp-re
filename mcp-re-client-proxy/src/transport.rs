// SPDX-License-Identifier: Apache-2.0
//! Remote-leg transport abstraction + proxy error type (MCPS-49, #196), on the
//! RFC 9421 carrier (ADR-MCPRE-050).
//!
//! The proxy forwards the SIGNED RFC 9421 request (method + `@target-uri` + headers
//! + body) to the remote MCP-RE server over some transport (HTTP, in-process) and
//! gets the signed [`HttpResponse`] back. The transport is abstracted so the
//! security pipeline is testable without real I/O.

use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::HttpRequest;
use mcp_re_client_core::HttpResponse;

/// The remote leg: send the signed RFC 9421 request, get the (signed) response
/// back. A transport-level failure (connection refused, timeout) is `Err` and is
/// treated by the proxy as a transport failure, never as bad evidence.
pub trait RemoteTransport {
    /// Round-trip the signed request to the remote endpoint.
    fn round_trip(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError>;
}

/// A transport-level failure on the remote leg (NOT an MCP-RE verdict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    /// A human-readable description (diagnostics only).
    pub detail: String,
}

impl TransportError {
    /// Build a transport error with a diagnostic message.
    pub fn new(detail: impl Into<String>) -> Self {
        TransportError {
            detail: detail.into(),
        }
    }
}

/// A proxy-handling failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// No route is configured for the requested route id (local config error).
    UnknownRoute(String),
    /// The local plain-MCP request was malformed (missing method/id).
    MalformedRequest,
    /// The remote leg failed at the transport level.
    Transport(TransportError),
    /// A fail-closed RFC 9421 security/protocol verdict; carries the frozen wire code.
    FailedClosed(HttpProfileError),
}

impl ProxyError {
    /// The frozen `mcp-re.*` wire reason for a fail-closed verdict, if any.
    pub fn wire_code(&self) -> Option<&'static str> {
        match self {
            ProxyError::FailedClosed(error) => Some(error.wire_code()),
            _ => None,
        }
    }
}

impl From<HttpProfileError> for ProxyError {
    fn from(error: HttpProfileError) -> Self {
        ProxyError::FailedClosed(error)
    }
}
