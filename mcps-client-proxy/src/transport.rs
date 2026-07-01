//! Remote-leg transport abstraction + proxy error type (MCPS-49, #196).
//!
//! The proxy forwards the SIGNED request to the remote MCP-S server/proxy over
//! some transport (stdio, HTTP, in-process). The library abstracts that behind
//! [`RemoteTransport`] so the security pipeline is testable without real I/O; the
//! mode-specific binary supplies a concrete transport.

use mcps_client_core::CorrelationError;
use mcps_core::McpsError;

/// The remote leg: send signed request bytes, get the (possibly signed) response
/// bytes back. A transport-level failure (connection refused, timeout) is reported
/// as `Err` and treated by the proxy as ABSENCE of evidence (pre-evidence transport
/// failure), never as bad evidence.
pub trait RemoteTransport {
    /// Round-trip the signed request to the remote endpoint.
    fn round_trip(&self, request_bytes: &[u8]) -> Result<Vec<u8>, TransportError>;
}

/// A transport-level failure on the remote leg (NOT an MCP-S verdict).
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
    /// The remote leg failed at the transport level before any evidence.
    Transport(TransportError),
    /// A fail-closed MCP-S security/protocol verdict; carries the frozen wire error.
    FailedClosed(McpsError),
}

impl ProxyError {
    /// The frozen `mcps.*` wire reason for a fail-closed verdict, if this error is a
    /// security/protocol verdict (`None` for local config / transport failures,
    /// which are not wire reasons).
    pub fn wire_code(&self) -> Option<&'static str> {
        match self {
            ProxyError::FailedClosed(error) => Some(error.wire_code()),
            _ => None,
        }
    }
}

impl From<McpsError> for ProxyError {
    fn from(error: McpsError) -> Self {
        ProxyError::FailedClosed(error)
    }
}

impl From<CorrelationError> for ProxyError {
    fn from(error: CorrelationError) -> Self {
        ProxyError::FailedClosed(error.to_mcps_error())
    }
}
