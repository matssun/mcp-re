//! The server seam shared by the native and sidecar-wrapped targets (MCPS-017).
//!
//! Both the native [`EchoServer`] and the sidecar [`Proxy`] (wrapping an
//! unmodified inner server) expose the same `handle(request, now) -> response`
//! shape. [`McpReServer`] unifies them so the stdio/HTTP harnesses can drive
//! EITHER and prove identical Core outcomes — the native-vs-sidecar parity
//! acceptance milestone (ADR-MCPS-011).

use mcp_re_proxy::Proxy;

use crate::echo_server::EchoServer;
use crate::fixtures::documented_echo_server;
use crate::fixtures::documented_proxy_server;

/// A handler that maps one inbound request to one response (signed MCP-RE
/// response on success, JSON-RPC error object on failure). `now_unix` pins the
/// verification clock.
pub trait McpReServer {
    /// Handle one request and return the response bytes.
    fn handle(&self, request: &[u8], now_unix: i64) -> Vec<u8>;
}

impl McpReServer for EchoServer {
    fn handle(&self, request: &[u8], now_unix: i64) -> Vec<u8> {
        EchoServer::handle(self, request, now_unix)
    }
}

impl McpReServer for Proxy {
    fn handle(&self, request: &[u8], now_unix: i64) -> Vec<u8> {
        // The proxy serves only via the async path (ADR-MCPRE-051); this
        // conformance harness drives one request to completion on a private
        // runtime via the test-support helper (not a production serving path).
        mcp_re_proxy::test_support::block_on_handle(self, request, now_unix)
    }
}

/// Which documented target a harness should run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKind {
    /// The native MCP-RE echo server.
    Native,
    /// An ordinary MCP server fronted by the MCP-RE sidecar proxy.
    SidecarWrapped,
}

impl ServerKind {
    /// Parse the `--mode` CLI token (`native` | `proxy`).
    pub fn from_mode(mode: &str) -> Option<Self> {
        match mode {
            "native" => Some(ServerKind::Native),
            "proxy" => Some(ServerKind::SidecarWrapped),
            _ => None,
        }
    }

    /// The `--mode` CLI token for this kind.
    pub fn mode_arg(self) -> &'static str {
        match self {
            ServerKind::Native => "native",
            ServerKind::SidecarWrapped => "proxy",
        }
    }
}

/// Build the documented server of the given kind (both share the same key,
/// resolver, audience, and skew, so only the wrapping differs).
pub fn build_server(kind: ServerKind) -> Box<dyn McpReServer> {
    match kind {
        ServerKind::Native => Box::new(documented_echo_server()),
        ServerKind::SidecarWrapped => Box::new(documented_proxy_server()),
    }
}
