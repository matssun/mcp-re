//! Local client-side MCP-RE proxy (MCPS-49, #196) — the first adoption bridge.
//!
//! This is the MODE-SPECIFIC layer above the pure `mcp-re-client-core` seam: it owns
//! the route registry, the remote transport adapter, and the request-handling
//! pipeline that wires every client-core piece (signing, authorization binding,
//! custody, correlation, response verification, enforcement, audit). The local
//! client speaks PLAIN MCP and never sees an MCP-RE field (ADR-MCPS-044 §Proxy
//! transparency); the proxy is a security ADAPTER, not an orchestrator — route
//! resolution is static and it performs no tool choice / planning / intent routing.
//!
//! The transport is abstracted behind [`RemoteTransport`] so the security pipeline
//! is testable without real I/O; a binary supplies a concrete stdio/HTTP transport.

pub mod proxy;
pub mod route;
pub mod transport;

pub use proxy::CallParams;
pub use proxy::ClientProxy;
pub use proxy::ProxyResponse;
pub use proxy::ResponseKind;
pub use route::ClientVerification;
pub use route::Route;
pub use route::RouteRegistry;
pub use transport::ProxyError;
pub use transport::RemoteTransport;
pub use transport::TransportError;
