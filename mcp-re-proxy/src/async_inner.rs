//! ADR-MCPRE-051 §3 (Phase 3) — the ASYNC inner-server seam.
//!
//! The async analogue of [`crate::proxy::InnerServer`]: an already-verified,
//! stripped, verified-context-injected request in; the inner server's response
//! bytes out — but AWAITED, so the per-core runtime worker is never blocked on
//! the inner round-trip. This is the seam the production inner plane
//! ([`crate::http_inner`], a per-core `hyper` client pool to stateless
//! Streamable-HTTP inner backends) plugs into; the async serving path
//! ([`crate::proxy::Proxy::handle_with_transport_async`]) awaits it instead of the
//! sync [`InnerServer`](crate::proxy::InnerServer), which stays for the stdio
//! dev/compat serving path.
//!
//! Contract, identical to the sync inner: `dispatch` ALWAYS yields response bytes.
//! A backend failure is NOT an error return — it is a synthesized JSON-RPC error
//! *response* the proxy still signs (a hostile or dead inner can never suppress the
//! signature; ADR-MCPS §response-signing). So the seam carries no `Result`: an
//! upstream outage becomes signed fail-closed bytes, never an unsigned pass-through
//! and never a silent allow.

#![cfg(feature = "async_serve")]

use std::future::Future;
use std::pin::Pin;

/// The boxed, `Send` future an [`AsyncInnerServer`] returns: the inner server's
/// response bytes. Borrows the request for the duration of the call (the async
/// serving path holds the forwarded bytes across the await).
pub type InnerResponseFuture<'a> = Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>>;

/// An unmodified inner MCP server reached over an ASYNC transport (ADR-MCPRE-051
/// §3). Plain JSON-RPC request bytes in, plain JSON-RPC response bytes out, awaited
/// so the inner round-trip never blocks a per-core runtime worker.
///
/// Like the sync [`InnerServer`](crate::proxy::InnerServer), `dispatch` never
/// fails: an unreachable/slow/dead backend is surfaced as a synthesized JSON-RPC
/// error *response* (which the proxy signs), never as an error return — so the
/// fail-closed posture holds and the client always receives signed bytes.
pub trait AsyncInnerServer: Send + Sync {
    /// Dispatch one (already verified + stripped + context-injected) request to the
    /// inner server, awaiting its response bytes.
    fn dispatch<'a>(&'a self, request: &'a [u8]) -> InnerResponseFuture<'a>;
}

/// A synthesized JSON-RPC error *response* (no `result`) returned when the inner
/// is unreachable — no inner wired, an inner-backend transport/timeout failure, a
/// non-2xx status, or (in the pool) all backends ejected / pool exhausted. It
/// carries no `result`, so `Proxy::build_signed_response` wraps it as a SIGNED
/// `inner_error` envelope: the client receives signed, fail-closed bytes, never an
/// unsigned pass-through and never a silent allow (ADR-MCPS response-signing +
/// ADR-MCPRE-051 §4 fail-closed posture).
pub(crate) fn inner_unavailable_response() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"inner server unavailable"}}"#.to_vec()
}
