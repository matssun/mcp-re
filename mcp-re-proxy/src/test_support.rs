//! Test / embedding helpers for driving the async serving path synchronously.
//!
//! The production data plane is the per-core async fleet ([`crate::async_fleet`]);
//! [`crate::proxy::Proxy`] exposes only the async request entry point
//! [`Proxy::handle_with_transport_async`](crate::proxy::Proxy::handle_with_transport_async).
//! Tests and embedders that want a single request driven to completion use these
//! helpers, which own a private current-thread `tokio` runtime for the call. This
//! is NOT a serving path and never runs in production — it is the explicit,
//! clearly-named seam that replaced the old synchronous `Proxy::handle`.

use crate::proxy::Proxy;
use crate::transport::TransportIdentity;

/// Drive one request (no transport identity, no LB-assertion header) through the
/// async serving path to completion on a private current-thread runtime.
pub fn block_on_handle(proxy: &Proxy, request_bytes: &[u8], now_unix: i64) -> Vec<u8> {
    block_on_handle_with_transport(proxy, request_bytes, now_unix, None, None)
}

/// Drive one request carrying an optional verified transport identity and/or
/// LB-assertion header through the async serving path to completion.
pub fn block_on_handle_with_transport(
    proxy: &Proxy,
    request_bytes: &[u8],
    now_unix: i64,
    transport_identity: Option<&TransportIdentity>,
    lb_assertion_header: Option<&str>,
) -> Vec<u8> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime for block_on_handle");
    runtime.block_on(proxy.handle_with_transport_async(
        request_bytes,
        now_unix,
        transport_identity,
        lb_assertion_header,
    ))
}
