//! Demo proxy wiring (MCPS-047, MCP-RE-EPIC-P6 Child Issue 3; ADR-MCPRE-051).
//!
//! This is the demo-specific glue that points the EXISTING `mcp-re-proxy`
//! [`Proxy`](mcp_re_proxy::Proxy) at an inner MCP server. Under ADR-MCPRE-051 the
//! signing PEP no longer launches a stdio subprocess: its sole inner plane is a
//! stateless HTTP client ([`HttpInnerPool`](mcp_re_proxy::http_inner::HttpInnerPool)).
//! The unmodified `mcp-re-demo-fileserver` stdio server is fronted by the
//! out-of-TCB `mcp-re-stdio-bridge` (see [`crate::bridge::BridgeProcess`]) and
//! reached over HTTP. All the subprocess launch hardening (controlled working
//! directory, minimized environment, bounded stderr, sandbox, `setrlimit`) now
//! lives in the bridge crate, OUTSIDE the cryptographic TCB.
//!
//! This module reinvents nothing: the verify → strip-caller-`.verified` →
//! inject-sidecar-verified-context → sign path lives in `mcp-re-proxy`'s `Proxy`;
//! the HTTP inner pool lives in `mcp-re-proxy`. It only assembles them for the
//! demo. The inner HTTP URL is RESOLVED BY THE CALLER (the integration test /
//! runnable bin spawns the bridge fronting the real fileserver and hands its
//! `http://<addr>/` URL here); nothing here hardcodes a path.

use std::time::Duration;

use mcp_re_core::SigningKey;
use mcp_re_core::TrustResolver;
use mcp_re_proxy::http_inner::HttpInnerPool;
use mcp_re_proxy::InnerLogSink;
use mcp_re_proxy::Proxy;
use std::sync::Arc;

/// The per-request timeout the demo's HTTP inner plane uses. Generous relative to
/// a local bridge round-trip (which spawns / relays to the stdio fileserver), so a
/// slow machine under heavy `bazel test` load never spuriously fails closed.
const DEMO_INNER_TIMEOUT: Duration = Duration::from_secs(30);

/// The inputs that locate and identify a demo proxy instance.
///
/// `inner_http_url` is the base URL of the [`crate::bridge::BridgeProcess`] the
/// caller stood up fronting the real inner stdio server (e.g.
/// `http://127.0.0.1:54321/`). The remaining fields are the proxy's verification +
/// response-signing identities, injected so the wiring carries no ambient config.
pub struct DemoProxyConfig {
    /// Base HTTP URL of the out-of-TCB stdio↔HTTP bridge fronting the real inner
    /// MCP server. The proxy's async HTTP inner plane POSTs already-verified,
    /// stripped, verified-context-injected JSON-RPC requests here.
    pub inner_http_url: String,
    /// The proxy's response-signing key.
    pub server_signing_key: SigningKey,
    /// The proxy's signer identity (the `server_signer` / response `verifier`).
    pub server_signer: String,
    /// The key id advertised in signed responses.
    pub server_key_id: String,
    /// The expected audience the inbound request must target.
    pub audience: String,
    /// Maximum clock skew tolerated during verification (seconds).
    pub max_clock_skew_secs: i64,
}

/// Assemble a demo [`Proxy`] whose async inner plane is an
/// [`HttpInnerPool`](mcp_re_proxy::http_inner::HttpInnerPool) pointed at the
/// caller-provided bridge URL (which fronts the real `mcp-re-demo-fileserver`),
/// resolving inbound signers through `resolver`.
///
/// The returned proxy drives the production serving path: every inbound request
/// is verified, any caller-supplied `.verified` block is stripped, a fresh
/// sidecar-owned verified context is injected, the request is forwarded to the
/// HTTP inner (the bridge, which relays it over stdio to the real fileserver),
/// and the inner result is signed. The `log_sink` receives the two proxy-level
/// events (`inner_request_forwarded`, `inner_response_signed`); the subprocess
/// lifecycle events (`inner_spawned`/`inner_exited`) are emitted by the BRIDGE
/// (out of the PEP's TCB), on its own diagnostic channel.
///
/// Fails closed (`Err`) if the inner URL cannot be parsed — surfaced at
/// construction, never silently at serve time.
pub fn build_demo_proxy(
    config: DemoProxyConfig,
    resolver: Box<dyn TrustResolver + Send + Sync>,
    log_sink: Arc<dyn InnerLogSink + Send + Sync>,
) -> Result<Proxy, String> {
    let pool = HttpInnerPool::from_url_strs(vec![config.inner_http_url], DEMO_INNER_TIMEOUT)?;
    let proxy = Proxy::new(
        config.server_signing_key,
        config.server_signer,
        config.server_key_id,
        resolver,
        config.audience,
        config.max_clock_skew_secs,
    )
    .with_async_inner(Box::new(pool))
    .with_log_sink(log_sink);
    Ok(proxy)
}
