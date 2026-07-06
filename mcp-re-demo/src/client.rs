//! The demo `HostSession` client (MCPS-046, ADR-MCPS-015 / MCP-RE-EPIC-P6.5).
//!
//! [`DemoHostClient`] is the host/ambassador side of the single-node demo. It is
//! a thin harness over the UNCHANGED [`HostSession`]: the session does all of the
//! real work (nonce from the injected RNG, `issued_at`/`expires_at` from the
//! injected clock + configured lifetime, `request_hash` correlation by JSON-RPC
//! id, response verification against the STORED hash). The client adds only the
//! demo-facing surface and the firm invariants the demo must demonstrate:
//!
//! - it drives [`HostSession`] (the stateful session), never the bare stateless
//!   [`HostSigner`](mcp_re_host::HostSigner) directly — so freshness, nonce, and
//!   pending-request tracking are always applied;
//! - it exposes the public *signer identity* but NO private-key accessor (the
//!   language model never holds keys, ADR-MCPS-003); and
//! - it stays transport-light: it produces and consumes raw JSON-RPC bytes and
//!   keeps any local stdio piping in the demo crate, so `mcp-re-host` itself
//!   remains networking/async-free (ADR-MCPS-015).
//!
//! Rejection behaviour is inherited verbatim from [`HostSession`] and asserted by
//! the demo tests: an unknown response id and a duplicate in-flight request id
//! both fail closed, and a wrong response hash is refused without evicting the
//! pending entry.

use mcp_re_core::McpReError;
use mcp_re_core::TrustResolver;
use mcp_re_core::VerifiedResponse;
use mcp_re_host::Clock;
use mcp_re_host::HostSession;
use mcp_re_host::HostSigner;
use mcp_re_host::NonceSource;
use mcp_re_host::VerifiedResult;
use serde_json::Value;

/// A demo client that signs MCP-RE requests and verifies the bound responses,
/// generic over the injected [`Clock`] and [`NonceSource`].
///
/// Construct with [`DemoHostClient::with_defaults`] for the conservative default
/// request lifetime, or [`DemoHostClient::new`] to set an explicit lifetime.
pub struct DemoHostClient<C, N> {
    session: HostSession<C, N>,
}

impl<C: Clock, N: NonceSource> DemoHostClient<C, N> {
    /// Construct a demo client with an explicit request lifetime (seconds).
    pub fn new(
        signer: HostSigner,
        clock: C,
        nonce_source: N,
        request_lifetime_secs: i64,
    ) -> Self {
        DemoHostClient {
            session: HostSession::new(signer, clock, nonce_source, request_lifetime_secs),
        }
    }

    /// Construct a demo client with the session's conservative default lifetime.
    pub fn with_defaults(signer: HostSigner, clock: C, nonce_source: N) -> Self {
        DemoHostClient {
            session: HostSession::with_defaults(signer, clock, nonce_source),
        }
    }

    /// The signer identity (public — an identity, not a secret).
    ///
    /// There is deliberately NO accessor that returns the signing key: the model
    /// can drive signing through this client but can never read the key.
    pub fn signer(&self) -> &str {
        self.session.signer()
    }

    /// Sign a request, returning the wire bytes and storing its `request_hash`
    /// keyed by `id` for later response verification.
    ///
    /// Delegates to [`HostSession::sign_request`]; the session is the sole author
    /// of the envelope's `nonce`, `issued_at`, and `expires_at`. Reusing an
    /// in-flight `id` fails closed with [`McpReError::ReplayDetected`].
    pub fn sign_request(
        &mut self,
        id: &Value,
        method: &str,
        params: serde_json::Map<String, Value>,
        on_behalf_of: &str,
        audience: &str,
        authorization_hash: &str,
    ) -> Result<Vec<u8>, McpReError> {
        self.session
            .sign_request(id, method, params, on_behalf_of, audience, authorization_hash)
    }

    /// Convenience for `tools/call`: builds `{"name","arguments"}` params and
    /// signs them, storing the `request_hash` keyed by `id`.
    pub fn sign_tool_call(
        &mut self,
        id: &Value,
        tool_name: &str,
        arguments: Value,
        on_behalf_of: &str,
        audience: &str,
        authorization_hash: &str,
    ) -> Result<Vec<u8>, McpReError> {
        self.session
            .sign_tool_call(id, tool_name, arguments, on_behalf_of, audience, authorization_hash)
    }

    /// Verify a signed server response against the request hash STORED for the
    /// response's JSON-RPC id (never a caller-supplied expected hash).
    ///
    /// Fails closed: an UNKNOWN response id has no stored hash and yields
    /// [`McpReError::MissingEnvelope`]; a wrong binding yields
    /// [`McpReError::ResponseHashMismatch`] and leaves the pending entry in place.
    pub fn verify_response<R: TrustResolver>(
        &mut self,
        response_bytes: &[u8],
        resolver: &R,
    ) -> Result<VerifiedResponse, McpReError> {
        self.session.verify_response(response_bytes, resolver)
    }

    /// Verify AND unwrap a signed server response (issue #4077): the same bound
    /// verification as [`DemoHostClient::verify_response`], plus restoration of
    /// the original MCP `result` shape (scalar/array/object) and surfacing of an
    /// inner ERROR as [`mcp_re_host::UnwrappedResult::InnerError`]. Consumers that
    /// read the payload use this; the raw wire `result` still carries the
    /// `value`/`inner_error` wrappers + signature `_meta`.
    pub fn verify_and_unwrap_response<R: TrustResolver>(
        &mut self,
        response_bytes: &[u8],
        resolver: &R,
    ) -> Result<VerifiedResult, McpReError> {
        self.session.verify_and_unwrap_response(response_bytes, resolver)
    }

    /// The request hash stored for `id`, if a request is pending under it.
    pub fn stored_request_hash(&self, id: &Value) -> Option<&str> {
        self.session.stored_request_hash(id)
    }

    /// The number of outstanding (pending) requests awaiting a verified response.
    pub fn pending_count(&self) -> usize {
        self.session.pending_count()
    }

    /// Cancel one outstanding request by JSON-RPC id, dropping its pending entry.
    ///
    /// Returns `true` if an entry was present and removed, `false` for an unknown
    /// id (a no-op).
    pub fn cancel_request(&mut self, id: &Value) -> bool {
        self.session.cancel_request(id)
    }
}
