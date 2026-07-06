//! Stateful client host session (MCPS-033, ADR-MCPS-015).
//!
//! [`HostSession`] is a thin, stateful layer over the UNCHANGED [`HostSigner`].
//! It owns the three responsibilities the bare signer leaves to the caller:
//!
//! - **Freshness stamping** — `issued_at`/`expires_at` are generated from an
//!   injected [`Clock`] plus a configured request lifetime (conservative default
//!   ≤ 5 minutes, ADR-MCPS-015 / MCP_RE_SPEC §5).
//! - **Nonce generation** — each request `nonce` is drawn from an injected
//!   [`NonceSource`] (≥128-bit, opaque, Base64URL-safe).
//! - **Request/response correlation** — the Core-computed `request_hash` is
//!   stored keyed by JSON-RPC id; a signed response is verified against the
//!   STORED hash (never a caller-supplied expected hash).
//!
//! The session stays transport-free: it produces and consumes raw JSON-RPC bytes
//! and verifies responses against a caller-supplied [`TrustResolver`] passed as
//! data per call. It adds no networking/async dependency.
//!
//! The pending map is keyed by JSON-RPC id so the follow-up correlation/cleanup
//! hardening (#3854: duplicate-id rejection, expiry, cancellation, pending_count)
//! can layer on without reworking this structure.

use std::collections::BTreeMap;

use mcp_re_core::request_hash;
use mcp_re_core::unix_to_rfc3339_utc;
use mcp_re_core::unwrap_verified_result;
use mcp_re_core::verify_response;
use mcp_re_core::McpReError;
use mcp_re_core::TrustResolver;
use mcp_re_core::VerifiedResponse;
use serde_json::Value;

use crate::clock::Clock;
use crate::nonce::NonceSource;
use crate::nonce::NONCE_BYTES;
use crate::pending::PendingRequest;
use crate::signer::HostSigner;
use crate::verified_result::VerifiedResult;

/// The conservative default request lifetime in seconds (ADR-MCPS-015: ≤ 5 min).
pub const DEFAULT_REQUEST_LIFETIME_SECS: i64 = 300;

/// A stateful client session that signs MCP-RE requests and verifies the bound
/// responses, generic over the injected [`Clock`] and [`NonceSource`].
///
/// Construct with [`HostSession::with_defaults`] for the conservative default
/// lifetime, or [`HostSession::new`] to set an explicit lifetime.
pub struct HostSession<C, N> {
    signer: HostSigner,
    clock: C,
    nonce_source: N,
    request_lifetime_secs: i64,
    /// Outstanding requests: JSON-RPC id (canonical string) -> the
    /// [`PendingRequest`] (stored `request_hash` + expiry). Keyed by id so
    /// response verification binds to the exact request signed under that id,
    /// and so duplicate-id rejection and expiry cleanup are O(log n) lookups.
    pending: BTreeMap<String, PendingRequest>,
}

impl<C: Clock, N: NonceSource> HostSession<C, N> {
    /// Construct a session with an explicit request lifetime (seconds).
    pub fn new(signer: HostSigner, clock: C, nonce_source: N, request_lifetime_secs: i64) -> Self {
        HostSession {
            signer,
            clock,
            nonce_source,
            request_lifetime_secs,
            pending: BTreeMap::new(),
        }
    }

    /// Construct a session with the conservative default lifetime
    /// ([`DEFAULT_REQUEST_LIFETIME_SECS`]).
    pub fn with_defaults(signer: HostSigner, clock: C, nonce_source: N) -> Self {
        Self::new(signer, clock, nonce_source, DEFAULT_REQUEST_LIFETIME_SECS)
    }

    /// The signer identity (public — an identity, not a secret).
    pub fn signer(&self) -> &str {
        self.signer.signer()
    }

    /// Sign a request, returning the wire bytes and storing its `request_hash`
    /// keyed by `id` for later response verification.
    ///
    /// The session is the sole author of the envelope's `nonce`, `issued_at`, and
    /// `expires_at` (drawn from the injected clock + RNG); a caller-supplied
    /// `_meta` request block is overwritten by [`HostSigner`].
    pub fn sign_request(
        &mut self,
        id: &Value,
        method: &str,
        params: serde_json::Map<String, Value>,
        on_behalf_of: &str,
        audience: &str,
        authorization_hash: &str,
    ) -> Result<Vec<u8>, McpReError> {
        // Fail closed BEFORE drawing a nonce or signing: a second request that
        // reuses an in-flight id is a replay of that id. Clobbering the stored
        // hash would let a response bind to the wrong request, so refuse rather
        // than overwrite. The id is signable again once its entry is evicted (a
        // verified response, `cancel_request`, or `expire_pending`).
        let key = id_key(id);
        if self.pending.contains_key(&key) {
            return Err(McpReError::ReplayDetected);
        }

        let nonce = self.next_nonce();
        let issued_unix = self.clock.now_unix();
        // Fail closed on freshness-window overflow rather than panic (debug) or
        // wrap to a stale past `expires_at` (release): an extreme configured
        // `request_lifetime_secs` plus a pathological clock could overflow this
        // i64 add. A request whose expiry cannot be computed must not be signed.
        let expires_unix = issued_unix
            .checked_add(self.request_lifetime_secs)
            .ok_or(McpReError::CanonicalizationFailed)?;
        let issued_at = unix_to_rfc3339_utc(issued_unix);
        let expires_at = unix_to_rfc3339_utc(expires_unix);

        let bytes = self.signer.sign_request(
            id,
            method,
            params,
            on_behalf_of,
            audience,
            authorization_hash,
            &nonce,
            &issued_at,
            &expires_at,
        )?;

        // Store the Core-computed request_hash, keyed by JSON-RPC id, so response
        // verification binds to exactly this request — never a caller value.
        let signed_value: Value =
            serde_json::from_slice(&bytes).map_err(|_| McpReError::CanonicalizationFailed)?;
        let hash = request_hash(&signed_value)?;
        self.pending
            .insert(key, PendingRequest::new(hash, expires_unix));

        Ok(bytes)
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
        let mut params = serde_json::Map::new();
        params.insert("name".to_string(), Value::String(tool_name.to_string()));
        params.insert("arguments".to_string(), arguments);
        self.sign_request(id, "tools/call", params, on_behalf_of, audience, authorization_hash)
    }

    /// Verify a signed server response against the request hash STORED for the
    /// response's JSON-RPC id (never a caller-supplied expected hash).
    ///
    /// Returns [`McpReError::MissingEnvelope`] if no request was signed for that
    /// id — an UNKNOWN id has no stored hash to bind against, so the session
    /// refuses to verify rather than trust the response (fail closed).
    ///
    /// On a fully verified response the pending entry is REMOVED (success-path
    /// eviction): the id is then free to be reused. A FAILED verification leaves
    /// the entry in place, so a later correctly-bound response can still verify.
    pub fn verify_response<R: TrustResolver>(
        &mut self,
        response_bytes: &[u8],
        resolver: &R,
    ) -> Result<VerifiedResponse, McpReError> {
        let id = response_id(response_bytes)?;
        let key = id_key(&id);
        let expected_hash = self
            .pending
            .get(&key)
            .ok_or(McpReError::MissingEnvelope)?
            .request_hash();
        let verified = verify_response(response_bytes, resolver, expected_hash)?;
        // Verified: evict the pending entry (only on success).
        self.pending.remove(&key);
        Ok(verified)
    }

    /// Verify a signed server response AND unwrap its `result` back to the
    /// original MCP shape (issue #4077). Same fail-closed binding contract as
    /// [`HostSession::verify_response`]; on success it ALSO inverts the proxy's
    /// `build_signed_response` reshape via [`unwrap_verified_result`], so the
    /// caller sees the original scalar/array/object — and an inner ERROR surfaces
    /// as [`mcp_re_core::UnwrappedResult::InnerError`] (to be rendered as a JSON-RPC
    /// error), never as a success.
    ///
    /// Consumers that read the response payload MUST use this rather than reading
    /// the raw wire `result`, which still carries the `value`/`inner_error`
    /// wrappers and the signature `_meta`.
    pub fn verify_and_unwrap_response<R: TrustResolver>(
        &mut self,
        response_bytes: &[u8],
        resolver: &R,
    ) -> Result<VerifiedResult, McpReError> {
        let verified = self.verify_response(response_bytes, resolver)?;
        // Verification succeeded, so the bytes parse and carry a `result` object.
        let value: Value = serde_json::from_slice(response_bytes)
            .map_err(|_| McpReError::CanonicalizationFailed)?;
        let result = value.get("result").ok_or(McpReError::MissingEnvelope)?;
        let unwrapped = unwrap_verified_result(result)?;
        Ok(VerifiedResult::new(verified, unwrapped))
    }

    /// The request hash stored for `id`, if a request is pending under it.
    ///
    /// Exposed for correlation tests / introspection; returns `None` for an
    /// unknown, cancelled, expired, or already-verified id.
    pub fn stored_request_hash(&self, id: &Value) -> Option<&str> {
        self.pending.get(&id_key(id)).map(PendingRequest::request_hash)
    }

    /// The number of outstanding (pending) requests awaiting a verified response.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Cancel one outstanding request by JSON-RPC id, dropping its pending entry.
    ///
    /// Returns `true` if an entry was present and removed, `false` if the id was
    /// unknown (already verified, expired, cancelled, or never signed) — a no-op.
    pub fn cancel_request(&mut self, id: &Value) -> bool {
        self.pending.remove(&id_key(id)).is_some()
    }

    /// Drop every pending request that is expired at `now_unix` (Unix seconds,
    /// UTC), returning the number of entries removed.
    ///
    /// Long-lived hosts call this periodically (with the injected clock's `now`)
    /// so abandoned requests do not accumulate. Expiry is inclusive of the
    /// request's `expires_at` instant (the freshness window has closed).
    pub fn expire_pending(&mut self, now_unix: i64) -> usize {
        let before = self.pending.len();
        self.pending
            .retain(|_id, entry| !entry.is_expired_at(now_unix));
        before - self.pending.len()
    }

    /// Draw the next nonce: `NONCE_BYTES` of injected entropy, Base64URL-no-pad.
    fn next_nonce(&mut self) -> String {
        let mut bytes = [0u8; NONCE_BYTES];
        self.nonce_source.fill(&mut bytes);
        mcp_re_core::b64url_encode(&bytes)
    }
}

/// Canonical map key for a JSON-RPC id. The MCP-RE id domain is a string or a
/// safe integer (MCP_RE_SPEC §4); serializing the `Value` gives a stable key that
/// distinguishes `"1"` (string) from `1` (number).
fn id_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

/// Extract the JSON-RPC `id` from response bytes for correlation lookup.
///
/// A response without an object body or without an `id` cannot be correlated, so
/// it maps to [`McpReError::MissingEnvelope`] (fail closed — no stored hash to
/// bind against).
fn response_id(response_bytes: &[u8]) -> Result<Value, McpReError> {
    let value: Value =
        serde_json::from_slice(response_bytes).map_err(|_| McpReError::CanonicalizationFailed)?;
    value
        .get("id")
        .cloned()
        .ok_or(McpReError::MissingEnvelope)
}
