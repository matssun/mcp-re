//! Stateful client host session (MCPS-033, ADR-MCPS-015).
//!
//! [`HostSession`] is a thin, stateful layer over the UNCHANGED [`HostSigner`].
//! It owns the three responsibilities the bare signer leaves to the caller:
//!
//! - **Freshness stamping** — `issued_at`/`expires_at` are generated from an
//!   injected [`Clock`] plus a configured request lifetime (conservative default
//!   ≤ 5 minutes, ADR-MCPS-015 / MCPS_SPEC §5).
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

use mcps_core::request_hash;
use mcps_core::unix_to_rfc3339_utc;
use mcps_core::unwrap_verified_result;
use mcps_core::verify_response;
use mcps_core::McpsError;
use mcps_core::TrustResolver;
use mcps_core::VerifiedResponse;
use serde_json::Value;

use crate::clock::Clock;
use crate::nonce::NonceSource;
use crate::nonce::NONCE_BYTES;
use crate::pending::PendingRequest;
use crate::signer::HostSigner;
use crate::verified_result::VerifiedResult;

/// The conservative default request lifetime in seconds (ADR-MCPS-015: ≤ 5 min).
pub const DEFAULT_REQUEST_LIFETIME_SECS: i64 = 300;

/// The maximum request lifetime the session will sign (ADR-MCPS-015 / MCPS_SPEC
/// §5: the freshness window is ≤ 5 minutes). The verifier's `check_freshness`
/// enforces no maximum span, so the ceiling is a producer-side obligation: a
/// mis-configured host must not be able to mint a long-lived (over-cap) window
/// that a compliant verifier would nonetheless accept.
pub const MAX_REQUEST_LIFETIME_SECS: i64 = DEFAULT_REQUEST_LIFETIME_SECS;

/// A stateful client session that signs MCP-S requests and verifies the bound
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
    ///
    /// Fails closed (`Err`) on a lifetime that violates the ADR-MCPS-015 window
    /// contract: a non-positive value (a request that is already expired at
    /// issue, or a degenerate/negative window) or one exceeding
    /// [`MAX_REQUEST_LIFETIME_SECS`] (the ≤ 5-minute ceiling). Enforcing this at
    /// construction keeps a mis-configured host from silently minting an over-cap
    /// window that a compliant verifier — which imposes no maximum span — accepts.
    pub fn new(
        signer: HostSigner,
        clock: C,
        nonce_source: N,
        request_lifetime_secs: i64,
    ) -> Result<Self, String> {
        if request_lifetime_secs <= 0 {
            return Err(format!(
                "request_lifetime_secs must be positive (ADR-MCPS-015), got {request_lifetime_secs}"
            ));
        }
        if request_lifetime_secs > MAX_REQUEST_LIFETIME_SECS {
            return Err(format!(
                "request_lifetime_secs {request_lifetime_secs} exceeds the ADR-MCPS-015 \
                 ceiling of {MAX_REQUEST_LIFETIME_SECS}s (≤ 5-minute freshness window)"
            ));
        }
        Ok(HostSession {
            signer,
            clock,
            nonce_source,
            request_lifetime_secs,
            pending: BTreeMap::new(),
        })
    }

    /// Construct a session with the conservative default lifetime
    /// ([`DEFAULT_REQUEST_LIFETIME_SECS`]). Infallible: the default is within the
    /// [`MAX_REQUEST_LIFETIME_SECS`] ceiling by construction.
    pub fn with_defaults(signer: HostSigner, clock: C, nonce_source: N) -> Self {
        Self::new(signer, clock, nonce_source, DEFAULT_REQUEST_LIFETIME_SECS)
            .expect("DEFAULT_REQUEST_LIFETIME_SECS is within the ADR-MCPS-015 ceiling")
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
    ) -> Result<Vec<u8>, McpsError> {
        // Enforce the MCPS_SPEC §4 id domain at the producer: a JSON-RPC id must
        // be a string or a safe integer. A Null/array/object/float id would be
        // signed and keyed (via `id_key`) despite being out of domain, and would
        // only be caught — if at all — downstream. Reject it here, before drawing
        // a nonce or signing, so the host never mints an out-of-domain id.
        reject_out_of_domain_id(id)?;

        // Fail closed BEFORE drawing a nonce or signing: a second request that
        // reuses an in-flight id is a replay of that id. Clobbering the stored
        // hash would let a response bind to the wrong request, so refuse rather
        // than overwrite. The id is signable again once its entry is evicted (a
        // verified response, `cancel_request`, or `expire_pending`).
        let key = id_key(id);
        if self.pending.contains_key(&key) {
            return Err(McpsError::ReplayDetected);
        }

        let nonce = self.next_nonce();
        let issued_unix = self.clock.now_unix();
        // Fail closed on freshness-window overflow rather than panic (debug) or
        // wrap to a stale past `expires_at` (release): an extreme configured
        // `request_lifetime_secs` plus a pathological clock could overflow this
        // i64 add. A request whose expiry cannot be computed must not be signed.
        let expires_unix = issued_unix
            .checked_add(self.request_lifetime_secs)
            .ok_or(McpsError::CanonicalizationFailed)?;
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
            serde_json::from_slice(&bytes).map_err(|_| McpsError::CanonicalizationFailed)?;
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
    ) -> Result<Vec<u8>, McpsError> {
        let mut params = serde_json::Map::new();
        params.insert("name".to_string(), Value::String(tool_name.to_string()));
        params.insert("arguments".to_string(), arguments);
        self.sign_request(id, "tools/call", params, on_behalf_of, audience, authorization_hash)
    }

    /// Verify a signed server response against the request hash STORED for the
    /// response's JSON-RPC id (never a caller-supplied expected hash).
    ///
    /// Returns [`McpsError::MissingEnvelope`] if no request was signed for that
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
    ) -> Result<VerifiedResponse, McpsError> {
        let id = response_id(response_bytes)?;
        let key = id_key(&id);
        let expected_hash = self
            .pending
            .get(&key)
            .ok_or(McpsError::MissingEnvelope)?
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
    /// as [`mcps_core::UnwrappedResult::InnerError`] (to be rendered as a JSON-RPC
    /// error), never as a success.
    ///
    /// Consumers that read the response payload MUST use this rather than reading
    /// the raw wire `result`, which still carries the `value`/`inner_error`
    /// wrappers and the signature `_meta`.
    pub fn verify_and_unwrap_response<R: TrustResolver>(
        &mut self,
        response_bytes: &[u8],
        resolver: &R,
    ) -> Result<VerifiedResult, McpsError> {
        let verified = self.verify_response(response_bytes, resolver)?;
        // Verification succeeded, so the bytes parse and carry a `result` object.
        let value: Value = serde_json::from_slice(response_bytes)
            .map_err(|_| McpsError::CanonicalizationFailed)?;
        let result = value.get("result").ok_or(McpsError::MissingEnvelope)?;
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
        mcps_core::b64url_encode(&bytes)
    }
}

/// Reject a JSON-RPC id outside the MCPS_SPEC §4 domain (a string or a safe
/// integer). A `Null`, boolean, array, object, or non-integer/unsafe-integer
/// number id is out of domain and must not be signed.
///
/// Fails closed with [`McpsError::CanonicalizationFailed`]: an out-of-domain id
/// is a protected-message value-domain violation (the same class as an unsafe
/// integer or non-integer number the code already rejects there), and the frozen
/// taxonomy carries no dedicated invalid-id code.
fn reject_out_of_domain_id(id: &Value) -> Result<(), McpsError> {
    match id {
        Value::String(_) => Ok(()),
        // A safe integer serializes as an i64 or u64; a fractional or
        // out-of-i64/u64-range number does not, so it is rejected.
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(()),
        _ => Err(McpsError::CanonicalizationFailed),
    }
}

/// Canonical map key for a JSON-RPC id. The MCP-S id domain is a string or a
/// safe integer (MCPS_SPEC §4); serializing the `Value` gives a stable key that
/// distinguishes `"1"` (string) from `1` (number). Callers on the signing path
/// pre-validate the id with [`reject_out_of_domain_id`], so the `unwrap_or_default`
/// fallback is unreachable for a validated id (and a stable "" key for any
/// hypothetical unserializable id still fails closed downstream).
fn id_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

/// Extract the JSON-RPC `id` from response bytes for correlation lookup.
///
/// A response without an object body or without an `id` cannot be correlated, so
/// it maps to [`McpsError::MissingEnvelope`] (fail closed — no stored hash to
/// bind against).
fn response_id(response_bytes: &[u8]) -> Result<Value, McpsError> {
    let value: Value =
        serde_json::from_slice(response_bytes).map_err(|_| McpsError::CanonicalizationFailed)?;
    value
        .get("id")
        .cloned()
        .ok_or(McpsError::MissingEnvelope)
}
