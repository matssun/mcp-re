// SPDX-License-Identifier: Apache-2.0
//! The production RFC 9421 serving handler (ADR-MCPRE-050 sole carrier,
//! ADR-MCPRE-051 §1–§4 per-core async data plane).
//!
//! [`HttpProfileProxy`] is the server-side PEP the async fleet runs per request. It
//! is the production promotion of the proven `examples/http_profile_proxy.rs`
//! pipeline onto the per-core async data plane, verifying/signing the **RFC 9421 +
//! RFC 9530 HTTP evidence carrier** — the signature rides in the RFC 9421 HTTP
//! headers, not a JSON-RPC `_meta` block, on the served path.
//!
//! Per request:
//!   1. reconstruct the [`HttpRequest`] (method, `@target-uri`, headers, body);
//!   2. `verify_request_full` — RFC 9421 signature + RFC 9530 Content-Digest + the
//!      request evidence block (audience / artifact bindings), fail-closed;
//!   3. Mode-A transport binding — bind the verified request actor to the mTLS peer
//!      identity (when a binding policy is configured);
//!   4. `dispatch_request_with_async_tier` — the authoritative async §4 replay
//!      admission, awaited (fail-closed on replay / store outage);
//!   5. strip the proxy-owned top-level `_meta` and forward the clean JSON-RPC to
//!      the stateless Streamable-HTTP inner backend via the async inner pool;
//!   6. `sign_delegated_response_full` — sign the reply with the active delegated
//!      key + inline credential, bound to THIS request (ADR-MCPRE-052).
//! Any fail-closed step emits a delegated-signed rejection receipt instead.

use std::sync::Arc;

use mcp_re_core::McpReError;
use mcp_re_http_profile::build_delegated_rejection;
use mcp_re_http_profile::build_delegated_rejection_preflight;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RejectionReason;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

use crate::async_inner::AsyncInnerServer;
use crate::async_serve::ServedHttpRequest;
use crate::async_serve::ServedHttpResponse;
use crate::delegated_server_signer::DelegatedServerSigner;
use crate::http_profile_dispatch::dispatch_request_with_async_tier;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::transport::TransportBindingPolicy;

/// The trust seam: resolve a presented keyid FOR a signing slot to a structured
/// actor (identity + verification key). A key not trusted for `slot` resolves to
/// `None` (fail closed). `Send + Sync` so one `HttpProfileProxy` serves every core.
pub type ActorResolver = Box<dyn Fn(&str, SignerSlot) -> Option<ResolvedActor> + Send + Sync>;

/// The RFC 9421 server-side PEP run by the async fleet (ADR-MCPRE-051).
///
/// Holds ONLY the RFC 9421 serving state — the verifier, signer, and evidence all
/// operate on the HTTP message, not a JSON-RPC `_meta` envelope. `Send + Sync`
/// (MCPRE-111): one instance is
/// shared across all per-core runtimes.
pub struct HttpProfileProxy {
    /// Trust resolution for request (client) and response (server) signing slots.
    resolve_actor: ActorResolver,
    /// The verifier's expected audience tuple (audience id + `@target-uri` + route);
    /// `target_uri` must equal the request `@target-uri` (enforced in verify).
    expected_audience: AudienceTuple,
    /// The ADR-MCPRE-052 delegated-signing custody — the ONLY response-signing mode.
    /// Every response and rejection is signed by the active short-TTL delegated key +
    /// inline credential; the root is never on the request path, and the proxy fails
    /// closed when no valid delegated key is available. There is no direct-root mode.
    signer: Arc<DelegatedServerSigner>,
    /// The authoritative async replay tier (ADR-MCPRE-051 §4).
    replay_async: crate::async_replay::AsyncReplayTier,
    /// Deployment replay-durability posture (fleet-strict + declared tier).
    dispatch_cfg: ProxyDispatchConfig,
    /// The async inner-plane client to the stateless Streamable-HTTP backend.
    inner_async: Box<dyn AsyncInnerServer>,
    /// Optional Mode-A transport binding: bind the verified request actor to the
    /// mTLS peer identity. `None` disables the channel binding.
    transport_binding: Option<Box<dyn TransportBindingPolicy + Send + Sync>>,
    /// Response-signature validity window (seconds added to `created`).
    sig_ttl_secs: i64,
}

impl HttpProfileProxy {
    /// Construct the serving PEP (ADR-MCPRE-052 delegated-signing — the only response-
    /// signing mode). `resolve_actor` is the trust seam; `expected_audience` the
    /// verifier audience; `dispatch_cfg`/`inner_async` the replay/inner planes. There
    /// is no directly-held server key on the serving struct — only the shared
    /// [`DelegatedServerSigner`] whose snapshot the cold-path rotor keeps fresh. Every
    /// response and rejection is signed by the active delegated key + inline
    /// credential, failing closed when none is valid.
    #[allow(clippy::too_many_arguments)]
    pub fn new_delegated(
        resolve_actor: ActorResolver,
        expected_audience: AudienceTuple,
        replay_async: crate::async_replay::AsyncReplayTier,
        dispatch_cfg: ProxyDispatchConfig,
        inner_async: Box<dyn AsyncInnerServer>,
        sig_ttl_secs: i64,
        delegated_signer: Arc<DelegatedServerSigner>,
    ) -> Self {
        HttpProfileProxy {
            resolve_actor,
            expected_audience,
            signer: delegated_signer,
            replay_async,
            dispatch_cfg,
            inner_async,
            transport_binding: None,
            sig_ttl_secs,
        }
    }

    /// Bind the verified request actor to the mTLS peer identity (Mode A, ADR-MCPS-014).
    pub fn with_transport_binding(
        mut self,
        binding: Box<dyn TransportBindingPolicy + Send + Sync>,
    ) -> Self {
        self.transport_binding = Some(binding);
        self
    }

    /// Serve one request end to end on the async data plane. Always returns a
    /// [`ServedHttpResponse`] — a signed reply on success, a signed rejection receipt
    /// on any fail-closed step. Only the replay admission and the inner round-trip
    /// are awaited; the RFC 9421 verify/sign are inline CPU (ADR-MCPRE-051 §2).
    pub async fn handle(&self, req: ServedHttpRequest, now: i64) -> ServedHttpResponse {
        let http_req = HttpRequest {
            method: req.method,
            target_uri: req.target_uri,
            headers: req.headers,
            body: req.body,
        };

        // Step 2 — verify (RFC 9421 + RFC 9530 + evidence block). DPoP artifact
        // bindings derive their credential from the covered Authorization header, so
        // no external material is supplied here; any binding lacking a credential
        // still fails closed.
        let no_material = |_b: &ArtifactBinding| None;
        let verified = match verify_request_full(
            &http_req,
            &self.expected_audience,
            &no_material,
            self.resolve_actor.as_ref(),
            now,
        ) {
            Ok(v) => v,
            // Preflight failure: the request never verified, so there is no
            // trustworthy request hash — the rejection is signed unbound.
            Err(e) => return self.rejection(&http_req, e.wire_code(), 403, now, None),
        };

        // Step 3 — Mode-A transport binding: the verified request actor must match
        // the mTLS peer identity. Fail closed on mismatch.
        if let Some(binding) = &self.transport_binding {
            if binding
                .check(&verified.resolved_actor.actor_id(), req.identity.as_ref())
                .is_err()
            {
                // Request-bound failure: the request verified, so bind the
                // rejection to it via `;req`.
                return self.rejection(
                    &http_req,
                    "mcp-re.transport_binding_failed",
                    403,
                    now,
                    Some(&verified.evidence),
                );
            }
        }

        // Step 4 — authoritative async §4 replay admission (awaited). No MRTR
        // continuation context on the base serving path.
        if let Err(e) =
            dispatch_request_with_async_tier(&verified, &self.replay_async, None, &self.dispatch_cfg)
                .await
        {
            return self.rejection(&http_req, e.wire_code(), 409, now, Some(&verified.evidence));
        }

        // Step 5 — strip the proxy-owned top-level `_meta` (the request evidence
        // block) so the backend sees clean MCP, then forward through the async inner.
        let forwarded = strip_top_level_meta(&http_req.body);
        let inner_bytes = self.inner_async.dispatch(&forwarded).await;

        // Step 6 — sign the backend reply, bound to THIS request. `Direct` signs
        // with the held server key; `Delegated` signs with the active delegated key
        // and the inline credential, failing closed if no valid key is available.
        let mut response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: inner_bytes,
        };
        let expires = now + self.sig_ttl_secs;
        match self.signer.current(now) {
            Some(a) => match sign_delegated_response_full(
                &mut response,
                &http_req,
                &verified.evidence,
                &a.server_signer,
                &a.credential,
                a.key.as_ref(),
                &a.delegated_kid,
                now,
                expires,
            ) {
                Ok(()) => served(response),
                Err(e) => self.rejection(&http_req, e.wire_code(), 500, now, Some(&verified.evidence)),
            },
            // Fail-closed issuance past expiry (ADR-MCPRE-052 §6): no valid delegated
            // key, so no signed response can be produced. The frozen signer-side
            // availability token (never a client verification verdict).
            None => self.rejection(
                &http_req,
                McpReError::DelegatedSigningUnavailable.wire_code(),
                503,
                now,
                Some(&verified.evidence),
            ),
        }
    }

    /// Build a signed rejection receipt bound to `request` (or preflight-unbound),
    /// with the injected `now` for the signature window (fail-closed freshness).
    ///
    /// Signs the rejection with the active delegated key and the inline credential
    /// (ADR-MCPRE-052) — request-bound when `bound` is `Some` (the request verified),
    /// preflight-unbound when `None` (the request never earned a trustworthy hash).
    /// Never root-signed. If no valid delegated key exists, a last-resort UNSIGNED
    /// error is emitted rather than a bogus signature.
    fn rejection(
        &self,
        request: &HttpRequest,
        wire_code: &'static str,
        status: u16,
        now: i64,
        bound: Option<&RequestEvidence>,
    ) -> ServedHttpResponse {
        let reason = RejectionReason {
            wire_code,
            message: format!("mcp-re http-profile proxy rejected: {wire_code}"),
        };
        let expires = now + self.sig_ttl_secs;
        let resp = match self.signer.current(now) {
            Some(a) => {
                let built = match bound {
                    Some(ev) => build_delegated_rejection(
                        request,
                        ev,
                        &reason,
                        status,
                        &a.server_signer,
                        &a.credential,
                        a.key.as_ref(),
                        &a.delegated_kid,
                        now,
                        expires,
                    ),
                    None => build_delegated_rejection_preflight(
                        Some(request),
                        &reason,
                        status,
                        &a.server_signer,
                        &a.credential,
                        a.key.as_ref(),
                        &a.delegated_kid,
                        now,
                        expires,
                    ),
                };
                built.unwrap_or_else(|_| unsigned_error(status, wire_code))
            }
            None => unsigned_error(status, wire_code),
        };
        served(resp)
    }
}

/// Wrap a fully-built [`HttpResponse`] as a [`ServedHttpResponse`].
fn served(resp: HttpResponse) -> ServedHttpResponse {
    ServedHttpResponse {
        status: resp.status,
        headers: resp.headers,
        body: resp.body,
    }
}

/// Remove the top-level `_meta` object (the proxy-owned request evidence block) so
/// the forwarded body is clean MCP JSON-RPC. Non-object bodies pass through.
fn strip_top_level_meta(body: &[u8]) -> Vec<u8> {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("_meta");
            }
            serde_json::to_vec(&v).unwrap_or_else(|_| body.to_vec())
        }
        Err(_) => body.to_vec(),
    }
}

/// A last-resort unsigned error body when even the signed rejection cannot be built
/// (a server-key failure). Never a silent allow — an explicit error status.
fn unsigned_error(status: u16, wire_code: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE, "message": wire_code },
            "id": serde_json::Value::Null,
        }))
        .unwrap_or_default(),
    }
}
