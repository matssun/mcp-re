// SPDX-License-Identifier: Apache-2.0
//! The production RFC 9421 serving handler (ADR-MCPRE-050 sole carrier,
//! ADR-MCPRE-051 §1–§4 per-core async data plane).
//!
//! [`HttpProfileProxy`] is the server-side PEP the async fleet runs per request. It
//! is the production promotion of the proven `examples/http_profile_proxy.rs`
//! pipeline onto the per-core async data plane, verifying/signing the **RFC 9421 +
//! RFC 9530 HTTP evidence carrier** — there is NO object/JCS `_meta` signature and
//! NO canonicalization preimage on the served path.
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
//!   6. `sign_response_full` — sign the reply, bound to THIS request.
//! Any fail-closed step emits a `build_signed_rejection` receipt instead.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::build_signed_rejection;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RejectionReason;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

use crate::async_inner::AsyncInnerServer;
use crate::async_serve::ServedHttpRequest;
use crate::async_serve::ServedHttpResponse;
use crate::http_profile_dispatch::dispatch_request_with_async_tier;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::transport::TransportBindingPolicy;

/// The trust seam: resolve a presented keyid FOR a signing slot to a structured
/// actor (identity + verification key). A key not trusted for `slot` resolves to
/// `None` (fail closed). `Send + Sync` so one `HttpProfileProxy` serves every core.
pub type ActorResolver = Box<dyn Fn(&str, SignerSlot) -> Option<ResolvedActor> + Send + Sync>;

/// The RFC 9421 server-side PEP run by the async fleet (ADR-MCPRE-051).
///
/// Holds ONLY the RFC 9421 serving state — there is no object/JCS verifier, signer,
/// or `_meta` envelope anywhere in it. `Send + Sync` (MCPRE-111): one instance is
/// shared across all per-core runtimes.
pub struct HttpProfileProxy {
    /// Trust resolution for request (client) and response (server) signing slots.
    resolve_actor: ActorResolver,
    /// The verifier's expected audience tuple (audience id + `@target-uri` + route);
    /// `target_uri` must equal the request `@target-uri` (enforced in verify).
    expected_audience: AudienceTuple,
    /// The server response-signing identity named in the response evidence block.
    server_identity: ActorIdentity,
    /// The server response-signing key. A short-TTL in-memory delegated key
    /// (ADR-MCPRE-052 custody) or a directly-held server key.
    server_key: SigningKey,
    /// The keyid the response signature is emitted under.
    server_key_id: String,
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
    /// Construct a serving PEP. `resolve_actor` is the trust seam; `expected_audience`
    /// the verifier audience; `server_identity`/`server_key`/`server_key_id` the
    /// response-signing custody; `dispatch_cfg`/`inner_async` the replay/inner planes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resolve_actor: ActorResolver,
        expected_audience: AudienceTuple,
        server_identity: ActorIdentity,
        server_key: SigningKey,
        server_key_id: impl Into<String>,
        replay_async: crate::async_replay::AsyncReplayTier,
        dispatch_cfg: ProxyDispatchConfig,
        inner_async: Box<dyn AsyncInnerServer>,
        sig_ttl_secs: i64,
    ) -> Self {
        HttpProfileProxy {
            resolve_actor,
            expected_audience,
            server_identity,
            server_key,
            server_key_id: server_key_id.into(),
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
            Err(e) => return self.rejection(&http_req, e.wire_code(), 403, now),
        };

        // Step 3 — Mode-A transport binding: the verified request actor must match
        // the mTLS peer identity. Fail closed on mismatch.
        if let Some(binding) = &self.transport_binding {
            if binding
                .check(&verified.resolved_actor.actor_id(), req.identity.as_ref())
                .is_err()
            {
                return self.rejection(&http_req, "mcp-re.transport_binding_failed", 403, now);
            }
        }

        // Step 4 — authoritative async §4 replay admission (awaited). No MRTR
        // continuation context on the base serving path.
        if let Err(e) =
            dispatch_request_with_async_tier(&verified, &self.replay_async, None, &self.dispatch_cfg)
                .await
        {
            return self.rejection(&http_req, e.wire_code(), 409, now);
        }

        // Step 5 — strip the proxy-owned top-level `_meta` (the request evidence
        // block) so the backend sees clean MCP, then forward through the async inner.
        let forwarded = strip_top_level_meta(&http_req.body);
        let inner_bytes = self.inner_async.dispatch(&forwarded).await;

        // Step 6 — sign the backend reply, bound to THIS request.
        let mut response = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: inner_bytes,
        };
        match sign_response_full(
            &mut response,
            &http_req,
            &verified.evidence,
            &self.server_identity,
            &self.server_key,
            &self.server_key_id,
            now,
            now + self.sig_ttl_secs,
        ) {
            Ok(()) => ServedHttpResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
            },
            Err(e) => self.rejection(&http_req, e.wire_code(), 500, now),
        }
    }

    /// Build a signed rejection receipt bound to `request`, on the server key, with
    /// the injected `now` for the signature window (fail-closed freshness).
    fn rejection(
        &self,
        request: &HttpRequest,
        wire_code: &'static str,
        status: u16,
        now: i64,
    ) -> ServedHttpResponse {
        let resp = build_signed_rejection(
            Some(request),
            &RejectionReason {
                wire_code,
                message: format!("mcp-re http-profile proxy rejected: {wire_code}"),
            },
            status,
            &self.server_key,
            &self.server_key_id,
            now,
            now + self.sig_ttl_secs,
        )
        .unwrap_or_else(|_| unsigned_error(status, wire_code));
        ServedHttpResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        }
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
