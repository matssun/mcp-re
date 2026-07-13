// SPDX-License-Identifier: Apache-2.0
//! The local client-side MCP-RE proxy pipeline (MCPS-49, #196), on the RFC 9421
//! carrier (ADR-MCPRE-050).
//!
//! The local client speaks PLAIN MCP to this proxy; the proxy signs the outbound
//! request as RFC 9421 + RFC 9530 via `mcp-re-client-core`, forwards it to the
//! remote MCP-RE endpoint, verifies the signed response bound to that request, and
//! returns PLAIN MCP. The local client never emits, parses, or negotiates any
//! MCP-RE field; the signature rides in the RFC 9421 HTTP headers, not a JSON-RPC
//! `_meta` block.
//!
//! ## PURGE 2026-07-11 — lean RFC 9421 pipeline
//! The object-era enforcement-mode engine, in-flight correlation store, MRT
//! continuation retention, and authorization-binding providers are **deferred**
//! (rebuilt on RFC 9421 later); this is the signing/verification adapter core.

use mcp_re_client_core::build_signed_request;
use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::DelegatedOutcome;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_core::SigningKey;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

use crate::route::ClientVerification;
use crate::route::RouteRegistry;
use crate::transport::ProxyError;
use crate::transport::RemoteTransport;

/// Per-call parameters the mode-specific layer supplies (RFC 9421 freshness + the
/// verification clock). The binary fills these from its nonce source and clock.
#[derive(Debug, Clone)]
pub struct CallParams {
    /// A fresh anti-replay nonce (RFC 9421 `nonce`).
    pub nonce: String,
    /// Signature creation time, Unix seconds (RFC 9421 `created`).
    pub created: i64,
    /// Signature expiry time, Unix seconds (RFC 9421 `expires`).
    pub expires: i64,
    /// Current time (Unix seconds) for response verification.
    pub now_unix: i64,
}

/// The proxy's response to the local client: plain MCP, plus the verified kind so
/// the embedding layer can distinguish a genuine success from a provably-denied
/// request (a verified rejection receipt) without re-parsing.
#[derive(Debug, Clone)]
pub struct ProxyResponse {
    /// The plain MCP JSON-RPC response to return to the local client — a `result`
    /// on success, or a JSON-RPC `error` when the server provably rejected.
    pub plain_response: Value,
    /// Whether the verified response was a success or a delegated rejection receipt.
    pub kind: ResponseKind,
}

/// The verified outcome the proxy hands its embedding layer. A verified REJECTION is
/// NOT a proxy failure — the server provably denied the request; the proxy converts
/// the signed receipt to a plain JSON-RPC error and reports the classification. An
/// UNVERIFIABLE response (unsigned / direct-root in delegated mode / bad signature)
/// is a `ProxyError` instead — the channel is compromised or misconfigured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseKind {
    /// A verified success response.
    Success,
    /// A verified delegated rejection receipt, converted to plain JSON-RPC error.
    /// `wire_code` is the server's frozen `mcp-re.*` reason; `bound` distinguishes a
    /// request-bound receipt from a preflight-unbound one.
    VerifiedRejection {
        wire_code: Option<String>,
        bound: bool,
    },
}

/// The local client-side MCP-RE proxy. Holds the static route registry, the client
/// signing key + keyid, and the remote transport.
pub struct ClientProxy {
    registry: RouteRegistry,
    signing_key: SigningKey,
    key_id: String,
    transport: Box<dyn RemoteTransport>,
}

impl ClientProxy {
    /// Construct a proxy from its wired pieces.
    pub fn new(
        registry: RouteRegistry,
        signing_key: SigningKey,
        key_id: impl Into<String>,
        transport: Box<dyn RemoteTransport>,
    ) -> Self {
        ClientProxy {
            registry,
            signing_key,
            key_id: key_id.into(),
            transport,
        }
    }

    /// Handle one plain-MCP request on `route_id`: sign (RFC 9421) → forward →
    /// verify the bound signed response → return plain MCP. Fails closed on any
    /// verification failure.
    pub fn handle(
        &self,
        route_id: &str,
        plain_request: &Value,
        params: &CallParams,
    ) -> Result<ProxyResponse, ProxyError> {
        let route = self
            .registry
            .get(route_id)
            .ok_or_else(|| ProxyError::UnknownRoute(route_id.to_string()))?;

        // Parse the ordinary MCP request (transparency: it carries no MCP-RE fields).
        let id = plain_request.get("id").cloned().unwrap_or(Value::Null);
        let method = plain_request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ProxyError::MalformedRequest)?
            .to_string();
        let req_params: Map<String, Value> = plain_request
            .get("params")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        // Sign the RFC 9421 request through the client-core seam.
        let inputs = RequestSigningInputs::new(
            self.key_id.clone(),
            route.audience.clone(),
            route.artifact_bindings.clone(),
            &params.nonce,
            params.created,
            params.expires,
        )
        .with_headers(route.extra_headers.clone());
        let signed = build_signed_request(
            &id,
            &method,
            req_params,
            &route.target_uri,
            &inputs,
            &self.signing_key,
        )?;

        // Forward to the remote MCP-RE endpoint.
        let response = self
            .transport
            .round_trip(signed.request())
            .map_err(ProxyError::Transport)?;

        // Verify the signed response bound to THIS request under the route's required
        // profile (configured profile = required profile). Fail closed on any failure;
        // no cross-profile fallback.
        match &route.verification {
            // ADR-MCPRE-052 delegated-signing (the only mode): a delegated-signed
            // success OR rejection receipt carrying the inline credential. No
            // direct-root / unsigned / object downgrade is accepted
            // (verify_delegated_response fails closed).
            ClientVerification::DelegatedRequired(policy, revocation) => {
                let expectation =
                    ResponseExpectation::new(signed.request().clone(), signed.evidence().clone());
                // The route's REQUIRED revocation source (§3 step 7). Consulted with the
                // credential's delegated_kid / issuer_kid / jti; an empty static list is
                // the explicit TTL-only posture, never a silent default.
                let verified = verify_delegated_response(
                    &response,
                    route.resolve_actor.as_ref(),
                    &expectation,
                    policy,
                    revocation.as_ref(),
                    params.now_unix,
                )?;
                match verified.outcome {
                    DelegatedOutcome::Success => {
                        let plain = plain_response_from_verified(&response.body)?;
                        Ok(ProxyResponse {
                            plain_response: plain,
                            kind: ResponseKind::Success,
                        })
                    }
                    // A VERIFIED rejection receipt: the request was provably denied.
                    // Convert the signed receipt to a plain JSON-RPC error for the
                    // local client and report the classification (fail closed — this
                    // is never returned as a success result).
                    DelegatedOutcome::Rejection { bound, wire_code } => Ok(ProxyResponse {
                        plain_response: plain_error_from_rejection(&id),
                        kind: ResponseKind::VerifiedRejection { wire_code, bound },
                    }),
                }
            }
        }
    }
}

/// Convert a VERIFIED delegated rejection receipt to a PLAIN JSON-RPC error for the
/// local client (transparency: the client sees ordinary JSON-RPC, not an MCP-RE
/// field — the `mcp-re.*` classification is surfaced to the embedding layer via
/// [`ResponseKind::VerifiedRejection`], not to the client). The proxy has already
/// verified the receipt's signature, so this is a provable denial, not a guess.
fn plain_error_from_rejection(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE,
            "message": "request rejected by the MCP-RE server",
        },
    })
}

/// Rebuild a PLAIN MCP response from a verified signed response: strip the
/// proxy-owned top-level `_meta` (the RFC 9421 response evidence block) from the
/// body, returning ordinary JSON-RPC.
fn plain_response_from_verified(response_body: &[u8]) -> Result<Value, ProxyError> {
    let mut object: Value =
        serde_json::from_slice(response_body).map_err(|_| ProxyError::MalformedRequest)?;
    if let Some(result) = object.get_mut("result").and_then(Value::as_object_mut) {
        result.remove("_meta");
    }
    if let Some(top) = object.as_object_mut() {
        top.remove("_meta");
    }
    Ok(json!({
        "jsonrpc": "2.0",
        "id": object.get("id").cloned().unwrap_or(Value::Null),
        "result": object.get("result").cloned().unwrap_or(Value::Null),
    }))
}
