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
use mcp_re_client_core::verify_signed_response;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_core::SigningKey;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

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

/// The proxy's response to the local client: plain MCP.
#[derive(Debug, Clone)]
pub struct ProxyResponse {
    /// The plain MCP JSON-RPC response to return to the local client.
    pub plain_response: Value,
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
        );
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

        // Verify the signed response bound to THIS request (RFC 9421 `;req` +
        // response evidence block). Fail closed on any failure.
        let mut expectation =
            ResponseExpectation::new(signed.request().clone(), signed.evidence().clone());
        if let Some(keyid) = &route.expected_server_keyid {
            expectation = expectation.with_expected_server_signer(keyid.clone());
        }
        verify_signed_response(
            &response,
            route.resolve_actor.as_ref(),
            &expectation,
            params.now_unix,
        )?;

        // Return the (now trusted) response body as plain MCP, with the proxy-owned
        // `_meta` evidence block stripped.
        let plain = plain_response_from_verified(&response.body)?;
        Ok(ProxyResponse {
            plain_response: plain,
        })
    }
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
