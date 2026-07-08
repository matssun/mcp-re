//! Native MCP-RE echo server (MCPS-011) — the first conformance target.
//!
//! [`EchoServer`] natively speaks the MCP-RE profile: it verifies an inbound
//! signed MCP-RE request with `mcp_re_core::verify_request`, runs the trivial
//! `echo` tool, and returns a **signed** MCP-RE response bound to the verified
//! request (`request_hash`). Verification failures become JSON-RPC error
//! objects carrying the `mcp-re.*` wire code (spec §12/§13).
//!
//! The logic here is transport-agnostic (raw request bytes -> raw response
//! bytes). The stdio (MCPS-012) and Streamable HTTP (MCPS-013) harnesses wrap
//! this same handler in a transport so the conformance suite proves identical
//! Core outcomes across transports (ADR-MCPS-011).
//!
//! This crate (`mcp-re-conformance`) MAY use `std`; `mcp-re-core` stays pure.

use std::cell::RefCell;

use mcp_re_core::json_rpc_error_object;
use mcp_re_core::request_signing_preimage;
use mcp_re_core::response_signing_preimage;
use mcp_re_core::unix_to_rfc3339_utc;
use mcp_re_core::verify_request;
use mcp_re_core::InMemoryReplayCache;
use mcp_re_core::McpReError;
use mcp_re_core::SigningKey;
use mcp_re_core::TrustResolver;
use mcp_re_core::VerificationConfig;
use mcp_re_core::VerifiedRequest;
use mcp_re_core::REQUEST_META_KEY;
use mcp_re_core::RESPONSE_META_KEY;
use mcp_re_core::SIG_ALG_ED25519;
use mcp_re_core::VERSION_DRAFT_01;
use serde_json::json;
use serde_json::Value;

/// A native MCP-RE echo server. Holds the server signing key, the inbound trust
/// resolver, the verification policy, and a replay cache (interior mutability so
/// `handle` takes `&self` yet still detects replays across calls).
pub struct EchoServer {
    signing_key: SigningKey,
    server_signer: String,
    key_id: String,
    resolver: Box<dyn TrustResolver>,
    config: VerificationConfig,
    replay: RefCell<InMemoryReplayCache>,
}

impl EchoServer {
    /// Construct an echo server.
    ///
    /// * `signing_key` / `server_signer` / `key_id` — the server's response key.
    /// * `resolver` — resolves inbound request signers (caller-injected).
    /// * `expected_audience` — the audience this server accepts.
    /// * `max_clock_skew_secs` — symmetric freshness allowance.
    pub fn new(
        signing_key: SigningKey,
        server_signer: impl Into<String>,
        key_id: impl Into<String>,
        resolver: Box<dyn TrustResolver>,
        expected_audience: impl Into<String>,
        max_clock_skew_secs: i64,
    ) -> Self {
        EchoServer {
            signing_key,
            server_signer: server_signer.into(),
            key_id: key_id.into(),
            resolver,
            config: VerificationConfig {
                expected_audience: expected_audience.into(),
                max_clock_skew_secs,
            },
            replay: RefCell::new(InMemoryReplayCache::new(max_clock_skew_secs)),
        }
    }

    /// Handle one inbound request and return the raw response bytes (a signed
    /// MCP-RE response on success, or a JSON-RPC error object on any failure).
    /// Never panics.
    pub fn handle(&self, request_bytes: &[u8], now_unix: i64) -> Vec<u8> {
        // Best-effort id extraction for error responses (null if unavailable).
        let parsed: Option<Value> = serde_json::from_slice(request_bytes).ok();
        let id_value = parsed
            .as_ref()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(Value::Null);

        let verify_result = {
            // A poisoned/contended borrow must not panic; fail closed instead.
            match self.replay.try_borrow() {
                Ok(replay) => verify_request(
                    request_bytes,
                    self.resolver.as_ref(),
                    &*replay,
                    &self.config,
                    now_unix,
                ),
                Err(_) => Err(McpReError::ReplayCacheUnavailable),
            }
        };

        match verify_result {
            Ok(verified) => {
                match self.build_signed_response(parsed.as_ref(), &verified, now_unix, &id_value) {
                    Ok(bytes) => bytes,
                    Err(err) => json_rpc_error_object(&err, &id_value),
                }
            }
            Err(err) => json_rpc_error_object(&err, &id_value),
        }
    }

    /// Build and sign the echo response bound to the verified request.
    fn build_signed_response(
        &self,
        request: Option<&Value>,
        verified: &VerifiedRequest,
        now_unix: i64,
        id_value: &Value,
    ) -> Result<Vec<u8>, McpReError> {
        // Echo the request's params.arguments.text (empty string if absent).
        let echoed = request
            .and_then(|v| v["params"]["arguments"]["text"].as_str())
            .unwrap_or("")
            .to_string();

        let issued_at = unix_to_rfc3339_utc(now_unix);

        // Build the full JSON-RPC response with the response envelope; the
        // signature.value is omitted from the preimage (ADR-MCPS-004).
        let mut response = json!({
            "jsonrpc": "2.0",
            "id": id_value.clone(),
            "result": {
                "content": [ { "type": "text", "text": echoed } ],
                "_meta": {
                    RESPONSE_META_KEY: {
                        "request_hash": verified.request_hash,
                        "server_signer": self.server_signer,
                        "issued_at": issued_at,
                        "signature": {
                            "alg": SIG_ALG_ED25519,
                            "key_id": self.key_id,
                        }
                    }
                }
            }
        });

        let preimage = response_signing_preimage(&response)?;
        let signature = self.signing_key.sign(&preimage);

        // Insert the signature value into the response envelope.
        response["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
            Value::String(signature);

        serde_json::to_vec(&response).map_err(|_| McpReError::CanonicalizationFailed)
    }
}

/// Build a signed MCP-RE `tools/call` echo request (conformance/test helper).
///
/// Constructs the canonical request object, computes the request signing
/// preimage (ADR-MCPS-004), signs it with `signing_key`, and returns the
/// serialized wire bytes. Reused by tests and the stdio/HTTP harnesses to drive
/// the server with a known-valid request.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_request(
    signing_key: &SigningKey,
    signer: &str,
    key_id: &str,
    audience: &str,
    on_behalf_of: &str,
    authorization_hash: &str,
    nonce: &str,
    issued_at: &str,
    expires_at: &str,
    tool_text: &str,
    id: &str,
) -> Result<Vec<u8>, McpReError> {
    let mut request = json!({
        "id": id,
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "text": tool_text },
            "_meta": {
                REQUEST_META_KEY: {
                    "version": VERSION_DRAFT_01,
                    "signer": signer,
                    "on_behalf_of": on_behalf_of,
                    "audience": audience,
                    "authorization_hash": authorization_hash,
                    "nonce": nonce,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "signature": {
                        "alg": SIG_ALG_ED25519,
                        "key_id": key_id,
                    }
                }
            }
        }
    });

    let preimage = request_signing_preimage(&request)?;
    let signature = signing_key.sign(&preimage);
    request["params"]["_meta"][REQUEST_META_KEY]["signature"]["value"] = Value::String(signature);

    serde_json::to_vec(&request).map_err(|_| McpReError::CanonicalizationFailed)
}
