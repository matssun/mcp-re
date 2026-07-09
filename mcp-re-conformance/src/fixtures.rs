//! Documented conformance fixtures (MCPS-012+).
//!
//! The fixed test identities and keys from MCP_RE_SPEC §10, in one place so every
//! conformance target — the in-process [`EchoServer`], the stdio harness
//! (MCPS-012), and the Streamable HTTP harness (MCPS-013) — drives the SAME
//! server identity. These are documented TEST vectors, never production keys.
//!
//! Seeds: signer = `[1u8; 32]`, server = `[2u8; 32]`. The signer's public key is
//! `iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w` (matches the committed vectors'
//! `resolver.public_key_b64url`).

use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_proxy::Proxy;
use serde_json::json;
use serde_json::Value;

use crate::echo_server::EchoServer;

/// Request signer DID (the agent).
pub const SIGNER: &str = "did:example:agent-1";
/// Request signer key id.
pub const SIGNER_KEY_ID: &str = "key-1";
/// Server signer DID (also the accepted audience).
pub const SERVER: &str = "did:example:server-1";
/// Server signer key id.
pub const SERVER_KEY_ID: &str = "server-key-1";
/// The audience this server accepts (equals [`SERVER`]).
pub const AUDIENCE: &str = "did:example:server-1";
/// The end user the agent acts on behalf of.
pub const ON_BEHALF_OF: &str = "did:example:user-1";
/// Authorization hash carried in the documented request envelope.
pub const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
/// Documented `issued_at` for the canonical request window.
pub const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
/// Documented `expires_at` for the canonical request window.
pub const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
/// Symmetric clock-skew allowance used across all conformance harnesses.
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// The agent's signing key (seed `[1u8; 32]`).
pub fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}

/// The server's signing key (seed `[2u8; 32]`).
pub fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}

/// Resolver a SERVER uses to verify inbound requests (knows the signer key).
pub fn inbound_resolver() -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    resolver
}

/// Resolver a CLIENT uses to verify server responses (knows the server key).
pub fn response_resolver() -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    resolver
}

/// Build the documented echo server: server key + inbound resolver + the
/// accepted audience and the standard skew allowance.
pub fn documented_echo_server() -> EchoServer {
    EchoServer::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        MAX_CLOCK_SKEW_SECS,
    )
}

/// A plain, MCP-RE-unaware inner server: echoes `params.arguments.text` in an
/// ordinary JSON-RPC result. It never sees the transport envelope (the proxy
/// strips it) and holds no keys — exactly an "unmodified inner MCP server".
pub fn plain_echo_inner(request: &[u8]) -> Vec<u8> {
    let value: Value = match serde_json::from_slice(request) {
        Ok(value) => value,
        Err(_) => Value::Null,
    };
    let text = value["params"]["arguments"]["text"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "content": [ { "type": "text", "text": text } ] }
    });
    serde_json::to_vec(&response).unwrap_or_default()
}

/// Build the documented sidecar: the MCP-RE proxy (same key/resolver/audience as
/// the native server) fronting the unmodified [`plain_echo_inner`].
pub fn documented_proxy_server() -> Proxy {
    Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        MAX_CLOCK_SKEW_SECS,
    )
    .with_async_inner(Box::new(plain_echo_inner))
}
