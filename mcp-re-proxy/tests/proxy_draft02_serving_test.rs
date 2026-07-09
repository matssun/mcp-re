//! ADR-MCPS-045 Phase 3b.5 — the server sidecar SERVES draft-02 end to end.
//!
//! 3a wired the VERIFY step to `verify_request_dispatch`, but the forwarding +
//! response-signing path was still draft-01-only: a draft-02 verdict reaching
//! `build_forwarded_request` failed closed (it demanded a draft-01
//! `authorization_hash`). These tests pin the version-branched serving path:
//!
//!   * a draft-02 request verifies, forwards, and the proxy injects a draft-02
//!     verified context carrying `version` + `authorization_binding` (NOT a
//!     draft-01 `authorization_hash` placeholder);
//!   * the signed response carries the PROTECTED `version` + `canonicalization_id`
//!     and binds to the request hash (verifies through the client draft-02 path);
//!   * the draft-01 serving path is byte-for-byte unchanged (authorization_hash
//!     context, no `version` in either the context or the response envelope).
//!
//! The draft-02 request is signed by `mcp-re-client-core` (the real client seam);
//! the draft-01 request by `mcp-re-host` (the legacy ambassador).

use std::sync::Mutex;
use std::sync::Arc;

use mcp_re_client_core::build_signed_request_with_signer;
use mcp_re_client_core::verify_signed_response;
use mcp_re_client_core::Environment;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::SignerPolicy;
use mcp_re_client_core::SoftwareSigner;
use mcp_re_core::verify_response;
use mcp_re_core::AuthorizationBinding;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_core::CANONICALIZATION_ID_INT53_V1;
use mcp_re_core::RESPONSE_META_KEY;
use mcp_re_core::VERIFIED_META_KEY;
use mcp_re_host::HostSigner;
use mcp_re_proxy::test_support::block_on_handle;
use mcp_re_proxy::Proxy;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const NONCE: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
// A valid 32-byte b64url digest for the opaque-bytes binding.
const DIGEST: &str = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const SKEW: i64 = 300;

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn now() -> i64 {
    mcp_re_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}

fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

/// The bytes the inner server received (so the injected verified context is
/// observable).
type Captured = Arc<Mutex<Option<Value>>>;

/// A proxy wrapping a plain-MCP echo inner that records the forwarded request.
fn proxy_with_capture() -> (Proxy, Captured) {
    let captured: Captured = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses forwarded request");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        *sink.lock().unwrap() = Some(value);
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "content": [ { "type": "text", "text": "ok" } ] }
        }))
        .expect("serialize inner response")
    };
    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
    )
    .with_async_inner(Box::new(inner));
    (proxy, captured)
}

/// The verified-context block the proxy injected into the forwarded request.
fn injected_context(captured: &Captured) -> Value {
    captured
        .lock().unwrap()
        .as_ref()
        .expect("inner was reached")["params"]["_meta"][VERIFIED_META_KEY]
        .clone()
}

/// Sign a draft-02 `tools/call` via the real client-core seam.
fn signed_draft02() -> (Vec<u8>, String) {
    let signer = SoftwareSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID);
    let policy = SignerPolicy::new(SIGNER, Environment::Production, true);
    let binding = AuthorizationBinding::OpaqueBytes {
        digest_alg: "sha256".to_string(),
        digest_value: DIGEST.to_string(),
    };
    let inputs = RequestSigningInputs::with_default_canonicalization(
        SIGNER, SIGNER_KEY_ID, ON_BEHALF_OF, AUDIENCE, binding, NONCE, ISSUED_AT, EXPIRES_AT,
    );
    let mut params = Map::new();
    params.insert("name".to_string(), json!("echo"));
    params.insert("arguments".to_string(), json!({ "text": "hi" }));
    let signed = build_signed_request_with_signer(
        &json!("req-d02"),
        "tools/call",
        params,
        &inputs,
        &signer,
        &policy,
    )
    .expect("client-core signs draft-02");
    (signed.wire_bytes().to_vec(), signed.request_hash().to_string())
}

/// Sign a draft-01 `tools/call` via the legacy host ambassador.
fn signed_draft01() -> Vec<u8> {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
        .sign_tool_call(
            &json!("req-d01"),
            "echo",
            json!({ "text": "hi" }),
            ON_BEHALF_OF,
            AUDIENCE,
            "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o",
            NONCE,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs draft-01")
}

#[test]
fn draft02_request_forwards_with_a_draft02_verified_context() {
    let (proxy, captured) = proxy_with_capture();
    let (request, _hash) = signed_draft02();

    let response = block_on_handle(&proxy, &request, now());
    assert!(
        serde_json::from_slice::<Value>(&response).unwrap().get("error").is_none(),
        "draft-02 request must serve, not error: {}",
        String::from_utf8_lossy(&response)
    );

    let ctx = injected_context(&captured);
    assert_eq!(ctx["version"], "draft-02", "context must be the draft-02 profile");
    // The typed binding is attested — NOT a draft-01 authorization_hash sentinel.
    assert_eq!(ctx["authorization_binding"]["binding_type"], "opaque-bytes");
    assert_eq!(ctx["authorization_binding"]["digest_value"], DIGEST);
    assert!(
        ctx.get("authorization_hash").is_none(),
        "draft-02 context must NOT carry a draft-01 authorization_hash placeholder: {ctx}"
    );
    assert_eq!(ctx["canonicalization_id"], CANONICALIZATION_ID_INT53_V1);
}

#[test]
fn draft02_response_is_protected_and_request_bound() {
    let (proxy, _captured) = proxy_with_capture();
    let (request, request_hash) = signed_draft02();

    let response = block_on_handle(&proxy, &request, now());

    // The signed response carries the PROTECTED draft-02 identifiers.
    let parsed: Value = serde_json::from_slice(&response).expect("parse response");
    let envelope = &parsed["result"]["_meta"][RESPONSE_META_KEY];
    assert_eq!(envelope["version"], "draft-02");
    assert_eq!(envelope["canonicalization_id"], CANONICALIZATION_ID_INT53_V1);

    // ...and it verifies + binds to the request through the client draft-02 path.
    let expectation = ResponseExpectation::new(&request_hash, CANONICALIZATION_ID_INT53_V1)
        .with_expected_server_signer(SERVER);
    verify_signed_response(&response, &server_resolver(), &expectation)
        .expect("draft-02 response verifies and binds to the request hash");
}

#[test]
fn draft01_serving_path_is_unchanged() {
    let (proxy, captured) = proxy_with_capture();
    let request = signed_draft01();
    let expected_hash =
        mcp_re_core::request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).expect("hash");

    let response = block_on_handle(&proxy, &request, now());

    // Draft-01 context: the bare authorization_hash, no draft-02 protected fields.
    let ctx = injected_context(&captured);
    assert!(ctx["authorization_hash"].is_string(), "draft-01 keeps authorization_hash: {ctx}");
    assert!(ctx.get("version").is_none(), "draft-01 context carries no version: {ctx}");
    assert!(ctx.get("authorization_binding").is_none());

    // Draft-01 response: no protected version/canonicalization_id; binds via the
    // draft-01 verifier exactly as before.
    let parsed: Value = serde_json::from_slice(&response).expect("parse");
    let envelope = &parsed["result"]["_meta"][RESPONSE_META_KEY];
    assert!(envelope.get("version").is_none(), "draft-01 response carries no version");
    assert!(envelope.get("canonicalization_id").is_none());
    verify_response(&response, &server_resolver(), &expected_hash)
        .expect("draft-01 response still verifies + binds");
}
