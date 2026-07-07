//! MCPS-023 — opt-in Phase 5 policy enforcement on the sidecar (ADR-MCPS-013).
//!
//! With a `PolicyEvaluator` attached, the proxy evaluates the authorization
//! artifact AFTER Core verification and BEFORE dispatch: out-of-scope, revoked,
//! expired, or unauthorized requests fail closed (the inner server is never
//! reached) with the matching `mcp-re.authorization_*` error. Without an evaluator
//! the proxy behaves exactly as a pre-Phase-5 sidecar.

use std::sync::Mutex;
use std::sync::Arc;

use mcp_re_core::canonicalize;
use mcp_re_core::request_hash;
use mcp_re_core::sha256_hash_id;
use mcp_re_core::verify_response;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_host::HostSigner;
use mcp_re_policy::mint_reference_grant;
use mcp_re_policy::GrantedOperation;
use mcp_re_policy::InMemoryRevocationSource;
use mcp_re_policy::PolicyEvaluator;
use mcp_re_policy::ReferenceGrantSpec;
use mcp_re_policy::ReferenceProfile;
use mcp_re_policy::RevocationSource;
use mcp_re_policy::RevocationStatus;
use mcp_re_policy::RevocationUnavailable;
use mcp_re_policy::AUTHORIZATION_META_KEY;
use mcp_re_policy::REFERENCE_PROFILE_ID;
use mcp_re_proxy::ExactMatchBinding;
use mcp_re_proxy::IdentitySource;
use mcp_re_proxy::Proxy;
use mcp_re_proxy::TransportIdentity;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUER: &str = "did:example:authority-1";
const ISSUER_KEY_ID: &str = "authority-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const SKEW: i64 = 300;

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn issuer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[42u8; 32])
}
fn now() -> i64 {
    mcp_re_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}

/// A resolver holding BOTH the request signer key (Core) and the grant issuer key
/// (policy) — the proxy reuses one resolver for both.
fn resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r.insert(ISSUER, ISSUER_KEY_ID, issuer_key().public_key());
    r
}
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

type Calls = Arc<Mutex<Vec<Value>>>;

fn proxy_with_recorder(enforce: bool) -> (Proxy, Calls) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let calls_for_inner = Arc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses");
        let text = value["params"]["arguments"]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        calls_for_inner.lock().unwrap().push(value);
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "content": [ { "type": "text", "text": text } ] }
        }))
        .expect("serialize inner response")
    };

    let mut proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    );
    if enforce {
        let mut evaluator = PolicyEvaluator::new();
        evaluator.register(Box::new(ReferenceProfile::new()));
        proxy = proxy
            .with_policy_enforcement(evaluator, Box::new(InMemoryRevocationSource::new()));
    }
    (proxy, calls)
}

fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

fn spec(tool: &str) -> ReferenceGrantSpec {
    ReferenceGrantSpec {
        issuer: ISSUER.to_string(),
        grantee: SIGNER.to_string(),
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        operations: vec![GrantedOperation {
            method: "tools/call".to_string(),
            tool: tool.to_string(),
            arguments: None,
        }],
        not_before: GRANT_NOT_BEFORE.to_string(),
        expires_at: GRANT_EXPIRES_AT.to_string(),
        revocation_id: "rev-1".to_string(),
    }
}

/// Sign a tools/call request for `request_tool`, carrying a grant for `grant_tool`
/// (when `with_block`). Returns the signed request bytes.
fn signed_request(nonce: &str, request_tool: &str, grant_tool: &str, with_block: bool) -> Vec<u8> {
    let artifact = mint_reference_grant(&spec(grant_tool), &issuer_key(), ISSUER_KEY_ID).unwrap();
    let authorization_hash = sha256_hash_id(&canonicalize(&artifact).unwrap());

    let mut params = Map::new();
    params.insert("name".to_string(), json!(request_tool));
    params.insert("arguments".to_string(), json!({ "text": "hello" }));
    if with_block {
        let mut meta = Map::new();
        meta.insert(
            AUTHORIZATION_META_KEY.to_string(),
            json!({ "profile": REFERENCE_PROFILE_ID, "artifact": mcp_re_core::b64url_encode(&artifact) }),
        );
        params.insert("_meta".to_string(), Value::Object(meta));
    }
    host()
        .sign_request(
            &Value::String("req-1".to_string()),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            &authorization_hash,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs")
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse");
    value["error"]["message"].as_str().expect("message").to_string()
}

#[test]
fn enforced_in_scope_request_is_allowed_and_signed() {
    let (proxy, calls) = proxy_with_recorder(true);
    let request = signed_request("nonce-allow-01", "echo", "echo", true);
    let expected_hash =
        request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).unwrap();

    let response = proxy.handle(&request, now());

    assert_eq!(calls.lock().unwrap().len(), 1, "in-scope request reaches the inner once");
    // The inner never sees the MCP-RE authorization block.
    assert!(
        calls.lock().unwrap()[0]["params"]["_meta"]
            .get(AUTHORIZATION_META_KEY)
            .is_none(),
        "authorization block stripped before forwarding"
    );
    let verified = verify_response(&response, &server_resolver(), &expected_hash)
        .expect("response verifies and binds");
    assert_eq!(verified.server_signer(), SERVER);
}

#[test]
fn enforced_out_of_scope_request_is_denied_before_dispatch() {
    let (proxy, calls) = proxy_with_recorder(true);
    // Grant only `echo`, but call `delete_everything`.
    let request = signed_request("nonce-scope-01", "delete_everything", "echo", true);

    let response = proxy.handle(&request, now());

    assert_eq!(calls.lock().unwrap().len(), 0, "denied request must NOT reach the inner");
    assert_eq!(error_message(&response), "mcp-re.authorization_scope_denied");
}

#[test]
fn enforced_request_without_block_is_denied() {
    let (proxy, calls) = proxy_with_recorder(true);
    let request = signed_request("nonce-noblk-01", "echo", "echo", false);

    let response = proxy.handle(&request, now());

    assert_eq!(calls.lock().unwrap().len(), 0, "no authorization → inner never reached");
    assert_eq!(error_message(&response), "mcp-re.authorization_block_missing");
}

#[test]
fn enforced_revoked_grant_is_denied() {
    // Build a proxy whose revocation source revokes rev-1.
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let calls_for_inner = Arc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).unwrap();
        calls_for_inner.lock().unwrap().push(value);
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": "req-1", "result": {} })).unwrap()
    };
    let mut revocation = InMemoryRevocationSource::new();
    revocation.revoke("rev-1");
    let mut evaluator = PolicyEvaluator::new();
    evaluator.register(Box::new(ReferenceProfile::new()));
    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_policy_enforcement(evaluator, Box::new(revocation));

    let request = signed_request("nonce-revk-01", "echo", "echo", true);
    let response = proxy.handle(&request, now());

    assert_eq!(calls.lock().unwrap().len(), 0, "revoked grant → inner never reached");
    assert_eq!(error_message(&response), "mcp-re.authorization_revoked");
}

#[test]
fn unenforced_proxy_ignores_the_authorization_block_and_forwards() {
    // No policy enforcement: even an out-of-scope grant is irrelevant; the request
    // is forwarded exactly as a pre-Phase-5 sidecar (block stripped on the way in).
    let (proxy, calls) = proxy_with_recorder(false);
    let request = signed_request("nonce-unenf-01", "delete_everything", "echo", true);

    let response = proxy.handle(&request, now());

    assert_eq!(calls.lock().unwrap().len(), 1, "without enforcement the request is forwarded");
    assert!(
        calls.lock().unwrap()[0]["params"]["_meta"]
            .get(AUTHORIZATION_META_KEY)
            .is_none(),
        "authorization block is still stripped before forwarding"
    );
    // A normal signed response (not an authorization error).
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert!(value.get("error").is_none(), "no denial without enforcement");
}

#[test]
fn satisfied_transport_binding_does_not_rescue_failed_authz() {
    // CORE INVARIANT: a matching mTLS transport identity must NOT let an
    // out-of-scope (Phase 5) request through. Authorization is evaluated before
    // the binding; a denial fails closed even when the binding would pass.
    let (proxy, calls) = proxy_with_recorder(true);
    let proxy = proxy.with_transport_binding(Box::new(ExactMatchBinding::new()));
    // Grant only `echo`, but call `delete_everything`; identity == signer so the
    // ExactMatch binding is satisfied on its own.
    let request = signed_request("nonce-authz-bind", "delete_everything", "echo", true);
    let id = TransportIdentity::new(SIGNER, IdentitySource::UriSan);

    let response = proxy.handle_with_transport(&request, now(), Some(&id), None);

    assert_eq!(calls.lock().unwrap().len(), 0, "denied request must NOT reach the inner");
    assert_eq!(error_message(&response), "mcp-re.authorization_scope_denied");
}

/// `RevocationSource` is part of the public surface used to wire enforcement.
#[test]
fn revocation_source_trait_is_reachable() {
    let source = InMemoryRevocationSource::new();
    assert_eq!(
        source.revocation_status("rev-1"),
        Ok(RevocationStatus::NotRevoked)
    );
}

/// M-10: when the injected revocation source is UNAVAILABLE, the proxy must fail
/// closed with the DISTINCT `mcp-re.authorization_revocation_unavailable` token (not
/// `mcp-re.authorization_revoked`), and the inner must never be reached. This proves
/// the operational-vs-verdict split survives end-to-end through the PEP.
#[test]
fn enforced_unavailable_revocation_source_denies_with_distinct_token() {
    /// A revocation source whose backend is always indeterminate.
    struct AlwaysUnavailable;
    impl RevocationSource for AlwaysUnavailable {
        fn revocation_status(
            &self,
            _revocation_id: &str,
        ) -> Result<RevocationStatus, RevocationUnavailable> {
            Err(RevocationUnavailable::new("test backend down"))
        }
    }

    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let calls_for_inner = Arc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).unwrap();
        calls_for_inner.lock().unwrap().push(value);
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": "req-1", "result": {} })).unwrap()
    };
    let mut evaluator = PolicyEvaluator::new();
    evaluator.register(Box::new(ReferenceProfile::new()));
    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_policy_enforcement(evaluator, Box::new(AlwaysUnavailable));

    let request = signed_request("nonce-unavail-01", "echo", "echo", true);
    let response = proxy.handle(&request, now());

    assert_eq!(
        calls.lock().unwrap().len(),
        0,
        "an unavailable revocation backend must fail closed; inner never reached"
    );
    assert_eq!(
        error_message(&response),
        "mcp-re.authorization_revocation_unavailable",
        "an outage must surface its OWN token, distinct from authorization_revoked"
    );
}
