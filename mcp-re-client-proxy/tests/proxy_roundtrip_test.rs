//! MCPS-49 (#196): the local proxy signs a plain-MCP request, forwards it to a
//! remote MCP-RE endpoint, verifies the signed response, and returns plain MCP —
//! proving the signed round-trip, the legacy-route path under explicit policy, and
//! transparency (the local client speaks plain MCP both ways).

use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::AuthorizationBindingPolicy;
use mcp_re_client_core::EnforcementMode;
use mcp_re_client_core::Environment;
use mcp_re_client_core::OpaqueBytesProvider;
use mcp_re_client_core::SignerAudienceBinding;
use mcp_re_client_core::SignerPolicy;
use mcp_re_client_core::SoftwareSigner;
use mcp_re_client_proxy::CallParams;
use mcp_re_client_proxy::ClientProxy;
use mcp_re_client_proxy::ProxyError;
use mcp_re_client_proxy::RemoteTransport;
use mcp_re_client_proxy::Route;
use mcp_re_client_proxy::RouteRegistry;
use mcp_re_client_proxy::TransportError;
use mcp_re_core::parse_rfc3339_utc;
use mcp_re_core::response_signing_preimage;
use mcp_re_core::verify_request_draft02;
use mcp_re_core::InMemoryReplayCache;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationConfig;
use mcp_re_core::{
    CANONICALIZATION_ID_INT53_V1, RESPONSE_META_KEY, SIG_ALG_ED25519, VERSION_DRAFT_02,
};
use serde_json::json;
use serde_json::Value;

const CLIENT_SEED: [u8; 32] = [42u8; 32];
const SERVER_SEED: [u8; 32] = [99u8; 32];
const CLIENT_SIGNER: &str = "did:example:client";
const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_SIGNER: &str = "did:example:server";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUED_AT: &str = "2026-06-30T20:00:00Z";
const EXPIRES_AT: &str = "2026-06-30T20:05:00Z";

fn audience() -> AudienceTuple {
    AudienceTuple::new("https", "api.example.com", 443, "acme", "tools", "prod").unwrap()
}

/// A remote MCP-RE endpoint: verifies the signed request and returns a signed
/// response bound to the request_hash.
struct McpReRemote;
impl RemoteTransport for McpReRemote {
    fn round_trip(&self, request_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        let client_key = SigningKey::from_seed_bytes(&CLIENT_SEED);
        let mut resolver = InMemoryTrustResolver::new();
        resolver.insert(CLIENT_SIGNER, CLIENT_KEY_ID, client_key.public_key());
        let mut replay = InMemoryReplayCache::new(60);
        let config = VerificationConfig {
            expected_audience: audience().to_audience_string(),
            max_clock_skew_secs: 60,
        };
        let now = parse_rfc3339_utc(ISSUED_AT).unwrap();
        let verified = verify_request_draft02(request_bytes, &resolver, &mut replay, &config, now)
            .map_err(|e| TransportError::new(format!("verify failed: {e}")))?;

        let server_key = SigningKey::from_seed_bytes(&SERVER_SEED);
        let mut object = json!({
            "jsonrpc": "2.0", "id": "req-1",
            "result": { "content": [{ "type": "text", "text": "pong" }], "_meta": { RESPONSE_META_KEY: {
                "version": VERSION_DRAFT_02,
                "canonicalization_id": CANONICALIZATION_ID_INT53_V1,
                "request_hash": verified.request_hash,
                "server_signer": SERVER_SIGNER,
                "issued_at": "2026-06-30T20:00:01Z",
                "signature": { "alg": SIG_ALG_ED25519, "key_id": SERVER_KEY_ID },
            }}}
        });
        let preimage = response_signing_preimage(&object).unwrap();
        object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
            Value::String(server_key.sign(&preimage));
        Ok(serde_json::to_vec(&object).unwrap())
    }
}

/// A legacy remote: returns a PLAIN, unsigned MCP response (no MCP-RE envelope).
struct LegacyRemote;
impl RemoteTransport for LegacyRemote {
    fn round_trip(&self, _request_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        Ok(serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": "req-1",
            "result": { "content": [{ "type": "text", "text": "legacy-pong" }] }
        }))
        .unwrap())
    }
}

fn route(mode: EnforcementMode, legacy_allowed: bool) -> Route {
    Route {
        route_id: "tools".to_string(),
        enforcement_mode: mode,
        legacy_allowed,
        signer_audience: SignerAudienceBinding {
            expected_server_signer: SERVER_SIGNER.to_string(),
            audience: audience(),
        },
        authz_policy: AuthorizationBindingPolicy::both_base_forms(),
        authz_provider: Box::new(OpaqueBytesProvider::new(b"grant".to_vec())),
    }
}

fn proxy<T: RemoteTransport + 'static>(route: Route, transport: T) -> ClientProxy {
    let signer = SoftwareSigner::new(
        SigningKey::from_seed_bytes(&CLIENT_SEED),
        CLIENT_SIGNER,
        CLIENT_KEY_ID,
    );
    let signer_policy = SignerPolicy::new(CLIENT_SIGNER, Environment::Production, true);
    let mut trust = InMemoryTrustResolver::new();
    trust.insert(
        SERVER_SIGNER,
        SERVER_KEY_ID,
        SigningKey::from_seed_bytes(&SERVER_SEED).public_key(),
    );
    ClientProxy::new(
        RouteRegistry::new().register(route),
        Box::new(signer),
        signer_policy,
        Box::new(trust),
        Box::new(transport),
    )
}

fn plain_request() -> Value {
    // Ordinary MCP — NO MCP-RE fields anywhere.
    json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": { "name": "echo", "arguments": { "text": "ping" } }
    })
}

fn params() -> CallParams {
    CallParams {
        on_behalf_of: "user:alice".to_string(),
        nonce: "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA".to_string(),
        issued_at: ISSUED_AT.to_string(),
        expires_at: EXPIRES_AT.to_string(),
        now_unix: parse_rfc3339_utc(ISSUED_AT).unwrap(),
        deadline_unix: parse_rfc3339_utc(EXPIRES_AT).unwrap(),
    }
}

#[test]
fn signed_round_trip_returns_plain_mcp() {
    let mut proxy = proxy(route(EnforcementMode::RequireMcpRe, false), McpReRemote);
    let req = plain_request();
    let out = proxy.handle("tools", &req, &params()).expect("round trip");

    // Transparency: the input carried no MCP-RE envelope...
    assert!(req["params"]["_meta"].is_null());
    // ...and the returned response is plain MCP with the envelope stripped.
    assert_eq!(out.plain_response["result"]["content"][0]["text"], "pong");
    assert!(out.plain_response["result"]["_meta"].is_null());
    assert_eq!(out.path, mcp_re_client_core::ClientPath::McpReVerified);
}

#[test]
fn legacy_route_under_explicit_policy_passes_through_audited() {
    // allow_legacy_explicit + legacy-allowlisted route + a plain/unsigned remote.
    let mut proxy = proxy(
        route(EnforcementMode::AllowLegacyExplicit, true),
        LegacyRemote,
    );
    let out = proxy
        .handle("tools", &plain_request(), &params())
        .expect("legacy fallback");
    assert_eq!(
        out.plain_response["result"]["content"][0]["text"],
        "legacy-pong"
    );
    // Audited as the explicit-legacy path (no runtime evidence).
    assert_eq!(out.path, mcp_re_client_core::ClientPath::LegacyExplicit);
    assert_eq!(
        out.audit.outcome,
        mcp_re_client_core::ClientOutcome::FellBackToLegacy
    );
}

#[test]
fn unsigned_response_under_require_mcp_re_fails_closed() {
    // Same plain/unsigned remote, but strict mode -> no fallback.
    let mut proxy = proxy(route(EnforcementMode::RequireMcpRe, true), LegacyRemote);
    let err = proxy
        .handle("tools", &plain_request(), &params())
        .unwrap_err();
    match err {
        ProxyError::FailedClosed(e) => assert_eq!(e.wire_code(), "mcp-re.missing_envelope"),
        other => panic!("expected fail-closed, got {other:?}"),
    }
}

#[test]
fn unknown_route_is_rejected() {
    let mut proxy = proxy(route(EnforcementMode::RequireMcpRe, false), McpReRemote);
    assert_eq!(
        proxy
            .handle("nope", &plain_request(), &params())
            .unwrap_err(),
        ProxyError::UnknownRoute("nope".to_string())
    );
}
