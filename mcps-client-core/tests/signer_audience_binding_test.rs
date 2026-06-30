//! MCPS-43 (#190): the audience tuple discriminates tenants/routes that share one
//! signer (wildcard / shared-SaaS). A request signed for tenant A's audience is
//! accepted only when the verifier expects exactly that audience; tenant B's
//! audience (same host, same signer) is rejected — hostname alone is insufficient.

use mcps_client_core::build_signed_tool_call;
use mcps_client_core::resolve_signer_audience;
use mcps_client_core::AudienceTuple;
use mcps_client_core::RequestSigningInputs;
use mcps_client_core::SignerAudienceBinding;
use mcps_client_core::SignerAudiencePolicy;
use mcps_client_core::TransportIdentity;
use mcps_core::parse_rfc3339_utc;
use mcps_core::verify_request_draft02;
use mcps_core::AuthorizationBinding;
use mcps_core::InMemoryReplayCache;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::VerificationConfig;
use serde_json::json;

const SEED: [u8; 32] = [42u8; 32];
const SIGNER: &str = "did:example:client";
const KEY_ID: &str = "client-key-1";
// One server signer serves many tenants on the same host (wildcard cert).
const SERVER_SIGNER: &str = "did:example:wildcard-saas";

fn aud(tenant: &str) -> AudienceTuple {
    AudienceTuple::new("https", "api.saas.example", 443, tenant, "tools", "prod").unwrap()
}

fn sign_for(audience_string: &str) -> Vec<u8> {
    let key = SigningKey::from_seed_bytes(&SEED);
    let inputs = RequestSigningInputs::with_default_canonicalization(
        SIGNER,
        KEY_ID,
        "user:alice",
        audience_string,
        AuthorizationBinding::OpaqueBytes {
            digest_alg: "sha256".to_string(),
            digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
        },
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        "2026-06-30T20:00:00Z",
        "2026-06-30T20:05:00Z",
    );
    build_signed_tool_call(&json!("req-1"), "echo", json!({}), &inputs, &key)
        .unwrap()
        .into_wire_bytes()
}

fn verify_with(bytes: &[u8], expected_audience: &str) -> Result<(), McpsError> {
    let key = SigningKey::from_seed_bytes(&SEED);
    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SIGNER, KEY_ID, key.public_key());
    let mut replay = InMemoryReplayCache::new(60);
    let config = VerificationConfig {
        expected_audience: expected_audience.to_string(),
        max_clock_skew_secs: 60,
    };
    let now = parse_rfc3339_utc("2026-06-30T20:00:00Z").unwrap();
    verify_request_draft02(bytes, &resolver, &mut replay, &config, now).map(|_| ())
}

#[test]
fn tenant_audience_discriminates_a_shared_signer() {
    let tenant_a = aud("acme");
    let request = sign_for(&tenant_a.to_audience_string());

    // The verifier expecting tenant A's audience accepts.
    assert!(verify_with(&request, &tenant_a.to_audience_string()).is_ok());

    // The SAME bytes, but the verifier expects tenant B's audience (same host,
    // same signer) -> rejected. Hostname alone would have wrongly accepted.
    let tenant_b = aud("globex");
    assert_eq!(
        verify_with(&request, &tenant_b.to_audience_string()).unwrap_err(),
        McpsError::InvalidAudience
    );
}

#[test]
fn resolved_binding_drives_the_request_audience() {
    // Resolve (signer, audience) from policy + verified transport, then sign with it.
    let binding = SignerAudienceBinding {
        expected_server_signer: SERVER_SIGNER.to_string(),
        audience: aud("acme"),
    };
    let policy = SignerAudiencePolicy::new().bind(binding);
    let transport = TransportIdentity {
        verified_host: "api.saas.example".to_string(),
        verified_identity: Some("spiffe://saas/acme".to_string()),
    };
    let resolved = resolve_signer_audience(&policy, &transport, "tools").unwrap();
    assert_eq!(resolved.expected_server_signer, SERVER_SIGNER);

    let request = sign_for(&resolved.audience_string());
    assert!(verify_with(&request, &resolved.audience_string()).is_ok());
}
