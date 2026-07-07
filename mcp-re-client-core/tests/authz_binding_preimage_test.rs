//! MCPS-45 (#192): a binding produced by an `AuthorizationBindingProvider` is
//! included VERBATIM in the signed request preimage and survives server-side
//! verification — proving the bind path is end-to-end and the core never alters or
//! interprets the binding.

use mcp_re_client_core::build_signed_tool_call;
use mcp_re_client_core::resolve_authorization_binding;
use mcp_re_client_core::AuthorizationBindingPolicy;
use mcp_re_client_core::BindingRequestContext;
use mcp_re_client_core::OpaqueBytesProvider;
use mcp_re_client_core::RequestSigningInputs;
use mcp_re_core::parse_rfc3339_utc;
use mcp_re_core::verify_request_draft02;
use mcp_re_core::InMemoryReplayCache;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationConfig;
use mcp_re_core::{sha256_hash_id, AuthorizationBinding, VerifiedAuthorization};
use serde_json::json;

const SEED: [u8; 32] = [42u8; 32];
const SIGNER: &str = "did:example:client";
const KEY_ID: &str = "client-key-1";
const AUDIENCE: &str = "did:example:server";

#[test]
fn provider_binding_is_signed_and_verifies_unchanged() {
    let artifact = b"grant-token-bytes".to_vec();
    let provider = OpaqueBytesProvider::new(artifact.clone());
    let policy = AuthorizationBindingPolicy::both_base_forms();
    let ctx = BindingRequestContext {
        audience: AUDIENCE,
        route_id: "route-a",
        method: Some("tools/call"),
        tool_id: Some("echo"),
        deadline_unix: parse_rfc3339_utc("2026-06-30T20:05:00Z").unwrap(),
    };
    let binding = resolve_authorization_binding(&provider, &policy, &ctx).unwrap();

    let key = SigningKey::from_seed_bytes(&SEED);
    let inputs = RequestSigningInputs::with_default_canonicalization(
        SIGNER,
        KEY_ID,
        "user:alice",
        AUDIENCE,
        binding.clone(),
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        "2026-06-30T20:00:00Z",
        "2026-06-30T20:05:00Z",
    );
    let signed = build_signed_tool_call(
        &json!("req-1"),
        "echo",
        json!({ "text": "hi" }),
        &inputs,
        &key,
    )
    .unwrap();

    let mut resolver = InMemoryTrustResolver::new();
    resolver.insert(SIGNER, KEY_ID, key.public_key());
    let replay = InMemoryReplayCache::new(60);
    let config = VerificationConfig {
        expected_audience: AUDIENCE.to_string(),
        max_clock_skew_secs: 60,
    };
    let now = parse_rfc3339_utc("2026-06-30T20:00:00Z").unwrap();

    let verified =
        verify_request_draft02(signed.wire_bytes(), &resolver, &replay, &config, now).unwrap();

    // The verifier recovered EXACTLY the provider's binding (bind-not-interpret).
    let recovered = verified
        .authorization
        .draft02_binding()
        .expect("draft-02 binding");
    assert_eq!(recovered, &binding);

    // And it is the opaque-bytes digest over the EXACT artifact bytes.
    match recovered {
        AuthorizationBinding::OpaqueBytes { digest_value, .. } => {
            let expected = sha256_hash_id(&artifact)
                .strip_prefix("sha256:")
                .unwrap()
                .to_string();
            assert_eq!(digest_value, &expected);
        }
        _ => panic!("expected opaque-bytes"),
    }

    // Sanity: the verified authorization is the draft-02 (typed) profile.
    assert!(matches!(
        verified.authorization,
        VerifiedAuthorization::Draft02Binding { .. }
    ));
}
