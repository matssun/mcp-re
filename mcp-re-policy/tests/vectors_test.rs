//! MCPS-022 — Phase 5 conformance vector runner (ADR-MCPS-013).
//!
//! Replays each committed vector in `tests/vectors/phase5_vectors.json` through
//! the REAL stack: `mcp_re_core::verify_request` (which MUST succeed — Core-level
//! failures are covered by the Phase 1–4 vectors) followed by
//! `PolicyEvaluator::evaluate` with the Reference Signed Authorization Profile.
//! The vectors are embedded at compile time (`include_str!`) so there is no
//! runtime filesystem dependency. Regenerate with
//! `bazel run //components/mcp-re/mcp-re-policy:gen_phase5_vectors`.

use mcp_re_core::verify_request;
use mcp_re_core::InMemoryReplayCache;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::VerificationConfig;
use mcp_re_core::VerificationKey;
use mcp_re_policy::AuthorizationDecision;
use mcp_re_policy::InMemoryRevocationSource;
use mcp_re_policy::PolicyEvaluator;
use mcp_re_policy::ReferenceProfile;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("vectors/phase5_vectors.json");

/// Build a resolver from the vector's trust entries (request signer + issuer).
fn resolver_from(trust: &Value) -> InMemoryTrustResolver {
    let mut resolver = InMemoryTrustResolver::new();
    for entry in trust.as_array().expect("trust is an array") {
        let signer = entry["signer"].as_str().expect("signer");
        let key_id = entry["key_id"].as_str().expect("key_id");
        let public_key = VerificationKey::from_b64url(entry["public_key"].as_str().expect("pk"))
            .expect("valid public key");
        resolver.insert(signer, key_id, public_key);
    }
    resolver
}

fn revocation_from(revoked: &Value) -> InMemoryRevocationSource {
    let mut source = InMemoryRevocationSource::new();
    for id in revoked.as_array().expect("revoked is an array") {
        source.revoke(id.as_str().expect("revocation id").to_string());
    }
    source
}

fn evaluator() -> PolicyEvaluator {
    let mut e = PolicyEvaluator::new();
    e.register(Box::new(ReferenceProfile::new()));
    e
}

/// The wire token (or "allow") that a decision represents.
fn decision_token(decision: &AuthorizationDecision) -> String {
    match decision {
        AuthorizationDecision::Allow => "allow".to_string(),
        AuthorizationDecision::Deny(err) => err.wire_code().to_string(),
    }
}

#[test]
fn every_committed_vector_replays_to_its_expected_decision() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS_JSON).expect("parse vectors json");
    assert!(!vectors.is_empty(), "vector set must not be empty");

    for vector in &vectors {
        let name = vector["name"].as_str().expect("name");
        let request = &vector["request"];
        let now_unix = vector["now_unix"].as_i64().expect("now_unix");
        let expected = vector["expected"].as_str().expect("expected");

        let resolver = resolver_from(&vector["trust"]);
        let revocation = revocation_from(&vector["revoked"]);
        let config = VerificationConfig {
            expected_audience: vector["config"]["expected_audience"]
                .as_str()
                .expect("expected_audience")
                .to_string(),
            max_clock_skew_secs: vector["config"]["max_clock_skew_secs"]
                .as_i64()
                .expect("max_clock_skew_secs"),
        };

        // Core verification MUST succeed for every Phase 5 vector — these vectors
        // exercise the policy layer, not Core's own failure paths.
        let request_bytes = serde_json::to_vec(request).expect("serialize request");
        let replay = InMemoryReplayCache::new(config.max_clock_skew_secs);
        let verified = verify_request(&request_bytes, &resolver, &replay, &config, now_unix)
            .unwrap_or_else(|e| {
                panic!("vector '{name}': Core verify_request must succeed, got {e}")
            });

        let decision = evaluator().evaluate(&verified, request, &resolver, &revocation, now_unix);
        assert_eq!(
            decision_token(&decision),
            expected,
            "vector '{name}': decision did not match expected"
        );
    }
}

#[test]
fn vector_set_covers_allow_and_every_deny_code() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS_JSON).expect("parse vectors json");
    let expected: std::collections::BTreeSet<String> = vectors
        .iter()
        .map(|v| v["expected"].as_str().expect("expected").to_string())
        .collect();

    for required in [
        "allow",
        "mcp-re.authorization_block_missing",
        "mcp-re.authorization_hash_mismatch",
        "mcp-re.authorization_profile_unsupported",
        "mcp-re.authorization_malformed",
        "mcp-re.authorization_signature_invalid",
        "mcp-re.authorization_signer_mismatch",
        "mcp-re.authorization_subject_mismatch",
        "mcp-re.authorization_audience_mismatch",
        "mcp-re.authorization_expired",
        "mcp-re.authorization_revoked",
        "mcp-re.authorization_scope_denied",
    ] {
        assert!(
            expected.contains(required),
            "vector set is missing coverage for '{required}'"
        );
    }
}
