//! MCPS-50 (#197) — discovery/enforcement conformance corpus (ADR-MCPS-043
//! §Compliance and Enforcement).
//!
//! The 14 acceptance vectors for stateless-primary discovery + the two normative
//! enforcement modes, exercised against the real `mcps-client-core` decision
//! surface (response verification → outcome classification → enforcement decision →
//! capability verdict → discovery). The corpus is the downgrade-resistance proof:
//! every "bad / inconsistent / downgrade-shaped" input fails closed, and a
//! stripped/tampered advert or an observability-only change never changes a verdict.
//!
//! Each vector is its own named test fn so the security traceability manifest can
//! map it (`//mcps-conformance:discovery_enforcement_conformance_test`).

use mcps_client_core::advert_mismatch;
use mcps_client_core::build_signed_tool_call;
use mcps_client_core::classify_response_result;
use mcps_client_core::decide;
use mcps_client_core::evaluate_capability;
use mcps_client_core::parse_legacy_advert;
use mcps_client_core::verify_signed_response;
use mcps_client_core::AbsenceReason;
use mcps_client_core::CapabilityPolicy;
use mcps_client_core::CapabilityVerdict;
use mcps_client_core::ClientPath;
use mcps_client_core::EnforcementDecision;
use mcps_client_core::EnforcementMode;
use mcps_client_core::EvidenceOutcome;
use mcps_client_core::ExchangeCapability;
use mcps_client_core::RequestSigningInputs;
use mcps_client_core::ResponseExpectation;
use mcps_core::response_signing_preimage;
use mcps_core::AuthorizationBinding;
use mcps_core::InMemoryTrustResolver;
use mcps_core::McpsError;
use mcps_core::SigningKey;
use mcps_core::TrustResolver;
use mcps_core::VerifiedResponse;
use mcps_core::{
    CANONICALIZATION_ID_INT53_V1, RESPONSE_META_KEY, SIG_ALG_ED25519, VERSION_DRAFT_01,
    VERSION_DRAFT_02,
};
use serde_json::json;
use serde_json::Value;

const CLIENT_SEED: [u8; 32] = [42u8; 32];
const SERVER_SEED: [u8; 32] = [99u8; 32];
const CLIENT_SIGNER: &str = "did:example:client";
const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_SIGNER: &str = "did:example:server";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server";

fn request_hash() -> String {
    let key = SigningKey::from_seed_bytes(&CLIENT_SEED);
    let inputs = RequestSigningInputs::with_default_canonicalization(
        CLIENT_SIGNER,
        CLIENT_KEY_ID,
        "user:alice",
        AUDIENCE,
        AuthorizationBinding::OpaqueBytes {
            digest_alg: "sha256".to_string(),
            digest_value: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_string(),
        },
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA",
        "2026-06-30T20:00:00Z",
        "2026-06-30T20:05:00Z",
    );
    build_signed_tool_call(
        &json!("req-1"),
        "echo",
        json!({ "text": "hi" }),
        &inputs,
        &key,
    )
    .unwrap()
    .request_hash()
    .to_string()
}

/// Build a response object, signed by `server_seed` under the given identity, then
/// apply `mutate` (e.g. to corrupt a field or set a bad selector) BEFORE returning
/// the serialized bytes. When `resign` is true the signature is computed after the
/// mutation (a validly-signed but semantically-bad response); when false the
/// signature is computed before, so post-mutation it is also signature-invalid.
fn response_bytes(
    request_hash: &str,
    server_seed: &[u8; 32],
    server_signer: &str,
    server_key_id: &str,
    resign: bool,
    mutate: impl FnOnce(&mut Value),
) -> Vec<u8> {
    let key = SigningKey::from_seed_bytes(server_seed);
    let mut object = json!({
        "jsonrpc": "2.0", "id": "req-1",
        "result": { "content": [{ "type": "text", "text": "hi" }], "_meta": { RESPONSE_META_KEY: {
            "version": VERSION_DRAFT_02,
            "canonicalization_id": CANONICALIZATION_ID_INT53_V1,
            "request_hash": request_hash,
            "server_signer": server_signer,
            "issued_at": "2026-06-30T20:00:01Z",
            "signature": { "alg": SIG_ALG_ED25519, "key_id": server_key_id },
        }}}
    });
    if resign {
        mutate(&mut object);
        let preimage = response_signing_preimage(&object).unwrap();
        object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
            Value::String(key.sign(&preimage));
    } else {
        let preimage = response_signing_preimage(&object).unwrap();
        object["result"]["_meta"][RESPONSE_META_KEY]["signature"]["value"] =
            Value::String(key.sign(&preimage));
        mutate(&mut object);
    }
    serde_json::to_vec(&object).unwrap()
}

/// A validly-signed, well-bound response (the happy path).
fn good_response(request_hash: &str) -> Vec<u8> {
    response_bytes(
        request_hash,
        &SERVER_SEED,
        SERVER_SIGNER,
        SERVER_KEY_ID,
        true,
        |_| {},
    )
}

fn resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(
        SERVER_SIGNER,
        SERVER_KEY_ID,
        SigningKey::from_seed_bytes(&SERVER_SEED).public_key(),
    );
    r
}

fn expectation(request_hash: &str) -> ResponseExpectation {
    ResponseExpectation::new(request_hash, CANONICALIZATION_ID_INT53_V1)
        .with_expected_server_signer(SERVER_SIGNER)
}

fn outcome(bytes: &[u8], rh: &str, resolver: &dyn TrustResolver) -> EvidenceOutcome {
    classify_response_result(verify_signed_response(bytes, resolver, &expectation(rh)))
}

fn draft02_exchange() -> ExchangeCapability {
    ExchangeCapability {
        version: VERSION_DRAFT_02.to_string(),
        canonicalization_id: Some(CANONICALIZATION_ID_INT53_V1.to_string()),
    }
}

// ---- 1. advertised + valid accepted under require_mcps ----------------------

#[test]
fn v01_advertised_and_valid_accepted_under_require_mcps() {
    let rh = request_hash();
    let out = outcome(&good_response(&rh), &rh, &resolver());
    assert!(matches!(out, EvidenceOutcome::Verified(_)));
    assert_eq!(
        decide(EnforcementMode::RequireMcps, false, &out),
        EnforcementDecision::AcceptMcps
    );
}

// ---- 2. absent under require_mcps rejected ----------------------------------

#[test]
fn v02_absent_under_require_mcps_rejected() {
    let out = EvidenceOutcome::Absent(AbsenceReason::PlainUnsigned);
    assert_eq!(
        decide(EnforcementMode::RequireMcps, true, &out),
        EnforcementDecision::FailClosed(McpsError::MissingEnvelope)
    );
}

// ---- 3. absent under explicit legacy accepted + audited ---------------------

#[test]
fn v03_absent_under_explicit_legacy_accepted_and_audited() {
    let out = EvidenceOutcome::Absent(AbsenceReason::PlainUnsigned);
    assert_eq!(
        decide(EnforcementMode::AllowLegacyExplicit, true, &out),
        EnforcementDecision::FallBackToLegacy {
            reason: AbsenceReason::PlainUnsigned
        }
    );
}

// ---- 4. unsigned response rejected (under require_mcps) ---------------------

#[test]
fn v04_unsigned_response_rejected() {
    let rh = request_hash();
    let plain = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": "req-1", "result": { "content": [] }
    }))
    .unwrap();
    let out = outcome(&plain, &rh, &resolver());
    // Absence (no envelope) -> fails closed under require_mcps.
    assert!(matches!(
        out,
        EvidenceOutcome::Absent(AbsenceReason::PlainUnsigned)
    ));
    assert!(matches!(
        decide(EnforcementMode::RequireMcps, true, &out),
        EnforcementDecision::FailClosed(_)
    ));
}

// ---- 5. invalid server_signer rejected --------------------------------------

#[test]
fn v05_invalid_server_signer_rejected() {
    let rh = request_hash();
    // Signed by an identity the resolver does not know.
    let bytes = response_bytes(
        &rh,
        &[7u8; 32],
        "did:example:evil",
        "evil-key",
        true,
        |_| {},
    );
    let out = outcome(&bytes, &rh, &resolver());
    assert!(matches!(
        out,
        EvidenceOutcome::Invalid(McpsError::ActorBindingFailed)
    ));
    assert!(matches!(
        decide(EnforcementMode::AllowLegacyExplicit, true, &out),
        EnforcementDecision::FailClosed(_)
    ));
}

// ---- 6. unsupported version rejected (downgrade-shaped) ---------------------

#[test]
fn v06_unsupported_version_rejected_is_bad_evidence() {
    let rh = request_hash();
    let bytes = response_bytes(&rh, &SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID, true, |o| {
        o["result"]["_meta"][RESPONSE_META_KEY]["version"] = json!("draft-99");
    });
    let out = outcome(&bytes, &rh, &resolver());
    // Bad evidence (NOT absence) -> never an eligible fallback.
    assert!(matches!(out, EvidenceOutcome::Invalid(_)));
    assert!(matches!(
        decide(EnforcementMode::AllowLegacyExplicit, true, &out),
        EnforcementDecision::FailClosed(_)
    ));
}

// ---- 7. unsupported canonicalization_id rejected (downgrade-shaped) ---------

#[test]
fn v07_unsupported_canonicalization_id_rejected_is_bad_evidence() {
    let rh = request_hash();
    let bytes = response_bytes(&rh, &SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID, true, |o| {
        o["result"]["_meta"][RESPONSE_META_KEY]["canonicalization_id"] =
            json!("mcps-jcs-floats-v2");
    });
    let out = outcome(&bytes, &rh, &resolver());
    assert!(matches!(out, EvidenceOutcome::Invalid(_)));
    assert!(matches!(
        decide(EnforcementMode::AllowLegacyExplicit, true, &out),
        EnforcementDecision::FailClosed(_)
    ));
}

// ---- 8. advert vs message mismatch does not downgrade -----------------------

#[test]
fn v08_advert_vs_message_mismatch_does_not_downgrade() {
    // The advert claims only draft-01, the verified exchange used draft-02. The
    // capability verdict (driven by the exchange) is SatisfiesPolicy; the advert
    // disagreement is observable but LOG-only.
    let advert = parse_legacy_advert(
        &json!({ "experimental": { "se.syncom/mcps": { "versions": ["draft-01"] } } }),
    )
    .unwrap();
    let exchange = draft02_exchange();
    assert_eq!(
        evaluate_capability(&exchange, &CapabilityPolicy::draft02_only()),
        CapabilityVerdict::SatisfiesPolicy
    );
    assert!(advert_mismatch(&advert, &exchange));
}

// ---- 9. stripped discovery does not downgrade -------------------------------

#[test]
fn v09_stripped_discovery_does_not_downgrade() {
    // No advert at all; the verdict is unchanged (the exchange is authoritative).
    assert!(parse_legacy_advert(&json!({ "experimental": {} })).is_none());
    assert_eq!(
        evaluate_capability(&draft02_exchange(), &CapabilityPolicy::draft02_only()),
        CapabilityVerdict::SatisfiesPolicy
    );
}

// ---- 10. tampered discovery does not weaken policy --------------------------

#[test]
fn v10_tampered_discovery_does_not_weaken_policy() {
    // A tampered advert claiming no MCP-S support cannot lower the verdict.
    let _tampered =
        parse_legacy_advert(&json!({ "experimental": { "se.syncom/mcps": { "versions": [] } } }));
    assert_eq!(
        evaluate_capability(&draft02_exchange(), &CapabilityPolicy::draft02_only()),
        CapabilityVerdict::SatisfiesPolicy
    );
}

// ---- 11. unknown key in the signed region fails closed ----------------------

#[test]
fn v11_unknown_key_in_signed_region_fails_closed() {
    let rh = request_hash();
    // Inject an unknown member into the response envelope and re-sign: the envelope
    // is structurally invalid (deny_unknown_fields), so it fails closed as bad
    // evidence, never as absence.
    let bytes = response_bytes(&rh, &SERVER_SEED, SERVER_SIGNER, SERVER_KEY_ID, true, |o| {
        o["result"]["_meta"][RESPONSE_META_KEY]["surprise"] = json!("unknown");
    });
    let out = outcome(&bytes, &rh, &resolver());
    assert!(matches!(out, EvidenceOutcome::Invalid(_)));
    assert!(!matches!(out, EvidenceOutcome::Absent(_)));
}

// ---- 12. observability change does not change the decision ------------------

#[test]
fn v12_observability_change_does_not_change_decision() {
    let rh = request_hash();
    let baseline = good_response(&rh);
    // Add a container-level trace key to result._meta AFTER signing — it is excluded
    // from the preimage, so the signature still verifies and the verdict is identical.
    let mut object: Value = serde_json::from_slice(&baseline).unwrap();
    object["result"]["_meta"]["traceparent"] = json!("00-aaaa-bbbb-01");
    let traced = serde_json::to_vec(&object).unwrap();

    let r = resolver();
    let base_out = outcome(&baseline, &rh, &r);
    let traced_out = outcome(&traced, &rh, &r);
    assert!(matches!(base_out, EvidenceOutcome::Verified(_)));
    assert!(matches!(traced_out, EvidenceOutcome::Verified(_)));
    assert_eq!(
        decide(EnforcementMode::RequireMcps, false, &base_out),
        decide(EnforcementMode::RequireMcps, false, &traced_out)
    );
}

// ---- 13. legacy explicitly allowed succeeds + marked ------------------------

#[test]
fn v13_legacy_explicitly_allowed_succeeds_and_marked() {
    let out = EvidenceOutcome::Absent(AbsenceReason::PlainUnsigned);
    let decision = decide(EnforcementMode::AllowLegacyExplicit, true, &out);
    let audit = mcps_client_core::audit_for_decision(&decision);
    assert_eq!(audit.path, ClientPath::LegacyExplicit);
    assert_eq!(
        audit.outcome,
        mcps_client_core::ClientOutcome::FellBackToLegacy
    );
    // Not allowlisted -> fails closed even in migration mode.
    assert!(matches!(
        decide(EnforcementMode::AllowLegacyExplicit, false, &out),
        EnforcementDecision::FailClosed(_)
    ));
}

// ---- 14. request_hash mismatch rejected (response-binding) ------------------

#[test]
fn v14_request_hash_mismatch_rejected() {
    let rh = request_hash();
    // A validly-signed response that binds a DIFFERENT request hash.
    let bytes = good_response("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let out = outcome(&bytes, &rh, &resolver());
    assert!(matches!(
        out,
        EvidenceOutcome::Invalid(McpsError::ResponseHashMismatch)
    ));
    assert!(matches!(
        decide(EnforcementMode::AllowLegacyExplicit, true, &out),
        EnforcementDecision::FailClosed(_)
    ));
}

/// Belt-and-suspenders: a `VerifiedResponse` is only producible by real
/// verification (its constructor is crate-private to mcps-core), so the accept
/// vectors above cannot be faked.
fn _proof_token_is_unforgeable(_v: &VerifiedResponse) {}
