// SPDX-License-Identifier: Apache-2.0
//! MCPRE-101 — full-profile body-block integration battery.
//!
//! Activates the previously-inert `se.syncom/mcp-re.http.request` /
//! `.response` body evidence blocks: profile + audience + strict artifact
//! enforcement on the request, `server_signer` + `request_evidence` on the
//! response, and the explicit `request_binding_mismatch` path on top of the
//! cryptographic `;req` floor.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            ("client-key-1", SignerSlot::Request) => ("client", client_key()),
            ("server-key-1", SignerSlot::Response) => ("server", server_key()),
            _ => return None,
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: key_id.into(),
            },
            verification_key: key.public_key(),
            slot,
        })
    }
}

fn server_identity() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: "server-key-1".into(),
    }
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "verifier-1".into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

/// A single DPoP binding over `token` (the ath primitive over the access token).
fn dpop_over(token: &[u8]) -> ArtifactBinding {
    ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, token)
}

fn request_block(bindings: Vec<ArtifactBinding>) -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: bindings,
        continuation: None,
        admission: None,
        admission_assertion: None,
    }
}

/// A JSON-RPC request carrying an `Authorization: Bearer` header (covered, and
/// the DPoP credential surface).
fn base_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    }
}

/// Sign a full-profile request with the given block; returns (request, evidence).
fn signed_full_request(
    block: &HttpRequestEvidenceBlock,
) -> (HttpRequest, mcp_re_http_profile::RequestEvidence) {
    let mut req = base_request();
    let ev = sign_request_full(
        &mut req,
        block,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("full sign");
    (req, ev)
}

/// The default resolver never supplies caller material — DPoP is header-derived.
fn no_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |_b: &ArtifactBinding| None
}

// ---------- positive full roundtrip ----------------------------------------

#[test]
fn full_request_roundtrip_exposes_audience_and_block() {
    let block = request_block(vec![dpop_over(ACCESS_TOKEN.as_bytes())]);
    let (req, _ev) = signed_full_request(&block);
    let v = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .expect("full request verifies");
    assert_eq!(v.audience().audience_id, "verifier-1");
    assert_eq!(v.audience_hash(), audience().audience_hash());
    // The claim "the full path populated the block" is now the return type, so what is
    // left to assert is the block's agreement with the signature it was protected by.
    assert_eq!(v.request_block().profile, v.profile_id());
    assert_eq!(v.resolved_actor().identity.role, "client");
}

#[test]
fn full_response_roundtrip_binds_request_evidence() {
    let block = request_block(vec![dpop_over(ACCESS_TOKEN.as_bytes())]);
    let (req, ev) = signed_full_request(&block);
    let verified = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .expect("request verifies");

    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response_full(
        &mut rsp,
        &req,
        &ev,
        &server_identity(),
        &server_key(),
        "server-key-1",
        CREATED,
        EXPIRES,
    )
    .expect("full response sign");

    let rv = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_bound_response(&rsp, &req, verified.evidence(), NOW)
        .expect("full response verifies");
    assert_eq!(
        rv.request_evidence_agreement.bound_request_evidence,
        rv.request_evidence_agreement.body_request_evidence
    );
    assert_eq!(rv.server_signer.keyid, "server-key-1");
}

// ---------- request-side negatives -----------------------------------------

#[test]
fn missing_request_block_fails_in_full_profile() {
    // A request signed WITHOUT a body block: the minimal path would accept it,
    // full profile must not.
    let mut req = base_request();
    mcp_re_http_profile::sign_request(
        &mut req,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "n",
    )
    .expect("minimal sign");
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .unwrap_err();
    assert_eq!(
        err,
        HttpProfileError::MissingEvidence("request evidence block")
    );
    assert_eq!(err.wire_code(), "mcp-re.missing_envelope");
}

#[test]
fn wrong_profile_in_block_fails() {
    let mut block = request_block(vec![dpop_over(ACCESS_TOKEN.as_bytes())]);
    block.profile = "someone-elses-profile".into();
    let (req, _ev) = signed_full_request(&block);
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::UnknownProfileTag);
}

#[test]
fn audience_mismatch_fails() {
    let block = request_block(vec![dpop_over(ACCESS_TOKEN.as_bytes())]);
    let (req, _ev) = signed_full_request(&block);
    let mut wrong = audience();
    wrong.audience_id = "some-other-verifier".into();
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &wrong, &no_material(), NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::AudienceMismatch);
    assert_eq!(err.wire_code(), "mcp-re.invalid_audience");
}

#[test]
fn artifact_binding_mismatch_fails() {
    // Binding commits to a different token than the one in the Authorization
    // header actually presented.
    let block = request_block(vec![dpop_over(b"a-different-token")]);
    let (req, _ev) = signed_full_request(&block);
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::ArtifactBindingFailed);
    assert_eq!(err.wire_code(), "mcp-re.artifact_binding_failed");
}

#[test]
fn unverifiable_binding_without_material_fails_closed() {
    // An mTLS binding whose certificate bytes the verifier cannot obtain (no
    // caller material) must fail — full profile never silently accepts.
    let mtls = ArtifactBinding::opaque_digest(ArtifactType::OauthMtls, b"\x30\x82der");
    let block = request_block(vec![mtls]);
    let (req, _ev) = signed_full_request(&block);
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::ArtifactBindingFailed);
}

#[test]
fn caller_supplied_material_verifies_non_header_binding() {
    let cert = b"\x30\x82der-cert-bytes";
    let mtls = ArtifactBinding::opaque_digest(ArtifactType::OauthMtls, cert);
    let block = request_block(vec![mtls]);
    let (req, _ev) = signed_full_request(&block);
    let material = |b: &ArtifactBinding| match b.artifact_type {
        ArtifactType::OauthMtls => Some(cert.to_vec()),
        _ => None,
    };
    Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &material, NOW)
        .expect("caller-supplied mTLS material verifies");
}

// ---------- response-side negatives ----------------------------------------

#[test]
fn response_request_evidence_mismatch_emits_request_binding_mismatch() {
    // Sign a response whose body block carries the WRONG request_evidence (a
    // second request's handle) while the ;req binding is to req_a. The ;req
    // cryptographic floor passes, so the explicit body comparison is reached and
    // produces the precise request_binding_mismatch code.
    let block = request_block(vec![dpop_over(ACCESS_TOKEN.as_bytes())]);
    let (req_a, _ev_a) = signed_full_request(&block);
    let verified_a = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req_a, &audience(), &no_material(), NOW)
        .expect("req_a verifies");

    // A genuinely different request (distinct nonce) → a different evidence
    // handle than req_a's.
    let mut req_b = base_request();
    let ev_b = sign_request_full(
        &mut req_b,
        &block,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-DIFFERENT",
    )
    .expect("sign b");
    assert_ne!(ev_b.digest_value, verified_a.evidence().digest_value);

    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    // ;req is bound to req_a, but the body block advertises req_b's evidence.
    sign_response_full(
        &mut rsp,
        &req_a,
        &ev_b,
        &server_identity(),
        &server_key(),
        "server-key-1",
        CREATED,
        EXPIRES,
    )
    .expect("sign");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_bound_response(&rsp, &req_a, verified_a.evidence(), NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::ResponseBindingMismatch);
    assert_eq!(err.wire_code(), "mcp-re.request_binding_mismatch");
}

#[test]
fn cryptographic_req_splice_still_fails_at_the_floor() {
    // Two independent full exchanges; splice B's response onto A's request. The
    // ;req signature floor rejects BEFORE any body comparison is reached.
    let block = request_block(vec![dpop_over(ACCESS_TOKEN.as_bytes())]);
    let (req_a, _ev_a) = signed_full_request(&block);
    let verified_a = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req_a, &audience(), &no_material(), NOW)
        .expect("req_a verifies");

    let mut req_b = base_request();
    req_b.body =
        br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read"}}"#.to_vec();
    let ev_b = sign_request_full(
        &mut req_b,
        &block,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-2",
    )
    .expect("sign b");

    let mut rsp_b = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response_full(
        &mut rsp_b,
        &req_b,
        &ev_b,
        &server_identity(),
        &server_key(),
        "server-key-1",
        CREATED,
        EXPIRES,
    )
    .expect("sign resp b");

    // Present rsp_b as the answer to req_a: ;req base uses req_a, signature fails.
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_bound_response(&rsp_b, &req_a, verified_a.evidence(), NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::ResponseSignatureInvalid);
}

// ---------- one conjunct at a time ------------------------------------------
//
// The negatives above each move MORE than one thing, so none of them is evidence that a
// particular production check is load-bearing. These two isolate the conjuncts that
// otherwise had no control of their own.

/// The audience rule is a CONJUNCTION: the block's tuple equals the verifier's own, AND
/// that tuple's `target_uri` agrees with the request's `@target-uri`. `audience_mismatch_fails`
/// moves `audience_id`, so it fails on the first conjunct and would still fail if the
/// second were deleted.
///
/// Here the tuples are EQUAL — the block carries the verifier's own audience — and only
/// the request's target differs, which a routed or reverse-proxied deployment can produce
/// without the client noticing. The signature covers `@target-uri`, so the request is
/// signed at its real target and the floor is satisfied: only the consistency conjunct
/// refuses it.
#[test]
fn a_target_uri_disagreeing_with_the_audience_tuple_fails() {
    let block = request_block(vec![dpop_over(ACCESS_TOKEN.as_bytes())]);
    let mut req = base_request();
    req.target_uri = "https://mcp.example.com/mcp?route=b".into();
    sign_request_full(
        &mut req,
        &block,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("full sign at a different target");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::AudienceMismatch);
    assert_eq!(err.wire_code(), "mcp-re.invalid_audience");
}

/// The `server_signer` correspondence check, isolated.
///
/// The block declares a signer keyid the response was NOT signed under, while everything
/// else agrees: the signature verifies, the seam resolves the signing keyid for the
/// `Response` slot, and the `request_evidence` handle is the caller's own. Only the
/// correspondence comparison refuses it — which is what makes this the control for that
/// conjunct. The existing response negatives move the request evidence or the `;req`
/// base instead, and both would still fail with the correspondence check deleted.
#[test]
fn a_block_declaring_a_signer_it_did_not_sign_as_fails() {
    let block = request_block(vec![dpop_over(ACCESS_TOKEN.as_bytes())]);
    let (req, _ev) = signed_full_request(&block);
    let verified = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .expect("request verifies");

    let mut lying = server_identity();
    lying.keyid = "server-key-NOT-THE-SIGNER".into();

    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response_full(
        &mut rsp,
        &req,
        verified.evidence(),
        &lying,
        &server_key(),
        "server-key-1",
        CREATED,
        EXPIRES,
    )
    .expect("full response sign");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_bound_response(&rsp, &req, verified.evidence(), NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::ResponseBindingMismatch);
}
