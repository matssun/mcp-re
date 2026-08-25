// SPDX-License-Identifier: Apache-2.0
//! MCPRE-122 — delegated-signing end-to-end battery (ADR-MCPRE-052 §3).
//!
//! A full request → delegated-key response round trip: the root mints a compact
//! JWS delegation credential, the DELEGATED key signs the RFC 9421 response, and
//! `verify_delegated_response_full` verifies the credential chain to the root and
//! the response signature under `cnf.jwk`. Covers the response-path rulings:
//! required delegation mode (§3 step 1) and the `keyid == delegated_kid` /
//! sign-under-`cnf.jwk` check (§3 step 8). Credential-scope checks (aud, profile,
//! audience-hash, key-use, trust-epoch, revocation) are unit-tested in
//! `delegation.rs`.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::sign_delegated_response_unbound;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedJwk;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedMcpRequest;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::DELEGATION_ALG;
use mcp_re_http_profile::DELEGATION_TYP;
use mcp_re_http_profile::JWK_CRV_ED25519;
use mcp_re_http_profile::JWK_KTY_OKP;
use mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING;
use mcp_re_http_profile::PROFILE_TAG;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const DELEGATED_SEED: [u8; 32] = [44u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";

const ROOT_KID: &str = "root-kid";
const DELEGATED_KID: &str = "root-kid/delegated/1";
const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
fn delegated_key() -> SigningKey {
    SigningKey::from_seed_bytes(&DELEGATED_SEED)
}

/// Resolver: the client key for the Request slot, and the ROOT key (by its
/// `issuer_kid`) for the Response slot — the credential's issuer is resolved for
/// the Response slot. The DELEGATED key is never enrolled here; it is authorized
/// by the credential alone.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            ("client-key-1", SignerSlot::Request) => ("client", client_key()),
            (ROOT_KID, SignerSlot::Response) => ("server", root_key()),
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

/// The delegated server-signer identity — its `keyid` IS the delegated key id.
fn server_signer() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: DELEGATED_KID.into(),
    }
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

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

/// No caller-supplied artifact material — DPoP `ath` is header-derived.
fn no_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |_b: &ArtifactBinding| None
}

fn signed_request() -> (HttpRequest, RequestEvidence, VerifiedMcpRequest) {
    let mut req = base_request();
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
        admission: None,
        admission_assertion: None,
        authorization_decision: None,
    };
    let ev = sign_request_full(
        &mut req,
        &block,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("sign request");
    let verified = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_request(&req, &audience(), &no_material(), NOW)
        .expect("verify request");
    (req, ev, verified)
}

/// Mint a valid delegation credential (root-signed) binding the delegated key.
fn valid_credential() -> String {
    let d = delegated_key();
    let header = DelegationHeader {
        typ: DELEGATION_TYP.into(),
        alg: DELEGATION_ALG.into(),
        kid: ROOT_KID.into(),
    };
    let claims = DelegationClaims {
        iss: "did:example:server".into(),
        iat: CREATED,
        nbf: CREATED,
        exp: EXPIRES,
        jti: "evt-1".into(),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_audience_hash: AUD_SCOPE.into(),
        mcp_re_server_signer: server_signer().actor_id(),
        mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
        delegated_kid: DELEGATED_KID.into(),
        issuer_kid: ROOT_KID.into(),
        trust_epoch: EPOCH.into(),
        cnf: Cnf {
            jwk: DelegatedJwk {
                kty: JWK_KTY_OKP.into(),
                crv: JWK_CRV_ED25519.into(),
                kid: DELEGATED_KID.into(),
                x: d.public_key().to_b64url(),
            },
        },
    };
    issue_delegation_credential(&root_key(), &header, &claims)
}

fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: AUD_SCOPE,
        accepted_epochs: epochs,
        max_clock_skew: 60,
    }
}

fn response_body() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
}

// --- positive ---------------------------------------------------------------

#[test]
fn valid_delegated_response_verifies_under_cnf_key() {
    let (req, ev, verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_full(
        &mut rsp,
        &req,
        &ev,
        &server_signer(),
        &valid_credential(),
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign delegated response");

    let rv = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req,
            verified_req.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .expect("delegated response verifies");
    // The accepted signer is the delegated identity, authorized via the credential
    // chain (its verification key is the delegated key).
    assert_eq!(
        rv.signature_facts.accepted_signer.identity.keyid,
        DELEGATED_KID
    );
    assert_eq!(
        rv.signature_facts
            .accepted_signer
            .verification_key
            .to_bytes(),
        delegated_key().public_key().to_bytes()
    );
}

// --- required mode (step 1) -------------------------------------------------

#[test]
fn direct_root_signed_response_is_rejected_credential_missing() {
    // A response signed directly by the root (server) key with NO delegation
    // credential must be rejected in required mode.
    let (req, ev, verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    // server_signer keyid is the ROOT here, and sign under the root key directly.
    let root_signer = ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: ROOT_KID.into(),
    };
    sign_response_full(
        &mut rsp,
        &req,
        &ev,
        &root_signer,
        &root_key(),
        ROOT_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign direct-root response");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req,
            verified_req.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationCredentialMissing);
}

// --- step 8: keyid / cnf binding --------------------------------------------

#[test]
fn response_keyid_not_delegated_kid_is_key_mismatch() {
    // The credential authorizes DELEGATED_KID, but the response signature is made
    // under a different RFC 9421 keyid.
    let (req, ev, verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_full(
        &mut rsp,
        &req,
        &ev,
        &server_signer(), // block server_signer.keyid == DELEGATED_KID
        &valid_credential(),
        &delegated_key(),
        "some-other-kid", // RFC 9421 keyid ≠ delegated_kid
        CREATED,
        EXPIRES,
    )
    .expect("sign");
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req,
            verified_req.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationKeyMismatch);
}

#[test]
fn response_signed_by_key_other_than_cnf_is_key_mismatch() {
    // The response is signed by an ATTACKER key while claiming DELEGATED_KID; the
    // signature does not verify under cnf.jwk.
    let (req, ev, verified_req) = signed_request();
    let attacker = SigningKey::from_seed_bytes(&[99u8; 32]);
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_full(
        &mut rsp,
        &req,
        &ev,
        &server_signer(),
        &valid_credential(),
        &attacker,
        DELEGATED_KID, // keyid matches, but the key is wrong
        CREATED,
        EXPIRES,
    )
    .expect("sign");
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req,
            verified_req.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationKeyMismatch);
}

// --- body tamper (content-digest floor) -------------------------------------

#[test]
fn body_tamper_is_caught_by_content_digest() {
    let (req, ev, verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_full(
        &mut rsp,
        &req,
        &ev,
        &server_signer(),
        &valid_credential(),
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign");
    // Flip a byte in the covered body.
    let last = rsp.body.len() - 2;
    rsp.body[last] ^= 0x01;
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req,
            verified_req.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .unwrap_err();
    assert_eq!(err, HttpProfileError::ContentDigestMismatch);
}

// --- trust epoch (step 6), end-to-end ---------------------------------------

#[test]
fn stale_epoch_rejected_end_to_end() {
    let (req, ev, verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_full(
        &mut rsp,
        &req,
        &ev,
        &server_signer(),
        &valid_credential(), // minted under EPOCH
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign");
    // Verifier's accepted set has advanced past the credential's epoch.
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req,
            verified_req.evidence(),
            &expectations(&["epoch-2"]),
            &|_| false,
            NOW,
        )
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationTrustEpochStale);
}

// --- custody-produced response (slice 4), end-to-end ------------------------

fn custody_cfg() -> CustodyConfig {
    CustodyConfig {
        issuer_kid: ROOT_KID.into(),
        iss: "did:example:server".into(),
        profile: PROFILE_TAG.into(),
        aud: VERIFIER_AUD.into(),
        audience_hash: AUD_SCOPE.into(),
        trust_epoch: EPOCH.into(),
        server_role: "server".into(),
        server_trust_domain: "example.com".into(),
        server_subject: "did:example:server".into(),
        ttl: 300,
        overlap: 60,
    }
}

/// The full chain: the custody state machine issues a delegated key + credential
/// and signs a response; a verifier accepts it via the attestation chain to the
/// root, and the root was touched exactly once (issuance), never per request.
#[test]
fn custody_signed_response_verifies_via_attestation_chain() {
    let (req, ev, verified_req) = signed_request();
    let root = root_key();
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = 100u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let mut custody = DelegatedSigningCustody::new(custody_cfg(), issue, factory);

    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    custody
        .sign_response(NOW, &mut rsp, &req, &ev)
        .expect("custody signs");

    let rv = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req,
            verified_req.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .expect("custody-signed response verifies");
    // A custody-issued key is profile-issued, so its kid is the RFC 7638 JWK
    // thumbprint of the key itself (#415 rev 2 §1.5). The key factory above hands
    // out seed [101; 32] first, so the kid is that key's thumbprint — derived from
    // the key material, not from an issuance counter.
    let first_issued = SigningKey::from_seed_bytes(&[101u8; 32]);
    assert_eq!(
        rv.signature_facts.accepted_signer.identity.keyid,
        mcp_re_http_profile::jwk_thumbprint_ed25519(&first_issued.public_key().to_b64url()),
    );
    assert_eq!(
        custody.root_invocations(),
        1,
        "root touched only at issuance"
    );
}

// --- revocation (step 7), end-to-end ----------------------------------------

#[test]
fn revoked_delegated_key_rejected_end_to_end() {
    let (req, ev, verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_full(
        &mut rsp,
        &req,
        &ev,
        &server_signer(),
        &valid_credential(),
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign");
    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req,
            verified_req.evidence(),
            &expectations(&[EPOCH]),
            &|kid| kid == DELEGATED_KID,
            NOW,
        )
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationRevoked);
}

/// A delegated PREFLIGHT receipt verifies with no request context at all, and says so in
/// its type: `VerifiedDelegatedUnboundResponse` carries no request binding to misread.
///
/// The operation had no in-crate test before the theorem registry needed one. Its evidence
/// lived only in a proxy integration test, which is a different unit — so the claim about
/// this operation had nothing resolvable behind it.
#[test]
fn a_delegated_preflight_receipt_verifies_without_request_binding() {
    let (_req, ev, _verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 400,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_unbound(
        &mut rsp,
        &server_signer(),
        &valid_credential(),
        &ev,
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign unbound delegated receipt");

    let rv = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_unbound_response(&rsp, &expectations(&[EPOCH]), &|_| false, NOW)
        .expect("the preflight receipt verifies unbound");
    assert_eq!(
        rv.signature_facts.accepted_signer.identity.keyid,
        DELEGATED_KID
    );
    assert_eq!(rv.delegation_issuer_kid, ROOT_KID);
}

/// Delegation stays REQUIRED on the unbound path: a receipt with no inline credential —
/// including a directly root-signed one — is refused rather than accepted more leniently
/// because there is no request to bind to.
#[test]
fn an_unbound_receipt_without_a_credential_is_refused() {
    let (_req, ev, _verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 400,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_unbound(
        &mut rsp,
        &server_signer(),
        &valid_credential(),
        &ev,
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign unbound delegated receipt");
    // Strip the credential from the covered block: the digest changes with it, so this is
    // the "no credential presented" case rather than a tamper.
    let body: serde_json::Value = serde_json::from_slice(&rsp.body).expect("body");
    let mut stripped = body.clone();
    stripped["_meta"]["se.syncom/mcp-re.http.response"]
        .as_object_mut()
        .expect("response block")
        .remove("server_delegation");
    let mut plain = HttpResponse {
        status: 400,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&stripped).expect("re-encode"),
    };
    mcp_re_http_profile::sign::sign_response_unbound(
        &mut plain,
        &root_key(),
        ROOT_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign root-signed unbound response");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_unbound_response(&plain, &expectations(&[EPOCH]), &|_| false, NOW)
        .expect_err("a directly root-signed unbound receipt is refused");
    assert_eq!(err, HttpProfileError::DelegationCredentialMissing);
}

// --- the delegated conjuncts that had no control of their own ---------------

/// The delegated BOUND path makes the same explicit `request_evidence` comparison the
/// direct full path makes, and it is load-bearing there too. The `;req` floor cannot
/// substitute for it: here the `;req` binding is to `req_a` and verifies, while the block
/// advertises a different exchange's handle.
#[test]
fn a_delegated_response_advertising_another_requests_evidence_is_refused() {
    let (req_a, _ev_a, verified_a) = signed_request();

    // A second, genuinely different request → a different evidence handle.
    let mut req_b = base_request();
    let block_b = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
        admission: None,
        admission_assertion: None,
        authorization_decision: None,
    };
    let ev_b = sign_request_full(
        &mut req_b,
        &block_b,
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
        body: response_body(),
    };
    // ;req is bound to req_a; the block advertises req_b's handle.
    sign_delegated_response_full(
        &mut rsp,
        &req_a,
        &ev_b,
        &server_signer(),
        &valid_credential(),
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req_a,
            verified_a.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .unwrap_err();
    assert_eq!(err, HttpProfileError::ResponseBindingMismatch);
}

/// The cnf.jwk signature check on the UNBOUND delegated path. `an_unbound_receipt_without_a_credential_is_refused`
/// fails at step 1 and says nothing about whether the signature is ever checked; this
/// presents a complete, valid credential and signs under an attacker key.
#[test]
fn an_unbound_receipt_signed_by_a_key_other_than_cnf_is_key_mismatch() {
    let (_req, ev, _verified_req) = signed_request();
    let attacker = SigningKey::from_seed_bytes(&[98u8; 32]);
    let mut rsp = HttpResponse {
        status: 400,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_unbound(
        &mut rsp,
        &server_signer(),
        &valid_credential(),
        &ev,
        &attacker,
        DELEGATED_KID, // keyid matches the credential; the key does not
        CREATED,
        EXPIRES,
    )
    .expect("sign unbound receipt under the wrong key");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_unbound_response(&rsp, &expectations(&[EPOCH]), &|_| false, NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationKeyMismatch);
}

/// A `;req` component is refused on the delegated unbound path for the same reason it is
/// refused on the seam-authorized one: a verified credential chain does not conjure a
/// request to resolve the reference against.
#[test]
fn a_req_component_is_refused_on_the_delegated_unbound_path() {
    let (req, ev, _verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_full(
        &mut rsp,
        &req,
        &ev,
        &server_signer(),
        &valid_credential(),
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign a request-bound delegated response");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_unbound_response(&rsp, &expectations(&[EPOCH]), &|_| false, NOW)
        .unwrap_err();
    assert_eq!(
        err,
        HttpProfileError::MalformedEvidence("req component without request context")
    );
}

/// Content-digest verification stays load-bearing on the unbound delegated path — the
/// credential is carried INSIDE the covered body, so a digest check that stopped
/// mattering would let the credential itself be swapped.
#[test]
fn an_unbound_receipt_body_tamper_is_caught_by_content_digest() {
    let (_req, ev, _verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 400,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_unbound(
        &mut rsp,
        &server_signer(),
        &valid_credential(),
        &ev,
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign unbound delegated receipt");
    let last = rsp.body.len() - 2;
    rsp.body[last] ^= 0x01;

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_unbound_response(&rsp, &expectations(&[EPOCH]), &|_| false, NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::ContentDigestMismatch);
}

/// The unbound delegated path resolves the credential's ROOT ISSUER through the same
/// trust seam every other path uses, and a root nobody vouches for is refused. This is
/// the unbound counterpart of the chain's trust anchor: without it a self-issued
/// credential would authorize its own signer.
#[test]
fn an_unbound_receipt_whose_root_is_unknown_to_the_seam_is_untrusted() {
    let (_req, ev, _verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 400,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_unbound(
        &mut rsp,
        &server_signer(),
        &valid_credential(),
        &ev,
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign unbound delegated receipt");

    // A seam that knows the client but has never heard of this root.
    let seam = |key_id: &str, slot: SignerSlot| -> Option<ResolvedActor> {
        match (key_id, slot) {
            ("client-key-1", SignerSlot::Request) => Some(ResolvedActor {
                identity: ActorIdentity {
                    role: "client".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:client".into(),
                    keyid: key_id.into(),
                },
                verification_key: client_key().public_key(),
                slot,
            }),
            _ => None,
        }
    };
    let err = Verifier::new(&VerifierPolicy::default(), &seam)
        .verify_delegated_unbound_response(&rsp, &expectations(&[EPOCH]), &|_| false, NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationIssuerUntrusted);
}

/// A credential whose SUBJECT BINDING and CONFIRMED KEY name different key ids.
///
/// `mcp_re_server_signer` scopes the credential to `disowned-kid`, so a block declaring
/// that signer passes the credential's scope check; `cnf.jwk`/`delegated_kid` confirm
/// `DELEGATED_KID`, and the response is signed by that key under that wire keyid. Every
/// other conjunct is satisfied — the chain verifies, the wire keyid equals the credential's
/// delegated kid, the signature verifies under `cnf.jwk` — so only the comparison of the
/// BLOCK's declared keyid against the credential's delegated kid refuses it.
///
/// Without it the product's accepted-signer identity would carry `disowned-kid` while the
/// signature verified under the key confirmed for `DELEGATED_KID`: the identity a consumer
/// attributes the response to would not be the identity the signature was accepted under,
/// which is exactly what the correspondence conjunct claims.
fn credential_scoped_to_another_keyid() -> (String, ActorIdentity) {
    let mut disowned = server_signer();
    disowned.keyid = "disowned-kid".into();
    let d = delegated_key();
    let header = DelegationHeader {
        typ: DELEGATION_TYP.into(),
        alg: DELEGATION_ALG.into(),
        kid: ROOT_KID.into(),
    };
    let claims = DelegationClaims {
        iss: "did:example:server".into(),
        iat: CREATED,
        nbf: CREATED,
        exp: EXPIRES,
        jti: "evt-disowned".into(),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_audience_hash: AUD_SCOPE.into(),
        mcp_re_server_signer: disowned.actor_id(),
        mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
        delegated_kid: DELEGATED_KID.into(),
        issuer_kid: ROOT_KID.into(),
        trust_epoch: EPOCH.into(),
        cnf: Cnf {
            jwk: DelegatedJwk {
                kty: JWK_KTY_OKP.into(),
                crv: JWK_CRV_ED25519.into(),
                kid: DELEGATED_KID.into(),
                x: d.public_key().to_b64url(),
            },
        },
    };
    (
        issue_delegation_credential(&root_key(), &header, &claims),
        disowned,
    )
}

#[test]
fn a_block_naming_a_keyid_the_credential_did_not_confirm_is_key_mismatch() {
    let (req, ev, verified_req) = signed_request();
    let (credential, disowned) = credential_scoped_to_another_keyid();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_full(
        &mut rsp,
        &req,
        &ev,
        &disowned, // block keyid == the credential's subject binding, not its cnf kid
        &credential,
        &delegated_key(),
        DELEGATED_KID, // wire keyid == the credential's delegated kid
        CREATED,
        EXPIRES,
    )
    .expect("sign");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_bound_response(
            &rsp,
            &req,
            verified_req.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationKeyMismatch);
}

/// The same correspondence conjunct on the unbound path, where there is no request
/// evidence to cross-check the attribution against either.
#[test]
fn an_unbound_receipt_naming_a_keyid_the_credential_did_not_confirm_is_key_mismatch() {
    let (_req, ev, _verified_req) = signed_request();
    let (credential, disowned) = credential_scoped_to_another_keyid();
    let mut rsp = HttpResponse {
        status: 400,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_unbound(
        &mut rsp,
        &disowned,
        &credential,
        &ev,
        &delegated_key(),
        DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("sign");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_unbound_response(&rsp, &expectations(&[EPOCH]), &|_| false, NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationKeyMismatch);
}

/// The unbound analogue of `response_keyid_not_delegated_kid_is_key_mismatch`: the RFC 9421
/// wire keyid must be the credential's delegated kid, not merely a keyid whose signature
/// happens to verify under `cnf.jwk`.
///
/// The block names the confirmed kid and the signature verifies under the confirmed key,
/// so nothing else objects; only the wire-keyid comparison refuses it. Without it a
/// receipt could advertise an unconfirmed keyid on the wire — the coordinate a peer
/// caches, pins and reports — while presenting a credential for a different one.
#[test]
fn an_unbound_receipt_whose_wire_keyid_is_not_the_delegated_kid_is_key_mismatch() {
    let (_req, ev, _verified_req) = signed_request();
    let mut rsp = HttpResponse {
        status: 400,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_unbound(
        &mut rsp,
        &server_signer(), // block keyid == the credential's delegated kid
        &valid_credential(),
        &ev,
        &delegated_key(), // signed by the confirmed key
        "some-other-kid", // but advertised under a keyid the credential never confirmed
        CREATED,
        EXPIRES,
    )
    .expect("sign");

    let err = Verifier::new(&VerifierPolicy::default(), &resolver())
        .verify_delegated_unbound_response(&rsp, &expectations(&[EPOCH]), &|_| false, NOW)
        .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationKeyMismatch);
}
