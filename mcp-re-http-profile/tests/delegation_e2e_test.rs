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
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::verify_delegated_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::DelegatedJwk;
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
use mcp_re_http_profile::VerifiedHttpRequestEvidence;
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
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec(),
    }
}

/// No caller-supplied artifact material — DPoP `ath` is header-derived.
fn no_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |_b: &ArtifactBinding| None
}

fn signed_request() -> (HttpRequest, RequestEvidence, VerifiedHttpRequestEvidence) {
    let mut req = base_request();
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
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
    let verified = verify_request_full(&req, &audience(), &no_material(), &resolver(), NOW)
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
        policy: mcp_re_http_profile::VerifierPolicy::default(),
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

    let rv = verify_delegated_response_full(
        &rsp,
        &req,
        &verified_req,
        &resolver(),
        &expectations(&[EPOCH]),
        &|_| false,
        NOW,
    )
    .expect("delegated response verifies");
    // The verified server actor is the delegated identity, authorized via the
    // credential chain (its verification key is the delegated key).
    assert_eq!(rv.server_signer.as_ref().unwrap().keyid, DELEGATED_KID);
    assert_eq!(
        rv.resolved_server_actor.verification_key.to_bytes(),
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

    let err = verify_delegated_response_full(
        &rsp,
        &req,
        &verified_req,
        &resolver(),
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
    let err = verify_delegated_response_full(
        &rsp,
        &req,
        &verified_req,
        &resolver(),
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
    let err = verify_delegated_response_full(
        &rsp,
        &req,
        &verified_req,
        &resolver(),
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
    let err = verify_delegated_response_full(
        &rsp,
        &req,
        &verified_req,
        &resolver(),
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
    let err = verify_delegated_response_full(
        &rsp,
        &req,
        &verified_req,
        &resolver(),
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
    let issue =
        move |h: &DelegationHeader, c: &DelegationClaims| Some(issue_delegation_credential(&root, h, c));
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

    let rv = verify_delegated_response_full(
        &rsp,
        &req,
        &verified_req,
        &resolver(),
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
        rv.server_signer.as_ref().unwrap().keyid,
        mcp_re_http_profile::jwk_thumbprint_ed25519(&first_issued.public_key().to_b64url()),
    );
    assert_eq!(custody.root_invocations(), 1, "root touched only at issuance");
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
    let err = verify_delegated_response_full(
        &rsp,
        &req,
        &verified_req,
        &resolver(),
        &expectations(&[EPOCH]),
        &|kid| kid == DELEGATED_KID,
        NOW,
    )
    .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationRevoked);
}
