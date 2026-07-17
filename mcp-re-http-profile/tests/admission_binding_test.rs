// SPDX-License-Identifier: Apache-2.0
//! Admission binding through the request evidence block (#414 §4.3/§5, #415 §7,
//! issue #433).
//!
//! The admission binding rides in the request evidence block — protected by
//! `content-digest`, like every other block field — and the §7 currency check
//! runs against the binding the verifier extracts from the signed body. The
//! load-bearing property: a signed, fresh, "admitted" assertion is STILL refused
//! once the authoritative generation has moved on. A snapshot is not currency.

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use sha2::Digest;
use sha2::Sha256;

use mcp_re_http_profile::check_admission;
use mcp_re_http_profile::issue_admission_assertion;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AdmissionBinding;
use mcp_re_http_profile::AdmissionClaims;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::AdmissionStatus;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::AuthoritativeAdmission;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const CLIENT_KEY_ID: &str = "client-key-1";
const ISSUER_KID: &str = "admission-root-1";
const TARGET: &str = "https://mcp.example.com/mcp";
const AUD: &str = "mcp.example.com";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[11u8; 32])
}
fn authority_root() -> SigningKey {
    SigningKey::from_seed_bytes(&[44u8; 32])
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    |kid: &str, slot: SignerSlot| {
        (kid == CLIENT_KEY_ID && slot == SignerSlot::Request).then(|| ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:client".into(),
                keyid: kid.into(),
            },
            verification_key: client_key().public_key(),
            slot,
        })
    }
}

fn issuer_resolver() -> impl Fn(&str) -> Option<mcp_re_core::VerificationKey> {
    |kid: &str| (kid == ISSUER_KID).then(|| authority_root().public_key())
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: AUD.into(),
        target_uri: TARGET.into(),
        route: None,
    }
}

fn admission_claims(generation: u64, status: AdmissionStatus) -> AdmissionClaims {
    AdmissionClaims {
        iss: "did:example:admission".into(),
        iat: NOW - 10,
        nbf: NOW - 10,
        exp: NOW + 300,
        jti: format!("adm#{generation}"),
        aud: mcp_re_http_profile::Audience::One(AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_admission_id: "workload-7".into(),
        mcp_re_admission_generation: generation,
        mcp_re_admitted_state_digest: b64url_encode(&Sha256::digest(b"admitted-state")),
        mcp_re_admission_status: status,
        issuer_kid: ISSUER_KID.into(),
    }
}

fn issue(c: &AdmissionClaims) -> String {
    issue_admission_assertion(c, |input| {
        b64url_decode(&authority_root().sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
    })
    .expect("issue")
}

/// Sign a request whose evidence block carries an admission binding. The binding
/// is protected because `content-digest` covers the body it sits in.
fn signed_request_with_admission(binding: Option<AdmissionBinding>) -> HttpRequest {
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), "Bearer tok".into()),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec(),
    };
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"tok")],
        continuation: None,
        admission: binding,
    };
    sign_request_full(&mut req, &block, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-adm")
        .expect("signs");
    req
}

/// Extract the admission binding a verified request carries and run the §7 check.
fn verify_and_check(
    req: &HttpRequest,
    assertion: &str,
    authoritative: Option<&AuthoritativeAdmission>,
    policy: &AdmissionPolicy,
) -> Result<(), HttpProfileError> {
    let verified = verify_request_full(
        req,
        &audience(),
        &|_b: &ArtifactBinding| None,
        &resolver(),
        NOW,
    )?;
    // The binding is inside the protected block the verifier just parsed.
    let binding = verified
        .request_block
        .as_ref()
        .and_then(|b| b.admission.clone())
        .expect("the request carries an admission binding");
    check_admission(
        &binding,
        assertion,
        authoritative,
        PROFILE_TAG,
        &[AUD],
        policy,
        NOW,
        issuer_resolver(),
    )
    .map(|_| ())
}

#[test]
fn a_bound_current_admitted_call_passes() {
    let claims = admission_claims(5, AdmissionStatus::Admitted);
    let req = signed_request_with_admission(Some(AdmissionBinding::opaque_from(&claims)));
    let auth = AuthoritativeAdmission { generation: 5, status: AdmissionStatus::Admitted };
    verify_and_check(&req, &issue(&claims), Some(&auth), &AdmissionPolicy::default())
        .expect("a current admitted workload is served");
}

/// THE case. The admission binding is signed into the request, the assertion is
/// fresh and says admitted — yet the authoritative generation is now 6. A snapshot
/// does not confer currency, so the call is refused.
#[test]
fn a_bound_but_stale_generation_is_refused() {
    let claims = admission_claims(5, AdmissionStatus::Admitted);
    let req = signed_request_with_admission(Some(AdmissionBinding::opaque_from(&claims)));
    let auth = AuthoritativeAdmission { generation: 6, status: AdmissionStatus::Admitted };
    assert_eq!(
        verify_and_check(&req, &issue(&claims), Some(&auth), &AdmissionPolicy::default())
            .unwrap_err(),
        HttpProfileError::AdmissionNotCurrent,
    );
}

/// The binding is covered by the signature: tampering it after signing breaks the
/// request's content-digest, so an attacker cannot swap in a higher generation.
#[test]
fn tampering_the_admission_binding_breaks_the_signature() {
    let claims = admission_claims(5, AdmissionStatus::Admitted);
    let mut req = signed_request_with_admission(Some(AdmissionBinding::opaque_from(&claims)));
    // Rewrite the bound generation in the signed body.
    let body = String::from_utf8(req.body.clone()).unwrap();
    req.body = body.replace("\"generation\":5", "\"generation\":6").into_bytes();
    assert!(
        verify_request_full(&req, &audience(), &|_b: &ArtifactBinding| None, &resolver(), NOW)
            .is_err(),
        "a tampered admission binding must fail the content-digest"
    );
}

/// A request that carries no admission binding is served when admission is not
/// enforced — the binding is optional, so admission-free deployments are unchanged.
#[test]
fn no_binding_verifies_when_admission_is_not_enforced() {
    let req = signed_request_with_admission(None);
    let verified = verify_request_full(&req, &audience(), &|_b: &ArtifactBinding| None, &resolver(), NOW)
        .expect("verifies");
    assert!(verified.request_block.as_ref().unwrap().admission.is_none());
}
