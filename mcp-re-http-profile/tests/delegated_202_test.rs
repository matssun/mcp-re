// SPDX-License-Identifier: Apache-2.0
//! Delegated signed 202 via a covered credential header (#424, owner ruling
//! 2026-07-17).
//!
//! The ruling resolved the three-way conflict (§3.4 bodyless / delegated-only /
//! credential-in-body) by carrying the compact-JWS credential in a dedicated
//! `mcp-re-delegation` header that MUST be covered by the response signature. That
//! preserves all three: MCP's bodyless 202, delegated-only signing, and
//! self-contained verification.
//!
//! The load-bearing property is the coverage: an uncovered credential header is
//! one an intermediary could swap, so the negative that strips it from the covered
//! set is the point of the whole design.

use mcp_re_core::SigningKey;

use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_delegated_accepted_202;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::verify_delegated_accepted_202;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::DelegatedJwk;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::DELEGATION_ALG;
use mcp_re_http_profile::DELEGATION_TYP;
use mcp_re_http_profile::JWK_CRV_ED25519;
use mcp_re_http_profile::JWK_KTY_OKP;
use mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING;
use mcp_re_http_profile::MAX_DELEGATION_HEADER_LEN;
use mcp_re_http_profile::MCP_RE_DELEGATION_HEADER;
use mcp_re_http_profile::PROFILE_TAG;

const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const NOW: i64 = 1_700_000_100;
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const DELEGATED_KID: &str = "delegated-kid-1";
const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[11u8; 32])
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[33u8; 32])
}
fn delegated_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[55u8; 32])
}

fn server_signer() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: DELEGATED_KID.into(),
    }
}

/// The trust seam: the client key for Request, the ROOT (by issuer_kid) for
/// Response — the credential's issuer is resolved for the Response slot. The
/// delegated key is never enrolled; the credential authorizes it.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key().public_key()),
            (ROOT_KID, SignerSlot::Response) => ("server", root_key().public_key()),
            _ => return None,
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: key_id.into(),
            },
            verification_key: key,
            slot,
        })
    }
}

fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        policy: VerifierPolicy::default(),
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: AUD_SCOPE,
        accepted_epochs: epochs,
        max_clock_skew: 60,
    }
}

/// Mint a root-signed credential attesting `delegated_kid`/`server_signer`.
fn credential() -> String {
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
        jti: "evt-202".into(),
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

fn notification(nonce: &str) -> HttpRequest {
    notification_method(nonce, "notifications/initialized")
}

fn notification_method(nonce: &str, method: &str) -> HttpRequest {
    let mut r = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: format!(r#"{{"jsonrpc":"2.0","method":"{method}"}}"#).into_bytes(),
    };
    sign_request(&mut r, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, nonce)
        .expect("notification signs");
    r
}

fn no_revocation() -> impl Fn(&str) -> bool {
    |_| false
}

fn sign_ack(note: &HttpRequest) -> mcp_re_http_profile::HttpResponse {
    sign_delegated_accepted_202(note, &credential(), &delegated_key(), DELEGATED_KID, CREATED, EXPIRES)
        .expect("the PEP delegated-signs the acceptance")
}

// --- positive ----------------------------------------------------------------

#[test]
fn a_delegated_202_verifies_via_the_credential_chain() {
    let note = notification("n-ok");
    let ack = sign_ack(&note);

    assert_eq!(ack.status, 202);
    assert!(ack.body.is_empty(), "still bodyless");
    assert!(
        ack.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(MCP_RE_DELEGATION_HEADER)),
        "the credential rides in the header"
    );
    // The credential header is a covered component.
    let sig_input = ack
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
        .unwrap()
        .1
        .clone();
    assert!(
        sig_input.contains("\"mcp-re-delegation\""),
        "the credential MUST be covered by the signature: {sig_input}"
    );

    let actor =
        verify_delegated_accepted_202(&ack, &note, &resolver(), &expectations(&[EPOCH]), &no_revocation(), NOW)
            .expect("the client verifies the delegated acknowledgement");
    assert_eq!(actor.identity.keyid, DELEGATED_KID);
}

// --- negatives the ruling requires -------------------------------------------

/// The credential header stripped from the COVERED set (still on the wire). An
/// uncovered credential is unprotected — exactly what the coverage requirement
/// exists to forbid. This is the load-bearing negative.
#[test]
fn a_credential_header_not_covered_is_rejected() {
    let note = notification("n-uncov");
    let mut ack = sign_ack(&note);
    for h in ack.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace(" \"mcp-re-delegation\"", "");
        }
    }
    assert_eq!(
        verify_delegated_accepted_202(&ack, &note, &resolver(), &expectations(&[EPOCH]), &no_revocation(), NOW)
            .unwrap_err(),
        HttpProfileError::MissingCoveredComponent(MCP_RE_DELEGATION_HEADER),
    );
}

/// The credential header absent entirely: delegation is required.
#[test]
fn a_missing_credential_header_is_rejected() {
    let note = notification("n-miss");
    let mut ack = sign_ack(&note);
    ack.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(MCP_RE_DELEGATION_HEADER));
    assert_eq!(
        verify_delegated_accepted_202(&ack, &note, &resolver(), &expectations(&[EPOCH]), &no_revocation(), NOW)
            .unwrap_err(),
        HttpProfileError::DelegationCredentialMissing,
    );
}

/// A DUPLICATED credential header — an ambiguous credential surface is a protocol
/// error, not a pick-one.
#[test]
fn a_duplicated_credential_header_is_rejected() {
    let note = notification("n-dup");
    let mut ack = sign_ack(&note);
    let cred = ack
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(MCP_RE_DELEGATION_HEADER))
        .unwrap()
        .1
        .clone();
    ack.headers.push((MCP_RE_DELEGATION_HEADER.into(), cred));
    assert_eq!(
        verify_delegated_accepted_202(&ack, &note, &resolver(), &expectations(&[EPOCH]), &no_revocation(), NOW)
            .unwrap_err(),
        HttpProfileError::DuplicateHeader(MCP_RE_DELEGATION_HEADER),
    );
}

/// A credential header over the size bound is rejected before parsing — an
/// unbounded header is a memory/DoS surface.
#[test]
fn an_oversized_credential_header_is_rejected() {
    let note = notification("n-big");
    let mut ack = sign_ack(&note);
    for h in ack.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case(MCP_RE_DELEGATION_HEADER) {
            h.1 = "x".repeat(MAX_DELEGATION_HEADER_LEN + 1);
        }
    }
    assert_eq!(
        verify_delegated_accepted_202(&ack, &note, &resolver(), &expectations(&[EPOCH]), &no_revocation(), NOW)
            .unwrap_err(),
        HttpProfileError::MalformedEvidence("delegation header too large"),
    );
}

/// The revocation seam is live: a revoked delegated key is refused.
#[test]
fn a_revoked_delegated_key_is_rejected() {
    let note = notification("n-rev");
    let ack = sign_ack(&note);
    let revoked = |id: &str| id == DELEGATED_KID;
    assert_eq!(
        verify_delegated_accepted_202(&ack, &note, &resolver(), &expectations(&[EPOCH]), &revoked, NOW)
            .unwrap_err(),
        HttpProfileError::DelegationRevoked,
    );
}

/// The splice: an acknowledgement for notification A (`initialized`) presented
/// against a content-DISTINCT notification B (`cancelled`). The `;req` binding
/// covers `@method`/`@target-uri`/`content-digest`/`content-type`, so B's
/// different body (different `content-digest`) makes the signature refuse it.
///
/// Note the binding granularity: `;req` binds the request's COVERED CONTENT, not
/// its nonce. Two byte-identical notifications differing only in nonce share one
/// ack — correctly, since they are indistinguishable messages. A bodyless 202 has
/// no body to carry a full request-evidence handle, so instance-level (nonce)
/// binding is not expressible here; content-level binding is, and that is what a
/// splice across DISTINCT messages needs.
#[test]
fn a_delegated_202_binds_only_to_its_own_notification() {
    let note_a = notification_method("n-a", "notifications/initialized");
    let note_b = notification_method("n-b", "notifications/cancelled");
    let ack_a = sign_ack(&note_a);
    verify_delegated_accepted_202(&ack_a, &note_a, &resolver(), &expectations(&[EPOCH]), &no_revocation(), NOW)
        .expect("binds to A");
    assert!(
        verify_delegated_accepted_202(&ack_a, &note_b, &resolver(), &expectations(&[EPOCH]), &no_revocation(), NOW)
            .is_err(),
        "A's acknowledgement must not acknowledge B"
    );
}

/// A wrong trust epoch is refused (the credential's epoch must be accepted).
#[test]
fn a_stale_trust_epoch_is_rejected() {
    let note = notification("n-epoch");
    let ack = sign_ack(&note);
    assert_eq!(
        verify_delegated_accepted_202(&ack, &note, &resolver(), &expectations(&["epoch-2"]), &no_revocation(), NOW)
            .unwrap_err(),
        HttpProfileError::DelegationTrustEpochStale,
    );
}
