// SPDX-License-Identifier: Apache-2.0
//! Bodyless component sets and the signed 202 (#415 rev 2 §3.4/§8.1, issues
//! #424/#418).
//!
//! A signed 202 states exactly one thing: the enforcement boundary
//! authenticated and accepted the message. Not that a cancellation completed,
//! not that the inner application saw it, not that anything was done. These
//! tests pin the mechanics; `signed_202_binds_only_to_its_own_notification` pins
//! the property that makes the claim meaningful at all — an acknowledgement that
//! could be lifted onto another message would acknowledge nothing.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_accepted_202;
use mcp_re_http_profile::sign_bodyless_request;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::verify_accepted_202;
use mcp_re_http_profile::verify_bodyless_request;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::STATUS_ACCEPTED;

const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const NOW: i64 = 1_700_000_100;
const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_KEY_ID: &str = "server-key-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[11u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[22u8; 32])
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key()),
            (SERVER_KEY_ID, SignerSlot::Response) => ("server", server_key()),
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

fn policy() -> VerifierPolicy {
    VerifierPolicy::default()
}

/// A one-way MCP notification POST: an ordinary bodied request, signed by the
/// ordinary request rules. Nothing about being one-way makes it unauthenticable —
/// that was the misconception #418 corrected.
fn notification(nonce: &str, method: &str) -> HttpRequest {
    let mut r = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: format!(r#"{{"jsonrpc":"2.0","method":"{method}"}}"#).into_bytes(),
    };
    sign_request(&mut r, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, nonce)
        .expect("a notification signs like any request");
    r
}

// --- the signed 202 ----------------------------------------------------------

#[test]
fn signed_202_verifies_against_its_notification() {
    let note = notification("n-init", "notifications/initialized");
    let ack = sign_accepted_202(&note, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("the PEP signs its acceptance");

    assert_eq!(ack.status, STATUS_ACCEPTED);
    assert!(ack.body.is_empty(), "an accepted notification gets no body");
    assert!(
        !ack.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")),
        "a bodyless response has no content-type: there is no content to describe"
    );

    let actor = verify_accepted_202(&ack, &note, &resolver(), &policy(), NOW)
        .expect("the client verifies the acknowledgement");
    assert_eq!(actor.identity.keyid, SERVER_KEY_ID);
}

/// The property that makes the 202 mean anything: it binds to the exact
/// notification it acknowledges, via the mandatory `;req` components. A bodyless
/// response has no body, so it cannot restate its `request_evidence` the way a
/// bodied response does — the `;req` binding is the ONLY binding, which is why
/// it is mandatory rather than optional. An acknowledgement that could be lifted
/// onto another message would acknowledge nothing.
#[test]
fn signed_202_binds_only_to_its_own_notification() {
    let note_a = notification("n-a", "notifications/initialized");
    let note_b = notification("n-b", "notifications/cancelled");
    let ack_a = sign_accepted_202(&note_a, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("signs");

    verify_accepted_202(&ack_a, &note_a, &resolver(), &policy(), NOW).expect("binds to A");
    assert_eq!(
        verify_accepted_202(&ack_a, &note_b, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::ResponseSignatureInvalid,
        "A's acknowledgement must not acknowledge B"
    );
}

/// The digest of empty content is a signed STATEMENT that there is no body — not
/// ceremony. Without it, a body stripped in flight and an intentionally empty one
/// would be indistinguishable. Inject content and the digest no longer holds.
#[test]
fn content_injected_into_a_signed_202_is_caught() {
    let note = notification("n-inj", "notifications/initialized");
    let mut ack = sign_accepted_202(&note, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("signs");
    ack.body = br#"{"cancelled":true}"#.to_vec();
    assert_eq!(
        verify_accepted_202(&ack, &note, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::MalformedEvidence("content on a bodyless message"),
    );
}

/// content-type present when the named set says it must be absent. Not a harmless
/// extra: the set states there is no content, and a content-type asserts
/// otherwise. The named set is enforced exactly, in both directions.
#[test]
fn content_type_on_a_bodyless_202_is_rejected() {
    let note = notification("n-ct", "notifications/initialized");
    let mut ack = sign_accepted_202(&note, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("signs");
    ack.headers.push(("Content-Type".into(), "application/json".into()));
    assert_eq!(
        verify_accepted_202(&ack, &note, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::MalformedEvidence("content-type on a bodyless message"),
    );
}

/// A missing `;req` binding is the splice-enabling shape: without it the
/// acknowledgement floats free of any request.
#[test]
fn a_202_without_its_req_binding_is_rejected() {
    let note = notification("n-nb", "notifications/initialized");
    let mut ack = sign_accepted_202(&note, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("signs");
    for h in ack.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace(" \"@target-uri\";req", "");
        }
    }
    assert_eq!(
        verify_accepted_202(&ack, &note, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::MissingCoveredComponent("@target-uri"),
    );
}

/// The bodyless set is a distinct set, not a relaxed one: a non-202 status signed
/// under it is not an acceptance acknowledgement.
#[test]
fn a_bodyless_response_that_is_not_202_is_rejected() {
    let note = notification("n-st", "notifications/initialized");
    let mut ack = sign_accepted_202(&note, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("signs");
    ack.status = 200;
    assert_eq!(
        verify_accepted_202(&ack, &note, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::MalformedEvidence("bodyless acknowledgement status"),
    );
}

/// A client key presented on an acknowledgement fails the Response slot: the
/// trust seam decides who may acknowledge, exactly as for any response.
#[test]
fn a_202_signed_by_a_request_key_fails_the_response_slot() {
    let note = notification("n-slot", "notifications/initialized");
    let ack = sign_accepted_202(&note, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES)
        .expect("signs");
    assert_eq!(
        verify_accepted_202(&ack, &note, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::UnresolvedKeyId,
    );
}

// --- the bodyless request set (§8.1) ----------------------------------------

#[test]
fn bodyless_request_round_trips() {
    let mut req = HttpRequest {
        method: "DELETE".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![],
        body: Vec::new(),
    };
    let evidence = sign_bodyless_request(
        &mut req,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        "n-del",
    )
    .expect("a bodyless request signs");
    assert!(
        !req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")),
        "no content-type on a bodyless request"
    );
    let (actor, verified) = verify_bodyless_request(&req, &resolver(), &policy(), NOW)
        .expect("a bodyless request verifies");
    assert_eq!(actor.identity.keyid, CLIENT_KEY_ID);
    assert_eq!(verified, evidence, "the handle is the signer's");
}

/// A GET is the other bodyless request shape §8.1 names.
#[test]
fn bodyless_get_request_round_trips() {
    let mut req = HttpRequest {
        method: "GET".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![],
        body: Vec::new(),
    };
    sign_bodyless_request(&mut req, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-get")
        .expect("signs");
    verify_bodyless_request(&req, &resolver(), &policy(), NOW).expect("verifies");
}

#[test]
fn content_type_on_a_bodyless_request_is_rejected() {
    let mut req = HttpRequest {
        method: "DELETE".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![],
        body: Vec::new(),
    };
    sign_bodyless_request(&mut req, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-x")
        .expect("signs");
    req.headers.push(("Content-Type".into(), "application/json".into()));
    assert_eq!(
        verify_bodyless_request(&req, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::MalformedEvidence("content-type on a bodyless message"),
    );
}

/// The named sets do not leak into each other: a BODIED request is still required
/// to carry and cover its content-type. Dropping the requirement for bodyless
/// messages must not have weakened the bodied set.
#[test]
fn the_bodied_request_set_still_requires_content_type() {
    let note = notification("n-bodied", "notifications/initialized");
    let mut stripped = note.clone();
    stripped
        .headers
        .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
    // The bodied verifier still demands it — a body without a media type is not
    // suddenly acceptable because a bodyless set exists.
    assert!(
        mcp_re_http_profile::verify_request(&stripped, &resolver(), NOW).is_err(),
        "the bodied set is unchanged"
    );
}
