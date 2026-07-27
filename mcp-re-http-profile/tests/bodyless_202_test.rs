// SPDX-License-Identifier: Apache-2.0
//! Bodyless component sets and the signed 202 (#415 rev 2 §3.4/§8.1, issues
//! #424/#418).
//!
//! A signed 202 states exactly one thing: the enforcement boundary
//! authenticated and accepted the message. Not that a cancellation completed,
//! not that the inner application saw it, not that anything was done. These
//! tests pin the mechanics; `an_acknowledgement_binds_to_one_transmission_not_to_content`
//! pins the exact reach of the acknowledgement — it names ONE transmission and cannot
//! be lifted onto any other, including a byte-identical resend (C019b).

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

/// The exact reach of the acknowledgement, both directions, in one test.
///
/// The `;req` components (`@method`, `@target-uri`, `content-digest`,
/// `content-type`) are the ONLY binding a bodyless 202 has — it has no body in which
/// to restate its `request_evidence` — and every one of them is a function of the
/// request's CONTENT:
///
/// * a 202 for notification A does NOT verify against a different notification B —
///   an acknowledgement liftable onto another message would acknowledge nothing;
/// * a 202 for notification A DOES verify against a byte-identical notification A',
///   because nothing unique to a request instance is covered. The request `nonce`
///   lives in its own `@signature-params` (not a coverable component) and the request
///   evidence block carries no instance field.
///
/// The second assertion is the standing "Binding granularity" ruling
/// (`docs/spec/http-profile-conformance-notes.md` §3.4), pinned so the contract is
/// visible rather than implied: byte-identical notifications are the ordinary case
/// (`notifications/initialized`, a retried `notifications/cancelled`), so a verified
/// 202 does not prove that THIS transmission reached the boundary. If the ruling
/// changes, this test is the one that must change with it.
#[test]
fn an_acknowledgement_binds_to_one_transmission_not_to_content() {
    let note_a = notification("n-a", "notifications/initialized");
    let note_b = notification("n-b", "notifications/cancelled");
    let ack_a = sign_accepted_202(&note_a, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("signs");

    verify_accepted_202(&ack_a, &note_a, &resolver(), &policy(), NOW).expect("binds to A");
    assert_eq!(
        verify_accepted_202(&ack_a, &note_b, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::ResponseBindingMismatch,
        "A's acknowledgement must not acknowledge a DIFFERENT notification B"
    );

    // THE INVARIANT (C019b, owner ruling 2026-07-27). Same method, same target, same
    // body — a distinct TRANSMISSION differing only in the request signature's own
    // nonce. Before this ruling the covered set reached nothing that distinguished
    // them and A's acknowledgement verified against this too, so a captured ack could
    // be presented as evidence for a later resend that the server had in fact rejected
    // as a replay. The server could tell the two apart; the client could not.
    let note_a_again = notification("n-a-again", "notifications/initialized");
    assert_ne!(
        signature_input_of(&note_a),
        signature_input_of(&note_a_again),
        "the two transmissions must genuinely be distinct request instances"
    );
    assert_eq!(
        verify_accepted_202(&ack_a, &note_a_again, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::ResponseBindingMismatch,
        "an acknowledgement for transmission A must NOT verify for a distinct \
         transmission A', even with identical method, target and body content"
    );
}

/// The coordinate is re-derived from the request, never trusted from the response: a
/// forged header naming some other transmission is refused even though the 202's own
/// signature is valid over it.
#[test]
fn a_forged_request_evidence_header_is_refused() {
    let note_a = notification("n-a", "notifications/initialized");
    let mut ack = sign_accepted_202(&note_a, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("signs");
    for (name, value) in ack.headers.iter_mut() {
        if name.eq_ignore_ascii_case("mcp-re-request-evidence") {
            *value = "0".repeat(value.len());
        }
    }
    assert!(
        verify_accepted_202(&ack, &note_a, &resolver(), &policy(), NOW).is_err(),
        "a request-evidence value the verifier cannot re-derive must fail closed"
    );
}

/// Stripping the coordinate is not a downgrade to content-level binding: the header is
/// a REQUIRED covered component, so its absence fails closed rather than falling back.
#[test]
fn a_missing_request_evidence_header_is_refused() {
    let note_a = notification("n-a", "notifications/initialized");
    let mut ack = sign_accepted_202(&note_a, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("signs");
    ack.headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("mcp-re-request-evidence"));
    assert_eq!(
        verify_accepted_202(&ack, &note_a, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::MissingEvidence("response request-evidence"),
        "there is no weaker content-level mode to fall back to"
    );
}

/// The `Signature-Input` header value, used to show two notifications are distinct
/// request instances even when their covered content is identical.
fn signature_input_of(request: &HttpRequest) -> String {
    request
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
        .map(|(_, v)| v.clone())
        .expect("a signed request carries signature-input")
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

// --- C047: PRESENT ⇒ COVERED on the bodyless request set --------------------
//
// The bodied request path enforces that `authorization`, `dpop`, and the MCP transport
// headers are covered whenever they are present. The bodyless path (§8.1) enforced
// none of them, and its signer built components from a closed three-element set so it
// could not have covered them anyway. A bodyless request could therefore present a
// bearer credential entirely outside its own signature.

/// A bodyless request carrying `Authorization` must have it COVERED — and the signer
/// must produce exactly that, or the two ends disagree.
#[test]
fn a_bodyless_request_covers_a_present_authorization_header() {
    let mut req = HttpRequest {
        method: "DELETE".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Authorization".into(), "Bearer token-abc".into())],
        body: Vec::new(),
    };
    sign_bodyless_request(&mut req, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-auth")
        .expect("signs");
    assert!(
        signature_input_of(&req).contains("\"authorization\""),
        "the signer must cover a present authorization header: {}",
        signature_input_of(&req)
    );
    verify_bodyless_request(&req, &resolver(), &policy(), NOW)
        .expect("a bodyless request with a covered credential verifies");
}

/// The attack the gap allowed: swap the presented bearer token. With the credential
/// covered this breaks the signature; the point of this test is that the header cannot
/// be left uncovered in the first place — see the sibling test below.
#[test]
fn swapping_a_covered_bearer_token_on_a_bodyless_request_is_caught() {
    let mut req = HttpRequest {
        method: "DELETE".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Authorization".into(), "Bearer token-abc".into())],
        body: Vec::new(),
    };
    sign_bodyless_request(&mut req, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-swap")
        .expect("signs");
    for (name, value) in req.headers.iter_mut() {
        if name.eq_ignore_ascii_case("authorization") {
            *value = "Bearer token-ATTACKER".into();
        }
    }
    assert!(
        verify_bodyless_request(&req, &resolver(), &policy(), NOW).is_err(),
        "a swapped bearer token must invalidate the signature"
    );
}

/// The core of C047: a credential ADDED after signing — so it is present but not
/// covered — must be rejected rather than silently accepted as part of the request.
/// Before the fix this verified, because the bodyless verifier never asked.
#[test]
fn an_uncovered_authorization_header_on_a_bodyless_request_is_rejected() {
    let mut req = HttpRequest {
        method: "DELETE".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![],
        body: Vec::new(),
    };
    sign_bodyless_request(&mut req, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-inject")
        .expect("signs");
    // An intermediary attaches a credential the signature says nothing about.
    req.headers.push(("Authorization".into(), "Bearer token-INJECTED".into()));
    assert_eq!(
        verify_bodyless_request(&req, &resolver(), &policy(), NOW).unwrap_err(),
        HttpProfileError::MissingCoveredComponent("authorization"),
        "a present-but-uncovered credential must fail closed, not ride along"
    );
}

/// Same rule for `dpop` and for the MCP transport headers, so the fix is not
/// authorization-specific.
#[test]
fn uncovered_dpop_and_mcp_transport_headers_on_a_bodyless_request_are_rejected() {
    for (header, expected) in [
        ("DPoP", "dpop"),
        ("Mcp-Method", "mcp-method"),
        ("Mcp-Name", "mcp-name"),
        ("Mcp-Protocol-Version", "mcp-protocol-version"),
    ] {
        let mut req = HttpRequest {
            method: "DELETE".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: vec![],
            body: Vec::new(),
        };
        sign_bodyless_request(&mut req, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-h")
            .expect("signs");
        req.headers.push((header.into(), "injected".into()));
        assert_eq!(
            verify_bodyless_request(&req, &resolver(), &policy(), NOW).unwrap_err(),
            HttpProfileError::MissingCoveredComponent(expected),
            "an uncovered {header} must fail closed on the bodyless path"
        );
    }
}

/// And the signer covers each of them when present, so a legitimately-signed bodyless
/// request carrying them still round-trips. Without this half the fix would simply make
/// those requests unsignable.
#[test]
fn the_bodyless_signer_covers_every_conditionally_mandatory_header() {
    let mut req = HttpRequest {
        method: "DELETE".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![
            ("Authorization".into(), "Bearer t".into()),
            ("DPoP".into(), "proof".into()),
            ("Mcp-Method".into(), "notifications/cancelled".into()),
            ("Mcp-Name".into(), "tool-a".into()),
            ("Mcp-Protocol-Version".into(), "2026-07-28".into()),
        ],
        body: Vec::new(),
    };
    sign_bodyless_request(&mut req, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-all")
        .expect("signs");
    let input = signature_input_of(&req);
    for name in ["authorization", "dpop", "mcp-method", "mcp-name", "mcp-protocol-version"] {
        assert!(input.contains(&format!("\"{name}\"")), "{name} must be covered: {input}");
    }
    verify_bodyless_request(&req, &resolver(), &policy(), NOW).expect("verifies");
}
