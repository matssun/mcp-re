// SPDX-License-Identifier: Apache-2.0
//! MCP transport-header coverage (#415 rev 2 §4.1, issue #425).
//!
//! `Mcp-Method` states, in the clear, which JSON-RPC method a request carries.
//! Uncovered, that claim can diverge from the signed body: an intermediary reads
//! `tools/list` off the header and routes, logs, or authorizes on it while the
//! signed body says `tools/call`. The proxy never routes on these headers
//! (ADR-MCPS-025 — they are untrusted hints, the body is authoritative), but a
//! covered header cannot LIE about a signed body, which is worth more than a
//! header nobody is permitted to believe.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::verify_request;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const NOW: i64 = 1_700_000_100;
const CLIENT_KEY_ID: &str = "client-key-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[11u8; 32])
}

fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
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
}

const BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

fn signed(extra: &[(&str, &str)]) -> HttpRequest {
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    for (k, v) in extra {
        headers.push(((*k).to_string(), (*v).to_string()));
    }
    let mut r = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers,
        body: BODY.to_vec(),
    };
    sign_request(&mut r, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-mcp")
        .expect("signing succeeds");
    r
}

fn signature_input(r: &HttpRequest) -> String {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
        .expect("signature-input present")
        .1
        .clone()
}

// --- positive: covered and matching -----------------------------------------

#[test]
fn mcp_transport_headers_are_covered_when_present() {
    let r = signed(&[
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "read"),
        ("Mcp-Protocol-Version", "2026-07-28"),
    ]);
    let input = signature_input(&r);
    for expected in ["\"mcp-method\"", "\"mcp-name\"", "\"mcp-protocol-version\""] {
        assert!(
            input.contains(expected),
            "the signer must cover {expected} when it is present: {input}"
        );
    }
    verify_request(&r, &resolver(), NOW).expect("covered-and-matching verifies");
}

/// A deployment whose protocol version does not define these headers never sends
/// them, and signs exactly what it signed before — the rule is
/// version-conditional without the signer being told which version it is on.
#[test]
fn absent_headers_are_not_covered_and_still_verify() {
    let r = signed(&[]);
    let input = signature_input(&r);
    assert!(!input.contains("mcp-method"), "nothing to cover: {input}");
    verify_request(&r, &resolver(), NOW).expect("a request without MCP headers verifies");
}

// --- negative: present but uncovered ----------------------------------------

/// The conditional-mandatory rule, on the `authorization`/`dpop` pattern: a
/// present header that is not covered is rejected. Otherwise a sender could
/// attach an unsigned method claim to a signed request and have it read
/// downstream as though the signature stood behind it.
#[test]
fn present_but_uncovered_mcp_method_is_rejected() {
    let mut r = signed(&[("Mcp-Method", "tools/call")]);
    // Strip it from the covered set post-signing, leaving the header on the wire.
    for h in r.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace(" \"mcp-method\"", "");
        }
    }
    assert_eq!(
        verify_request(&r, &resolver(), NOW).unwrap_err(),
        HttpProfileError::MissingCoveredComponent("mcp-method"),
    );
}

#[test]
fn present_but_uncovered_mcp_name_is_rejected() {
    let mut r = signed(&[("Mcp-Method", "tools/call"), ("Mcp-Name", "read")]);
    for h in r.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace(" \"mcp-name\"", "");
        }
    }
    assert_eq!(
        verify_request(&r, &resolver(), NOW).unwrap_err(),
        HttpProfileError::MissingCoveredComponent("mcp-name"),
    );
}

// --- negative: header/body divergence ---------------------------------------

/// The §4.1 gap this closes. The header and the body are BOTH covered and the
/// signature is valid — this is not tampering. It is the signer stating two
/// different methods, and the verifier refuses rather than picking one.
#[test]
fn header_body_method_divergence_is_rejected() {
    let mut r = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            // The header says tools/list; the body below says tools/call.
            ("Mcp-Method".into(), "tools/list".into()),
        ],
        body: BODY.to_vec(),
    };
    sign_request(&mut r, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-div")
        .expect("the client really does sign the contradiction");

    let err = verify_request(&r, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::McpMethodDivergence);
    assert_eq!(err.wire_code(), "mcp-re.malformed_envelope");
}

/// Pin that the divergent request was otherwise perfectly valid: correct the
/// header to agree with the body, re-sign, and it verifies. So the divergence
/// check is what rejected it — not some incidental failure.
#[test]
fn the_divergent_request_is_otherwise_valid() {
    let r = signed(&[("Mcp-Method", "tools/call")]);
    verify_request(&r, &resolver(), NOW)
        .expect("the same request with an agreeing header verifies");
}

/// A body with no `method` (a response or notification shape) has nothing to
/// diverge from; the divergence rule does not invent a violation.
#[test]
fn body_without_a_method_does_not_diverge() {
    let mut r = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Mcp-Method".into(), "tools/call".into()),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_request(&mut r, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-nom")
        .expect("signing succeeds");
    verify_request(&r, &resolver(), NOW).expect("no body method: nothing to compare");
}

// --- session-id is scoped out ------------------------------------------------

/// `mcp-session-id` is NOT coverable: protocol sessions are a 2025-11-25 concept
/// that 2026-07-28 removes, and MCP-RE's serving path is stateless per-request by
/// design — there is no session for a session id to identify. Covering it would
/// manufacture the appearance of a binding over nothing, so the closed allowlist
/// rejects it as an unknown covered component. That is the intended answer.
#[test]
fn mcp_session_id_is_not_a_coverable_component() {
    let mut r = signed(&[("Mcp-Session-Id", "sess-1")]);
    // The signer did not cover it (it is not in the coverable set)...
    assert!(!signature_input(&r).contains("mcp-session-id"));
    // ...and a sender that hand-crafts it into the covered set is rejected.
    for h in r.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace("\"content-type\"", "\"content-type\" \"mcp-session-id\"");
        }
    }
    assert_eq!(
        verify_request(&r, &resolver(), NOW).unwrap_err(),
        HttpProfileError::MalformedEvidence("unknown covered component"),
    );
}

/// An unrelated foreign header stays rejected: widening the allowlist for the MCP
/// transport headers must not have opened it generally.
#[test]
fn the_component_allowlist_is_still_closed() {
    let mut r = signed(&[]);
    for h in r.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace("\"content-type\"", "\"content-type\" \"x-acme-custom\"");
        }
    }
    assert_eq!(
        verify_request(&r, &resolver(), NOW).unwrap_err(),
        HttpProfileError::MalformedEvidence("unknown covered component"),
    );
}
