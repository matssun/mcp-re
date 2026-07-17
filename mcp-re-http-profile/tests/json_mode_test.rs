// SPDX-License-Identifier: Apache-2.0
//! JSON-mode enforcement on covered exchanges (#415 rev 2 §3.4, issue #423).
//!
//! §3.4 restricts covered exchanges to JSON mode. A `text/event-stream` response
//! to a covered request is a profile VIOLATION — not a streaming opt-in — and
//! must fail verification.
//!
//! The reason it must fail rather than degrade: per-event SSE evidence is
//! explicitly deferred to a future companion profile, so there is no way to make
//! a per-event statement today. A stream admitted here would carry a signature
//! over the response as a whole while every event inside it went individually
//! unattested — evidence that looks complete and covers nothing that matters.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::sign_response;
use mcp_re_http_profile::verify_request;
use mcp_re_http_profile::verify_response;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

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

fn request_with(content_type: &str) -> HttpRequest {
    let mut r = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Content-Type".into(), content_type.into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
    };
    sign_request(&mut r, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "n-json")
        .expect("signing succeeds");
    r
}

/// Sign a response with `content_type` against a valid JSON request. The signer
/// is honest — the message is genuinely signed and its digest genuinely matches.
/// Only the media type is out of profile, which is the point: this is not a
/// broken message, it is a well-formed one the profile cannot evidence.
fn signed_sse_response() -> (HttpRequest, HttpResponse) {
    let req = request_with("application/json");
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "text/event-stream".into())],
        body: b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n".to_vec(),
    };
    sign_response(&mut rsp, &req, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("the server really does sign it");
    (req, rsp)
}

#[test]
fn sse_response_on_a_covered_exchange_is_rejected() {
    let (req, rsp) = signed_sse_response();
    let err = verify_response(&rsp, &req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::NonJsonMediaType);
    assert_eq!(err.wire_code(), "mcp-re.serialization_failed");
}

/// The signature over that SSE response is perfectly valid. Pinning this makes
/// the test's claim precise: JSON mode is a profile rule enforced on its own, not
/// a side effect of some cryptographic check happening to fail.
#[test]
fn the_rejected_sse_response_was_genuinely_signed() {
    let (req, mut rsp) = signed_sse_response();
    // Swap ONLY the media type to JSON and re-sign nothing: the message body is
    // still SSE bytes, but with a JSON content-type the profile's media gate
    // passes and the failure moves to the digest/signature layer instead. That
    // shows the media gate is what rejected the original, by itself.
    for h in rsp.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("content-type") {
            h.1 = "application/json".into();
        }
    }
    let err = verify_response(&rsp, &req, &resolver(), NOW).unwrap_err();
    assert_ne!(
        err,
        HttpProfileError::NonJsonMediaType,
        "with a JSON media type the §3.4 gate no longer fires"
    );
}

#[test]
fn sse_request_on_a_covered_exchange_is_rejected() {
    let req = request_with("text/event-stream");
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::NonJsonMediaType);
}

/// Any non-JSON media type is out of profile, not just SSE — a signed HTML or
/// octet-stream body is equally something the profile cannot make an MCP evidence
/// statement about.
#[test]
fn other_non_json_media_types_are_rejected_too() {
    for ct in ["text/html", "application/octet-stream", "text/plain"] {
        let req = request_with(ct);
        assert_eq!(
            verify_request(&req, &resolver(), NOW).unwrap_err(),
            HttpProfileError::NonJsonMediaType,
            "{ct} is not JSON mode"
        );
    }
}

/// Parameters are part of the media type's value, not a different media type.
/// The full header value stays covered by the signature either way.
#[test]
fn json_with_parameters_is_still_json_mode() {
    let req = request_with("application/json; charset=utf-8");
    verify_request(&req, &resolver(), NOW).expect("a charset parameter is still JSON mode");
}

/// Media types are case-insensitive (RFC 9110 §8.3.1); a verifier that only
/// accepted the lowercase spelling would reject conforming senders.
#[test]
fn media_type_comparison_is_case_insensitive() {
    let req = request_with("Application/JSON");
    verify_request(&req, &resolver(), NOW).expect("media types are case-insensitive");
}

/// A `+json` structured suffix is NOT `application/json`. The profile carries
/// JSON-RPC over `application/json`; admitting look-alike types would widen the
/// value domain the evidence statements are defined over.
#[test]
fn json_structured_suffix_types_are_not_json_mode() {
    let req = request_with("application/problem+json");
    assert_eq!(
        verify_request(&req, &resolver(), NOW).unwrap_err(),
        HttpProfileError::NonJsonMediaType,
    );
}
