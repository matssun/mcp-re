// SPDX-License-Identifier: Apache-2.0
//! Seed Work Item 3 — the minimal standards-profile proof path with its
//! negative battery: request roundtrip, response roundtrip bound to the
//! request, then body tamper, response splice, wrong content-digest, missing
//! covered component, stale window, wrong keyid, foreign tag, and
//! content-encoding rejection. All negatives assert the typed fail-closed
//! error, not printed diagnostics (S8).

use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::sign_response;
use mcp_re_http_profile::verify_request;
use mcp_re_http_profile::verify_response;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

/// The trust seam: only the named keyids resolve; anything else is untrusted.
fn resolver() -> impl Fn(&str) -> Option<VerificationKey> {
    move |key_id: &str| match key_id {
        "client-key-1" => Some(client_key().public_key()),
        "server-key-1" => Some(server_key().public_key()),
        _ => None,
    }
}

fn request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp?route=a".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec(),
    }
}

fn signed_request() -> HttpRequest {
    let mut req = request();
    sign_request(&mut req, &client_key(), "client-key-1", CREATED, EXPIRES, "nonce-1")
        .expect("signing succeeds");
    req
}

fn signed_exchange() -> (HttpRequest, HttpResponse) {
    let req = signed_request();
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response(&mut rsp, &req, &server_key(), "server-key-1", CREATED, EXPIRES)
        .expect("response signing succeeds");
    (req, rsp)
}

// ---------- positive paths -------------------------------------------------

#[test]
fn request_roundtrip_verifies_and_yields_split_form_evidence() {
    let req = signed_request();
    let verified = verify_request(&req, &resolver(), NOW).expect("verifies");
    assert_eq!(verified.evidence.digest_alg, "sha256");
    assert_eq!(verified.nonce, "nonce-1");
    assert_eq!(verified.key_id, "client-key-1");
}

#[test]
fn signer_and_verifier_derive_the_same_evidence_handle() {
    let mut req = request();
    let signer_evidence =
        sign_request(&mut req, &client_key(), "client-key-1", CREATED, EXPIRES, "nonce-1")
            .expect("signing succeeds");
    let verified = verify_request(&req, &resolver(), NOW).expect("verifies");
    assert_eq!(signer_evidence, verified.evidence);
}

#[test]
fn response_roundtrip_bound_to_request_verifies() {
    let (req, rsp) = signed_exchange();
    verify_response(&rsp, &req, &resolver(), NOW).expect("response verifies");
}

#[test]
fn authorization_header_is_covered_when_present() {
    let mut req = request();
    req.headers.push(("Authorization".into(), "Bearer token-abc".into()));
    sign_request(&mut req, &client_key(), "client-key-1", CREATED, EXPIRES, "n")
        .expect("signing succeeds");
    verify_request(&req, &resolver(), NOW).expect("verifies with authorization covered");

    // Tampering with the bearer token after signing must break the signature.
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("authorization") {
            h.1 = "Bearer token-EVIL".into();
        }
    }
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::InvalidSignature);
}

// ---------- the seed's negative battery ------------------------------------

#[test]
fn body_tamper_fails_closed() {
    let mut req = signed_request();
    req.body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm"}}"#.to_vec();
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::ContentDigestMismatch);
    assert_eq!(err.wire_code(), "mcp-re.invalid_signature");
}

#[test]
fn response_splice_fails_closed() {
    // Two independent exchanges; splice exchange B's response onto request A.
    let (req_a, _rsp_a) = signed_exchange();
    let mut req_b = request();
    req_b.target_uri = "https://mcp.example.com/mcp?route=b".into();
    sign_request(&mut req_b, &client_key(), "client-key-1", CREATED, EXPIRES, "nonce-2")
        .expect("signing succeeds");
    let mut rsp_b = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response(&mut rsp_b, &req_b, &server_key(), "server-key-1", CREATED, EXPIRES)
        .expect("response signing succeeds");

    // rsp_b verifies against its own request but MUST NOT verify against req_a:
    verify_response(&rsp_b, &req_b, &resolver(), NOW).expect("own request ok");
    let err = verify_response(&rsp_b, &req_a, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::ResponseSignatureInvalid);
    assert_eq!(err.wire_code(), "mcp-re.response_sig_invalid");
}

#[test]
fn wrong_content_digest_fails_closed() {
    let mut req = signed_request();
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("content-digest") {
            h.1 = "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".into();
        }
    }
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::ContentDigestMismatch);
}

#[test]
fn missing_covered_component_fails_closed() {
    let mut req = signed_request();
    // Rewrite Signature-Input to drop content-digest from the covered set.
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace(" \"content-digest\"", "");
        }
    }
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::MissingCoveredComponent("content-digest"));
    assert_eq!(err.wire_code(), "mcp-re.missing_envelope");
}

#[test]
fn stale_window_fails_closed() {
    let req = signed_request();
    let after_expiry = EXPIRES + 1;
    let err = verify_request(&req, &resolver(), after_expiry).unwrap_err();
    assert_eq!(err, HttpProfileError::StaleWindow);
    assert_eq!(err.wire_code(), "mcp-re.expired_request");

    let before_created = CREATED - 1;
    let err = verify_request(&req, &resolver(), before_created).unwrap_err();
    assert_eq!(err, HttpProfileError::StaleWindow);
}

#[test]
fn wrong_keyid_fails_closed() {
    let mut req = request();
    // Signed with the client key but claiming an unknown keyid: trust
    // resolution must reject before any signature check.
    sign_request(&mut req, &client_key(), "rogue-key-9", CREATED, EXPIRES, "n")
        .expect("signing succeeds");
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::UnresolvedKeyId);
    assert_eq!(err.wire_code(), "mcp-re.actor_binding_failed");
}

#[test]
fn keyid_swap_to_another_trusted_key_fails_the_signature() {
    let mut req = request();
    // Signed by the CLIENT key but claiming the SERVER keyid: resolution
    // succeeds (both are trusted) but the signature must not verify.
    sign_request(&mut req, &client_key(), "server-key-1", CREATED, EXPIRES, "n")
        .expect("signing succeeds");
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::InvalidSignature);
}

#[test]
fn foreign_tag_fails_closed() {
    let mut req = signed_request();
    for h in req.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace("tag=\"mcp-re-http-v1\"", "tag=\"someone-elses-profile\"");
        }
    }
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::UnknownProfileTag);
    assert_eq!(err.wire_code(), "mcp-re.unsupported_version");
}

#[test]
fn content_encoding_fails_closed() {
    let mut req = signed_request();
    req.headers.push(("Content-Encoding".into(), "gzip".into()));
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert_eq!(err, HttpProfileError::ContentEncodingPresent);
    assert_eq!(err.wire_code(), "mcp-re.canonicalization_failed");
}

#[test]
fn unsigned_request_fails_closed() {
    let req = request();
    let err = verify_request(&req, &resolver(), NOW).unwrap_err();
    assert!(matches!(err, HttpProfileError::MissingEvidence(_)));
}

#[test]
fn duplicate_authorization_fails_closed() {
    let mut req = request();
    req.headers.push(("Authorization".into(), "Bearer one".into()));
    req.headers.push(("authorization".into(), "Bearer two".into()));
    let err =
        sign_request(&mut req, &client_key(), "client-key-1", CREATED, EXPIRES, "n").unwrap_err();
    assert_eq!(err, HttpProfileError::DuplicateHeader("authorization"));
}
