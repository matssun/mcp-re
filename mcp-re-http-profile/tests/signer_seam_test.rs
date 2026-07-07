// SPDX-License-Identifier: Apache-2.0
//! MCPRE-106 — external-signer custody seam (`sign_request_with_signer` /
//! `sign_response_with_signer`).
//!
//! Proves the additive seam is wire-identical to local-key signing (so KMS/HSM
//! custody changes nothing on the wire), enforces the raw 64-byte Ed25519 return
//! contract, and still fails closed under tamper / wrong-key.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::sign_request_with_signer;
use mcp_re_http_profile::sign_response_with_signer;
use mcp_re_http_profile::verify_request;
use mcp_re_http_profile::verify_response;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

/// The external-signer callback the seam expects: RFC 9421 base bytes in, raw
/// 64-byte Ed25519 signature out. Here it wraps a local key (the KMS lane wraps
/// `GcpKmsEd25519Backend::sign_raw_ed25519` through the identical contract).
fn raw_ed25519_signer(key: &SigningKey) -> impl Fn(&[u8]) -> Result<Vec<u8>, HttpProfileError> + '_ {
    move |base: &[u8]| {
        mcp_re_core::b64url_decode(&key.sign(base))
            .map_err(|_| HttpProfileError::InvalidSignature)
    }
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

fn base_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec(),
    }
}

fn base_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    }
}

/// The seam is wire-identical to local-key signing: deterministic Ed25519 over
/// the same base yields byte-identical Signature / Signature-Input headers.
#[test]
fn external_signer_is_byte_identical_to_local_key() {
    let mut via_local = base_request();
    sign_request(&mut via_local, &client_key(), "client-key-1", CREATED, EXPIRES, "nonce-1")
        .expect("local sign");

    let mut via_seam = base_request();
    sign_request_with_signer(
        &mut via_seam,
        raw_ed25519_signer(&client_key()),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("seam sign");

    assert_eq!(via_local.headers, via_seam.headers, "seam must be wire-identical to local-key signing");
}

/// A seam-signed request verifies under the unmodified verifier.
#[test]
fn external_signer_request_verifies() {
    let mut req = base_request();
    sign_request_with_signer(
        &mut req,
        raw_ed25519_signer(&client_key()),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("seam sign");
    verify_request(&req, &resolver(), NOW).expect("seam-signed request verifies");
}

/// A seam-signed response verifies, bound to its request via `;req`.
#[test]
fn external_signer_response_verifies() {
    let mut req = base_request();
    sign_request(&mut req, &client_key(), "client-key-1", CREATED, EXPIRES, "nonce-1").expect("sign req");

    let mut rsp = base_response();
    sign_response_with_signer(
        &mut rsp,
        &req,
        raw_ed25519_signer(&server_key()),
        "server-key-1",
        CREATED,
        EXPIRES,
    )
    .expect("seam sign response");
    verify_response(&rsp, &req, &resolver(), NOW).expect("seam-signed response verifies");
}

/// The seam enforces the raw 64-byte Ed25519 return: a signer handing back the
/// wrong length (DER-wrapped, truncated) fails closed rather than emitting a
/// malformed Signature header.
#[test]
fn external_signer_wrong_length_fails_closed() {
    for bad_len in [0usize, 63, 65, 72] {
        let mut req = base_request();
        let err = sign_request_with_signer(
            &mut req,
            |_base| Ok(vec![0u8; bad_len]),
            "client-key-1",
            CREATED,
            EXPIRES,
            "nonce-1",
        )
        .expect_err("a non-64-byte signature must be rejected");
        assert_eq!(err, HttpProfileError::InvalidSignature, "len {bad_len}");
    }
}

/// A signer error propagates (fails closed), never emitting a partial signature.
#[test]
fn external_signer_error_propagates() {
    let mut req = base_request();
    let err = sign_request_with_signer(
        &mut req,
        |_base| Err(HttpProfileError::InvalidSignature),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect_err("signer failure must propagate");
    assert_eq!(err, HttpProfileError::InvalidSignature);
}

/// Wrong key: a seam signature from a different key does not verify under the
/// resolver's trusted key.
#[test]
fn external_signer_wrong_key_does_not_verify() {
    let foreign = SigningKey::from_seed_bytes(&[0x09; 32]);
    let mut req = base_request();
    sign_request_with_signer(
        &mut req,
        raw_ed25519_signer(&foreign),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("seam sign with foreign key");
    // Cryptographically valid signature, but not under the key the resolver trusts.
    assert!(verify_request(&req, &resolver(), NOW).is_err(), "foreign-key signature must not verify");
}
