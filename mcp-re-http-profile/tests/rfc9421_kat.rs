// SPDX-License-Identifier: Apache-2.0
//! RFC 9421 known-answer test (S15: the RFC's own worked example is the
//! independent oracle — not this project's code re-run).
//!
//! Appendix B.2.6 signs the B.2 test-request with the B.1.4 Ed25519 test key
//! (`test-key-ed25519`) over ("date" "@method" "@path" "@authority"
//! "content-type" "content-length");created=1618884473;keyid="test-key-ed25519".
//! Ed25519 is deterministic, so byte-comparing the signature against the RFC's
//! printed `sig-b26` value is honest (never generalize this to ECDSA).
//!
//! Key material and expected bytes below are copied verbatim from the RFC text
//! (rfc9421.txt, B.1.4 JWK form and B.2.6), not from any re-rendering.

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::sigbase::signature_base;
use mcp_re_http_profile::sigbase::SourceMessage;
use mcp_re_http_profile::CoveredComponent;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::SignatureParams;

/// B.1.4 JWK `d` (the Ed25519 seed, base64url).
const B14_SEED_B64URL: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";

/// B.1.4 JWK `x` (the raw public key, base64url).
const B14_PUBLIC_B64URL: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

/// The exact B.2.6 signature base (RFC 8792 line-wrapping unfolded).
const B26_SIGNATURE_BASE: &str = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\
\"@method\": POST\n\
\"@path\": /foo\n\
\"@authority\": example.com\n\
\"content-type\": application/json\n\
\"content-length\": 18\n\
\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";

/// The RFC's printed `sig-b26` signature value (standard base64, unfolded).
const B26_SIGNATURE_B64: &str =
    "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";

/// The B.2 test-request, as far as B.2.6's covered components see it.
fn b26_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: "http://example.com/foo?param=Value&Pet=dog".into(),
        headers: vec![
            ("Host".into(), "example.com".into()),
            ("Date".into(), "Tue, 20 Apr 2021 02:07:55 GMT".into()),
            ("Content-Type".into(), "application/json".into()),
            ("Content-Length".into(), "18".into()),
        ],
        body: br#"{"hello": "world"}"#.to_vec(),
    }
}

fn b26_components() -> Vec<CoveredComponent> {
    vec![
        CoveredComponent::new("date"),
        CoveredComponent::new("@method"),
        CoveredComponent::new("@path"),
        CoveredComponent::new("@authority"),
        CoveredComponent::new("content-type"),
        CoveredComponent::new("content-length"),
    ]
}

fn b26_params() -> SignatureParams {
    SignatureParams {
        created: Some(1618884473),
        expires: None,
        nonce: None,
        keyid: Some("test-key-ed25519".into()),
        alg: None,
        tag: None,
    }
}

fn b14_signing_key() -> SigningKey {
    let seed_bytes = b64url_decode(B14_SEED_B64URL).expect("valid JWK d");
    let seed: [u8; 32] = seed_bytes.try_into().expect("32-byte seed");
    SigningKey::from_seed_bytes(&seed)
}

#[test]
fn signature_base_matches_rfc9421_b26_byte_for_byte() {
    let request = b26_request();
    let base = signature_base(
        &b26_components(),
        &b26_params(),
        &SourceMessage::Request(&request),
    )
    .expect("base builds");
    assert_eq!(
        String::from_utf8(base).unwrap(),
        B26_SIGNATURE_BASE,
        "signature base must be byte-identical to RFC 9421 B.2.6"
    );
}

#[test]
fn private_key_derives_the_rfc_public_key() {
    let expected: [u8; 32] = b64url_decode(B14_PUBLIC_B64URL)
        .expect("valid JWK x")
        .try_into()
        .expect("32-byte key");
    assert_eq!(
        b14_signing_key().public_key().to_bytes(),
        expected,
        "B.1.4 private key must derive the B.1.4 public key"
    );
}

#[test]
fn signing_the_base_reproduces_the_rfc_signature() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let signature_b64url = b14_signing_key().sign(B26_SIGNATURE_BASE.as_bytes());
    let expected_bytes = STANDARD.decode(B26_SIGNATURE_B64).expect("valid base64");
    assert_eq!(
        signature_b64url,
        b64url_encode(&expected_bytes),
        "deterministic Ed25519 signature must byte-match RFC 9421 sig-b26"
    );
}

#[test]
fn rfc_signature_verifies_under_the_rfc_public_key() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let expected_bytes = STANDARD.decode(B26_SIGNATURE_B64).expect("valid base64");
    let key = b14_signing_key().public_key();
    mcp_re_core::verify_ed25519(
        B26_SIGNATURE_BASE.as_bytes(),
        &b64url_encode(&expected_bytes),
        &key,
    )
    .expect("RFC signature verifies over the RFC base");
}

#[test]
fn tampered_rfc_base_fails_verification() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let expected_bytes = STANDARD.decode(B26_SIGNATURE_B64).expect("valid base64");
    let key = b14_signing_key().public_key();
    let tampered = B26_SIGNATURE_BASE.replace("/foo", "/bar");
    mcp_re_core::verify_ed25519(tampered.as_bytes(), &b64url_encode(&expected_bytes), &key)
        .expect_err("tampered base must not verify");
}
