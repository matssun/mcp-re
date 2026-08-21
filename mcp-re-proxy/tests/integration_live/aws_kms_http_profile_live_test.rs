// SPDX-License-Identifier: Apache-2.0
//! Live AWS KMS — HTTP standards-profile (RFC 9421 + RFC 9530) lane
//! (ADR-MCPRE-050 + MCPRE-106). The AWS twin of `gcp_kms_http_profile_live_test`.
//!
//! This lane proves AWS KMS can sign an RFC 9421 request/response — through the
//! profile's PRODUCTION external-signer seam (`sign_request_with_signer` /
//! `sign_response_with_signer`, MCPRE-106) — that the UNMODIFIED
//! `verify_request` / `verify_response` accept, with tamper + wrong-key
//! negatives. The private key never leaves KMS; the profile owns base
//! construction and header assembly, KMS provides only the raw signature.
//!
//! Two entry points share one lane body:
//!   * `*_offline_local_seed` — NOT ignored: runs in the blocking feature-gated
//!     CI job via `AwsKmsEd25519Backend::for_test_with_local_seed` (no network),
//!     guarding the KMS-backend → seam wiring on every push.
//!   * `*_live` — `#[ignore]`: the real AWS KMS backend; run from the cloud
//!     script / nightly lane with `-- --ignored` and `MCP_RE_AWS_KMS_*` set. FAILS
//!     LOUDLY if its configuration is absent — never a silent pass.
//!
//! Required environment for the live lanes:
//!   * `MCP_RE_AWS_KMS_KEY_ID`   — an `ECC_NIST_EDWARDS25519` key id/ARN/alias.
//!   * `MCP_RE_AWS_KMS_REGION`   — the region.
//!   * Credentials: the static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` pair,
//!     or `MCP_RE_AWS_USE_WEB_IDENTITY=1` for the IRSA path (what the on-EKS run
//!     uses — no IAM key material in the pod).
//!   * `MCP_RE_AWS_KMS_ENDPOINT` — OPTIONAL emulator endpoint override.
#![cfg(feature = "aws_kms_keysource")]

use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::sign_request_with_signer;
use mcp_re_http_profile::sign_response_with_signer;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_proxy::AwsKmsConfig;
use mcp_re_proxy::AwsKmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

const REQ_KEY_ID: &str = "aws-kms-req-1";
const RSP_KEY_ID: &str = "aws-kms-rsp-1";
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "aws-kms http-profile lane: required env var {name} is not set — this lane must run \
             against a real/emulated AWS KMS; it does not pass without verifying"
        ),
    }
}

/// The live AWS KMS signer, failing loudly if unconfigured.
fn live_signer() -> KmsResponseSigner {
    let config = AwsKmsConfig {
        region: require_env("MCP_RE_AWS_KMS_REGION"),
        key_id: require_env("MCP_RE_AWS_KMS_KEY_ID"),
        endpoint: std::env::var("MCP_RE_AWS_KMS_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty()),
    };
    // The IRSA path is not a different signature — it is a different way of getting
    // the credential that authorizes the same `Sign`. Running this lane both ways is
    // how "no IAM key material in the pod" stops being a claim about configuration
    // and becomes one about a signature that verified.
    let backend = if std::env::var("MCP_RE_AWS_USE_WEB_IDENTITY").is_ok_and(|v| v == "1") {
        AwsKmsEd25519Backend::from_web_identity(
            &config,
            std::env::var("MCP_RE_AWS_STS_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty()),
        )
        .expect("construct AWS KMS backend through IRSA (GetPublicKey must succeed and be Ed25519)")
    } else {
        require_env("AWS_ACCESS_KEY_ID");
        AwsKmsEd25519Backend::from_env(&config)
            .expect("construct AWS KMS backend (GetPublicKey must succeed and be Ed25519)")
    };
    KmsResponseSigner::new(Box::new(backend))
}

/// An offline signer over the SAME backend adapter, using a local seed instead
/// of a network round-trip — exercises the KMS-backend → seam wiring hermetically.
fn offline_signer() -> KmsResponseSigner {
    let backend = AwsKmsEd25519Backend::for_test_with_local_seed(&[7u8; 32], "alias/offline")
        .expect("local-seed KMS backend");
    KmsResponseSigner::new(Box::new(backend))
}

/// The external-signer closure the profile seam expects: RFC 9421 base bytes in,
/// raw 64-byte Ed25519 signature out. Wraps the KMS signer (which returns
/// base64url and self-verifies before returning).
fn kms_sign_base(signer: &KmsResponseSigner, base: &[u8]) -> Result<Vec<u8>, HttpProfileError> {
    let b64url = signer
        .sign_response(base)
        .map_err(|_| HttpProfileError::InvalidSignature)?;
    mcp_re_core::b64url_decode(&b64url).map_err(|_| HttpProfileError::InvalidSignature)
}

fn actor(role: &str, key_id: &str, pubkey: &VerificationKey, slot: SignerSlot) -> ResolvedActor {
    ResolvedActor {
        identity: ActorIdentity {
            role: role.into(),
            trust_domain: "example.com".into(),
            subject: format!("did:example:{role}"),
            keyid: key_id.into(),
        },
        verification_key: pubkey.clone(),
        slot,
    }
}

/// Resolver mapping the request/response keyids to the one KMS public key, each
/// vouched for its own slot (a wrong-slot key fails, per MCPRE-100).
fn resolver(pubkey: &VerificationKey) -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    let pk = pubkey.clone();
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (REQ_KEY_ID, SignerSlot::Request) => Some(actor("client", REQ_KEY_ID, &pk, slot)),
        (RSP_KEY_ID, SignerSlot::Response) => Some(actor("server", RSP_KEY_ID, &pk, slot)),
        _ => None,
    }
}

fn base_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    }
}

fn base_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    }
}

/// Sign an RFC 9421 REQUEST via the KMS-backed seam; the unmodified verifier
/// accepts it, a post-signing body tamper fails closed, and the signature does
/// not verify under a foreign key.
fn run_request_lane(signer: &KmsResponseSigner) {
    let pubkey = signer.response_public_key().expect("KMS public key");

    let mut req = base_request();
    sign_request_with_signer(
        &mut req,
        |base| kms_sign_base(signer, base),
        REQ_KEY_ID,
        CREATED,
        EXPIRES,
        "nonce-http-1",
    )
    .expect("AWS KMS must sign an RFC 9421 request through the profile seam");

    Verifier::new(&VerifierPolicy::default(), &resolver(&pubkey))
        .verify_request_floor(&req, NOW)
        .expect("an AWS KMS-signed HTTP-profile request MUST verify under verify_request");

    // Negative — tamper the covered content after signing.
    let mut tampered = req.clone();
    let last = tampered.body.len() - 1;
    tampered.body[last] ^= 0x01;
    assert!(
        Verifier::new(&VerifierPolicy::default(), &resolver(&pubkey))
            .verify_request_floor(&tampered, NOW)
            .is_err(),
        "a post-signing body tamper must fail closed"
    );

    // Negative — the live signature must not verify under a foreign key.
    let foreign = SigningKey::from_seed_bytes(&[0x09; 32]).public_key();
    assert!(
        Verifier::new(&VerifierPolicy::default(), &resolver(&foreign))
            .verify_request_floor(&req, NOW)
            .is_err(),
        "an AWS KMS HTTP-profile signature must NOT verify under a foreign key"
    );
}

/// Sign an RFC 9421 RESPONSE via the KMS-backed seam, bound to a request through
/// `;req`; the unmodified verifier accepts it and a tamper fails closed.
fn run_response_lane(signer: &KmsResponseSigner) {
    let pubkey = signer.response_public_key().expect("KMS public key");

    // A request the response binds to. Sign it with a local key (the request leg
    // is not what this lane proves); the response is the KMS-signed artifact.
    let req_key = SigningKey::from_seed_bytes(&[0x11; 32]);
    let mut req = base_request();
    sign_request(
        &mut req,
        &req_key,
        REQ_KEY_ID,
        CREATED,
        EXPIRES,
        "nonce-http-2",
    )
    .expect("sign bound request");
    let req_resolver = {
        let req_pub = req_key.public_key();
        let rsp_pub = pubkey.clone();
        move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
            (REQ_KEY_ID, SignerSlot::Request) => Some(actor("client", REQ_KEY_ID, &req_pub, slot)),
            (RSP_KEY_ID, SignerSlot::Response) => Some(actor("server", RSP_KEY_ID, &rsp_pub, slot)),
            _ => None,
        }
    };

    let mut rsp = base_response();
    sign_response_with_signer(
        &mut rsp,
        &req,
        |base| kms_sign_base(signer, base),
        RSP_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("AWS KMS must sign an RFC 9421 response through the profile seam");

    Verifier::new(&VerifierPolicy::default(), &req_resolver)
        .verify_bound_response_floor(&rsp, &req, NOW)
        .expect("an AWS KMS-signed HTTP-profile response MUST verify under verify_response");

    // Negative — tamper the response content after signing.
    let mut tampered = rsp.clone();
    let last = tampered.body.len() - 1;
    tampered.body[last] ^= 0x01;
    assert!(
        Verifier::new(&VerifierPolicy::default(), &req_resolver)
            .verify_bound_response_floor(&tampered, &req, NOW)
            .is_err(),
        "a post-signing response tamper must fail closed"
    );
}

// ---- offline (hermetic, runs in blocking CI) ------------------------------

#[test]
fn aws_kms_http_profile_request_offline_local_seed() {
    run_request_lane(&offline_signer());
}

#[test]
fn aws_kms_http_profile_response_offline_local_seed() {
    run_response_lane(&offline_signer());
}

// ---- live (real AWS KMS; ignored) -----------------------------------------

#[test]
#[ignore = "requires a live or emulated AWS KMS (run with --ignored and MCP_RE_AWS_KMS_* set)"]
fn aws_kms_http_profile_request_live() {
    run_request_lane(&live_signer());
}

#[test]
#[ignore = "requires a live or emulated AWS KMS (run with --ignored and MCP_RE_AWS_KMS_* set)"]
fn aws_kms_http_profile_response_live() {
    run_response_lane(&live_signer());
}
