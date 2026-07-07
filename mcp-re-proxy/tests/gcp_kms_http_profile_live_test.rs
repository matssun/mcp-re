// SPDX-License-Identifier: Apache-2.0
//! Live GCP Cloud KMS — HTTP standards-profile (RFC 9421 + RFC 9530) lane
//! (ADR-MCPRE-050 + MCPRE-106).
//!
//! The sibling `gcp_kms_draft02_live_test` proves Cloud KMS can sign a draft-02
//! envelope. This lane closes the equivalent gap for the HTTP standards profile:
//! it proves Cloud KMS can sign an RFC 9421 request/response — through the
//! profile's PRODUCTION external-signer seam (`sign_request_with_signer` /
//! `sign_response_with_signer`, MCPRE-106) — that the UNMODIFIED
//! `verify_request` / `verify_response` accept, with tamper + wrong-key
//! negatives. The private key never leaves KMS; the profile owns base
//! construction and header assembly, KMS provides only the raw signature.
//!
//! Two entry points share one lane body:
//!   * `*_offline_local_seed` — NOT ignored: runs in the blocking feature-gated
//!     CI job via `GcpKmsEd25519Backend::for_test_with_local_seed` (no network),
//!     guarding the KMS-backend → seam wiring on every push.
//!   * `*_live` — `#[ignore]`: the real Cloud KMS backend; run from the cloud
//!     script / nightly lane with `-- --ignored` and `MCP_RE_GCP_*` set. FAILS
//!     LOUDLY if its configuration is absent — never a silent pass.
//!
//! Required environment for the live lanes:
//!   * `MCP_RE_GCP_KEY_VERSION`  — full `EC_SIGN_ED25519` key-version resource path.
//!   * `MCP_RE_GCP_ACCESS_TOKEN` (bearer) or `MCP_RE_GCP_USE_METADATA=1`.
//!   * `MCP_RE_GCP_KMS_ENDPOINT` — OPTIONAL emulator endpoint override.
#![cfg(feature = "gcp_kms_keysource")]

use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
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
use mcp_re_proxy::GcpKmsConfig;
use mcp_re_proxy::GcpKmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

const REQ_KEY_ID: &str = "gcp-kms-req-1";
const RSP_KEY_ID: &str = "gcp-kms-rsp-1";
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "gcp-kms http-profile lane: required env var {name} is not set — this lane must run \
             against a real/emulated Cloud KMS; it does not pass without verifying"
        ),
    }
}

/// The live Cloud KMS signer, failing loudly if unconfigured.
fn live_signer() -> KmsResponseSigner {
    let config = GcpKmsConfig {
        key_version_name: require_env("MCP_RE_GCP_KEY_VERSION"),
        endpoint: std::env::var("MCP_RE_GCP_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
    };
    let use_metadata = std::env::var("MCP_RE_GCP_USE_METADATA").is_ok_and(|v| v == "1");
    if !use_metadata {
        require_env("MCP_RE_GCP_ACCESS_TOKEN");
    }
    let backend = GcpKmsEd25519Backend::new(&config, use_metadata)
        .expect("construct GCP KMS backend (getPublicKey must succeed and be Ed25519)");
    KmsResponseSigner::new(Box::new(backend))
}

/// An offline signer over the SAME backend adapter, using a local seed instead
/// of a network round-trip — exercises the KMS-backend → seam wiring hermetically.
fn offline_signer() -> KmsResponseSigner {
    let backend = GcpKmsEd25519Backend::for_test_with_local_seed(&[7u8; 32])
        .expect("local-seed KMS backend");
    KmsResponseSigner::new(Box::new(backend))
}

/// The external-signer closure the profile seam expects: RFC 9421 base bytes in,
/// raw 64-byte Ed25519 signature out. Wraps the KMS signer (which returns
/// base64url and self-verifies before returning).
fn kms_sign_base(signer: &KmsResponseSigner, base: &[u8]) -> Result<Vec<u8>, HttpProfileError> {
    let b64url = signer.sign_response(base).map_err(|_| HttpProfileError::InvalidSignature)?;
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
    .expect("Cloud KMS must sign an RFC 9421 request through the profile seam");

    verify_request(&req, &resolver(&pubkey), NOW)
        .expect("a Cloud KMS-signed HTTP-profile request MUST verify under verify_request");

    // Negative — tamper the covered content after signing.
    let mut tampered = req.clone();
    let last = tampered.body.len() - 1;
    tampered.body[last] ^= 0x01;
    assert!(
        verify_request(&tampered, &resolver(&pubkey), NOW).is_err(),
        "a post-signing body tamper must fail closed"
    );

    // Negative — the live signature must not verify under a foreign key.
    let foreign = SigningKey::from_seed_bytes(&[0x09; 32]).public_key();
    assert!(
        verify_request(&req, &resolver(&foreign), NOW).is_err(),
        "a Cloud KMS HTTP-profile signature must NOT verify under a foreign key"
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
    sign_request(&mut req, &req_key, REQ_KEY_ID, CREATED, EXPIRES, "nonce-http-2")
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
    .expect("Cloud KMS must sign an RFC 9421 response through the profile seam");

    verify_response(&rsp, &req, &req_resolver, NOW)
        .expect("a Cloud KMS-signed HTTP-profile response MUST verify under verify_response");

    // Negative — tamper the response content after signing.
    let mut tampered = rsp.clone();
    let last = tampered.body.len() - 1;
    tampered.body[last] ^= 0x01;
    assert!(
        verify_response(&tampered, &req, &req_resolver, NOW).is_err(),
        "a post-signing response tamper must fail closed"
    );
}

// ---- offline (hermetic, runs in blocking CI) ------------------------------

#[test]
fn gcp_kms_http_profile_request_offline_local_seed() {
    run_request_lane(&offline_signer());
}

#[test]
fn gcp_kms_http_profile_response_offline_local_seed() {
    run_response_lane(&offline_signer());
}

// ---- live (real Cloud KMS; ignored) ---------------------------------------

#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCP_RE_GCP_* set)"]
fn gcp_kms_http_profile_request_live() {
    run_request_lane(&live_signer());
}

#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCP_RE_GCP_* set)"]
fn gcp_kms_http_profile_response_live() {
    run_response_lane(&live_signer());
}
