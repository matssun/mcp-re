// SPDX-License-Identifier: Apache-2.0
//! MCPRE-103 — ADR-MCPRE-050 full-profile parity gate (integration declaration).
//!
//! This battery is the executable evidence behind the parity-green declaration:
//! it drives the **integrated** live path end-to-end —
//!
//! ```text
//! sign_request_full → verify_request_full → dispatch_request
//!                                          → sign_response_full → verify_response_full
//! ```
//!
//! — and proves the `se.syncom/mcp-re.http.request` / `.response` body evidence
//! blocks, the five-tuple replay key, and the MRTR continuation binding are
//! ACTIVE in that path, not merely defined by the frozen conformance corpus.
//! Each of ADR-MCPRE-050's acceptance behaviours is asserted here as a state
//! transition of the integrated verifier, so a regression that silently
//! deactivated a block (accepting where it must reject) fails this gate.
//!
//! Acceptance coverage (ADR-MCPRE-050 §Consequences):
//!   1. request body tamper fails                              → `body_tamper_*`
//!   2. response splice fails                                  → `response_splice_*`
//!   3. response request_evidence mismatch → request_binding   → `response_evidence_*`
//!   4. DPoP/RAR artifact mismatch fails                       → `artifact_*`
//!   5. replay fails                                           → `replay_*`
//!   6. MRTR continuation mismatch fails                       → `continuation_*`
//!   7. third-party RFC 9421 cross-verification passes         → SEPARATE GATE:
//!      `rfc9421_cross_verification_test` + the `rfc9421-cross-verify` CI
//!      no-merge job (MCPRE-99). Deliberately NOT re-executed here — one source
//!      of truth for RFC 9421 interop; this battery composes with it.
//!
//! The positive baseline (`full_exchange_activates_all_blocks`) asserts the
//! body blocks are live on the accepting path before the negatives prove each
//! rejects.

use mcp_re_core::InMemoryReplayCache;
use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::dispatch_request;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::verify_response_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::DispatchConfig;
use mcp_re_http_profile::DispatchError;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::RetainedContinuation;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const RAR_DETAILS: &[u8] = b"rar-authorization-details-json";

const PREV_BASE: &[u8] = b"previous-request-signature-base";
const IRR_BASE: &[u8] = b"input-required-response-signature-base";
const REQ_STATE: &[u8] = b"opaque-request-state";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
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

fn server_identity() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: "server-key-1".into(),
    }
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "verifier-1".into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

/// A request block carrying BOTH a DPoP (`ath`, header-derived) and a RAR
/// (material-supplied) artifact binding, plus an MRTR continuation — so the
/// integrated path exercises every active surface at once.
fn full_block() -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![
            ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, ACCESS_TOKEN.as_bytes()),
            ArtifactBinding::opaque_digest(ArtifactType::OauthRar, RAR_DETAILS),
        ],
        continuation: Some(HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE)),
        admission: None,
    }
}

fn base_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec(),
    }
}

/// The RAR credential material closure. DPoP is header-derived (needs no
/// material); RAR is caller-supplied, so this returns the committed details for
/// a RAR binding and `None` otherwise.
fn rar_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |b: &ArtifactBinding| match b.artifact_type {
        ArtifactType::OauthRar => Some(RAR_DETAILS.to_vec()),
        _ => None,
    }
}

fn signed_request(block: &HttpRequestEvidenceBlock, nonce: &str) -> (HttpRequest, RequestEvidence) {
    let mut req = base_request();
    let ev = sign_request_full(&mut req, block, &client_key(), "client-key-1", CREATED, EXPIRES, nonce)
        .expect("full sign");
    (req, ev)
}

fn matching_ctx() -> RetainedContinuation<'static> {
    RetainedContinuation {
        previous_request_base: PREV_BASE,
        input_required_response_base: IRR_BASE,
        request_state: REQ_STATE,
    }
}

/// A shared/durable replay cache stand-in so the integrated path runs under the
/// fleet-strict posture the parity gate declares (the pure profile knows only
/// the core `is_single_process_reference` signal; the proxy `ReplayDurabilityTier`
/// gate is a separate deployment concern).
struct DurableCache(InMemoryReplayCache);
impl ReplayCache for DurableCache {
    fn check_and_insert(
        &self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        self.0.check_and_insert(signer, audience, nonce, expires_at_unix)
    }
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::Durable
    }
}
fn strict_cache() -> DurableCache {
    DurableCache(InMemoryReplayCache::new(0))
}
fn strict_cfg() -> DispatchConfig {
    DispatchConfig { fleet_strict: true }
}

fn response_body() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
}

// ---------- positive baseline: the integrated path is LIVE -----------------

#[test]
fn full_exchange_activates_all_blocks() {
    let block = full_block();
    let (req, ev) = signed_request(&block, "nonce-1");

    // Request body block is active: audience + block surfaced by verification.
    let verified = verify_request_full(&req, &audience(), &rar_material(), &resolver(), NOW)
        .expect("full request verifies");
    assert!(verified.request_block.is_some(), "request body block must be active");
    assert_eq!(verified.audience_hash.as_deref(), Some(audience().audience_hash()).as_deref());

    // Dispatcher drives replay + continuation over the verified evidence.
    let cache = strict_cache();
    let outcome = dispatch_request(&verified, &cache, Some(matching_ctx()), &strict_cfg())
        .expect("dispatch admits");
    assert!(outcome.continuation_verified, "continuation must be active");

    // Response body block is active: server_signer + request_evidence bound.
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_response_full(&mut rsp, &req, &ev, &server_identity(), &server_key(), "server-key-1", CREATED, EXPIRES)
        .expect("full response sign");
    let rv = verify_response_full(&rsp, &req, &verified, &resolver(), NOW).expect("full response verifies");
    assert_eq!(rv.bound_request_evidence, rv.body_request_evidence, "response binds request evidence");
    assert_eq!(rv.server_signer.as_ref().unwrap().keyid, "server-key-1");
}

// ---------- #1 request body tamper -----------------------------------------

#[test]
fn body_tamper_fails_in_integrated_path() {
    let block = full_block();
    let (mut req, _ev) = signed_request(&block, "nonce-1");
    // Flip a byte of the covered content after signing.
    let last = req.body.len() - 1;
    req.body[last] ^= 0x01;
    let err = verify_request_full(&req, &audience(), &rar_material(), &resolver(), NOW).unwrap_err();
    assert_eq!(err.wire_code(), "mcp-re.digest_mismatch");
}

// ---------- #2 response splice ---------------------------------------------

#[test]
fn response_splice_fails_in_integrated_path() {
    let block = full_block();
    let (req_a, _ev_a) = signed_request(&block, "nonce-a");
    let verified_a = verify_request_full(&req_a, &audience(), &rar_material(), &resolver(), NOW)
        .expect("req_a verifies");

    // An independent exchange B with a DISTINCT body, so its ;req binding base
    // differs from req_a's and the cryptographic floor (not just the body-evidence
    // comparison) rejects the splice.
    let mut req_b = base_request();
    req_b.body = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read"}}"#.to_vec();
    let ev_b = sign_request_full(&mut req_b, &block, &client_key(), "client-key-1", CREATED, EXPIRES, "nonce-b")
        .expect("sign b");
    let mut rsp_b = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_response_full(&mut rsp_b, &req_b, &ev_b, &server_identity(), &server_key(), "server-key-1", CREATED, EXPIRES)
        .expect("sign resp b");

    // Splice rsp_b onto req_a: the ;req cryptographic floor rejects.
    let err = verify_response_full(&rsp_b, &req_a, &verified_a, &resolver(), NOW).unwrap_err();
    assert_eq!(err.wire_code(), "mcp-re.response_sig_invalid");
}

// ---------- #3 response request_evidence mismatch → request_binding --------

#[test]
fn response_evidence_mismatch_emits_request_binding_mismatch() {
    let block = full_block();
    let (req_a, _ev_a) = signed_request(&block, "nonce-a");
    let verified_a = verify_request_full(&req_a, &audience(), &rar_material(), &resolver(), NOW)
        .expect("req_a verifies");

    // A different request's evidence handle, advertised by a response whose ;req
    // is still bound to req_a: the crypto floor passes, the body comparison trips.
    let (_req_b, ev_b) = signed_request(&block, "nonce-b");
    assert_ne!(ev_b.digest_value, verified_a.evidence.digest_value);

    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_response_full(&mut rsp, &req_a, &ev_b, &server_identity(), &server_key(), "server-key-1", CREATED, EXPIRES)
        .expect("sign");
    let err = verify_response_full(&rsp, &req_a, &verified_a, &resolver(), NOW).unwrap_err();
    assert_eq!(err.wire_code(), "mcp-re.request_binding_mismatch");
}

// ---------- #4 DPoP/RAR artifact mismatch ----------------------------------

#[test]
fn artifact_mismatch_fails_in_integrated_path() {
    // The RAR binding commits to RAR_DETAILS, but the material closure hands back
    // different bytes: strict artifact enforcement rejects.
    let block = full_block();
    let (req, _ev) = signed_request(&block, "nonce-1");
    let wrong_rar = |b: &ArtifactBinding| match b.artifact_type {
        ArtifactType::OauthRar => Some(b"a-different-rar-detail".to_vec()),
        _ => None,
    };
    let err = verify_request_full(&req, &audience(), &wrong_rar, &resolver(), NOW).unwrap_err();
    assert_eq!(err.wire_code(), "mcp-re.artifact_binding_failed");
}

// ---------- #5 replay ------------------------------------------------------

#[test]
fn replay_fails_in_integrated_path() {
    let block = full_block();
    let (req, _ev) = signed_request(&block, "nonce-1");
    let verified = verify_request_full(&req, &audience(), &rar_material(), &resolver(), NOW)
        .expect("verifies");
    let cache = strict_cache();

    dispatch_request(&verified, &cache, Some(matching_ctx()), &strict_cfg()).expect("first admit");
    let err = dispatch_request(&verified, &cache, Some(matching_ctx()), &strict_cfg()).unwrap_err();
    assert_eq!(err, DispatchError::ReplayDetected);
    assert_eq!(err.wire_code(), "mcp-re.replay_detected");
}

// ---------- #6 MRTR continuation mismatch ----------------------------------

#[test]
fn continuation_mismatch_fails_in_integrated_path() {
    let block = full_block();
    let (req, _ev) = signed_request(&block, "nonce-1");
    let verified = verify_request_full(&req, &audience(), &rar_material(), &resolver(), NOW)
        .expect("verifies");
    let cache = strict_cache();

    // Tampered requestState against the retained bases.
    let bad_ctx = RetainedContinuation {
        request_state: b"tampered-request-state",
        ..matching_ctx()
    };
    let err = dispatch_request(&verified, &cache, Some(bad_ctx), &strict_cfg()).unwrap_err();
    assert_eq!(err, DispatchError::Profile(HttpProfileError::ContinuationBindingFailed));
    assert_eq!(err.wire_code(), "mcp-re.continuation_binding_failed");
}

// ---------- #7 third-party RFC 9421 cross-verification ----------------------
//
// Covered by the SEPARATE MCPRE-99 gate — `rfc9421_cross_verification_test` and
// the `rfc9421-cross-verify` CI no-merge job (an independent python-cryptography
// Ed25519 implementation over the frozen `external_kat.json`). Not re-executed
// here to keep one source of truth for RFC 9421 interop; the parity declaration
// composes this integrated battery (#1–#6) with that gate (#7).
//
// This documentation test records the composition at the point of the parity
// battery; the interop assertion itself lives in the referenced MCPRE-99 gate.
#[test]
fn third_party_cross_verification_is_a_separate_gate() {
    // Fleet-strict is the posture the parity battery runs under; #7's interop
    // proof is `rfc9421_cross_verification_test` + the CI no-merge job.
    assert!(strict_cfg().fleet_strict);
}
