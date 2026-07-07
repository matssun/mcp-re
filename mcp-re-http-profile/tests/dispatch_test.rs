// SPDX-License-Identifier: Apache-2.0
//! MCPRE-102 — dispatcher seam battery: replay + MRTR continuation driven from
//! verified full-profile evidence.
//!
//! These exercise `dispatch_request` end-to-end: a real `sign_request_full` /
//! `verify_request_full` produces the verified evidence context, and the
//! dispatcher then constructs the five-tuple replay key, admits it, and verifies
//! any MRTR continuation. The fleet-strict gate is proven at the pure-profile
//! layer (the core `is_single_process_reference` signal), not the proxy tier.

use mcp_re_core::InMemoryReplayCache;
use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;
use mcp_re_http_profile::dispatch_request;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::verify_request_full;
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
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::RetainedContinuation;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedHttpRequestEvidence;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_core::SigningKey;

const CLIENT_A_SEED: [u8; 32] = [11u8; 32];
const CLIENT_B_SEED: [u8; 32] = [33u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";

const ACCESS_TOKEN: &str = "access-token-xyz";

const PREV_BASE: &[u8] = b"previous-request-signature-base";
const IRR_BASE: &[u8] = b"input-required-response-signature-base";
const REQ_STATE: &[u8] = b"opaque-request-state";

fn client_a_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_A_SEED)
}
fn client_b_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_B_SEED)
}

/// A resolver with two distinct client actors: `client-key-1`/`did:example:host-a`
/// and `client-key-2`/`did:example:host-b`. Same-nonce-different-actor uses both.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (subject, key) = match (key_id, slot) {
            ("client-key-1", SignerSlot::Request) => ("did:example:host-a", client_a_key()),
            ("client-key-2", SignerSlot::Request) => ("did:example:host-b", client_b_key()),
            _ => return None,
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: subject.into(),
                keyid: key_id.into(),
            },
            verification_key: key.public_key(),
            slot,
        })
    }
}

fn audience(audience_id: &str) -> AudienceTuple {
    AudienceTuple {
        audience_id: audience_id.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

fn request_block(audience: AudienceTuple, continuation: Option<HttpContinuation>) -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience,
        // A DPoP `ath` binding over the covered Authorization header — the block
        // grammar requires at least one artifact binding; `no_material` suffices
        // because DPoP is header-derived.
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation,
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

fn no_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |_b: &ArtifactBinding| None
}

/// Sign + verify a full-profile request, returning the verified evidence the
/// dispatcher consumes. `key`/`key_id` pick the signing actor; `nonce` and the
/// block's audience drive the replay key.
fn verified_request(
    key: &SigningKey,
    key_id: &str,
    nonce: &str,
    block: &HttpRequestEvidenceBlock,
) -> VerifiedHttpRequestEvidence {
    let mut req = base_request();
    sign_request_full(&mut req, block, key, key_id, CREATED, EXPIRES, nonce).expect("full sign");
    verify_request_full(&req, &block.audience, &no_material(), &resolver(), NOW).expect("full verify")
}

// ---------- replay ---------------------------------------------------------

/// Acceptance #1: duplicate nonce for the same actor/audience/profile fails replay.
#[test]
fn duplicate_nonce_same_actor_audience_profile_is_replay() {
    let block = request_block(audience("verifier-1"), None);
    let ev = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let mut cache = InMemoryReplayCache::new(0);
    let cfg = DispatchConfig::default();

    let first = dispatch_request(&ev, &mut cache, None, &cfg).expect("first admit");
    assert!(!first.continuation_verified);
    // Re-present the identical verified evidence: same five-tuple → replay.
    let err = dispatch_request(&ev, &mut cache, None, &cfg).expect_err("replay must be detected");
    assert_eq!(err, DispatchError::ReplayDetected);
    assert_eq!(err.wire_code(), "mcp-re.replay_detected");
}

/// Acceptance #2: the same nonce under a different audience does not collide.
#[test]
fn same_nonce_different_audience_does_not_collide() {
    let mut cache = InMemoryReplayCache::new(0);
    let cfg = DispatchConfig::default();

    let block_a = request_block(audience("verifier-1"), None);
    let ev_a = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block_a);
    let block_b = request_block(audience("verifier-2"), None);
    let ev_b = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block_b);

    dispatch_request(&ev_a, &mut cache, None, &cfg).expect("audience-1 admit");
    // Same actor, profile, nonce — different audience_hash: a distinct key.
    dispatch_request(&ev_b, &mut cache, None, &cfg).expect("audience-2 must not collide");
}

/// Acceptance #3: the same nonce for a different resolved actor does not collide.
#[test]
fn same_nonce_different_resolved_actor_does_not_collide() {
    let mut cache = InMemoryReplayCache::new(0);
    let cfg = DispatchConfig::default();

    let block = request_block(audience("verifier-1"), None);
    let ev_a = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let ev_b = verified_request(&client_b_key(), "client-key-2", "nonce-1", &block);

    dispatch_request(&ev_a, &mut cache, None, &cfg).expect("actor-a admit");
    // Same audience, profile, nonce — different actor_id: a distinct key.
    dispatch_request(&ev_b, &mut cache, None, &cfg).expect("actor-b must not collide");
}

// ---------- fleet-strict tier gate -----------------------------------------

/// A test-only replay cache that self-declares the `Durable` class, standing in
/// for a shared/production tier at the pure-profile layer.
struct DurableTestCache(InMemoryReplayCache);

impl ReplayCache for DurableTestCache {
    fn check_and_insert(
        &mut self,
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

/// Acceptance #4: fleet-strict rejects the single-process reference cache
/// (renamed from "non-shared replay tier": the pure profile knows only the core
/// `is_single_process_reference` signal, not the proxy `ReplayDurabilityTier`).
#[test]
fn fleet_strict_rejects_single_process_reference_cache() {
    let block = request_block(audience("verifier-1"), None);
    let ev = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let mut cache = InMemoryReplayCache::new(0);
    let cfg = DispatchConfig { fleet_strict: true };

    let err = dispatch_request(&ev, &mut cache, None, &cfg).expect_err("strict must refuse");
    assert_eq!(err, DispatchError::NonSharedReplayTier);
    assert_eq!(err.wire_code(), "mcp-re.replay_cache_unavailable");
}

/// Fleet-strict admits a cache that declares itself durable (the follow-up proxy
/// adapter layers the richer `ReplayDurabilityTier` gate on top).
#[test]
fn fleet_strict_admits_durable_cache() {
    let block = request_block(audience("verifier-1"), None);
    let ev = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let mut cache = DurableTestCache(InMemoryReplayCache::new(0));
    let cfg = DispatchConfig { fleet_strict: true };

    dispatch_request(&ev, &mut cache, None, &cfg).expect("durable cache admitted under strict");
}

// ---------- MRTR continuation ----------------------------------------------

fn continuation_block() -> HttpRequestEvidenceBlock {
    let cont = HttpContinuation::build(PREV_BASE, IRR_BASE, REQ_STATE);
    request_block(audience("verifier-1"), Some(cont))
}

fn matching_ctx() -> RetainedContinuation<'static> {
    RetainedContinuation {
        previous_request_base: PREV_BASE,
        input_required_response_base: IRR_BASE,
        request_state: REQ_STATE,
    }
}

/// A well-formed continuation verifies and is reported as such.
#[test]
fn continuation_round_trips_through_dispatch() {
    let block = continuation_block();
    let ev = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let mut cache = InMemoryReplayCache::new(0);

    let outcome = dispatch_request(&ev, &mut cache, Some(matching_ctx()), &DispatchConfig::default())
        .expect("continuation must verify");
    assert!(outcome.continuation_verified);
}

/// Acceptance #5: a continuation with changed `requestState` fails.
#[test]
fn continuation_changed_request_state_fails() {
    let block = continuation_block();
    let ev = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let mut cache = InMemoryReplayCache::new(0);
    let ctx = RetainedContinuation {
        request_state: b"tampered-request-state",
        ..matching_ctx()
    };

    let err = dispatch_request(&ev, &mut cache, Some(ctx), &DispatchConfig::default())
        .expect_err("changed requestState must fail");
    assert_eq!(err, DispatchError::Profile(HttpProfileError::ContinuationBindingFailed));
    assert_eq!(err.wire_code(), "mcp-re.continuation_binding_failed");
}

/// Acceptance #6: a continuation with the wrong previous-request evidence fails.
#[test]
fn continuation_wrong_previous_request_evidence_fails() {
    let block = continuation_block();
    let ev = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let mut cache = InMemoryReplayCache::new(0);
    let ctx = RetainedContinuation {
        previous_request_base: b"a-different-previous-request",
        ..matching_ctx()
    };

    let err = dispatch_request(&ev, &mut cache, Some(ctx), &DispatchConfig::default())
        .expect_err("wrong previous-request evidence must fail");
    assert_eq!(err, DispatchError::Profile(HttpProfileError::ContinuationBindingFailed));
}

/// Acceptance #7: a continuation with the wrong input-required response evidence fails.
#[test]
fn continuation_wrong_input_required_response_evidence_fails() {
    let block = continuation_block();
    let ev = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let mut cache = InMemoryReplayCache::new(0);
    let ctx = RetainedContinuation {
        input_required_response_base: b"a-different-input-required-response",
        ..matching_ctx()
    };

    let err = dispatch_request(&ev, &mut cache, Some(ctx), &DispatchConfig::default())
        .expect_err("wrong input-required response evidence must fail");
    assert_eq!(err, DispatchError::Profile(HttpProfileError::ContinuationBindingFailed));
}

/// A request carrying a continuation but no retained context fails closed: an
/// unverifiable binding must never be admitted.
#[test]
fn continuation_without_retained_context_fails_closed() {
    let block = continuation_block();
    let ev = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let mut cache = InMemoryReplayCache::new(0);

    let err = dispatch_request(&ev, &mut cache, None, &DispatchConfig::default())
        .expect_err("missing continuation context must fail closed");
    assert_eq!(err, DispatchError::Profile(HttpProfileError::ContinuationBindingFailed));
}

/// A spliced continuation must NOT burn the nonce: the replay insert is last, so
/// after a continuation-binding failure the same nonce is still fresh.
#[test]
fn failed_continuation_does_not_burn_the_nonce() {
    let block = continuation_block();
    let ev = verified_request(&client_a_key(), "client-key-1", "nonce-1", &block);
    let mut cache = InMemoryReplayCache::new(0);
    let bad_ctx = RetainedContinuation {
        request_state: b"tampered",
        ..matching_ctx()
    };

    // First attempt fails on the continuation, before the replay insert.
    dispatch_request(&ev, &mut cache, Some(bad_ctx), &DispatchConfig::default())
        .expect_err("spliced continuation fails");
    // The good re-presentation still admits: the nonce was never burned.
    let outcome = dispatch_request(&ev, &mut cache, Some(matching_ctx()), &DispatchConfig::default())
        .expect("nonce must still be fresh after a failed continuation");
    assert!(outcome.continuation_verified);
}
