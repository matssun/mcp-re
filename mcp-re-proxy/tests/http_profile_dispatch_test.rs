// SPDX-License-Identifier: Apache-2.0
//! MCPRE-104 (#308) — the proxy replay-tier adapter around the HTTP-profile
//! dispatcher, driven end-to-end.
//!
//! These prove the four acceptance criteria of #308 against the real profile
//! sign/verify seam:
//!  1. under fleet-strict the adapter refuses a sub-minimum tier
//!     (redis-async / single-store-fail-closed);
//!  2. under fleet-strict it admits redis-wait-quorum / linearizable;
//!  3. an HTTP-profile request flows verify_request_full → (adapter) dispatch →
//!     sign_response_full → verify_response_full end-to-end;
//!  4. beneath the tier gate, the dispatcher's core is_single_process_reference
//!     refusal still fires (defense in depth) even with an acceptable declared tier.

use mcp_re_core::InMemoryReplayCache;
use mcp_re_core::ReplayCache;
use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;
use mcp_re_core::SigningKey;

use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::verify_response_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::DispatchError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedHttpRequestEvidence;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::http_profile_dispatch::dispatch_request_with_tier_gate;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchError;
use mcp_re_proxy::replay_tier::ReplayDurabilityTier;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_KEY_ID: &str = "server-key-1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

/// Resolves the client key in the Request slot and the server key in the Response
/// slot — so a full request+response round-trip verifies.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:host-a".into(),
                keyid: CLIENT_KEY_ID.into(),
            },
            verification_key: client_key().public_key(),
            slot,
        }),
        (SERVER_KEY_ID, SignerSlot::Response) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server-1".into(),
                keyid: SERVER_KEY_ID.into(),
            },
            verification_key: server_key().public_key(),
            slot,
        }),
        _ => None,
    }
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "verifier-1".into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

fn request_block() -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
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

/// A signed + verified request with a fresh `nonce`. Returns both the verified
/// evidence and the raw signed request (the e2e test needs the request to bind and
/// verify the response's `;req` components).
fn signed_and_verified(nonce: &str) -> (HttpRequest, VerifiedHttpRequestEvidence) {
    let block = request_block();
    let mut req = base_request();
    sign_request_full(&mut req, &block, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, nonce)
        .expect("full sign");
    let verified = verify_request_full(&req, &block.audience, &no_material(), &resolver(), NOW)
        .expect("full verify");
    (req, verified)
}

/// A test-only replay cache that self-declares the `Durable` class — a shared /
/// production tier, so the dispatcher's core single-process gate does NOT fire.
struct DurableTestCache(InMemoryReplayCache);

impl ReplayCache for DurableTestCache {
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

fn durable_cache() -> DurableTestCache {
    DurableTestCache(InMemoryReplayCache::new(0))
}

// --- AT1: fleet-strict refuses a sub-minimum declared tier -------------------

#[test]
fn fleet_strict_refuses_redis_async_tier() {
    let (_req, verified) = signed_and_verified("nonce-async");
    let cache = durable_cache(); // durable cache: the core gate would pass...
    let cfg = ProxyDispatchConfig {
        fleet_strict: true,
        tier: Some(ReplayDurabilityTier::RedisAsyncBounded), // ...but the tier is sub-minimum
    };
    let err = dispatch_request_with_tier_gate(&verified, &cache, None, &cfg)
        .expect_err("fleet-strict must refuse a redis-async tier");
    assert_eq!(err, ProxyDispatchError::SubMinimumReplayTier(ReplayDurabilityTier::RedisAsyncBounded));
    assert_eq!(err.wire_code(), "mcp-re.replay_cache_unavailable");
}

#[test]
fn fleet_strict_refuses_single_store_fail_closed_tier() {
    let (_req, verified) = signed_and_verified("nonce-ssfc");
    let cache = durable_cache();
    let cfg = ProxyDispatchConfig {
        fleet_strict: true,
        tier: Some(ReplayDurabilityTier::SingleStoreFailClosed),
    };
    let err = dispatch_request_with_tier_gate(&verified, &cache, None, &cfg)
        .expect_err("fleet-strict must refuse a single-store-fail-closed tier");
    assert_eq!(
        err,
        ProxyDispatchError::SubMinimumReplayTier(ReplayDurabilityTier::SingleStoreFailClosed)
    );
    assert_eq!(err.wire_code(), "mcp-re.replay_cache_unavailable");
}

#[test]
fn fleet_strict_refuses_undeclared_tier() {
    let (_req, verified) = signed_and_verified("nonce-none");
    let cache = durable_cache();
    let cfg = ProxyDispatchConfig { fleet_strict: true, tier: None };
    let err = dispatch_request_with_tier_gate(&verified, &cache, None, &cfg)
        .expect_err("fleet-strict with no declared tier must fail closed");
    assert_eq!(err, ProxyDispatchError::NoDeclaredReplayTier);
    assert_eq!(err.wire_code(), "mcp-re.replay_cache_unavailable");
}

// --- AT2: fleet-strict admits an acceptable tier -----------------------------

#[test]
fn fleet_strict_admits_redis_wait_quorum_tier() {
    let (_req, verified) = signed_and_verified("nonce-wq");
    let cache = durable_cache();
    let cfg = ProxyDispatchConfig {
        fleet_strict: true,
        tier: Some(ReplayDurabilityTier::RedisWaitQuorum { quorum: 2, timeout_ms: 500 }),
    };
    let outcome = dispatch_request_with_tier_gate(&verified, &cache, None, &cfg)
        .expect("redis-wait-quorum meets the strict-production minimum");
    assert!(!outcome.continuation_verified);
}

#[test]
fn fleet_strict_admits_linearizable_tier() {
    let (_req, verified) = signed_and_verified("nonce-lin");
    let cache = durable_cache();
    let cfg = ProxyDispatchConfig {
        fleet_strict: true,
        tier: Some(ReplayDurabilityTier::Linearizable),
    };
    dispatch_request_with_tier_gate(&verified, &cache, None, &cfg)
        .expect("linearizable meets the strict-production minimum");
}

// --- AT4: the core single-process refusal fires BENEATH the tier gate --------

#[test]
fn core_single_process_gate_fires_beneath_an_acceptable_tier() {
    let (_req, verified) = signed_and_verified("nonce-defense");
    // The operator DECLARES an acceptable tier (passes the upper gate)...
    let cfg = ProxyDispatchConfig {
        fleet_strict: true,
        tier: Some(ReplayDurabilityTier::Linearizable),
    };
    // ...but the ACTUAL wired cache self-declares the single-process reference class.
    let single_process = InMemoryReplayCache::new(0);
    let err = dispatch_request_with_tier_gate(&verified, &single_process, None, &cfg)
        .expect_err("the core single-process gate must still fire beneath the tier gate");
    assert_eq!(err, ProxyDispatchError::Dispatch(DispatchError::NonSharedReplayTier));
    assert_eq!(err.wire_code(), "mcp-re.replay_cache_unavailable");
}

#[test]
fn non_fleet_strict_skips_the_tier_gate_but_keeps_core_admission() {
    // Without fleet-strict, a sub-minimum tier and a single-process cache are BOTH
    // acceptable (the deployment made no strict claim); the request still admits.
    let (_req, verified) = signed_and_verified("nonce-lax");
    let single_process = InMemoryReplayCache::new(0);
    let cfg = ProxyDispatchConfig {
        fleet_strict: false,
        tier: Some(ReplayDurabilityTier::RedisAsyncBounded),
    };
    dispatch_request_with_tier_gate(&verified, &single_process, None, &cfg)
        .expect("non-strict admits regardless of tier / cache class");
}

// --- AT3: full verify → adapter dispatch → sign → verify_response end-to-end --

#[test]
fn http_profile_request_flows_verify_dispatch_serve_end_to_end() {
    // 1. Sign + verify the request (capturing the RequestEvidence handle the
    //    response must carry back).
    let block = request_block();
    let mut req = base_request();
    let req_evidence =
        sign_request_full(&mut req, &block, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "nonce-e2e")
            .expect("sign request");
    let verified_request =
        verify_request_full(&req, &block.audience, &no_material(), &resolver(), NOW).expect("verify request");

    // 2. Dispatch through the ADAPTER under fleet-strict with an acceptable tier and
    //    a durable cache — the replay key is admitted (Fresh).
    let cache = durable_cache();
    let cfg = ProxyDispatchConfig {
        fleet_strict: true,
        tier: Some(ReplayDurabilityTier::RedisWaitQuorum { quorum: 2, timeout_ms: 500 }),
    };
    let outcome = dispatch_request_with_tier_gate(&verified_request, &cache, None, &cfg)
        .expect("verified request admitted through the adapter");
    assert!(!outcome.continuation_verified, "first-leg request carries no continuation");

    // A replay of the identical request is now rejected beneath the (passing) tier gate.
    let replay = dispatch_request_with_tier_gate(&verified_request, &cache, None, &cfg)
        .expect_err("second dispatch of the same five-tuple is a replay");
    assert_eq!(replay, ProxyDispatchError::Dispatch(DispatchError::ReplayDetected));
    assert_eq!(replay.wire_code(), "mcp-re.replay_detected");

    // 3. Serve: build + sign the response bound to this request, then verify it
    //    end-to-end (verify_response_full closes the profile round-trip).
    let mut resp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    let server_signer = ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server-1".into(),
        keyid: SERVER_KEY_ID.into(),
    };
    sign_response_full(&mut resp, &req, &req_evidence, &server_signer, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("sign response");
    let verified_response =
        verify_response_full(&resp, &req, &verified_request, &resolver(), NOW).expect("verify response e2e");
    assert_eq!(
        verified_response.server_signer.expect("server_signer present").keyid,
        SERVER_KEY_ID
    );
}
