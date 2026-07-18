// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-052 delegated-signing PRODUCTION WIRING (MCPRE-122 phase 2).
//!
//! The sibling `delegated_serving_test` proves the serving CONTRACT with a hand-built
//! rotor. This lane proves the PRODUCTION WIRING: it drives the real
//! `build_delegated_signing(config, root)` from a real, parser-produced [`Config`] in
//! delegated-signing (the only response mode), exactly as the serving binary does —
//! only the socket/TLS layer (covered by the fleet tests) is left out. The root issuer
//! here is a fake/in-memory `SigningKey` (the KMS-as-root swap is proven through the
//! same seam by `gcp_kms_delegated_signing_live_test`), so the test is hermetic.
//!
//! Proven end-to-end through the production wiring:
//!   * a valid request is served with a delegated-signed response that verifies via the
//!     credential→root attestation chain, and the ROOT issuer is touched ONLY at
//!     issuance/rotation — never per request;
//!   * a replayed request is rejected with a delegated-signed, request-BOUND receipt;
//!   * once the delegated key expires with no successor, serving FAILS CLOSED (503,
//!     unsigned) — no stale-key extension, no direct-root fallback;
//!   * a controlled rotation within the overlap window mints a successor and the
//!     response then verifies under the new delegated key.
//!
//! This is the local "green" gate that must pass before any GKE validation of
//! delegated-required mode.

use std::sync::Arc;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::verify_delegated_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedHttpRequestEvidence;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::async_serve::ServedHttpResponse;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::HttpProfileProxy;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [44u8; 32];
const NOW: i64 = 1_700_000_100;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const CLIENT_KEY_ID: &str = "client-key-1";
// Under delegated-required mode the credential's issuer kid defaults to --server-key-id.
const ROOT_KID: &str = "root-kid";
const AUDIENCE: &str = "verifier-1";
const EPOCH: &str = "epoch-1";
// Custody policy defaults (no --delegated-ttl-secs/--delegated-overlap-secs supplied).
const TTL: i64 = 300;
const OVERLAP: i64 = 60;

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: AUDIENCE.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

/// The real serving Config in delegated-required mode, produced by the production CLI
/// parser. Filesystem paths are placeholders — the delegated wiring reads config
/// fields (audience, server-signer/-key-id, trust domain, ttl/overlap/epoch), not
/// files. A durable replay selection satisfies the parse-time unsafe-config checks.
fn delegated_config() -> mcp_re_proxy::cli::Config {
    let args: Vec<String> = [
        "--bind", "127.0.0.1:8443",
        "--audience", AUDIENCE,
        "--server-signer", "did:example:server",
        "--server-key-id", ROOT_KID,
        "--signing-key-seed", "/dev/null",
        "--tls-cert", "/dev/null",
        "--tls-key", "/dev/null",
        "--client-ca", "/dev/null",
        "--trust", "/dev/null",
        "--inner-http-url", "http://127.0.0.1:9",
        "--target-uri", TARGET,
        "--route", "a",
        "--replay-cache", "file",
        "--replay-path", "/tmp/mcp-re-delegated-prod-test-replay",
        "--delegated-trust-epoch", EPOCH,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    mcp_re_proxy::cli::parse_args(&args).expect("parse delegated-required serving config")
}

/// The client key for the Request slot; the ROOT public key (by its issuer kid) for the
/// Response slot — matching how a verifier resolves the credential's issuer. The
/// delegated key is never enrolled; the credential authorizes it.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + Send + Sync + Clone {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key().public_key()),
            (ROOT_KID, SignerSlot::Response) => ("server", root_key().public_key()),
            _ => return None,
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: key_id.into(),
            },
            verification_key: key,
            slot,
        })
    }
}

fn actor_resolver() -> ActorResolver {
    let r = resolver();
    Box::new(move |kid: &str, slot: SignerSlot| r(kid, slot))
}

fn canned_inner() -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
    Box::new(|_forwarded: &[u8]| -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
    })
}

/// Build the serving proxy the SAME way `app::run` does in delegated-required mode:
/// `build_delegated_signing` off the (in-memory) root, then `new_delegated`. Returns
/// the proxy plus the rotor so the test can drive controlled rotation/expiry (in the
/// binary a background thread does this).
fn build_proxy(
    config: &mcp_re_proxy::cli::Config,
) -> (HttpProfileProxy, mcp_re_proxy::ProdDelegatedRotor) {
    let wiring = mcp_re_proxy::build_delegated_signing(config, root_key())
        .expect("build delegated signing wiring from config");
    let expected_audience = AudienceTuple {
        audience_id: config.audience.clone(),
        target_uri: config.target_uri.clone(),
        route: config.route.clone(),
    };
    let proxy = HttpProfileProxy::new_delegated(
        actor_resolver(),
        expected_audience,
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig { fleet_strict: false, tier: None },
        canned_inner(),
        300,
        Arc::clone(&wiring.signer),
    );
    (proxy, wiring.rotor)
}

/// A client-signed request whose freshness window `[created, expires]` brackets the
/// serve instant `verify_now`, so serving at a chosen time exercises the SIGNING step
/// (not a request-freshness rejection). Verified at `verify_now` for response binding.
fn signed_request_at(
    nonce: &str,
    created: i64,
    expires: i64,
    verify_now: i64,
) -> (HttpRequest, RequestEvidence, VerifiedHttpRequestEvidence) {
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
            admission: None,
    };
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec(),
    };
    let evidence =
        sign_request_full(&mut req, &block, &client_key(), CLIENT_KEY_ID, created, expires, nonce)
            .expect("client signs RFC 9421 request");
    let no_material = |_b: &ArtifactBinding| None;
    let r = resolver();
    let verified =
        verify_request_full(&req, &audience(), &no_material, &move |k: &str, s| r(k, s), verify_now)
            .expect("client's own request verifies (for response binding)");
    (req, evidence, verified)
}

/// A request whose freshness window is centered on `at` (±100s).
fn signed_request(nonce: &str, at: i64) -> (HttpRequest, RequestEvidence, VerifiedHttpRequestEvidence) {
    signed_request_at(nonce, at - 100, at + 200, at)
}

fn served_of(req: &HttpRequest) -> ServedHttpRequest {
    ServedHttpRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body: req.body.clone(),
        identity: None,
        assertion: None,
    }
}

fn http_response(served: ServedHttpResponse) -> HttpResponse {
    HttpResponse {
        status: served.status,
        headers: served.headers,
        body: served.body,
    }
}

fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        policy: mcp_re_http_profile::VerifierPolicy::default(),
        verifier_audiences: &[AUDIENCE],
        expected_audience_hash: AUDIENCE,
        accepted_epochs: epochs,
        max_clock_skew: 60,
    }
}

// --- the whole production wiring: success, replay, expiry, rotation ----------

#[tokio::test]
async fn delegated_required_wiring_serves_verifies_and_rotates() {
    let config = delegated_config();
    let (proxy, mut rotor) = build_proxy(&config);

    // Startup issuance (the binary does this before serving; fail closed if it errors).
    // key1 exp = NOW + TTL.
    rotor.rotate(NOW).expect("startup: initial delegated key issued");

    // --- success: a delegated-signed response verifies via the attestation chain ---
    let mut first_delegated_kid: Option<String> = None;
    for i in 0..5 {
        let (req, _ev, verified_req) = signed_request(&format!("nonce-ok-{i}"), NOW);
        let served = proxy.handle(served_of(&req), NOW).await;
        assert_eq!(served.status, 200, "delegated-required request served");
        let resp = http_response(served);
        assert!(
            String::from_utf8(resp.body.clone()).unwrap().contains("server_delegation"),
            "response carries the inline delegation credential"
        );
        let r = resolver();
        let verified = verify_delegated_response_full(
            &resp,
            &req,
            &verified_req,
            &move |k: &str, s| r(k, s),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .expect("delegated response verifies via the credential→root chain");
        // Profile-issued kids are RFC 7638 JWK thumbprints (#415 rev 2 §1.5), so
        // the property asserted here is the one that matters — the signer is a
        // delegated key, NOT the root — rather than a kid literal.
        first_delegated_kid = Some(verified.server_signer.as_ref().unwrap().keyid.clone());
        assert_ne!(
            verified.server_signer.as_ref().unwrap().keyid,
            ROOT_KID,
            "signed by the delegated key, not the root"
        );
    }
    let first_delegated_kid = first_delegated_kid.expect("the success loop ran");
    // Zero root ops on the request path: the root was touched ONLY at issuance.
    assert_eq!(rotor.root_invocations(), 1, "root issuer off the request path");

    // --- bound rejection: a replay is rejected with a request-bound receipt --------
    let (req, _ev, verified_req) = signed_request("nonce-replay", NOW);
    assert_eq!(proxy.handle(served_of(&req), NOW).await.status, 200);
    let served = proxy.handle(served_of(&req), NOW).await;
    assert_eq!(served.status, 409, "replay rejected");
    let resp = http_response(served);
    assert!(
        String::from_utf8(resp.body.clone()).unwrap().contains("server_delegation"),
        "the rejection carries the inline delegation credential"
    );
    let r = resolver();
    verify_delegated_response_full(
        &resp,
        &req,
        &verified_req,
        &move |k: &str, s| r(k, s),
        &expectations(&[EPOCH]),
        &|_| false,
        NOW,
    )
    .expect("bound delegated rejection verifies");

    // --- rotation: a successor minted in the overlap window keeps serving (no gap) --
    // The rotor wakes at key1.exp - overlap; rotate there → key2 (exp = ROT + TTL).
    let rot = NOW + TTL - OVERLAP + 10;
    rotor.rotate(rot).expect("rotation mints a successor");
    assert_eq!(rotor.root_invocations(), 2, "one more root op for the successor");
    let (req, _ev, verified_req) = signed_request("nonce-after-rotate", rot);
    let served = proxy.handle(served_of(&req), rot).await;
    assert_eq!(served.status, 200, "serving continues under the successor key");
    let resp = http_response(served);
    let r = resolver();
    let verified = verify_delegated_response_full(
        &resp,
        &req,
        &verified_req,
        &move |k: &str, s| r(k, s),
        &expectations(&[EPOCH]),
        &|_| false,
        rot,
    )
    .expect("successor delegated response verifies");
    // The successor is a DIFFERENT delegated key: distinct key material yields a
    // distinct RFC 7638 thumbprint, so the kid changing is itself the proof that
    // rotation minted a new key rather than re-serving the old one.
    assert_ne!(
        verified.server_signer.as_ref().unwrap().keyid,
        first_delegated_kid,
        "signed by the SUCCESSOR delegated key, not the predecessor"
    );
    assert_ne!(
        verified.server_signer.as_ref().unwrap().keyid,
        ROOT_KID,
        "and still not the root"
    );

    // --- fail closed: past the successor's expiry with no further rotation ---------
    // key2 exp = ROT + TTL. Advance there WITHOUT rotating: the hot path has no valid
    // key, so serving refuses (503, unsigned) — no stale-key extension, no direct-root
    // fallback. The request itself is fresh at this instant, so this exercises the
    // SIGNING fail-closed path, not a request-freshness rejection.
    let expired = rot + TTL;
    let (req, _ev, _v) = signed_request("nonce-expired", expired);
    let served = proxy.handle(served_of(&req), expired).await;
    assert_eq!(served.status, 503, "expired delegated key ⇒ fail closed");
    let body: serde_json::Value = serde_json::from_slice(&served.body).expect("json");
    assert_eq!(
        body.pointer("/error/message").and_then(|m| m.as_str()),
        Some(mcp_re_core::McpReError::DelegatedSigningUnavailable.wire_code()),
        "fail-closed emits the frozen unavailable token, unsigned"
    );
    assert!(
        !served.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("signature-input")),
        "the fail-closed error is unsigned"
    );
}
