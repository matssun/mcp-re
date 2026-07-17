// SPDX-License-Identifier: Apache-2.0
//! The ADR-MCPRE-052 delegated-signing SERVING cutover, end-to-end through the
//! production PEP (`HttpProfileProxy`, MCPRE-122).
//!
//! Proves the serving contract — not merely the primitives:
//!   * a delegated-signed SUCCESS response from the proxy verifies via the
//!     credential→root attestation chain, carries the inline credential, and the
//!     root issuer is touched ONLY at issuance (never per request);
//!   * a request-BOUND rejection (verified request, later replay failure) is
//!     delegated-signed and verifies via the bound delegated path;
//!   * a PREFLIGHT (unbound) rejection (request never verified) is delegated-signed
//!     and verifies via the unbound delegated path — honestly not request-bound;
//!   * a MISSING/expired delegated key fails closed (no signed 200);
//!   * in delegated-required mode a DIRECT-root response is rejected
//!     `delegation_credential_missing`.
//!
//! The root issuer here is in-memory; the KMS-as-root path is proven separately
//! through the same issuer seam (`gcp_kms_delegated_signing_live_test`). This lane
//! isolates the question: does the HTTP-profile serving path use delegated evidence
//! correctly?

use std::sync::Arc;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::verify_delegated_response_full;
use mcp_re_http_profile::verify_delegated_response_unbound;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
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
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";
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
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

/// Trust seam for both the proxy and the client's response verification: the client
/// key for the Request slot, and the ROOT key (by its `issuer_kid`) for the Response
/// slot — the credential's issuer is resolved for the Response slot. The DELEGATED
/// key is never enrolled; it is authorized by the credential alone.
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

fn custody_cfg() -> CustodyConfig {
    CustodyConfig {
        issuer_kid: ROOT_KID.into(),
        iss: "did:example:server".into(),
        profile: PROFILE_TAG.into(),
        aud: VERIFIER_AUD.into(),
        audience_hash: AUD_SCOPE.into(),
        trust_epoch: EPOCH.into(),
        server_role: "server".into(),
        server_trust_domain: "example.com".into(),
        server_subject: "did:example:server".into(),
        ttl: TTL,
        overlap: OVERLAP,
    }
}

/// An in-memory-rooted rotor bound to `signer`. The root issuer is a fixed
/// in-memory key (the KMS-as-root swap is proven elsewhere through the same seam).
fn make_rotor(
    signer: Arc<DelegatedServerSigner>,
) -> DelegatedRotor<
    impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
    impl FnMut() -> SigningKey,
> {
    let root = root_key();
    let issue =
        move |h: &DelegationHeader, c: &DelegationClaims| Some(issue_delegation_credential(&root, h, c));
    let mut n = 100u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    DelegatedRotor::new(DelegatedSigningCustody::new(custody_cfg(), issue, factory), signer)
}

fn canned_inner() -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
    Box::new(|_forwarded: &[u8]| -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
    })
}

/// The serving proxy (delegated-signing — the only mode) sharing `signer` with a
/// rotor the caller drives.
fn delegated_proxy(signer: Arc<DelegatedServerSigner>) -> HttpProfileProxy {
    HttpProfileProxy::new_delegated(
        actor_resolver(),
        audience(),
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig { fleet_strict: false, tier: None },
        canned_inner(),
        300,
        signer,
    )
}

/// TEST-ONLY FIXTURE: produce a pre-052 direct-root response — the root key signs the
/// RFC 9421 response DIRECTLY (full response evidence block, NO delegation credential),
/// exactly as a pre-052 server did. Used ONLY to prove delegated-signing rejects it;
/// there is no such serving mode in production.
fn sign_legacy_direct_root_response_for_negative_test(
    req: &HttpRequest,
    request_evidence: &RequestEvidence,
) -> HttpResponse {
    let mut resp = HttpResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec(),
    };
    let identity = ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: ROOT_KID.into(),
    };
    sign_response_full(&mut resp, req, request_evidence, &identity, &root_key(), ROOT_KID, NOW, NOW + 300)
        .expect("root directly signs a pre-052 RFC 9421 response");
    resp
}

fn signed_request(nonce: &str) -> (HttpRequest, RequestEvidence, VerifiedHttpRequestEvidence) {
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
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
        sign_request_full(&mut req, &block, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, nonce)
            .expect("client signs RFC 9421 request");
    let no_material = |_b: &ArtifactBinding| None;
    let r = resolver();
    let verified = verify_request_full(&req, &audience(), &no_material, &move |k: &str, s| r(k, s), NOW)
        .expect("client's own request verifies (for response binding)");
    (req, evidence, verified)
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

fn http_response(served: mcp_re_proxy::async_serve::ServedHttpResponse) -> HttpResponse {
    HttpResponse {
        status: served.status,
        headers: served.headers,
        body: served.body,
    }
}

fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        policy: mcp_re_http_profile::VerifierPolicy::default(),
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: AUD_SCOPE,
        accepted_epochs: epochs,
        max_clock_skew: 60,
    }
}

fn wire_code_of(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/data/mcp_re_error/wire_code")
                .and_then(|w| w.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

// --- success: delegated response verifies, zero root ops per request --------

#[tokio::test]
async fn delegated_success_response_verifies_and_root_touched_once() {
    let signer = Arc::new(DelegatedServerSigner::new());
    let mut rotor = make_rotor(Arc::clone(&signer));
    rotor.rotate(NOW).expect("issue first delegated key");

    let proxy = delegated_proxy(Arc::clone(&signer));

    // Serve several requests under one delegated key.
    for i in 0..5 {
        let (req, _ev, verified_req) = signed_request(&format!("nonce-ok-{i}"));
        let served = proxy.handle(served_of(&req), NOW).await;
        assert_eq!(served.status, 200, "delegated request served");
        let resp = http_response(served);

        // The credential rides inline in the covered evidence block.
        let body_text = String::from_utf8(resp.body.clone()).expect("utf8");
        assert!(
            body_text.contains("server_delegation"),
            "response carries the inline delegation credential"
        );

        // The client verifies via the credential→root attestation chain.
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
        .expect("delegated success response verifies via the attestation chain");
        // Profile-issued kids are RFC 7638 JWK thumbprints (#415 rev 2 §1.5); the
        // property under test is that a DELEGATED key signed, never the root.
        assert_ne!(
            verified.server_signer.as_ref().unwrap().keyid,
            ROOT_KID,
            "signed by the delegated key, not the root"
        );
    }

    // The load-bearing property: the root issuer was touched ONLY at issuance.
    assert_eq!(rotor.root_invocations(), 1, "root never touched on the request path");
}

// --- bound rejection: verified request, later replay failure ----------------

#[tokio::test]
async fn delegated_bound_rejection_verifies() {
    let signer = Arc::new(DelegatedServerSigner::new());
    let mut rotor = make_rotor(Arc::clone(&signer));
    rotor.rotate(NOW).expect("issue");
    let proxy = delegated_proxy(Arc::clone(&signer));

    let (req, _ev, verified_req) = signed_request("nonce-bound-1");
    // First is served; the replayed second is rejected — bound to the request.
    assert_eq!(proxy.handle(served_of(&req), NOW).await.status, 200);
    let served = proxy.handle(served_of(&req), NOW).await;
    assert_eq!(served.status, 409, "replay rejected");
    let resp = http_response(served);
    assert!(
        String::from_utf8(resp.body.clone()).unwrap().contains("server_delegation"),
        "the rejection carries the inline delegation credential"
    );

    // A bound delegated rejection verifies via the request-bound delegated path.
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
    assert_eq!(wire_code_of(&resp.body), "mcp-re.replay_detected");
}

// --- preflight rejection: request never verified ----------------------------

#[tokio::test]
async fn delegated_preflight_rejection_verifies_unbound() {
    let signer = Arc::new(DelegatedServerSigner::new());
    let mut rotor = make_rotor(Arc::clone(&signer));
    rotor.rotate(NOW).expect("issue");
    let proxy = delegated_proxy(Arc::clone(&signer));

    // Tamper the body AFTER signing so verify_request_full fails (content-digest).
    let (mut req, _ev, _v) = signed_request("nonce-preflight-1");
    let last = req.body.len() - 2;
    req.body[last] ^= 0x01;

    let served = proxy.handle(served_of(&req), NOW).await;
    assert_eq!(served.status, 403, "unverifiable request rejected preflight");
    let resp = http_response(served);
    assert!(
        String::from_utf8(resp.body.clone()).unwrap().contains("server_delegation"),
        "the preflight rejection still carries the inline delegation credential"
    );

    // A preflight rejection is response-only signed: it verifies via the UNBOUND
    // delegated path, and does NOT pretend to be bound to a valid request.
    let r = resolver();
    verify_delegated_response_unbound(
        &resp,
        &move |k: &str, s| r(k, s),
        &expectations(&[EPOCH]),
        &|_| false,
        NOW,
    )
    .expect("preflight delegated rejection verifies unbound");
    // And it must NOT verify through the bound path (there is no trusted request).
    let (fresh, _e, verified_fresh) = signed_request("nonce-preflight-probe");
    let r2 = resolver();
    assert!(
        verify_delegated_response_full(
            &resp,
            &fresh,
            &verified_fresh,
            &move |k: &str, s| r2(k, s),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .is_err(),
        "an unbound preflight rejection is not accepted as a request-bound response"
    );
}

// --- fail closed: no delegated key available --------------------------------

#[tokio::test]
async fn missing_delegated_key_fails_closed() {
    // Rotor never rotated ⇒ no key published.
    let signer = Arc::new(DelegatedServerSigner::new());
    let proxy = delegated_proxy(Arc::clone(&signer));

    let (req, _ev, _v) = signed_request("nonce-failclosed-1");
    let served = proxy.handle(served_of(&req), NOW).await;
    assert_ne!(served.status, 200, "no delegated key ⇒ never a signed 200");
    assert_eq!(served.status, 503, "fail-closed unavailable");
    // No delegated key exists, so the boundary cannot delegated-sign the rejection:
    // it emits the last-resort UNSIGNED error (code in `error.message`), never a
    // bogus or direct-root signature.
    let body: serde_json::Value = serde_json::from_slice(&served.body).expect("json");
    // Assert against the FROZEN taxonomy token, not a magic string — the server-side
    // availability fault must render the registered `mcp-re.delegated_signing_unavailable`.
    assert_eq!(
        body.pointer("/error/message").and_then(|m| m.as_str()),
        Some(mcp_re_core::McpReError::DelegatedSigningUnavailable.wire_code()),
        "fail-closed emits the frozen delegated-signing-unavailable code, unsigned"
    );
    assert!(
        !served
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("signature-input")),
        "the last-resort error is unsigned (no RFC 9421 signature header)"
    );
}

// --- required mode: a direct-root response is rejected ----------------------

#[test]
fn direct_root_response_rejected_in_delegated_required_mode() {
    // A pre-052 server directly root-signs the response (no delegation credential) —
    // built from the test-only fixture, since no direct-root serving mode exists.
    let (req, ev, verified_req) = signed_request("nonce-directroot-1");
    let resp = sign_legacy_direct_root_response_for_negative_test(&req, &ev);

    // A delegated-signing verifier rejects it: no inline credential.
    let r = resolver();
    let err = verify_delegated_response_full(
        &resp,
        &req,
        &verified_req,
        &move |k: &str, s| r(k, s),
        &expectations(&[EPOCH]),
        &|_| false,
        NOW,
    )
    .unwrap_err();
    assert_eq!(err, HttpProfileError::DelegationCredentialMissing);
}
