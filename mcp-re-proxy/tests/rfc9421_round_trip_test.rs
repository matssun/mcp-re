// SPDX-License-Identifier: Apache-2.0
//! Local RFC 9421 round-trip through the PRODUCTION serving PEP
//! (`HttpProfileProxy`, ADR-MCPRE-050 sole carrier; ADR-MCPRE-052 delegated-signing
//! — the only response mode) — proof the wire carries only RFC 9421 HTTP-signature
//! evidence.
//!
//! A client signs an RFC 9421 + RFC 9530 request; the production `HttpProfileProxy`
//! (delegated-signing) verifies it, admits it against the async §4 replay tier,
//! forwards the stripped JSON-RPC to an in-process inner, and signs the reply as an
//! RFC 9421 response with the active delegated key + inline credential. The client
//! then verifies that response bound to its request. The test asserts the wire
//! carries RFC 9421 HTTP signatures — and no legacy object-profile `_meta.response`
//! signature envelope and no legacy `canonicalization_id` field appear on the wire.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::verify_delegated_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedHttpRequestEvidence;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;

use std::sync::Arc;

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

/// The trust seam shared by the proxy and the client's response verification: the
/// client key resolves for the Request slot, the ROOT key (by its issuer kid) for the
/// Response slot — the delegated key is authorized by the credential, not enrolled.
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
        audience_hash: VERIFIER_AUD.into(),
        trust_epoch: "epoch-1".into(),
        server_role: "server".into(),
        server_trust_domain: "example.com".into(),
        server_subject: "did:example:server".into(),
        ttl: TTL,
        overlap: OVERLAP,
    }
}

/// A delegated-signing proxy with its first key already published.
fn build_proxy() -> HttpProfileProxy {
    let signer = Arc::new(DelegatedServerSigner::new());
    let root = root_key();
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| Some(issue_delegation_credential(&root, h, c));
    let mut n = 100u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let mut rotor = DelegatedRotor::new(DelegatedSigningCustody::new(custody_cfg(), issue, factory), Arc::clone(&signer));
    rotor.rotate(NOW).expect("issue the first delegated key");
    let inner = Box::new(|_forwarded: &[u8]| -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
    });
    HttpProfileProxy::new_delegated(
        actor_resolver(),
        audience(),
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig { fleet_strict: false, tier: None },
        inner,
        300,
        signer,
    )
}

fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: VERIFIER_AUD,
        accepted_epochs: epochs,
        max_clock_skew: 60,
    }
}

/// Sign an RFC 9421 request carrying a DPoP artifact binding (its credential is the
/// covered `Authorization` header), and verify it for the response binding.
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

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn rfc9421_round_trip_zero_object_evidence() {
    let (req, _ev, verified_req) = signed_request("nonce-round-trip-1");
    let proxy = build_proxy();

    let served = ServedHttpRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body: req.body.clone(),
        identity: None,
        assertion: None,
    };
    let response = proxy.handle(served, NOW).await;

    assert_eq!(response.status, 200, "verified request is served");

    // POSITIVE: the reply carries RFC 9421 + RFC 9530 evidence in the HTTP headers.
    assert!(
        header(&response.headers, "signature-input").is_some(),
        "response carries an RFC 9421 Signature-Input header"
    );
    assert!(
        header(&response.headers, "signature").is_some(),
        "response carries an RFC 9421 Signature header"
    );
    assert!(
        header(&response.headers, "content-digest").is_some(),
        "response carries an RFC 9530 Content-Digest header"
    );

    // NEGATIVE: the body carries no LEGACY object-profile evidence — no
    // `canonicalization_id` field and no `_meta.response` object-signature envelope.
    // (The delegated response DOES carry its inline credential, which is a different,
    // RFC 9421-anchored carrier — not the legacy object signature.)
    let body_text = String::from_utf8(response.body.clone()).expect("utf8 body");
    assert!(
        !body_text.contains("canonicalization_id"),
        "no legacy canonicalization_id on the wire: {body_text}"
    );
    let body_json: serde_json::Value = serde_json::from_slice(&response.body).expect("json body");
    assert!(
        body_json
            .pointer("/result/_meta/se.syncom~1mcp-re.response")
            .is_none(),
        "no object-profile _meta.response signature envelope on the wire"
    );

    // THE ROUND-TRIP: the client verifies the response is a genuine delegated-signed
    // RFC 9421 reply bound to ITS request, chaining to the ROOT via the credential.
    let http_response = HttpResponse {
        status: response.status,
        headers: response.headers.clone(),
        body: response.body.clone(),
    };
    let r = resolver();
    let verified = verify_delegated_response_full(
        &http_response,
        &req,
        &verified_req,
        &move |kid: &str, slot: SignerSlot| r(kid, slot),
        &expectations(&["epoch-1"]),
        &|_| false,
        NOW,
    )
    .expect("client verifies the delegated RFC 9421 response bound to its request");
    assert_eq!(
        verified.server_signer.as_ref().unwrap().keyid,
        format!("{ROOT_KID}/delegated/1"),
        "response signed by the delegated key (chaining to the trusted root)"
    );
}

#[tokio::test]
async fn replayed_request_is_rejected() {
    let (req, _ev, _v) = signed_request("nonce-replay-1");
    let proxy = build_proxy();
    let served = || ServedHttpRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body: req.body.clone(),
        identity: None,
        assertion: None,
    };
    let first = proxy.handle(served(), NOW).await;
    assert_eq!(first.status, 200, "first submission is fresh");
    let replay = proxy.handle(served(), NOW).await;
    assert_eq!(replay.status, 409, "the same nonce is rejected as a replay");
}
