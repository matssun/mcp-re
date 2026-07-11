// SPDX-License-Identifier: Apache-2.0
//! Local RFC 9421 round-trip through the PRODUCTION serving PEP
//! (`HttpProfileProxy`, ADR-MCPRE-050 sole carrier) — the object/JCS purge proof.
//!
//! A client signs an RFC 9421 + RFC 9530 request; the production `HttpProfileProxy`
//! verifies it, admits it against the async §4 replay tier, forwards the stripped
//! JSON-RPC to an in-process inner, and signs the reply as an RFC 9421 response. The
//! client then verifies that response bound to its request. The test asserts the
//! wire carries RFC 9421 HTTP signatures — NOT an object `_meta` signature and NOT a
//! JCS `canonicalization_id` — i.e. there is zero object/JCS evidence on the wire.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::verify_response_bound_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::HttpProfileProxy;

use std::sync::Arc;

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
fn server_identity() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server-1".into(),
        keyid: SERVER_KEY_ID.into(),
    }
}
fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "verifier-1".into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

/// The trust seam shared by the proxy and the client's response verification: the
/// client key resolves for the Request slot, the server key for the Response slot.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + Send + Sync + Clone {
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
            identity: server_identity(),
            verification_key: server_key().public_key(),
            slot,
        }),
        _ => None,
    }
}

/// Sign an RFC 9421 request carrying a DPoP artifact binding (its credential is the
/// covered `Authorization` header, so the proxy's no-external-material verify path
/// admits it).
fn signed_request(nonce: &str) -> (HttpRequest, mcp_re_http_profile::RequestEvidence) {
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
    (req, evidence)
}

fn build_proxy() -> HttpProfileProxy {
    let resolve = resolver();
    let resolve_actor: ActorResolver = Box::new(move |kid: &str, slot: SignerSlot| resolve(kid, slot));
    // In-process inner: returns a canned MCP result for the stripped JSON-RPC.
    let inner = Box::new(|_forwarded: &[u8]| -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
    });
    HttpProfileProxy::new(
        resolve_actor,
        audience(),
        server_identity(),
        server_key(),
        SERVER_KEY_ID,
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig { fleet_strict: false, tier: None },
        inner,
        300,
    )
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn rfc9421_round_trip_zero_object_evidence() {
    let (req, request_evidence) = signed_request("nonce-round-trip-1");
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

    // NEGATIVE (the purge): the body carries NO object/JCS evidence — no draft-02
    // `canonicalization_id` and no object `_meta.response` signature value.
    let body_text = String::from_utf8(response.body.clone()).expect("utf8 body");
    assert!(
        !body_text.contains("canonicalization_id"),
        "no JCS canonicalization_id on the wire: {body_text}"
    );
    let body_json: serde_json::Value = serde_json::from_slice(&response.body).expect("json body");
    assert!(
        body_json
            .pointer("/result/_meta/se.syncom~1mcp-re.response")
            .is_none(),
        "no object-profile _meta.response signature envelope on the wire"
    );

    // THE ROUND-TRIP: the client verifies the response is a genuine RFC 9421 reply
    // bound to ITS request (the `;req` binding + response evidence block).
    let http_response = HttpResponse {
        status: response.status,
        headers: response.headers.clone(),
        body: response.body.clone(),
    };
    let resolve = resolver();
    let verified = verify_response_bound_full(
        &http_response,
        &req,
        &request_evidence,
        &move |kid: &str, slot: SignerSlot| resolve(kid, slot),
        NOW,
    )
    .expect("client verifies the RFC 9421 response bound to its request");
    assert_eq!(
        verified.resolved_server_actor.identity.keyid, SERVER_KEY_ID,
        "response signed by the trusted server key"
    );
}

#[tokio::test]
async fn replayed_request_is_rejected() {
    let (req, _ev) = signed_request("nonce-replay-1");
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
