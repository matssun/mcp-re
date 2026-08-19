// SPDX-License-Identifier: Apache-2.0
//! R8-C006 / R8-C013 — the bytes the inner server receives are the bytes the client
//! signed, or the inner server receives nothing at all.
//!
//! The PEP re-serializes the request body to strip its own `_meta` keys before
//! forwarding. `serde_json` without `arbitrary_precision` is not a faithful carrier:
//! a duplicate member name collapses to last-one-wins, and a number outside the
//! `f64` carrier's exact range comes back rewritten. Either way the backend would act
//! on a body that differs from the one the signature covers, while every signature
//! check upstream still passes — the alteration happens after verification.
//!
//! So the served path refuses those two shapes on the ORIGINAL bytes, before the
//! re-serialization. These tests assert the mechanism rather than the status: the
//! recording inner backend must never be dispatched at all.

use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedContextPolicy;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::delegated_server_signer::DelegatedRotor;
use mcp_re_proxy::delegated_server_signer::DelegatedServerSigner;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::http_profile_serve::HttpProfileProxy;

const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const TARGET: &str = "https://mcp.example.com/mcp";
const AUDIENCE: &str = "mcp.example.com";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[11u8; 32])
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[33u8; 32])
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: AUDIENCE.into(),
        target_uri: TARGET.into(),
        route: None,
    }
}

fn actor_resolver() -> mcp_re_proxy::http_profile_serve::ActorResolver {
    Box::new(|key_id: &str, slot: SignerSlot| {
        match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
                identity: ActorIdentity {
                    role: "client".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:client".into(),
                    keyid: key_id.into(),
                },
                verification_key: client_key().public_key(),
                slot,
            }),
            (ROOT_KID, SignerSlot::Response) => Some(ResolvedActor {
                identity: ActorIdentity {
                    role: "server".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:server".into(),
                    keyid: key_id.into(),
                },
                verification_key: root_key().public_key(),
                slot,
            }),
            _ => None,
        }
        .into()
    })
}

fn custody_cfg() -> CustodyConfig {
    CustodyConfig {
        issuer_kid: ROOT_KID.into(),
        iss: "did:example:server".into(),
        profile: PROFILE_TAG.into(),
        aud: AUDIENCE.into(),
        audience_hash: audience().audience_hash(),
        trust_epoch: "epoch-1".into(),
        server_role: "server".into(),
        server_trust_domain: "example.com".into(),
        server_subject: "did:example:server".into(),
        ttl: 300,
        overlap: 60,
    }
}

/// The inner backend records every dispatch. An empty log is the property under test:
/// a refusal that still reached the backend would have already handed it altered bytes.
type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

fn recording_inner(seen: Seen) -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
    Box::new(move |forwarded: &[u8]| -> Vec<u8> {
        seen.lock().unwrap().push(forwarded.to_vec());
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
    })
}

fn proxy(seen: Seen) -> HttpProfileProxy {
    let signer = Arc::new(DelegatedServerSigner::new());
    let root = root_key();
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = 100u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let mut rotor = DelegatedRotor::new(
        DelegatedSigningCustody::new(custody_cfg(), issue, factory),
        Arc::clone(&signer),
    );
    rotor.rotate(NOW).expect("issue a delegated key");
    HttpProfileProxy::new_delegated(
        actor_resolver(),
        audience(),
        AsyncReplayTier::new(
            Arc::new(InMemoryAsyncAtomicReplayStore::new()),
            mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
        ),
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
        recording_inner(seen),
        300,
        signer,
    )
    .with_verified_context_carrier(VerifiedContextPolicy::Disabled)
}

fn evidence_block() -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"tok",
        )],
        continuation: None,
        admission: None,
        admission_assertion: None,
    }
}

/// A genuinely signed request whose top-level body object carries `members` verbatim.
///
/// The members are spliced into the serialized bytes rather than built through
/// `serde_json`, because the shapes under test are exactly the ones `serde_json`
/// cannot represent: it would collapse the duplicate and round the decimal before
/// the request was ever signed. The signature is then computed over the spliced
/// bytes, so this is a legitimately signed body — not tampering, and every check
/// upstream of the forwarding stage passes.
fn signed_request_with_members(nonce: &str, members: &str) -> HttpRequest {
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), "Bearer tok".into()),
        ],
        body: serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "read" }
        }))
        .unwrap(),
    };
    // First sign to obtain the evidence block the verifier reads out of `_meta`...
    sign_request_full(
        &mut req,
        &evidence_block(),
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        nonce,
    )
    .expect("signing succeeds");

    // ...then splice the members into the top-level object and re-sign over the
    // result, so `content-digest` covers the exact bytes the client sends.
    let body = String::from_utf8(req.body.clone()).expect("json is utf-8");
    let rest = body.strip_prefix('{').expect("a JSON-RPC object body");
    req.body = format!("{{{members},{rest}").into_bytes();
    req.headers.retain(|(k, _)| {
        !k.eq_ignore_ascii_case("signature")
            && !k.eq_ignore_ascii_case("signature-input")
            && !k.eq_ignore_ascii_case("content-digest")
    });
    sign_request(
        &mut req,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        &format!("{nonce}-spliced"),
    )
    .expect("re-sign over the spliced bytes");
    req
}

fn served(req: &HttpRequest) -> ServedHttpRequest {
    ServedHttpRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body: req.body.clone(),
        identity: None,
        assertion: None,
    }
}

/// A duplicate member name survives verification (the signature covers the raw bytes)
/// but cannot survive the forwarding re-serialization: `serde_json::Map` keeps the last
/// one, so the backend would act on `{"a":2}` while the client signed both members.
#[tokio::test]
async fn a_duplicate_member_name_is_never_forwarded() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let p = proxy(Arc::clone(&seen));
    let req = signed_request_with_members("n-dup", r#""a":1,"a":2"#);

    let out = p.handle(served(&req), NOW).await;

    assert!(
        seen.lock().unwrap().is_empty(),
        "the inner server was dispatched with a body the re-serializer had already \
         collapsed to last-one-wins"
    );
    assert_eq!(out.status, 500, "refused, not served");
}

/// A number the `f64` carrier cannot hold exactly. `1234567890123456789.5` comes back
/// from `serde_json` as `1.2345678901234568e18`; forwarding that would hand the backend
/// a different amount than the one under signature.
#[tokio::test]
async fn a_number_the_f64_carrier_rewrites_is_never_forwarded() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let p = proxy(Arc::clone(&seen));
    let req = signed_request_with_members("n-num", r#""amount":1234567890123456789.5"#);

    let out = p.handle(served(&req), NOW).await;

    assert!(
        seen.lock().unwrap().is_empty(),
        "the inner server was dispatched with a rewritten number"
    );
    assert_eq!(out.status, 500, "refused, not served");
}

/// The negative control. The refusal is narrow: an ordinary body — including one
/// carrying a number and a repeated name in DIFFERENT objects, which the carrier
/// represents exactly — still reaches the inner server unaltered.
#[tokio::test]
async fn an_ordinary_body_still_forwards_unaltered() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let p = proxy(Arc::clone(&seen));
    let req = signed_request_with_members("n-ok", r#""a":1,"nested":{"a":2},"amount":12.5"#);

    let out = p.handle(served(&req), NOW).await;

    assert_eq!(out.status, 200, "an ordinary body is served");
    let forwarded = seen.lock().unwrap()[0].clone();
    let v: serde_json::Value =
        serde_json::from_slice(&forwarded).expect("json reaches the backend");
    assert_eq!(v["a"], serde_json::json!(1));
    assert_eq!(v["nested"]["a"], serde_json::json!(2));
    assert_eq!(v["amount"], serde_json::json!(12.5));
    assert_eq!(v["method"], serde_json::json!("tools/call"));
}
