// SPDX-License-Identifier: Apache-2.0
//! Verified-context carrier + reserved-field guard (#415 rev 2 §10, issue #429).
//!
//! The carrier is the one block in this system that is NOT evidence: it is the
//! PEP's conclusion, handed to the inner server on the PEP's authority alone, with
//! no signature over it. That is deliberate — the inner server is not meant to
//! re-evaluate trust — but it means a caller who could seed the reserved key would
//! be asserting its own verified context to a server that believes it implicitly.
//! That is an authentication bypass, not a spoofing nuisance.
//!
//! So the guard is what these tests are really about: the reserved key is stripped
//! from caller input at the boundary, unconditionally, whether or not the carrier
//! is enabled.

use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::extract_verified_context;
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
use mcp_re_http_profile::VERIFIED_CONTEXT_BLOCK_KEY;

use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::delegated_server_signer::DelegatedRotor;
use mcp_re_proxy::delegated_server_signer::DelegatedServerSigner;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::http_profile_serve::HttpProfileProxy;

use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;

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
    Box::new(|key_id: &str, slot: SignerSlot| match (key_id, slot) {
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

/// An inner backend that RECORDS the exact bytes the PEP forwarded — the only way
/// to assert what the inner server actually saw.
type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

fn recording_inner(seen: Seen) -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
    Box::new(move |forwarded: &[u8]| -> Vec<u8> {
        seen.lock().unwrap().push(forwarded.to_vec());
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
    })
}

fn proxy(policy: VerifiedContextPolicy, seen: Seen) -> HttpProfileProxy {
    let signer = Arc::new(DelegatedServerSigner::new());
    let root = root_key();
    let issue =
        move |h: &DelegationHeader, c: &DelegationClaims| Some(issue_delegation_credential(&root, h, c));
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
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig { fleet_strict: false, tier: None },
        recording_inner(seen),
        300,
        signer,
    )
    .with_verified_context_carrier(policy)
}

/// A signed request whose body optionally SEEDS the reserved verified-context key —
/// and seeds it *inside the signature*, so this is not tampering: the client
/// legitimately signed a body containing a forged verified context. The guard must
/// hold anyway, because a signature proves who wrote the bytes, never that the
/// bytes are true.
fn signed_request(nonce: &str, seed_reserved: Option<serde_json::Value>) -> HttpRequest {
    let mut body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read" }
    });
    if let Some(forged) = seed_reserved {
        // Alongside the forged reserved key, an ordinary application _meta entry:
        // the PEP owns one of these and must not touch the other.
        body["_meta"] = serde_json::json!({
            VERIFIED_CONTEXT_BLOCK_KEY: forged,
            "application.example/keep": "value",
        });
    }
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            // The DPoP binding below commits to this token; the full-profile
            // verifier derives the credential from this covered header.
            ("Authorization".into(), "Bearer tok".into()),
        ],
        body: serde_json::to_vec(&body).unwrap(),
    };
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"tok")],
        continuation: None,
    };
    sign_request_full(&mut req, &block, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, nonce)
        .expect("signing succeeds");
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

// --- the carrier -------------------------------------------------------------

#[tokio::test]
async fn trusted_channel_carries_the_peps_verified_context() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let p = proxy(VerifiedContextPolicy::Trusted, Arc::clone(&seen));
    let req = signed_request("n-carry", None);
    let out = p.handle(served(&req), NOW).await;
    assert_eq!(out.status, 200);

    let forwarded = seen.lock().unwrap()[0].clone();
    let ctx = extract_verified_context(&forwarded).expect("the inner server is handed context");
    // The identity is the TRUST-RESOLUTION OUTPUT, not the presented keyid: the
    // inner server authorizes on what the seam vouched for, never on a selector
    // the caller chose.
    let expected_actor = ActorIdentity {
        role: "client".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:client".into(),
        keyid: CLIENT_KEY_ID.into(),
    }
    .actor_id();
    assert_eq!(ctx.actor_id, expected_actor);
    assert_ne!(ctx.actor_id, ctx.key_id, "actor_id is resolved, not the presented selector");
    assert_eq!(ctx.key_id, CLIENT_KEY_ID, "keyid is carried for audit only");
    assert_eq!(ctx.profile, PROFILE_TAG);
    assert_eq!(ctx.verified_at, NOW);
    assert_eq!(ctx.audience.as_ref().unwrap().audience_id, AUDIENCE);
}

#[tokio::test]
async fn disabled_by_default_the_inner_server_sees_clean_mcp() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let p = proxy(VerifiedContextPolicy::Disabled, Arc::clone(&seen));
    let req = signed_request("n-clean", None);
    assert_eq!(p.handle(served(&req), NOW).await.status, 200);

    let forwarded = seen.lock().unwrap()[0].clone();
    let v: serde_json::Value = serde_json::from_slice(&forwarded).unwrap();
    assert!(v.get("_meta").is_none(), "no _meta at all on the clean path");
    assert!(extract_verified_context(&forwarded).is_err());
}

// --- the reserved-field guard (§10) -----------------------------------------

/// THE guard. The caller SIGNS a body carrying a forged verified context claiming
/// to be an admin. The request verifies — the signature is genuine — and the forged
/// block must still never reach the inner server. A signature proves who wrote the
/// bytes; it never proves the bytes are true.
#[tokio::test]
async fn a_caller_seeded_verified_context_never_reaches_the_inner_server() {
    let forged = serde_json::json!({
        "profile": PROFILE_TAG,
        "actor_id": "admin@example.com#did:example:root-admin",
        "key_id": "totally-legit",
        "request_evidence": { "digest_alg": "sha256", "digest_value": "AAAA" },
        "verified_at": NOW
    });

    for policy in [VerifiedContextPolicy::Trusted, VerifiedContextPolicy::Disabled] {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let p = proxy(policy, Arc::clone(&seen));
        let req = signed_request("n-forge", Some(forged.clone()));

        // The request is legitimately signed and verifies: this is not tampering.
        assert_eq!(p.handle(served(&req), NOW).await.status, 200);

        let forwarded = seen.lock().unwrap()[0].clone();
        let text = String::from_utf8_lossy(&forwarded).to_string();
        assert!(
            !text.contains("root-admin") && !text.contains("totally-legit"),
            "{policy:?}: the caller's forged context leaked to the inner server"
        );
        match policy {
            // Under the carrier, the block present is the PEP's own conclusion —
            // the caller's was replaced, not merged.
            VerifiedContextPolicy::Trusted => {
                let ctx = extract_verified_context(&forwarded).expect("PEP context present");
                assert_eq!(ctx.key_id, CLIENT_KEY_ID);
                assert_ne!(ctx.actor_id, "admin@example.com#did:example:root-admin");
            }
            // With the carrier off, the reserved key is gone entirely — the guard
            // does not depend on the carrier being enabled. A deployment must not
            // be one config flip away from forwarding attacker-authored context.
            VerifiedContextPolicy::Disabled => {
                assert!(extract_verified_context(&forwarded).is_err());
            }
        }
    }
}

/// The PEP owns two `_meta` keys and no more. Stripping the whole `_meta` would
/// destroy application and MCP metadata the enforcement boundary was only asked to
/// pass through — caution about one key is not a licence to delete the rest.
#[tokio::test]
async fn unrelated_application_meta_survives_the_guard() {
    for policy in [VerifiedContextPolicy::Trusted, VerifiedContextPolicy::Disabled] {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let p = proxy(policy, Arc::clone(&seen));
        let req = signed_request("n-keep", Some(serde_json::json!({ "actor_id": "forged" })));
        assert_eq!(p.handle(served(&req), NOW).await.status, 200);

        let forwarded = seen.lock().unwrap()[0].clone();
        let v: serde_json::Value = serde_json::from_slice(&forwarded).unwrap();

        // The forged reserved key is gone...
        assert!(
            !String::from_utf8_lossy(&forwarded).contains("forged"),
            "{policy:?}: the caller's forged context leaked"
        );
        // ...and the unrelated application key is untouched.
        assert_eq!(
            v["_meta"]["application.example/keep"],
            serde_json::json!("value"),
            "{policy:?}: the PEP destroyed metadata it does not own"
        );
        // The proxy-owned request-evidence block IS removed — the PEP consumed it.
        assert!(
            v["_meta"].get("se.syncom/mcp-re.http.request").is_none(),
            "{policy:?}: the consumed request-evidence block should not be forwarded"
        );
    }
}


/// The MCP transport contract enforced on the REAL served path (#425). A proxy
/// configured with the strict 2026-07-28 policy rejects a request that omits a
/// required transport header, with a signed rejection — proving §4.1 reaches
/// production, not just the profile crate's unit tests.
#[tokio::test]
async fn transport_contract_is_enforced_on_the_served_path() {
    use mcp_re_http_profile::McpTransportPolicy;
    use mcp_re_http_profile::VerifierPolicy;

    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let p = proxy(VerifiedContextPolicy::Disabled, Arc::clone(&seen)).with_verifier_policy(
        VerifierPolicy::default()
            .with_mcp_transport(McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"])),
    );

    // A conforming request is served.
    let mut ok = signed_request("n-tx-ok", None);
    ok.headers.push(("Mcp-Method".into(), "tools/call".into()));
    ok.headers.push(("Mcp-Name".into(), "read".into()));
    ok.headers.push(("MCP-Protocol-Version".into(), "2026-07-28".into()));
    // Re-sign so the new headers are covered (present ⇒ covered).
    let ok = resign(ok, "n-tx-ok2");
    assert_eq!(p.handle(served(&ok), NOW).await.status, 200);

    // A request OMITTING Mcp-Method is rejected before it reaches the inner server.
    let before = seen.lock().unwrap().len();
    let mut missing = signed_request("n-tx-miss", None);
    missing.headers.push(("MCP-Protocol-Version".into(), "2026-07-28".into()));
    let missing = resign(missing, "n-tx-miss2");
    let out = p.handle(served(&missing), NOW).await;
    assert_eq!(out.status, 403, "a required-header omission is refused");
    assert_eq!(
        seen.lock().unwrap().len(),
        before,
        "the rejected request never reached the inner server"
    );
}

/// Re-sign a request whose headers were mutated after the first signing, so the
/// added transport headers become covered components.
fn resign(mut req: HttpRequest, nonce: &str) -> HttpRequest {
    // Drop the prior signature material and the evidence block, then full-sign again.
    req.headers.retain(|(k, _)| {
        !k.eq_ignore_ascii_case("signature")
            && !k.eq_ignore_ascii_case("signature-input")
            && !k.eq_ignore_ascii_case("content-digest")
    });
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    // strip the request evidence block the first sign inserted, keep the rest
    let mut body = body;
    if let Some(m) = body.get_mut("_meta").and_then(|m| m.as_object_mut()) {
        m.remove("se.syncom/mcp-re.http.request");
        if m.is_empty() {
            body.as_object_mut().unwrap().remove("_meta");
        }
    }
    req.body = serde_json::to_vec(&body).unwrap();
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"tok")],
        continuation: None,
    };
    sign_request_full(&mut req, &block, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, nonce)
        .expect("re-sign");
    req
}
