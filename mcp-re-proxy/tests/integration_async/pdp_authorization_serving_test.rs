// SPDX-License-Identifier: Apache-2.0
//! The PDP-decision authorization profile through the production PEP — ADR-MCPRE-065 Slice 2.
//!
//! Slice 1 built the boundary and shipped no mechanism. This is the first production one: an
//! external authority signs a decision, the client carries it in the signed request, and
//! MCP-RE enforces it before dispatch.
//!
//! Every control drives a real signed request through `HttpProfileProxy::handle` with a real
//! Ed25519 authority key. None constructs a policy input directly, and none asserts only on
//! the HTTP status: a refusal that arrives after the tool ran is a log line, so the backend
//! call COUNT is the assertion that matters.
//!
//! The chain each control attacks one link of:
//!
//! ```text
//! digest correspondence -> authority trust -> JWS authentication
//!   -> actor relation -> action relation -> explicit Permit
//! ```

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::pdp_decision::issue_authorization_decision;
use mcp_re_http_profile::pdp_decision::DecidedActor;
use mcp_re_http_profile::pdp_decision::DecisionScope;
use mcp_re_http_profile::pdp_decision::PdpDecisionClaims;
use mcp_re_http_profile::pdp_decision::PdpDecisionFreshness;
use mcp_re_http_profile::pdp_decision::PdpDecisionOutcome;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::BindingType;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::authorization::AuthorizationFacet;
use mcp_re_proxy::authorization::AuthorizationRefusalFacet;
use mcp_re_proxy::authorization::PdpDecisionEvaluator;
use mcp_re_proxy::authorization::PdpDecisionPolicy;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;

const CLIENT_SEED: [u8; 32] = [31u8; 32];
const ROOT_SEED: [u8; 32] = [63u8; 32];
const PDP_SEED: [u8; 32] = [77u8; 32];
const OTHER_PDP_SEED: [u8; 32] = [78u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const PDP_KID: &str = "pdp-root-1";
const VERIFIER_AUD: &str = "verifier-1";
const TRUST_DOMAIN: &str = "example.com";
const SUBJECT: &str = "did:example:host-a";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
/// The AUTHORIZATION authority's root — a different key from the response-signing root and
/// from the client's, so "trusted to sign responses" or "trusted to sign requests" can never
/// be mistaken for "trusted to decide permission".
fn pdp_key() -> SigningKey {
    SigningKey::from_seed_bytes(&PDP_SEED)
}
fn other_pdp_key() -> SigningKey {
    SigningKey::from_seed_bytes(&OTHER_PDP_SEED)
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

fn actor_resolver() -> ActorResolver {
    Box::new(move |key_id: &str, slot: SignerSlot| {
        let (role, subject, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", SUBJECT, client_key().public_key()),
            (ROOT_KID, SignerSlot::Response) => {
                ("server", "did:example:server", root_key().public_key())
            }
            _ => return None::<ResolvedActor>.into(),
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: TRUST_DOMAIN.into(),
                subject: subject.into(),
                keyid: key_id.into(),
            },
            verification_key: key,
            slot,
        })
        .into()
    })
}

/// A principal-scoped decision permitting `tool` to `SUBJECT`.
fn decision_for(tool: Option<&str>, operation: &str) -> PdpDecisionClaims {
    PdpDecisionClaims {
        iss: "did:example:pdp".into(),
        iat: NOW - 5,
        nbf: NOW - 5,
        exp: NOW + 300,
        jti: "decision-1".into(),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_decided_actor: DecidedActor::Principal {
            trust_domain: TRUST_DOMAIN.into(),
            subject: SUBJECT.into(),
        },
        mcp_re_decided_operation: operation.into(),
        mcp_re_decided_target: tool.map(str::to_owned),
        mcp_re_decision: PdpDecisionOutcome::Permit,
        mcp_re_policy_version: "2026-08-01".into(),
        issuer_kid: PDP_KID.into(),
    }
}

fn issue(claims: &PdpDecisionClaims, key: &SigningKey) -> String {
    issue_authorization_decision(claims, |input| {
        b64url_decode(&key.sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
    })
    .expect("issues")
}

/// A signed call for `tool`, optionally carrying a decision. `nonce` must be fresh per call.
fn signed_call(tool: &str, nonce: &str, decision: Option<&str>) -> HttpRequest {
    signed_call_bound_by(tool, nonce, decision, |d| {
        ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, d.as_bytes())
    })
}

/// A signed `tools/call` whose params name NO tool.
///
/// The body is well formed and the operation takes a target, so the action coordinate is
/// `Absent` rather than `NotApplicable` — a third state, and the only way to reach it.
fn signed_call_naming_no_tool(nonce: &str, decision: &str) -> HttpRequest {
    signed_body(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#,
        nonce,
        decision,
    )
}

/// The same, with the caller choosing how the decision is bound — which is what lets a
/// control present the LINKAGE form where the evidence form is required.
fn signed_call_bound_by(
    tool: &str,
    nonce: &str,
    decision: Option<&str>,
    bind: impl Fn(&str) -> ArtifactBinding,
) -> HttpRequest {
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), "Bearer tok".into()),
        ],
        body: format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}"}}}}"#
        )
        .into_bytes(),
    };
    let mut bindings = vec![ArtifactBinding::opaque_digest(
        ArtifactType::OauthDpop,
        b"tok",
    )];
    if let Some(d) = decision {
        bindings.push(bind(d));
    }
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: bindings,
        continuation: None,
        admission: None,
        admission_assertion: None,
        authorization_decision: decision.map(str::to_owned),
    };
    sign_request_full(
        &mut req,
        &block,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        nonce,
    )
    .expect("signs");
    req
}

/// Sign an arbitrary JSON-RPC body carrying `decision` in evidence form.
fn signed_body(body: &str, nonce: &str, decision: &str) -> HttpRequest {
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), "Bearer tok".into()),
        ],
        body: body.as_bytes().to_vec(),
    };
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![
            ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"tok"),
            ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, decision.as_bytes()),
        ],
        continuation: None,
        admission: None,
        admission_assertion: None,
        authorization_decision: Some(decision.to_owned()),
    };
    sign_request_full(
        &mut req,
        &block,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        nonce,
    )
    .expect("signs");
    req
}

fn counting_inner(calls: Arc<AtomicUsize>) -> Box<dyn AsyncInnerServer> {
    Box::new(move |_forwarded: &[u8]| -> Vec<u8> {
        calls.fetch_add(1, Ordering::SeqCst);
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
    })
}

fn ready_signer() -> Arc<DelegatedServerSigner> {
    let signer = Arc::new(DelegatedServerSigner::new());
    let root = root_key();
    let issue_cred = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = 200u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let mut rotor = DelegatedRotor::new(
        DelegatedSigningCustody::new(
            CustodyConfig {
                issuer_kid: ROOT_KID.into(),
                iss: "did:example:server".into(),
                profile: PROFILE_TAG.into(),
                aud: VERIFIER_AUD.into(),
                audience_hash: "aud-scope-1".into(),
                trust_epoch: "epoch-1".into(),
                server_role: "server".into(),
                server_trust_domain: TRUST_DOMAIN.into(),
                server_subject: "did:example:server".into(),
                ttl: 300,
                overlap: 60,
            },
            issue_cred,
            factory,
        ),
        Arc::clone(&signer),
    );
    rotor.rotate(NOW).expect("issue first delegated key");
    std::mem::forget(rotor);
    signer
}

/// A proxy enforcing the PDP profile, trusting `trusted_kid` as its authorization authority.
fn proxy_with(
    scope: DecisionScope,
    trusted_kid: &'static str,
    calls: Arc<AtomicUsize>,
) -> HttpProfileProxy {
    let evaluator = PdpDecisionEvaluator::new(
        PdpDecisionPolicy {
            resolve_authority: Arc::new(move |kid: &str| {
                (kid == trusted_kid).then(|| pdp_key().public_key())
            }),
            accepted_scope: scope,
            freshness: PdpDecisionFreshness {
                max_clock_skew: 30,
                max_decision_age: 600,
            },
        },
        PROFILE_TAG,
        vec![VERIFIER_AUD.to_string()],
        Arc::new(|| NOW),
    );
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
        counting_inner(calls),
        300,
        ready_signer(),
    )
    .with_authorization(Arc::new(evaluator))
}

fn proxy(calls: Arc<AtomicUsize>) -> HttpProfileProxy {
    proxy_with(DecisionScope::Principal, PDP_KID, calls)
}

/// Serve, and hand back the audit records the exchange produced.
async fn serve_recorded(
    p: HttpProfileProxy,
    req: HttpRequest,
) -> (u16, Vec<mcp_re_proxy::AuditRecord>) {
    let sink = Arc::new(mcp_re_proxy::CollectingAuditSink::new());
    let p = p.with_audit_sink(sink.clone());
    let (status, _) = serve(&p, req).await;
    (status, sink.records())
}

async fn serve(p: &HttpProfileProxy, req: HttpRequest) -> (u16, String) {
    let served = p
        .handle(
            ServedHttpRequest {
                method: req.method,
                target_uri: req.target_uri,
                headers: req.headers,
                body: req.body,
                peer: None,
                assertion: None,
            },
            NOW,
        )
        .await;
    (
        served.status,
        String::from_utf8_lossy(&served.body).into_owned(),
    )
}

#[tokio::test]
async fn a_permit_decision_reaches_the_backend() {
    let calls = Arc::new(AtomicUsize::new(0));
    let d = issue(&decision_for(Some("read"), "tools/call"), &pdp_key());
    let (status, body) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-permit", Some(&d)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_explicit_deny_never_reaches_the_backend() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut claims = decision_for(Some("read"), "tools/call");
    claims.mcp_re_decision = PdpDecisionOutcome::Deny;
    let d = issue(&claims, &pdp_key());
    let (status, body) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-deny", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert!(body.contains("mcp-re.authorization_scope_denied"), "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_decision_issued_to_another_actor_does_not_authorize_this_one() {
    // The BEARER-TOKEN control. The decision is genuine, current, signed by the real
    // authority; the only thing wrong with it is that it names somebody else.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut claims = decision_for(Some("read"), "tools/call");
    claims.mcp_re_decided_actor = DecidedActor::Principal {
        trust_domain: TRUST_DOMAIN.into(),
        subject: "did:example:someone-else".into(),
    };
    let d = issue(&claims, &pdp_key());
    let (status, body) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-other-actor", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert!(
        body.contains("mcp-re.authorization_signer_mismatch"),
        "{body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_decision_for_another_trust_domain_does_not_authorize_this_subject() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut claims = decision_for(Some("read"), "tools/call");
    claims.mcp_re_decided_actor = DecidedActor::Principal {
        trust_domain: "other.example".into(),
        subject: SUBJECT.into(),
    };
    let d = issue(&claims, &pdp_key());
    let (status, _) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-other-domain", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_decision_for_another_tool_does_not_authorize_this_call() {
    let calls = Arc::new(AtomicUsize::new(0));
    let d = issue(&decision_for(Some("read"), "tools/call"), &pdp_key());
    let (status, body) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("delete", "n-other-tool", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert!(body.contains("mcp-re.authorization_scope_denied"), "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_decision_for_another_operation_does_not_authorize_this_one() {
    let calls = Arc::new(AtomicUsize::new(0));
    let d = issue(&decision_for(None, "tools/list"), &pdp_key());
    let (status, _) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-other-op", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// A call whose signed body names no tool, against a decision that names no target.
///
/// `Absent` is a THIRD state and it matches nothing: a request that named no tool was not
/// decided. Comparing two `Option`s instead of the typed value collapses it into the
/// not-applicable arm, and this call — which asks `tools/call` without saying what to call
/// — would be authorized by a decision about an operation that takes no target at all.
///
/// The existing tool controls cannot see that: they both name tools, so they exercise the
/// `(Some, Named)` arm and stay green with the `Absent` arm deleted.
#[tokio::test]
async fn a_call_naming_no_tool_is_not_authorized_by_a_targetless_decision() {
    let calls = Arc::new(AtomicUsize::new(0));
    let d = issue(&decision_for(None, "tools/call"), &pdp_key());
    let (status, _) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call_naming_no_tool("n-absent-target", &d),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // The control: the same decision, against a call that DOES name the tool the decision
    // is about, is refused for the target and not for the operation — so the refusal above
    // is about `Absent` rather than about `tools/call` being unauthorized in general.
    let named = issue(&decision_for(Some("read"), "tools/call"), &pdp_key());
    let (ok_status, _) = serve(
        &proxy(Arc::new(AtomicUsize::new(0))),
        signed_call("read", "n-absent-control", Some(&named)),
    )
    .await;
    assert_eq!(ok_status, 200);
}

#[tokio::test]
async fn a_decision_from_an_authority_this_deployment_does_not_trust_is_refused() {
    // Signed by a real key, under a kid the deployment's AUTHORIZATION resolver does not
    // know. Request-signer trust is irrelevant here and must not rescue it.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut claims = decision_for(Some("read"), "tools/call");
    claims.issuer_kid = "some-other-pdp".into();
    let d = issue(&claims, &pdp_key());
    let (status, body) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-untrusted", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert!(
        body.contains("mcp-re.authorization_signature_invalid"),
        "{body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_decision_signed_by_the_wrong_key_under_a_trusted_kid_is_refused() {
    let calls = Arc::new(AtomicUsize::new(0));
    let d = issue(&decision_for(Some("read"), "tools/call"), &other_pdp_key());
    let (status, body) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-forged", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert!(
        body.contains("mcp-re.authorization_signature_invalid"),
        "{body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_configured_profile_refuses_a_request_that_presents_no_decision() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (status, body) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-none", None),
    )
    .await;
    assert_eq!(status, 403);
    assert!(
        body.contains("mcp-re.authorization_block_missing"),
        "{body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_reference_binding_can_never_satisfy_the_enforcement_profile() {
    // THE structural negative. The linkage form carries the IDENTICAL digest of the very
    // same decision document, and the request is otherwise exactly the one that succeeds.
    // It must still be refused: a reference names an external decision MCP-RE authenticates
    // nothing about, and letting it stand in would let a call claim an enforcement decision
    // it never presented.
    let calls = Arc::new(AtomicUsize::new(0));
    let d = issue(&decision_for(Some("read"), "tools/call"), &pdp_key());
    let req = signed_call_bound_by("read", "n-reference", Some(&d), |doc| ArtifactBinding {
        binding_type: BindingType::ReferenceDigest,
        authorization_system_id: Some("urn:example:pdp".into()),
        reference_scheme_id: Some("urn:example:scheme".into()),
        reference_value: Some("decision-1".into()),
        ..ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, doc.as_bytes())
    });
    let (status, body) = serve(&proxy(Arc::clone(&calls)), req).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_decision_scoped_differently_from_the_deployments_profile_is_refused() {
    // The signed scope is what the decision IS; configuration is what the deployment
    // ACCEPTS. Neither infers the other, so one document cannot mean a principal grant here
    // and a credential grant next door.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut claims = decision_for(Some("read"), "tools/call");
    claims.mcp_re_decided_actor = DecidedActor::Credential {
        trust_domain: TRUST_DOMAIN.into(),
        subject: SUBJECT.into(),
        keyid: CLIENT_KEY_ID.into(),
    };
    let d = issue(&claims, &pdp_key());
    // The deployment accepts PRINCIPAL-scoped decisions; this one is credential-scoped, and
    // it matches this caller on every dimension. It is still refused.
    let (status, _) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-scope", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_credential_scoped_deployment_binds_the_signing_key() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut claims = decision_for(Some("read"), "tools/call");
    claims.mcp_re_decided_actor = DecidedActor::Credential {
        trust_domain: TRUST_DOMAIN.into(),
        subject: SUBJECT.into(),
        keyid: CLIENT_KEY_ID.into(),
    };
    let d = issue(&claims, &pdp_key());
    let p = proxy_with(DecisionScope::Credential, PDP_KID, Arc::clone(&calls));
    let (status, body) = serve(&p, signed_call("read", "n-cred-ok", Some(&d))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The same decision, naming a different signing credential for the same principal.
    let calls2 = Arc::new(AtomicUsize::new(0));
    let mut rotated = decision_for(Some("read"), "tools/call");
    rotated.mcp_re_decided_actor = DecidedActor::Credential {
        trust_domain: TRUST_DOMAIN.into(),
        subject: SUBJECT.into(),
        keyid: "client-key-2-rotated".into(),
    };
    let d2 = issue(&rotated, &pdp_key());
    let p2 = proxy_with(DecisionScope::Credential, PDP_KID, Arc::clone(&calls2));
    let (status2, _) = serve(&p2, signed_call("read", "n-cred-rotated", Some(&d2))).await;
    assert_eq!(
        status2, 403,
        "a credential-scoped decision does not survive rotation"
    );
    assert_eq!(calls2.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_stale_decision_is_refused_even_inside_its_own_validity_window() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut claims = decision_for(Some("read"), "tools/call");
    claims.iat = NOW - 10_000;
    claims.nbf = NOW - 10_000;
    claims.exp = NOW + 10_000;
    let d = issue(&claims, &pdp_key());
    let (status, body) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-stale", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert!(body.contains("mcp-re.authorization_expired"), "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_decision_issued_for_another_enforcement_point_is_refused() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut claims = decision_for(Some("read"), "tools/call");
    claims.aud = Audience::One("verifier-2".into());
    let d = issue(&claims, &pdp_key());
    let (status, body) = serve(
        &proxy(Arc::clone(&calls)),
        signed_call("read", "n-aud", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert!(
        body.contains("mcp-re.authorization_audience_mismatch"),
        "{body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_deployment_running_no_decision_profile_is_unaffected() {
    // `NotConfigured`, never `Authorized`: a proxy with no evaluator serves as before, and
    // the request carrying a decision is not thereby authorized by anything.
    let calls = Arc::new(AtomicUsize::new(0));
    let base = HttpProfileProxy::new_delegated(
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
        counting_inner(Arc::clone(&calls)),
        300,
        ready_signer(),
    );
    let (status, body) = serve(&base, signed_call("read", "n-off", None)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// --- ADR-MCPRE-065 Slice 3: the SDK producer's output, through this same PEP ----------
//
// The controls above build the evidence block by hand, which is right for attacking one
// link at a time but proves nothing about what a CLIENT can actually construct. These two
// drive the language SDKs' own path — the provider spec JSON that
// `AuthorizationDecisionProvider` emits, through `build_authorization` and
// `RequestSigningInputs::with_authorization_decision`, into the real signing core — and
// then serve the result. Without them, "the SDK can produce enforceable evidence" would
// be an inference from two separately-green test suites.

/// The spec JSON the Python and TypeScript `AuthorizationDecisionProvider` emit.
///
/// Written out rather than imported: the point is that THIS text, which the wrappers
/// produce, is what the core accepts.
fn decision_spec_json(decision: &str) -> String {
    format!(
        r#"[{{"artifact_type":"pdp-decision","form":"authorization-decision","material_b64url":"{}"}}]"#,
        mcp_re_core::b64url_encode(decision.as_bytes())
    )
}

/// Build a `tools/call` exactly as an SDK client does, from a provider list alone.
fn sdk_signed_call(tool: &str, nonce: &str, bindings_json: &str) -> HttpRequest {
    let provided = mcp_re_client_core::build_authorization(bindings_json).expect("legal spec");
    let mut inputs = mcp_re_client_core::RequestSigningInputs::new(
        CLIENT_KEY_ID,
        audience(),
        // DPoP stays the built-in, header-derived binding, as it is in both SDKs.
        {
            let mut b = vec![ArtifactBinding::opaque_digest(
                ArtifactType::OauthDpop,
                b"tok",
            )];
            b.extend(provided.bindings);
            b
        },
        nonce,
        CREATED,
        EXPIRES,
    )
    .with_headers(vec![("Authorization".into(), "Bearer tok".into())]);
    if let Some(jws) = provided.decision {
        inputs = inputs.with_authorization_decision(jws);
    }
    let mut params = serde_json::Map::new();
    params.insert("name".into(), serde_json::Value::String(tool.into()));
    mcp_re_client_core::build_signed_request(
        &serde_json::Value::from(1),
        "tools/call",
        params,
        TARGET,
        &inputs,
        &client_key(),
    )
    .expect("signs")
    .into_request()
}

#[tokio::test]
async fn a_decision_attached_through_the_sdk_producer_is_authorized_end_to_end() {
    let calls = Arc::new(AtomicUsize::new(0));
    let d = issue(&decision_for(Some("read"), "tools/call"), &pdp_key());
    let req = sdk_signed_call("read", "n-sdk-permit-0001-128bit", &decision_spec_json(&d));

    // The producer derived the binding; nothing in this test computed a digest.
    let block: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
    let block = &block["_meta"]["se.syncom/mcp-re.http.request"];
    assert_eq!(block["authorization_decision"].as_str(), Some(d.as_str()));

    let (status, body) = serve(&proxy(Arc::clone(&calls)), req).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the backend ran");
}

#[tokio::test]
async fn the_sdk_producer_cannot_build_the_half_pair_this_pep_refuses() {
    // The narrowing, measured against the enforcement point rather than restated: the
    // spec a generic opaque provider would emit for `pdp-decision` is refused at
    // construction, so the request the PEP would reject is never built.
    let d = issue(&decision_for(Some("read"), "tools/call"), &pdp_key());
    let generic = format!(
        r#"[{{"artifact_type":"pdp-decision","form":"opaque-bytes","material_b64url":"{}"}}]"#,
        mcp_re_core::b64url_encode(d.as_bytes())
    );
    let refusal = mcp_re_client_core::build_authorization(&generic).expect_err("half a pair");
    assert_eq!(
        refusal.wire_code(),
        "mcp-re.authorization_binding_type_unsupported"
    );

    // And what that construction WOULD have produced is exactly what this PEP refuses: a
    // `pdp-decision`/`opaque-digest` binding with no document to check it against. The
    // narrowing therefore removes a construction that could only ever be refused — it does
    // not invent a rule the enforcement point does not already hold.
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), "Bearer tok".into()),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    };
    let orphan = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![
            ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"tok"),
            ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, d.as_bytes()),
        ],
        continuation: None,
        admission: None,
        admission_assertion: None,
        authorization_decision: None,
    };
    sign_request_full(
        &mut req,
        &orphan,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        "n-sdk-half",
    )
    .expect("signs");

    let calls = Arc::new(AtomicUsize::new(0));
    let (status, body) = serve(&proxy(Arc::clone(&calls)), req).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a binding with no document authorizes nothing"
    );
}

// --- ADR-MCPRE-066 Slice 1: what the audit record says about authorization ------------
//
// Issue #637 measured the defect these controls close: with only Core's `reason` field, a
// policy denial and a Core verification failure are the same record shape, and a policy
// GRANT leaves no trace at all. The facet is a second coordinate, and these assert what
// each authority is entitled to put in it.

#[tokio::test]
async fn an_authorized_request_records_which_policy_permitted_what() {
    let calls = Arc::new(AtomicUsize::new(0));
    let d = issue(&decision_for(Some("read"), "tools/call"), &pdp_key());
    let (status, records) = serve_recorded(
        proxy(Arc::clone(&calls)),
        signed_call("read", "n-audit-grant", Some(&d)),
    )
    .await;
    assert_eq!(status, 200);

    let accepted = records
        .iter()
        .find(|r| r.event().event_type == "mcp-re.request.accepted")
        .expect("the admitted request is recorded");
    let mcp_re_proxy::AuditSubject::Request { authorization, .. } = &accepted.subject else {
        panic!("a request record");
    };
    let AuthorizationFacet::Authorized(a) = authorization else {
        panic!("a policy permitted this, and the record must say so: {authorization:?}");
    };
    // Who decided, under which policy, over what — none of it reconstructed here. The
    // authority is the PDP that issued the decision, not this proxy: an operator asking
    // "why was this permitted" is pointed at the party that answered.
    assert_eq!(a.authority, "did:example:pdp");
    assert_eq!(a.action.operation(), "tools/call");
    assert_eq!(a.action.target().named(), Some("read"));
    assert!(
        !a.attributable_to.digest_value.is_empty(),
        "the record names the exchange the decision was taken for"
    );
    // Decision provenance, through the real serving path: WHICH decision the authority
    // says this was, and WHICH exact evidence this proxy authenticated. The first is the
    // authenticated `jti`; the second is the digest the request's binding committed to,
    // and neither stands in for the other.
    assert_eq!(a.authority_decision_id, "decision-1");
    let bound = ArtifactBinding::opaque_digest(ArtifactType::PdpDecision, d.as_bytes());
    assert_eq!(a.decision_evidence.alg(), bound.digest_alg);
    assert_eq!(a.decision_evidence.value(), bound.digest_value);
    assert_ne!(
        a.decision_evidence.rendered(),
        a.authority_decision_id,
        "the two coordinates must not be one value under two names"
    );
    // Invariant 7: naming the evidence costs no byte of the decision document.
    assert!(!format!("{a:?}").contains(&d));
}

#[tokio::test]
async fn a_policy_denial_is_recorded_as_a_policy_denial_and_not_merely_as_a_rejection() {
    // THE #637 property. Core's `reason` cannot distinguish these two records; the
    // authorization coordinate can, and an operator reading it is not sent to inspect a
    // grant that was never consulted.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut claims = decision_for(Some("read"), "tools/call");
    claims.mcp_re_decision = PdpDecisionOutcome::Deny;
    let d = issue(&claims, &pdp_key());
    let (status, records) = serve_recorded(
        proxy(Arc::clone(&calls)),
        signed_call("read", "n-audit-deny", Some(&d)),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let rejected = records
        .iter()
        .find(|r| r.event().event_type == "mcp-re.request.rejected")
        .expect("the denial is recorded");
    let mcp_re_proxy::AuditSubject::Request { authorization, .. } = &rejected.subject else {
        panic!("a request record");
    };
    assert!(
        matches!(
            authorization,
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(_))
        ),
        "a policy decided and denied: {authorization:?}"
    );

    // ADR-MCPRE-066 Slice 2: and Core's own field is EMPTY, because Core reached no
    // verdict. This is the end of #637 — the policy's token is in the authorization
    // coordinate and nowhere else, so a reader can no longer mistake it for a Core one.
    assert_eq!(
        rejected.event().reason,
        None,
        "a policy denial is not a Core verdict, so Core must state none"
    );
    assert_eq!(rejected.event().event_type, "mcp-re.request.rejected");
}

#[tokio::test]
async fn a_request_refused_before_any_policy_ran_is_not_attributed_to_one() {
    // The other half of the same distinction. This request never presented a decision, so
    // the PDP profile refuses — but the refusal IS a policy verdict, so it must not be
    // confused with a request that failed before authorization was reached. A replay is
    // that second case, and `delegated_client_server_e2e_test` pins it; here the point is
    // that these two do not project to the same facet.
    let calls = Arc::new(AtomicUsize::new(0));
    let (status, records) = serve_recorded(
        proxy(Arc::clone(&calls)),
        signed_call("read", "n-audit-none", None),
    )
    .await;
    assert_eq!(status, 403);

    let rejected = records
        .iter()
        .find(|r| r.event().event_type == "mcp-re.request.rejected")
        .expect("the refusal is recorded");
    let mcp_re_proxy::AuditSubject::Request { authorization, .. } = &rejected.subject else {
        panic!("a request record");
    };
    assert_ne!(
        authorization,
        &AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
        "the configured profile reached a verdict; the record must not say none did"
    );
    assert_eq!(rejected.event().reason, None, "still not a Core verdict");
}

#[tokio::test]
async fn a_core_verification_failure_still_records_its_frozen_core_reason() {
    // The other side of Slice 2, and the reason it is not merely "stop writing a reason":
    // where Core DID reach a verdict, the record carries that verdict's frozen token
    // exactly as before. Only the case Core has nothing to say about goes quiet.
    let calls = Arc::new(AtomicUsize::new(0));
    let d = issue(&decision_for(Some("read"), "tools/call"), &pdp_key());
    let mut req = signed_call("read", "n-audit-core", Some(&d));
    req.body.extend_from_slice(b" ");
    let (status, records) = serve_recorded(proxy(Arc::clone(&calls)), req).await;
    assert_eq!(status, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let rejected = records
        .iter()
        .find(|r| r.event().event_type == "mcp-re.request.rejected")
        .expect("the refusal is recorded");
    assert_eq!(
        rejected.event().reason,
        Some("mcp-re.digest_mismatch"),
        "Core reached this verdict and the record says which one"
    );
    // And the authorization coordinate says no policy ever ran, which is true: the request
    // never got that far.
    let mcp_re_proxy::AuditSubject::Request { authorization, .. } = &rejected.subject else {
        panic!("a request record");
    };
    assert_eq!(
        authorization,
        &AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy)
    );
}
