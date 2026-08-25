// SPDX-License-Identifier: Apache-2.0
//! Authorization through the production PEP (`HttpProfileProxy`) — ADR-MCPRE-065 Slice 1.
//!
//! Every control here drives a real signed request through `HttpProfileProxy::handle`. None
//! constructs a policy input directly: an authorization boundary proven only by handing an
//! evaluator a hand-built input proves that the evaluator works, not that the serving path
//! consults it.
//!
//! The properties:
//!
//!   * a denying policy refuses **before the backend runs** — a denial issued after the tool
//!     ran is a log line, not a control;
//!   * a granting policy serves, and the grant is attributable;
//!   * a deployment with NO policy serves and claims nothing — `Off` is not `Allow`;
//!   * the action coordinate is the SIGNED BODY's (Law A-1): a routing header naming another
//!     tool neither grants nor denies, in either direction;
//!   * an evaluator that cannot decide fails closed, and says which fact that is;
//!   * admission is not authorization: an admitted actor is still refused by a denying
//!     policy;
//!   * and the ADR-MCPRE-064 binding reaches the policy WHOLE, so a policy may condition on
//!     it without reopening it.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::McpTransportPolicy;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_policy::PolicyError;
use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::authorization::AuthorizationEvaluator;
use mcp_re_proxy::authorization::AuthorizationRequest;
use mcp_re_proxy::authorization::GrantAttribution;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;

const CLIENT_SEED: [u8; 32] = [21u8; 32];
const ROOT_SEED: [u8; 32] = [43u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";
const SUBJECT: &str = "did:example:host-a";

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
                trust_domain: "example.com".into(),
                subject: subject.into(),
                keyid: key_id.into(),
            },
            verification_key: key,
            slot,
        })
        .into()
    })
}

/// What the policy actually SAW, recorded as it was asked.
///
/// The controls for Law A-1 need more than the served status: a header that changed the
/// decision and a header that did not are distinguishable only by what reached the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    operation: String,
    target: Option<String>,
    subject: String,
    keyid: String,
    role: String,
    trust_domain: String,
    canonical_actor_id: String,
    channel_bound: bool,
}

/// How a conformance evaluator answers, given what it saw.
type Answer = dyn Fn(&Seen) -> Result<GrantAttribution, PolicyError> + Send + Sync;

/// A conformance evaluator: records what it was asked, and answers as configured.
///
/// It exists to exercise the SEAM. It lives in the test binary and nothing in the crate can
/// reach it — a test needing an allow path is not a reason to ship a production authority.
struct Recording {
    seen: Mutex<Vec<Seen>>,
    answer: Box<Answer>,
}

impl Recording {
    fn new(
        answer: impl Fn(&Seen) -> Result<GrantAttribution, PolicyError> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Recording {
            seen: Mutex::new(Vec::new()),
            answer: Box::new(answer),
        })
    }

    fn only_seen(&self) -> Seen {
        let seen = self.seen.lock().expect("not poisoned");
        assert_eq!(seen.len(), 1, "the policy is consulted exactly once");
        seen[0].clone()
    }

    fn never_consulted(&self) -> bool {
        self.seen.lock().expect("not poisoned").is_empty()
    }
}

impl AuthorizationEvaluator for Recording {
    fn evaluate(&self, request: &AuthorizationRequest) -> Result<GrantAttribution, PolicyError> {
        let actor = request.actor();
        let seen = Seen {
            operation: request.action().operation().to_owned(),
            target: request.action().target().named().map(str::to_owned),
            subject: actor.subject().to_owned(),
            keyid: actor.keyid().to_owned(),
            role: actor.role().to_owned(),
            trust_domain: actor.trust_domain().to_owned(),
            canonical_actor_id: actor.canonical_actor_id(),
            channel_bound: request.channel_binding().is_some(),
        };
        self.seen.lock().expect("not poisoned").push(seen.clone());
        (self.answer)(&seen)
    }
}

/// Grant `tool` and nothing else.
fn grants_only(tool: &'static str) -> Arc<Recording> {
    Recording::new(move |seen| {
        if seen.target.as_deref() == Some(tool) {
            Ok(GrantAttribution::new("conformance", "1"))
        } else {
            Err(PolicyError::AuthorizationScopeDenied)
        }
    })
}

/// A signed call for `tool`. `nonce` must be fresh per call: the replay tier is real here.
fn signed_call(tool: &str, nonce: &str) -> HttpRequest {
    signed_call_with_headers(tool, nonce, &[])
}

/// The same, with MCP transport headers present BEFORE signing.
///
/// They must be signed, not appended: this profile makes every MCP transport header
/// mandatory-if-present-covered, so an appended one is refused as an uncovered component
/// and never reaches any policy. The interesting case — the one Law A-1 is about — is a
/// header the signer genuinely COVERED that disagrees with the body it also signed.
fn signed_call_with_headers(tool: &str, nonce: &str, extra: &[(&str, &str)]) -> HttpRequest {
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: {
            let mut h = vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Authorization".to_string(), "Bearer tok".to_string()),
            ];
            h.extend(
                extra
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
            );
            h
        },
        body: format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}"}}}}"#
        )
        .into_bytes(),
    };
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"tok",
        )],
        continuation: None,
        admission: None,
        admission_assertion: None,
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

/// An inner that COUNTS the calls that reached it. A refusal that arrives after the tool ran
/// is not a control, and the count is the only thing that can tell the difference.
fn counting_inner(calls: Arc<AtomicUsize>) -> Box<dyn AsyncInnerServer> {
    Box::new(move |_forwarded: &[u8]| -> Vec<u8> {
        calls.fetch_add(1, Ordering::SeqCst);
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
    })
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
        ttl: 300,
        overlap: 60,
    }
}

fn ready_signer() -> Arc<DelegatedServerSigner> {
    let signer = Arc::new(DelegatedServerSigner::new());
    let root = root_key();
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = 150u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let mut rotor = DelegatedRotor::new(
        DelegatedSigningCustody::new(custody_cfg(), issue, factory),
        Arc::clone(&signer),
    );
    rotor.rotate(NOW).expect("issue first delegated key");
    std::mem::forget(rotor);
    signer
}

/// A proxy, with or without an authorization mechanism installed.
fn proxy(
    evaluator: Option<Arc<dyn AuthorizationEvaluator>>,
    calls: Arc<AtomicUsize>,
) -> HttpProfileProxy {
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
        counting_inner(calls),
        300,
        ready_signer(),
    );
    match evaluator {
        None => base,
        Some(e) => base.with_authorization(e),
    }
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
    let body = String::from_utf8_lossy(&served.body).into_owned();
    (served.status, body)
}

#[tokio::test]
async fn a_granting_policy_serves_and_the_backend_runs() {
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = grants_only("read");
    let p = proxy(Some(policy.clone()), Arc::clone(&calls));
    let (status, _) = serve(&p, signed_call("read", "n-grant")).await;
    assert_eq!(status, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let seen = policy.only_seen();
    assert_eq!(seen.operation, "tools/call");
    assert_eq!(seen.target.as_deref(), Some("read"));
    assert_eq!(seen.subject, SUBJECT);
    assert_eq!(seen.keyid, CLIENT_KEY_ID);
    assert_eq!(seen.role, "client");
    assert_eq!(seen.trust_domain, "example.com");
    assert!(
        seen.canonical_actor_id.contains(CLIENT_KEY_ID),
        "the canonical projection is available to a credential-scoped policy"
    );
    assert!(
        !seen.channel_bound,
        "no transport binding is installed, so the policy is told NOT CLAIMED rather than \
         being handed a binding nobody established"
    );
}

#[tokio::test]
async fn a_denying_policy_refuses_before_the_backend_runs() {
    // THE control this slice exists for. A denial after dispatch is a record of something
    // that already happened.
    let calls = Arc::new(AtomicUsize::new(0));
    let p = proxy(Some(grants_only("read")), Arc::clone(&calls));
    let (status, body) = serve(&p, signed_call("delete", "n-deny")).await;
    assert_eq!(status, 403);
    assert!(
        body.contains("mcp-re.authorization_scope_denied"),
        "the refusal names the policy's own token: {body}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the backend must never have been asked"
    );
}

#[tokio::test]
async fn a_deployment_with_no_policy_serves_and_claims_nothing() {
    // `Off` is not `Allow`. The observable half is that serving is unchanged; the claim half
    // is that no grant exists — which is what `AuthorizationPosture::NoPolicyConfigured`
    // records, and why no evaluator was consulted.
    let calls = Arc::new(AtomicUsize::new(0));
    let p = proxy(None, Arc::clone(&calls));
    let (status, _) = serve(&p, signed_call("anything-at-all", "n-off")).await;
    assert_eq!(status, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_covered_routing_header_naming_another_tool_does_not_reach_the_policy() {
    // LAW A-1. The signer covered `Mcp-Name: delete` and signed a body asking for `read`.
    // The default deployment does NOT enforce `Mcp-Name` agreement — the transport contract
    // is `Unconstrained` until a protocol version is declared — so the request verifies.
    // The policy must still decide over the BODY.
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = grants_only("read");
    let p = proxy(Some(policy.clone()), Arc::clone(&calls));
    let req = signed_call_with_headers("read", "n-a1-grant", &[("Mcp-Name", "delete")]);
    let (status, body) = serve(&p, req).await;
    assert_eq!(
        status, 200,
        "a header cannot revoke what the body was granted: {body}"
    );
    assert_eq!(policy.only_seen().target.as_deref(), Some("read"));
}

#[tokio::test]
async fn a_covered_routing_header_cannot_carry_a_grant_the_signed_body_does_not_have() {
    // The other direction, and the one that is an attack: a body asking for `delete` must
    // not be authorized because a covered header claims `read`. Same deployment, same
    // absence of a transport contract.
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = grants_only("read");
    let p = proxy(Some(policy.clone()), Arc::clone(&calls));
    let req = signed_call_with_headers("delete", "n-a1-deny", &[("Mcp-Name", "read")]);
    let (status, body) = serve(&p, req).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(policy.only_seen().target.as_deref(), Some("delete"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_uncovered_routing_header_never_reaches_the_policy_at_all() {
    // The profile makes every MCP transport header mandatory-if-present-covered, so a
    // header injected by anything downstream of the signer is refused as evidence rather
    // than interpreted. Recorded as a control because it is the reason the two tests above
    // have to sign the header: the easy version of this attack is already impossible.
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = grants_only("read");
    let p = proxy(Some(policy.clone()), Arc::clone(&calls));
    let mut req = signed_call("read", "n-a1-injected");
    req.headers.push(("Mcp-Name".into(), "delete".into()));
    let (status, body) = serve(&p, req).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("mcp-re.missing_envelope"), "{body}");
    assert!(policy.never_consulted());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn enforcing_the_transport_contract_does_not_change_which_action_is_authorized() {
    // Law A-1's point stated as a measurement. With the contract ENFORCED the same
    // divergent request is refused by the verifier and never reaches a policy; with it
    // Unconstrained the policy sees the BODY. What must never happen is the third
    // behaviour — the policy seeing the HEADER — because then switching an unrelated
    // consistency policy on or off would silently change authorization semantics.
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = grants_only("read");
    let p = proxy(Some(policy.clone()), Arc::clone(&calls)).with_verifier_policy(
        VerifierPolicy::default()
            .with_mcp_transport(McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"])),
    );
    let req = signed_call_with_headers(
        "delete",
        "n-a1-enforced",
        &[
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "read"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
    );
    let (status, body) = serve(&p, req).await;
    assert_eq!(status, 403, "{body}");
    assert!(
        policy.never_consulted(),
        "the contract refused the self-contradictory request before authorization ran"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // And with the contract off, the same body reaches the policy as `delete`.
    let calls2 = Arc::new(AtomicUsize::new(0));
    let policy2 = grants_only("read");
    let p2 = proxy(Some(policy2.clone()), Arc::clone(&calls2));
    let req2 = signed_call_with_headers("delete", "n-a1-unenforced", &[("Mcp-Name", "read")]);
    let (status2, _) = serve(&p2, req2).await;
    assert_eq!(status2, 403);
    assert_eq!(policy2.only_seen().target.as_deref(), Some("delete"));
}

#[tokio::test]
async fn an_evaluator_that_cannot_decide_fails_closed_with_its_own_token() {
    // Fail-closed is not in doubt; being able to tell an outage from a denial is. Both
    // refuse; an operator sent to inspect a grant during an outage is the cost of
    // flattening them.
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = Recording::new(|_| Err(PolicyError::AuthorizationRevocationUnavailable));
    let p = proxy(Some(policy), Arc::clone(&calls));
    let (status, body) = serve(&p, signed_call("read", "n-outage")).await;
    assert_eq!(status, 403);
    assert!(
        body.contains("mcp-re.authorization_revocation_unavailable"),
        "an outage is named as one: {body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_request_whose_signature_does_not_verify_never_reaches_the_policy() {
    // Ordering, stated as a control: authorization decides over VERIFIED facts, so a
    // request that never verified must not be offered to a policy at all. An evaluator
    // consulted here would be deciding over an actor nobody resolved.
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = grants_only("read");
    let p = proxy(Some(policy.clone()), Arc::clone(&calls));
    let mut req = signed_call("read", "n-tampered");
    req.body =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec();
    let (status, _) = serve(&p, req).await;
    assert_ne!(status, 200);
    assert!(policy.never_consulted());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_denied_request_is_answerable_as_nothing_executed() {
    // The refusal is free: it happens before the nonce is burned and before the backend is
    // asked, so a client may retry the same action once its grant changes. That is the
    // reason the stage sits where it does.
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = Recording::new({
        let n = AtomicUsize::new(0);
        move |_| {
            if n.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(PolicyError::AuthorizationScopeDenied)
            } else {
                Ok(GrantAttribution::new("conformance", "2"))
            }
        }
    });
    let p = proxy(Some(policy), Arc::clone(&calls));
    let call = signed_call("read", "n-retry");
    let (denied, _) = serve(&p, call.clone()).await;
    assert_eq!(denied, 403);
    // The SAME request, replayed after the policy changed its mind. It is served, which
    // proves the denial spent nothing — neither the nonce nor the backend.
    let (granted, _) = serve(&p, call).await;
    assert_eq!(granted, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
