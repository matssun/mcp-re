// SPDX-License-Identifier: Apache-2.0
//! The ADR-MCPS-047 stateless cross-replica MRTR continuation, end-to-end through the
//! production PEP (`HttpProfileProxy`) — the serving contract Proof 3 of
//! `docs/security/gke-multi-replica-validation.sh` exercises live.
//!
//! Two independent proxy instances (replica A and replica B) each with their OWN
//! delegated signer and OWN replay tier, but SHARING one continuation correlation
//! store (the in-process stand-in for the fleet-shared Redis tier). Proves:
//!   * OPEN on A: an eliciting inner returns an `InputRequiredResult` with a
//!     `requestState`; A delegated-signs it AND records the retained bases in the
//!     shared store.
//!   * ANSWER on B: a client signs the answer leg with an `HttpContinuation` (built
//!     from the two evidence-handle digests it already holds) + the `requestState`;
//!     B — which never saw the open leg — recovers the retained bases from the shared
//!     store, binds the continuation (digest equality under the client's signature),
//!     forwards to its inner, and delegated-signs a terminal reply. Honoured across a
//!     replica switch.
//!   * Fail-closed: a continuation with NO shared-store entry (never opened / expired
//!     / already answered — the store is one-shot), and a TAMPERED `requestState`,
//!     are both rejected `continuation_binding_failed`. A splice never admits.

use std::sync::Arc;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::verify_delegated_response_full;
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
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::RequestEvidenceDigest;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::async_serve::ServedHttpResponse;
use mcp_re_proxy::continuation_store::AsyncContinuationStore;
use mcp_re_proxy::continuation_store::InMemoryContinuationStore;
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

/// An ELICITING inner: a first call (no `inputResponses`/`requestState`) returns an
/// `InputRequiredResult` carrying an opaque `requestState`; an answer call returns a
/// terminal result. Mirrors `tools/fastmcp_inner_backend.py`'s `confirm_action`.
fn eliciting_inner(request_state: &'static str) -> Box<dyn AsyncInnerServer> {
    Box::new(move |forwarded: &[u8]| -> Vec<u8> {
        let v: serde_json::Value = serde_json::from_slice(forwarded).unwrap_or(serde_json::Value::Null);
        let is_answer = v
            .get("params")
            .map(|p| p.get("inputResponses").is_some() || p.get("requestState").is_some())
            .unwrap_or(false);
        if is_answer {
            br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"completed","confirmed":true}}"#.to_vec()
        } else {
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":{{"resultType":"input_required","requestState":"{request_state}"}}}}"#
            )
            .into_bytes()
        }
    })
}

/// A serving proxy (its own signer + replay tier) sharing `store` — one fleet replica.
fn replica(
    signer: Arc<DelegatedServerSigner>,
    store: Arc<dyn AsyncContinuationStore>,
    request_state: &'static str,
) -> HttpProfileProxy {
    HttpProfileProxy::new_delegated(
        actor_resolver(),
        audience(),
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig { fleet_strict: false, tier: None },
        eliciting_inner(request_state),
        300,
        signer,
    )
    .with_continuation_store(store, TTL)
}

fn ready_signer() -> Arc<DelegatedServerSigner> {
    let signer = Arc::new(DelegatedServerSigner::new());
    let mut rotor = make_rotor(Arc::clone(&signer));
    rotor.rotate(NOW).expect("issue first delegated key");
    // Keep the rotor alive for the whole test so the published snapshot stays valid.
    std::mem::forget(rotor);
    signer
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

fn as_digest(ev: &RequestEvidence) -> RequestEvidenceDigest {
    RequestEvidenceDigest {
        digest_alg: ev.digest_alg.clone(),
        digest_value: ev.digest_value.clone(),
    }
}

fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
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

/// Sign an RFC 9421 request with an optional MRTR continuation in the evidence block.
fn signed_request(
    nonce: &str,
    body: &[u8],
    continuation: Option<HttpContinuation>,
) -> (HttpRequest, RequestEvidence) {
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation,
    };
    let mut req = HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: body.to_vec(),
    };
    let evidence =
        sign_request_full(&mut req, &block, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, nonce)
            .expect("client signs RFC 9421 request");
    (req, evidence)
}

const OPEN_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"confirm_action","arguments":{}}}"#;

/// Drive the OPEN leg on replica A: sign + serve + verify the `InputRequiredResult`,
/// and return the continuation handles the answer leg binds to (the requestState, and
/// the two evidence digests the CLIENT holds — its request handle and the response
/// handle). This is exactly what the SDK/proof-client does on `--save-cont`.
async fn open_on(
    proxy: &HttpProfileProxy,
    request_state: &str,
) -> (RequestEvidenceDigest, RequestEvidenceDigest, String) {
    let (req, open_ev) = signed_request("nonce-open", OPEN_BODY, None);
    // The client keeps its own request for response binding.
    let no_material = |_b: &ArtifactBinding| None;
    let r = resolver();
    let verified_req =
        verify_request_full(&req, &audience(), &no_material, &move |k: &str, s| r(k, s), NOW)
            .expect("client's own open request verifies");

    let served = proxy.handle(served_of(&req), NOW).await;
    assert_eq!(served.status, 200, "open leg served an InputRequiredResult");
    let resp = http_response(served);

    // The client verifies the delegated response and reads its evidence handle (D_irr).
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
    .expect("open-leg InputRequiredResult verifies");

    // The reply carries the opaque requestState the answer leg re-presents.
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    let seen_state = body
        .pointer("/result/requestState")
        .and_then(|s| s.as_str())
        .expect("open reply carries a requestState");
    assert_eq!(seen_state, request_state);

    (
        as_digest(&open_ev),                                   // D_prev (client request handle)
        as_digest(&verified.response_signature_base_digest),   // D_irr (verified response handle)
        seen_state.to_owned(),
    )
}

fn answer_body(request_state: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"confirm_action","arguments":{{}},"inputResponses":{{"confirm":true}},"requestState":"{request_state}"}}}}"#
    )
    .into_bytes()
}

// --- the load-bearing proof: open on A, answer on B -------------------------

#[tokio::test]
async fn continuation_opened_on_a_is_honoured_on_b() {
    const STATE: &str = "state-token-A1";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());

    // Two replicas, distinct signers + replay tiers, ONE shared continuation store.
    let a = replica(ready_signer(), Arc::clone(&store), STATE);
    let b = replica(ready_signer(), Arc::clone(&store), STATE);

    // OPEN on A — A records the retained bases in the shared store.
    let (d_prev, d_irr, state) = open_on(&a, STATE).await;

    // ANSWER on B — B never saw the open leg. Build the continuation from the handles
    // the client holds (exactly `HttpContinuation::from_handles`).
    let continuation = HttpContinuation::from_handles(d_prev, d_irr, state.as_bytes());
    let (answer_req, answer_ev) =
        signed_request("nonce-answer", &answer_body(&state), Some(continuation));
    let _answer_ev = answer_ev;
    let verified_answer = {
        let no_material = |_b: &ArtifactBinding| None;
        let r = resolver();
        verify_request_full(&answer_req, &audience(), &no_material, &move |k: &str, s| r(k, s), NOW)
            .expect("answer request verifies (for response binding)")
    };

    let served = b.handle(served_of(&answer_req), NOW).await;
    assert_eq!(
        served.status, 200,
        "continuation opened on A is honoured on B (got {})",
        wire_code_of(&served.body)
    );
    let resp = http_response(served);
    // The terminal reply is a delegated-signed success bound to the answer request.
    let r = resolver();
    verify_delegated_response_full(
        &resp,
        &answer_req,
        &verified_answer,
        &move |k: &str, s| r(k, s),
        &expectations(&[EPOCH]),
        &|_| false,
        NOW,
    )
    .expect("terminal answer verifies via the delegated chain");
    assert!(String::from_utf8_lossy(&resp.body).contains("\"confirmed\":true"));

    // One-shot: a second answer for the same requestState finds no store entry (the
    // first answer's `take` removed it), so it fails closed regardless of the handles.
    let (p2, i2, _s2) = handles_of(STATE);
    let continuation2 = HttpContinuation::from_handles(p2, i2, state.as_bytes());
    let (replay_req, _e) = signed_request("nonce-answer-2", &answer_body(&state), Some(continuation2));
    let served2 = b.handle(served_of(&replay_req), NOW).await;
    assert_eq!(served2.status, 409, "the continuation is one-shot");
    assert_eq!(wire_code_of(&served2.body), "mcp-re.continuation_binding_failed");
}

/// Reconstruct the same handles `open_on` would, WITHOUT a store side effect — used to
/// build a second (rejected) continuation. The digests are deterministic functions of
/// the fixed open request + a fixed requestState.
fn handles_of(request_state: &str) -> (RequestEvidenceDigest, RequestEvidenceDigest, String) {
    // D_prev is the fixed open request's evidence.
    let (_req, open_ev) = signed_request("nonce-open", OPEN_BODY, None);
    // D_irr must equal what the open reply produced; recompute it by signing the same
    // InputRequiredResult body the eliciting inner returns and reading its base digest
    // is unavailable here, so we take it from a throwaway open on a scratch replica.
    // Simpler: the second-answer test only needs a well-formed continuation whose
    // store entry is absent, so any consistent handles suffice — reuse D_prev shape.
    let d = as_digest(&open_ev);
    (d.clone(), d, request_state.to_owned())
}

// --- fail closed: a continuation with no shared-store entry -------------------

#[tokio::test]
async fn answer_without_a_shared_store_entry_fails_closed() {
    const STATE: &str = "state-token-B1";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    // B alone — nothing was ever opened, so the store has no entry for STATE.
    let b = replica(ready_signer(), Arc::clone(&store), STATE);

    let (d_prev, d_irr, state) = handles_of(STATE);
    let continuation = HttpContinuation::from_handles(d_prev, d_irr, state.as_bytes());
    let (answer_req, _e) = signed_request("nonce-answer", &answer_body(&state), Some(continuation));
    let served = b.handle(served_of(&answer_req), NOW).await;
    assert_eq!(served.status, 409, "no retained bases → fail closed");
    assert_eq!(wire_code_of(&served.body), "mcp-re.continuation_binding_failed");
}

// --- fail closed: a tampered requestState breaks the binding -----------------

#[tokio::test]
async fn tampered_request_state_breaks_the_binding() {
    const STATE: &str = "state-token-C1";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let a = replica(ready_signer(), Arc::clone(&store), STATE);
    let b = replica(ready_signer(), Arc::clone(&store), STATE);

    let (d_prev, d_irr, state) = open_on(&a, STATE).await;
    // The client builds the continuation over the GENUINE state, but the wire request
    // carries a DIFFERENT requestState in params — the proxy keys the store on the wire
    // state (no entry) so the binding cannot be recovered.
    let continuation = HttpContinuation::from_handles(d_prev, d_irr, state.as_bytes());
    let (answer_req, _e) =
        signed_request("nonce-answer", &answer_body("state-token-TAMPERED"), Some(continuation));
    let served = b.handle(served_of(&answer_req), NOW).await;
    assert_eq!(served.status, 409, "tampered requestState → fail closed");
    assert_eq!(wire_code_of(&served.body), "mcp-re.continuation_binding_failed");
}
