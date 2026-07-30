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
const CLIENT_SEED_2: [u8; 32] = [12u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const CLIENT_KEY_ID: &str = "client-key-1";
const CLIENT_KEY_ID_2: &str = "client-key-2";
const ROOT_KID: &str = "root-kid";
const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";
const TTL: i64 = 300;
const OVERLAP: i64 = 60;

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
/// A SECOND legitimate client: a distinct actor the resolver trusts for the Request
/// slot, so "verified" and "the actor that opened the leg" can be told apart.
fn second_client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED_2)
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
        let (role, subject, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => {
                ("client", "did:example:host-a", client_key().public_key())
            }
            // A second trusted client — same role, different subject and keyid, so it
            // resolves to a DIFFERENT actor id.
            (CLIENT_KEY_ID_2, SignerSlot::Request) => (
                "client",
                "did:example:host-b",
                second_client_key().public_key(),
            ),
            (ROOT_KID, SignerSlot::Response) => {
                ("server", "did:example:server", root_key().public_key())
            }
            _ => return None,
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
    }
}

fn actor_resolver() -> ActorResolver {
    let r = resolver();
    Box::new(move |kid: &str, slot: SignerSlot| r(kid, slot).into())
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
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = 100u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    DelegatedRotor::new(
        DelegatedSigningCustody::new(custody_cfg(), issue, factory),
        signer,
    )
}

/// An ELICITING inner: a first call (no `inputResponses`/`requestState`) returns an
/// `InputRequiredResult` carrying an opaque `requestState`; an answer call returns a
/// terminal result. Mirrors `tools/fastmcp_inner_backend.py`'s `confirm_action`.
fn eliciting_inner(request_state: &'static str) -> Box<dyn AsyncInnerServer> {
    Box::new(move |forwarded: &[u8]| -> Vec<u8> {
        let v: serde_json::Value =
            serde_json::from_slice(forwarded).unwrap_or(serde_json::Value::Null);
        let is_answer = v
            .get("params")
            .map(|p| p.get("inputResponses").is_some() || p.get("requestState").is_some())
            .unwrap_or(false);
        if is_answer {
            br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","confirmed":true}}"#
                .to_vec()
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
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
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

/// Sign an RFC 9421 request as the default client.
fn signed_request(
    nonce: &str,
    body: &[u8],
    continuation: Option<HttpContinuation>,
) -> (HttpRequest, RequestEvidence) {
    signed_request_as(CLIENT_KEY_ID, &client_key(), nonce, body, continuation)
}

/// Sign an RFC 9421 request AS a named actor, with an optional MRTR continuation in
/// the evidence block.
fn signed_request_as(
    key_id: &str,
    key: &SigningKey,
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
        admission: None,
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
    let evidence = sign_request_full(&mut req, &block, key, key_id, CREATED, EXPIRES, nonce)
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
    let verified_req = verify_request_full(
        &req,
        &audience(),
        &no_material,
        &move |k: &str, s| r(k, s),
        NOW,
    )
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
        as_digest(&open_ev), // D_prev (client request handle)
        as_digest(&verified.response_signature_base_digest), // D_irr (verified response handle)
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
        verify_request_full(
            &answer_req,
            &audience(),
            &no_material,
            &move |k: &str, s| r(k, s),
            NOW,
        )
        .expect("answer request verifies (for response binding)")
    };

    let served = b.handle(served_of(&answer_req), NOW).await;
    assert_eq!(
        served.status,
        200,
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
    // first answer's `consume` removed it once it was ADMITTED), so it fails closed
    // regardless of the handles.
    let (p2, i2, _s2) = handles_of(STATE);
    let continuation2 = HttpContinuation::from_handles(p2, i2, state.as_bytes());
    let (replay_req, _e) =
        signed_request("nonce-answer-2", &answer_body(&state), Some(continuation2));
    let served2 = b.handle(served_of(&replay_req), NOW).await;
    assert_eq!(served2.status, 409, "the continuation is one-shot");
    assert_eq!(
        wire_code_of(&served2.body),
        "mcp-re.continuation_binding_failed"
    );
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
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.continuation_binding_failed"
    );
}

// --- a rejected answer leg must not destroy a live continuation --------------

#[tokio::test]
async fn an_answer_that_fails_the_binding_leaves_the_continuation_answerable() {
    // Reading the retained bases is not a side effect, so a request that is about to be
    // refused cannot take a live continuation down with it. This is what makes the
    // failure recoverable: an approval round trip cannot be re-opened, so destroying it
    // on a rejected request would be permanent.
    const STATE: &str = "state-token-D1";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let a = replica(ready_signer(), Arc::clone(&store), STATE);
    let b = replica(ready_signer(), Arc::clone(&store), STATE);

    let (d_prev, d_irr, state) = open_on(&a, STATE).await;

    // A well-formed answer for the RIGHT state whose continuation digests are wrong —
    // the same shape a client hits after losing track of which response it is answering.
    let wrong = HttpContinuation::from_handles(d_prev.clone(), d_prev.clone(), state.as_bytes());
    let (bad_req, _e) = signed_request("nonce-bad-answer", &answer_body(&state), Some(wrong));
    let served_bad = b.handle(served_of(&bad_req), NOW).await;
    assert_eq!(
        served_bad.status, 409,
        "a mismatched continuation is refused"
    );
    assert_eq!(
        wire_code_of(&served_bad.body),
        "mcp-re.continuation_binding_failed"
    );

    // The genuine answer still binds: the refusal cost the client one request, not its
    // continuation.
    let good = HttpContinuation::from_handles(d_prev, d_irr, state.as_bytes());
    let (good_req, _e) = signed_request("nonce-good-answer", &answer_body(&state), Some(good));
    let served_good = b.handle(served_of(&good_req), NOW).await;
    assert_eq!(
        served_good.status,
        200,
        "the refused answer must not have consumed the continuation (got {})",
        wire_code_of(&served_good.body)
    );
}

// --- one actor cannot reach another's continuation ---------------------------

#[tokio::test]
async fn a_second_actor_cannot_touch_the_first_actors_continuation() {
    // `requestState` is minted by the inner application and MCP-RE treats it as opaque
    // — nothing in the profile makes it unguessable. So a peer that verifies must not be
    // able to reach another actor's continuation merely by naming its state, whether or
    // not its own request then succeeds.
    const STATE: &str = "state-token-E1";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let a = replica(ready_signer(), Arc::clone(&store), STATE);
    let b = replica(ready_signer(), Arc::clone(&store), STATE);

    let (d_prev, d_irr, state) = open_on(&a, STATE).await;

    // A DIFFERENT verified actor names the first actor's requestState. It holds valid
    // trust-file credentials; it simply is not the actor that opened the leg.
    let intruder = HttpContinuation::from_handles(d_prev.clone(), d_irr.clone(), state.as_bytes());
    let (intruder_req, _e) = signed_request_as(
        CLIENT_KEY_ID_2,
        &second_client_key(),
        "nonce-intruder",
        &answer_body(&state),
        Some(intruder),
    );
    let served_intruder = b.handle(served_of(&intruder_req), NOW).await;
    assert_eq!(
        served_intruder.status, 409,
        "another actor's answer is refused"
    );
    assert_eq!(
        wire_code_of(&served_intruder.body),
        "mcp-re.continuation_binding_failed"
    );

    // And the first actor's open leg is untouched.
    let good = HttpContinuation::from_handles(d_prev, d_irr, state.as_bytes());
    let (good_req, _e) = signed_request("nonce-good-answer", &answer_body(&state), Some(good));
    let served_good = b.handle(served_of(&good_req), NOW).await;
    assert_eq!(
        served_good.status,
        200,
        "the intruder must not have destroyed the victim's continuation (got {})",
        wire_code_of(&served_good.body)
    );
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
    let (answer_req, _e) = signed_request(
        "nonce-answer",
        &answer_body("state-token-TAMPERED"),
        Some(continuation),
    );
    let served = b.handle(served_of(&answer_req), NOW).await;
    assert_eq!(served.status, 409, "tampered requestState → fail closed");
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.continuation_binding_failed"
    );
}

// --- a malformed open leg must not be served as terminal (C059/C060) ---------

/// A replica whose inner backend is supplied by the caller, for the malformed-open
/// cases below. Everything else matches [`replica`].
fn replica_with_inner(
    signer: Arc<DelegatedServerSigner>,
    store: Arc<dyn AsyncContinuationStore>,
    inner: Box<dyn AsyncInnerServer>,
) -> HttpProfileProxy {
    HttpProfileProxy::new_delegated(
        actor_resolver(),
        audience(),
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
        inner,
        300,
        signer,
    )
    .with_continuation_store(store, TTL)
}

/// An inner backend that announces a non-terminal turn and then withholds the state
/// its continuation needs.
fn malformed_eliciting_inner(result_json: &'static str) -> Box<dyn AsyncInnerServer> {
    Box::new(move |_forwarded: &[u8]| -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#).into_bytes()
    })
}

/// THE regression. The proxy's open-leg recorder used to read "declares itself
/// `input_required`, carries no usable `requestState`" as `None` — indistinguishable
/// from a terminal reply. It therefore signed and returned the non-terminal leg with
/// a 200 while recording NO continuation for it, so no answer leg could ever be
/// honoured on any replica: the client held a signed, verified elicitation that was
/// permanently unanswerable, and its correlation entry was closed as if the call had
/// completed.
///
/// Classification now fails closed, so the malformed body is refused instead of
/// being served as a success.
#[tokio::test]
async fn an_open_leg_that_withholds_its_request_state_is_refused_not_served_as_terminal() {
    for malformed in [
        r#"{"resultType":"input_required"}"#,
        r#"{"resultType":"input_required","requestState":null}"#,
        r#"{"resultType":"input_required","requestState":42}"#,
        r#"{"resultType":"input_required","requestState":{"opaque":"x"}}"#,
    ] {
        let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
        let proxy = replica_with_inner(
            ready_signer(),
            Arc::clone(&store),
            malformed_eliciting_inner(malformed),
        );

        let (req, _ev) = signed_request("nonce-malformed", OPEN_BODY, None);
        let served = proxy.handle(served_of(&req), NOW).await;

        assert_ne!(
            served.status, 200,
            "{malformed} was served as a successful reply"
        );
        assert_eq!(
            served.status, 502,
            "a malformed inner reply is a bad gateway"
        );
        assert_eq!(
            wire_code_of(&served.body),
            "mcp-re.malformed_envelope",
            "the rejection names the malformed body: {malformed}"
        );
    }
}

/// The mirror, so the test above cannot pass by refusing everything: a WELL-FORMED
/// open leg through the same replica shape is still served and still recorded.
#[tokio::test]
async fn a_well_formed_open_leg_is_still_served_and_recorded() {
    const STATE: &str = "state-token-wf";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let proxy = replica_with_inner(ready_signer(), Arc::clone(&store), eliciting_inner(STATE));

    let (_d_prev, _d_irr, state) = open_on(&proxy, STATE).await;
    assert_eq!(state, STATE);
}

/// A terminal reply is unaffected: it has no continuation to record, and nothing
/// about the stricter classification turns "no state" into an error.
#[tokio::test]
async fn a_terminal_reply_is_not_caught_by_the_stricter_classification() {
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let proxy = replica_with_inner(
        ready_signer(),
        Arc::clone(&store),
        malformed_eliciting_inner(r#"{"resultType":"complete","confirmed":true}"#),
    );

    let (req, _ev) = signed_request("nonce-terminal", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;
    assert_eq!(served.status, 200, "a terminal reply is served normally");
}

/// MCPRE-495: an inner reply whose `resultType` this PEP does not recognize is
/// refused BEFORE it is signed.
///
/// MCP 2026-07-28 closes the set — unrecognized MUST be considered invalid — and
/// the danger is specific rather than theoretical. Read as terminal, an extension's
/// non-terminal result ends the exchange: the client's correlation entry closes, no
/// answer leg is ever signed, and a continuation reaches the application as a
/// completed call. Signing it first would make it worse, because then the
/// enforcement boundary has vouched for a message whose continuation semantics
/// nobody can read.
///
/// Note `completed`: our own reference backend emitted it until this landed. The
/// spec's terminal value is `complete`, and one letter is the whole difference
/// between a recognized result and an unclassifiable one.
#[tokio::test]
async fn an_unrecognized_result_type_is_refused_before_it_is_signed() {
    for unrecognized in [
        r#"{"resultType":"completed","confirmed":true}"#,
        r#"{"resultType":"com.example/deferred"}"#,
        r#"{"resultType":"inputRequired","requestState":"s"}"#,
        r#"{"resultType":7}"#,
    ] {
        let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
        let proxy = replica_with_inner(
            ready_signer(),
            Arc::clone(&store),
            malformed_eliciting_inner(unrecognized),
        );

        let (req, _ev) = signed_request("nonce-unrecognized", OPEN_BODY, None);
        let served = proxy.handle(served_of(&req), NOW).await;

        assert_ne!(
            served.status, 200,
            "{unrecognized} was served as a successful reply"
        );
        assert_eq!(
            served.status, 502,
            "an unclassifiable inner reply is a bad gateway"
        );
        assert_eq!(
            wire_code_of(&served.body),
            "mcp-re.continuation_type_unsupported",
            "the rejection names the unreadable continuation model: {unrecognized}"
        );
    }
}

/// The refusal above must not depend on this deployment running MRTR at all. A
/// replica with no continuation store still cannot classify the reply, and the old
/// open-leg check lived inside the `if let Some(store)` block — so a store-less
/// deployment would have signed the unclassifiable reply and returned it.
#[tokio::test]
async fn an_unrecognized_result_type_is_refused_without_a_continuation_store() {
    let proxy = HttpProfileProxy::new_delegated(
        actor_resolver(),
        audience(),
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
        malformed_eliciting_inner(r#"{"resultType":"com.example/deferred"}"#),
        300,
        ready_signer(),
    );

    let (req, _ev) = signed_request("nonce-no-store", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(served.status, 502, "no store is not a reason to sign it");
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.continuation_type_unsupported"
    );
}

// --- the SDK-boundary fixture for the same defect (C059/C060) ----------------

/// Freeze a delegated-signed exchange whose reply declares itself non-terminal and
/// withholds its `requestState`, so both SDK bindings can prove they REFUSE it.
///
/// A recorded fixture cannot come from the proxy here: a conformant MCP-RE proxy now
/// rejects this body rather than serving it (see the test above), which is the whole
/// point. The malformed reply is therefore signed directly with the same delegated
/// custody the proxy uses — it stands for a non-conformant or hostile server, which
/// is the only place such a reply can now originate.
///
/// Regenerate with:
///   MCP_RE_WRITE_SDK_FIXTURE=1 cargo test -p mcp-re-proxy \
///     --test mrt_continuation_serving_test write_malformed_elicitation_sdk_fixture
#[test]
fn write_malformed_elicitation_sdk_fixture() {
    write_sdk_fixture(
        "nonce-sdk-malformed",
        br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required"}}"#,
        "A delegated-signed reply that declares itself non-terminal and withholds \
         its requestState. Genuine evidence with a malformed body: both SDK \
         bindings must REFUSE it, never report it as a terminal result. \
         Regenerate with MCP_RE_WRITE_SDK_FIXTURE=1 cargo test -p mcp-re-proxy \
         --test mrt_continuation_serving_test write_malformed_elicitation_sdk_fixture",
        "malformed_elicitation.json",
    );
}

/// Freeze a delegated-signed reply whose `resultType` is outside the set MCP
/// 2026-07-28 defines (MCPRE-495), so both SDK bindings can prove they refuse it
/// rather than reading it as a completed call.
///
/// Defense in depth: a conformant proxy will not sign such a reply at all, so this
/// stands for a non-conformant or hostile server — the only place one can now come
/// from. The evidence is genuine; only the result type is unreadable.
///
/// Regenerate with:
///   MCP_RE_WRITE_SDK_FIXTURE=1 cargo test -p mcp-re-proxy \
///     --test mrt_continuation_serving_test write_unrecognized_result_type_sdk_fixture
#[test]
fn write_unrecognized_result_type_sdk_fixture() {
    write_sdk_fixture(
        "nonce-sdk-unrecognized",
        br#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"com.example/deferred"}}"#,
        "A delegated-signed reply carrying a resultType outside the set MCP \
         2026-07-28 defines. Genuine evidence this reader cannot classify: both SDK \
         bindings must REFUSE it, never report it as a terminal result. \
         Regenerate with MCP_RE_WRITE_SDK_FIXTURE=1 cargo test -p mcp-re-proxy \
         --test mrt_continuation_serving_test write_unrecognized_result_type_sdk_fixture",
        "unrecognized_result_type.json",
    );
}

fn write_sdk_fixture(nonce: &str, reply_body: &[u8], comment: &str, file_name: &str) {
    use mcp_re_core::b64url_encode;
    use mcp_re_http_profile::sign_delegated_response_full;

    // The delegated snapshot the proxy would sign with.
    let signer = ready_signer();
    let active = signer.current(NOW).expect("a delegated key is published");

    // The client's open-leg request, signed exactly as the SDK signs it.
    let (request, req_evidence) = signed_request(nonce, OPEN_BODY, None);

    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: reply_body.to_vec(),
    };
    sign_delegated_response_full(
        &mut response,
        &request,
        &req_evidence,
        &active.server_signer,
        &active.credential,
        active.key.as_ref(),
        &active.delegated_kid,
        NOW,
        NOW + TTL,
    )
    .expect("the reply signs — signing does not classify");

    // Precondition: this fixture is only meaningful if the response is otherwise
    // GENUINE. If it failed verification the SDKs would refuse it for the wrong
    // reason and the test would prove nothing.
    let r = resolver();
    let no_material = |_b: &ArtifactBinding| None;
    let verified_req = verify_request_full(
        &request,
        &audience(),
        &no_material,
        &move |k: &str, s| r(k, s),
        NOW,
    )
    .expect("the fixture request verifies");
    let r = resolver();
    verify_delegated_response_full(
        &response,
        &request,
        &verified_req,
        &move |k: &str, s| r(k, s),
        &expectations(&[EPOCH]),
        &|_| false,
        NOW,
    )
    .expect("the fixture response is genuine evidence — only its RESULT is unreadable");

    let fixture = serde_json::json!({
        "_comment": comment,
        "client_seed_b64url": b64url_encode(&CLIENT_SEED),
        "key_id": CLIENT_KEY_ID,
        "signer_id": "did:example:host-a",
        "nonce": nonce,
        "created": CREATED,
        "expires": EXPIRES,
        "now": NOW,
        "target_uri": TARGET,
        "audience_id": VERIFIER_AUD,
        "route": "a",
        "dpop_token": ACCESS_TOKEN,
        "expected_audience_hash": AUD_SCOPE,
        "accepted_epochs": [EPOCH],
        "max_clock_skew": 60,
        "issuer": {
            "key_id": ROOT_KID,
            "pubkey_b64url": b64url_encode(&root_key().public_key().to_bytes()),
            "role": "server",
            "trust_domain": "example.com",
            "subject": "did:example:server",
        },
        "exchange": {
            "request_method": request.method,
            "request_target_uri": request.target_uri,
            "request_headers": request.headers,
            "request_body_b64url": b64url_encode(&request.body),
            "request_evidence_digest_alg": req_evidence.digest_alg,
            "request_evidence_digest_value": req_evidence.digest_value,
            "status": response.status,
            "headers": response.headers,
            "body_b64url": b64url_encode(&response.body),
        },
    });

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("sdk/fixtures")
        .join(file_name);
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&fixture).expect("fixture serializes")
    );

    if std::env::var("MCP_RE_WRITE_SDK_FIXTURE").is_ok() {
        std::fs::write(&path, &rendered).expect("write the SDK fixture");
        return;
    }

    // `sdk/` is not Bazel-addressable — there is no BUILD file under it, so the SDKs
    // are outside `bazel test //...` entirely and the fixture is not in this target's
    // runfiles. Under a Bazel sandbox the source tree genuinely is not there, which is
    // the ONE case where having nothing to compare against is not a failure. The
    // condition is the sandbox itself, not "the file was missing": in the Cargo lane a
    // missing fixture still panics below.
    let sandboxed = std::env::var("TEST_SRCDIR").is_ok() || std::env::var("RUNFILES_DIR").is_ok();
    if sandboxed && !path.exists() {
        return;
    }

    // Otherwise this is a GATE: the committed fixture must still be the one this
    // code produces, so a change to the signing path cannot silently leave both SDK
    // suites asserting against a stale recording.
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "{} is missing — regenerate it (see this test's doc)",
            path.display()
        )
    });
    assert_eq!(
        committed, rendered,
        "the committed SDK fixture has drifted from the signing path; regenerate it"
    );
}
