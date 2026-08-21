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
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_inner::InnerOutcome;
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

/// The JSON-RPC `id` of the forwarded request, rendered for splicing into a canned reply.
///
/// A conformant backend echoes the request's id, and since ADR-MCPRE-058 §10 (ruling D5)
/// the PEP enforces that: an answer leg carries `id: 2`, so a fixture hard-coding `id: 1`
/// is a backend answering a call nobody made. These fixtures used to do exactly that and
/// nothing noticed, which is the correlation gap the rule closes.
fn echoed_id(forwarded: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(forwarded)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null)
        .to_string()
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
        let id = echoed_id(forwarded);
        if is_answer {
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"complete","confirmed":true}}}}"#
            )
            .into_bytes()
        } else {
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"input_required","requestState":"{request_state}"}}}}"#
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
        AsyncReplayTier::new(
            Arc::new(InMemoryAsyncAtomicReplayStore::new()),
            mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
        ),
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

/// The `execution_status` a signed rejection states about the exchange (ADR-MCPRE-058 §10).
///
/// Read from the BODY rather than inferred from the status code, deliberately: the whole
/// point of ruling D1 is that a status code cannot answer whether the action ran, and a test
/// asserting only on status would pass against the behaviour the ruling replaced.
fn retry_safety_of(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/data/mcp_re_error/retry_safety")
                .and_then(|w| w.as_str())
                .map(str::to_owned)
        })
}

fn execution_status_of(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/data/mcp_re_error/execution_status")
                .and_then(|w| w.as_str())
                .map(str::to_owned)
        })
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
        admission_assertion: None,
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
    let verified_req = Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_request(&req, &audience(), &no_material, NOW)
        .expect("client's own open request verifies");

    let served = proxy.handle(served_of(&req), NOW).await;
    assert_eq!(served.status, 200, "open leg served an InputRequiredResult");
    let resp = http_response(served);

    // The client verifies the delegated response and reads its evidence handle (D_irr).
    let r = resolver();
    let verified = Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_delegated_bound_response(
            &resp,
            &req,
            verified_req.evidence(),
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
        as_digest(&verified.signature_facts.response_signature_base_digest), // D_irr (verified response handle)
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
        Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
            .verify_request(&answer_req, &audience(), &no_material, NOW)
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
    Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_delegated_bound_response(
            &resp,
            &answer_req,
            verified_answer.evidence(),
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
        AsyncReplayTier::new(
            Arc::new(InMemoryAsyncAtomicReplayStore::new()),
            mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
        ),
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
    Box::new(move |forwarded: &[u8]| -> Vec<u8> {
        let id = echoed_id(forwarded);
        format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result_json}}}"#).into_bytes()
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
            "mcp-re.upstream_response_invalid",
            "the rejection names the malformed body: {malformed}"
        );
        // ADR-MCPRE-058 §10 (ruling D1): the backend has already run by the time the reply
        // is classified, so the refusal says so. A 502 alone is not evidence about whether
        // the action executed, and this exit used to offer nothing else.
        assert_eq!(
            execution_status_of(&served.body),
            Some("possibly_executed".to_owned()),
            "a post-dispatch refusal states its consequence: {malformed}"
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
        AsyncReplayTier::new(
            Arc::new(InMemoryAsyncAtomicReplayStore::new()),
            mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
        ),
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

// --- ADR-MCPRE-058 §10: the response-region controls (rulings D1/D2/D3/D5) ----

/// A proxy with NO continuation store, and an inner backend under the test's control.
fn replica_without_store(inner: Box<dyn AsyncInnerServer>) -> HttpProfileProxy {
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
        inner,
        300,
        ready_signer(),
    )
}

/// A continuation store whose WRITES always fail. Peek and consume behave normally, so
/// an exchange reaches the open-leg record and fails only there — which is the window
/// this control is about.
struct WriteFailingStore(InMemoryContinuationStore);

impl AsyncContinuationStore for WriteFailingStore {
    fn store<'a>(
        &'a self,
        _key: &'a str,
        _bases: &'a mcp_re_proxy::continuation_store::RetainedBases,
        _ttl_secs: i64,
    ) -> mcp_re_proxy::continuation_store::ContinuationFuture<'a, ()> {
        Box::pin(async {
            Err(
                mcp_re_proxy::continuation_store::ContinuationStoreError::Unavailable {
                    details: "the shared tier is down".to_string(),
                },
            )
        })
    }
    fn peek<'a>(
        &'a self,
        key: &'a str,
    ) -> mcp_re_proxy::continuation_store::ContinuationFuture<
        'a,
        Option<mcp_re_proxy::continuation_store::RetainedBases>,
    > {
        self.0.peek(key)
    }
    fn consume<'a>(
        &'a self,
        key: &'a str,
    ) -> mcp_re_proxy::continuation_store::ContinuationFuture<'a, bool> {
        self.0.consume(key)
    }
}

/// **D3.** An `input_required` reply on a deployment that cannot record the continuation
/// is refused, not served as a successful open leg.
///
/// The broken implementation this must catch is the one that was in the tree: the open-leg
/// recorder returned `Ok(false)` the moment it found no store, so the elicitation was
/// signed and returned with a 200. The client held a signed, verified instruction to
/// continue an exchange for which nothing had been kept, and found out one leg later, as
/// `continuation_binding_failed` — a code that on the wire reads like an attack signal.
///
/// The mutation is faithful only because the reply here is WELL-FORMED: it carries a
/// perfectly usable `requestState`, so nothing upstream of the recorder has any reason to
/// refuse it. `a_well_formed_open_leg_is_still_served_and_recorded` is the other half —
/// the same body through a proxy that HAS a store is served.
#[tokio::test]
async fn an_open_leg_is_refused_when_the_deployment_cannot_make_it_answerable() {
    let proxy = replica_without_store(eliciting_inner("state-token-unstorable"));

    let (req, _ev) = signed_request("nonce-d3", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_ne!(
        served.status, 200,
        "an unanswerable elicitation was served as a success"
    );
    assert_eq!(served.status, 503);
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.replay_cache_unavailable"
    );
    // D1. The backend has already run — the elicitation IS the backend's answer.
    assert_eq!(
        execution_status_of(&served.body),
        Some("possibly_executed".to_owned())
    );
}

/// **D1, at the exit that made it urgent.** A continuation-record failure lands after the
/// backend has run, and the status it returns is 503 — the status clients retry.
///
/// The broken implementation this must catch is the one that was in the tree: the same
/// 503, with nothing in the body. A client applying ordinary 503 semantics retries, the
/// retry carries a fresh nonce, replay admission passes it, and the action runs twice.
///
/// Asserted on the BODY. A status-only assertion passes against the old behaviour, which
/// is exactly why the old behaviour survived.
#[tokio::test]
async fn a_continuation_record_failure_after_dispatch_never_reads_as_retry_safe() {
    let store: Arc<dyn AsyncContinuationStore> =
        Arc::new(WriteFailingStore(InMemoryContinuationStore::new()));
    let proxy = replica_with_inner(ready_signer(), store, eliciting_inner("state-token-d1"));

    let (req, _ev) = signed_request("nonce-d1", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(served.status, 503);
    assert_eq!(
        execution_status_of(&served.body),
        Some("possibly_executed".to_owned()),
        "a 503 after the tool ran must not read as an ordinary outage"
    );
    assert_eq!(
        retry_safety_of(&served.body),
        Some("unsafe_without_reconciliation".to_owned())
    );
}

/// Non-vacuity control for the two above: a PRE-dispatch refusal on the same proxy still
/// reports that nothing executed.
///
/// Without this, both tests would pass against an implementation that stamped
/// `possibly_executed` on every rejection it ever emitted — which would be a different
/// lie, and a worse one, because it would make the field useless.
#[tokio::test]
async fn a_pre_dispatch_refusal_still_reports_that_nothing_executed() {
    let proxy = replica_without_store(eliciting_inner("state-token-nv"));

    let (req, _ev) = signed_request("nonce-nv", OPEN_BODY, None);
    // Serve it once so the nonce is spent, then replay it: replay admission refuses BEFORE
    // the dispatch.
    let _ = proxy.handle(served_of(&req), NOW).await;
    let replayed = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(replayed.status, 409);
    assert_eq!(wire_code_of(&replayed.body), "mcp-re.replay_detected");
    assert_ne!(
        execution_status_of(&replayed.body),
        Some("possibly_executed".to_owned()),
        "a replay refused before the dispatch did not execute anything"
    );
}

/// **D2 + D5.** An unparseable backend body is refused, on a deployment with NO
/// continuation store.
///
/// The store posture is the entire point of the test. Until ruling D2, the only
/// unconditional inspection of a reply was a `resultType` classifier that returned
/// `None` for a body that was not JSON — "not this check's business" — and every real
/// envelope check lived inside the open-leg recorder, which returns early with no store
/// wired. So MCP-RE signed unparseable bytes, retained them, recorded
/// `mcp-re.response.signed`, and the client's own verifier then rejected a message the
/// enforcement boundary had vouched for.
///
/// Running this WITHOUT a store is what makes the mutation faithful: with one wired, the
/// recorder catches the body and the test would pass while proving nothing about the
/// validator.
#[tokio::test]
async fn an_unparseable_backend_body_is_refused_even_with_no_continuation_store() {
    for garbage in [
        &b"not json at all"[..],
        &b""[..],
        &b"{\"jsonrpc\":\"2.0\","[..],
        &b"<html>502 Bad Gateway</html>"[..],
    ] {
        let proxy = replica_without_store(Box::new(move |_: &[u8]| garbage.to_vec()));
        let (req, _ev) = signed_request("nonce-garbage", OPEN_BODY, None);
        let served = proxy.handle(served_of(&req), NOW).await;

        assert_ne!(served.status, 200, "{garbage:?} was signed as a response");
        assert_eq!(served.status, 502);
        assert_eq!(
            wire_code_of(&served.body),
            "mcp-re.upstream_response_invalid",
            "{garbage:?}"
        );
        assert_eq!(
            execution_status_of(&served.body),
            Some("possibly_executed".to_owned()),
            "{garbage:?}"
        );
    }
}

/// **D5.** The JSON-RPC envelope rules, enforced end to end on the serving path.
///
/// Each body below is well-formed JSON and would have been signed and served before this
/// ruling. None of them is a legal response to the outstanding request, and MCP-RE is the
/// component with the authority to say so — the client can only refuse afterwards, having
/// already been told the boundary vouched for it.
#[tokio::test]
async fn an_illegal_json_rpc_envelope_is_refused_before_it_is_signed() {
    // The outstanding request is `OPEN_BODY`, whose id is 1.
    for (label, body) in [
        (
            "wrong id",
            r#"{"jsonrpc":"2.0","id":99,"result":{"ok":true}}"#,
        ),
        (
            "id type differs",
            r#"{"jsonrpc":"2.0","id":"1","result":{"ok":true}}"#,
        ),
        ("id absent", r#"{"jsonrpc":"2.0","result":{"ok":true}}"#),
        (
            "both members",
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true},"error":{"code":-1,"message":"x"}}"#,
        ),
        ("neither member", r#"{"jsonrpc":"2.0","id":1}"#),
        ("jsonrpc absent", r#"{"id":1,"result":{"ok":true}}"#),
        (
            "jsonrpc wrong",
            r#"{"jsonrpc":"1.0","id":1,"result":{"ok":true}}"#,
        ),
        (
            "error member malformed",
            r#"{"jsonrpc":"2.0","id":1,"error":{"message":"no code"}}"#,
        ),
    ] {
        let bytes = body.as_bytes().to_vec();
        let proxy = replica_without_store(Box::new(move |_: &[u8]| bytes.clone()));
        let (req, _ev) = signed_request("nonce-envelope", OPEN_BODY, None);
        let served = proxy.handle(served_of(&req), NOW).await;

        assert_eq!(served.status, 502, "{label} was accepted");
        assert_eq!(
            wire_code_of(&served.body),
            "mcp-re.upstream_response_invalid",
            "{label}"
        );
    }
}

/// The mirror, so the test above cannot pass by refusing everything: a LEGAL envelope
/// through the same store-less proxy is still served, and a JSON-RPC error is one of them.
///
/// The second case is the one worth stating. A JSON-RPC error is a valid terminal protocol
/// response — not a malformed message and not a transport failure — and collapsing it into
/// either would end the exchange on the wrong fact.
#[tokio::test]
async fn a_legal_envelope_is_still_served_and_a_json_rpc_error_is_one() {
    for (label, body) in [
        (
            "ordinary result",
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","ok":true}}"#,
        ),
        (
            "json-rpc error",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"the tool refused"}}"#,
        ),
        (
            "result with no resultType (pre-2026-07-28 server)",
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
        ),
    ] {
        let bytes = body.as_bytes().to_vec();
        let proxy = replica_without_store(Box::new(move |_: &[u8]| bytes.clone()));
        let (req, _ev) = signed_request("nonce-legal", OPEN_BODY, None);
        let served = proxy.handle(served_of(&req), NOW).await;

        assert_eq!(served.status, 200, "{label} was refused");
    }
}

/// An inner plane that ADMITS and then reports that nothing was dispatched.
///
/// This is the `admit`/`dispatch` race made deterministic: in production it happens when the
/// last in-flight permit is taken by another core between the two calls. The race itself is
/// not constructible in a test worth trusting — it needs two cores contending at a
/// controlled instant, and a test that merely simulated the timing would be asserting on its
/// own scaffolding. What IS worth pinning, and what this fixture pins, is the HANDLING: a
/// `NotDispatched` seen after the threshold must not walk the exchange's consequence back.
struct RacingInner;

impl AsyncInnerServer for RacingInner {
    fn admit(&self) -> Result<(), mcp_re_proxy::async_inner::NotAdmitted> {
        Ok(())
    }
    fn dispatch<'a>(
        &'a self,
        _request: &'a [u8],
    ) -> mcp_re_proxy::async_inner::InnerResponseFuture<'a> {
        Box::pin(async {
            mcp_re_proxy::async_inner::InnerOutcome::NotDispatched("lost the permit race")
        })
    }
}

/// **§8.5 gap (a).** A `NotDispatched` that arrives AFTER the threshold is reported at the
/// consequence the exchange has already crossed, not at the one the outcome would justify
/// on its own.
///
/// The tempting broken implementation is the one that looks MORE precise: `NotDispatched`
/// means nothing was transmitted, so answer `NothingExecuted` and let the client retry
/// safely. That is right about the outcome and wrong about the exchange. The floor was set
/// at the dispatch, and monotone consequence is not negotiable against a more precise late
/// observation — if it were, every post-dispatch refinement would be a chance to walk the
/// claim back.
#[tokio::test]
async fn a_late_not_dispatched_does_not_walk_the_consequence_back() {
    let proxy = replica_without_store(Box::new(RacingInner));

    let (req, _ev) = signed_request("nonce-race", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(served.status, 503);
    assert_eq!(wire_code_of(&served.body), "mcp-re.inner_plane_unavailable");
    assert_eq!(
        execution_status_of(&served.body),
        Some("possibly_executed".to_owned()),
        "the floor was set at the dispatch; a late outcome cannot lower it"
    );
}

/// The other side of gap (a), and the reason the test above is not simply pessimism: the
/// SAME outcome, refused BEFORE the threshold, is genuinely retry-safe.
///
/// Without this pair, `a_late_not_dispatched...` would be satisfied by an implementation
/// that stamped `possibly_executed` on every inner-plane failure — which would make the
/// whole D4 hoist pointless, since the hoist exists precisely to keep this case honest.
struct SaturatedInner;

impl AsyncInnerServer for SaturatedInner {
    fn admit(&self) -> Result<(), mcp_re_proxy::async_inner::NotAdmitted> {
        Err(mcp_re_proxy::async_inner::NotAdmitted(
            "inner plane is at its in-flight bound",
        ))
    }
    fn dispatch<'a>(
        &'a self,
        _request: &'a [u8],
    ) -> mcp_re_proxy::async_inner::InnerResponseFuture<'a> {
        panic!("a plane that refused at admit must never be dispatched to")
    }
}

#[tokio::test]
async fn a_saturated_plane_refused_before_the_threshold_is_retry_safe() {
    let proxy = replica_without_store(Box::new(SaturatedInner));

    let (req, _ev) = signed_request("nonce-saturated", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(served.status, 503);
    assert_eq!(wire_code_of(&served.body), "mcp-re.inner_plane_unavailable");
    assert_ne!(
        execution_status_of(&served.body),
        Some("possibly_executed".to_owned()),
        "nothing was transmitted and the threshold was never crossed"
    );
    // The `panic!` in `SaturatedInner::dispatch` is the real assertion: refusing at admit
    // must mean the dispatch never happens, not that it happens and is discarded.
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
    let verified_req = Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_request(&request, &audience(), &no_material, NOW)
        .expect("the fixture request verifies");
    let r = resolver();
    Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_delegated_bound_response(
            &response,
            &request,
            verified_req.evidence(),
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

// --- the cross-machine seam: an approval spent on a request that never ran ---

/// A retention store that accepts being opened and then cannot write.
///
/// Read-only after `open` has already proved it writable, which is the shape of the real
/// failure this covers: a volume that goes away under a running proxy, not a
/// misconfiguration caught at startup.
struct WedgedRetentionDir(std::path::PathBuf);

impl WedgedRetentionDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mcp-re-mrt-retention-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the retention root");
        WedgedRetentionDir(path)
    }

    fn wedge(&self) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o500))
            .expect("make the retention root unwritable");
    }
}

impl Drop for WedgedRetentionDir {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn replica_with_retention(
    signer: Arc<DelegatedServerSigner>,
    store: Arc<dyn AsyncContinuationStore>,
    request_state: &'static str,
    retention: Arc<mcp_re_proxy::transparency::EvidenceRetention>,
) -> HttpProfileProxy {
    replica(signer, store, request_state).with_evidence_retention(retention)
}

/// ADR-MCPRE-057 §4 — the state that belongs to neither machine alone.
///
/// The answer leg retires its continuation to enforce one-shot, and only THEN reserves
/// retention. A store outage in that window refuses before the backend runs, so the action
/// truly did not happen — but the human approval authorizing it is already gone. A client
/// told only "503" retries, passes replay admission on a fresh nonce, and is refused as
/// already-answered, having burned the approval for nothing.
///
/// Neither machine can state this on its own: the request machine truthfully says the
/// backend did not run, the continuation machine truthfully says the leg was consumed, and
/// the client needs the pair.
#[tokio::test]
async fn an_approval_spent_on_a_request_that_never_ran_is_not_reported_as_retry_safe() {
    const STATE: &str = "state-token-E1";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let a = replica(ready_signer(), Arc::clone(&store), STATE);

    let (d_prev, d_irr, state) = open_on(&a, STATE).await;

    let dir = WedgedRetentionDir::new("spent");
    let retention = Arc::new(
        mcp_re_proxy::transparency::EvidenceRetention::open(&dir.0)
            .expect("retention opens while the root is writable"),
    );
    let b = replica_with_retention(ready_signer(), Arc::clone(&store), STATE, retention);
    // Only now does the volume go away — after the proxy proved it writable at startup.
    dir.wedge();

    let continuation = HttpContinuation::from_handles(d_prev, d_irr, state.as_bytes());
    let (answer_req, _e) = signed_request("nonce-answer", &answer_body(&state), Some(continuation));
    let served = b.handle(served_of(&answer_req), NOW).await;

    assert_eq!(served.status, 503, "refused before the backend could run");
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.evidence_retention_unavailable"
    );

    let body: serde_json::Value = serde_json::from_slice(&served.body).unwrap();
    let err = body
        .pointer("/error/data/mcp_re_error")
        .expect("the rejection carries the mcp-re error object");
    assert_eq!(
        err.get("execution_status").and_then(|v| v.as_str()),
        Some("not_executed")
    );
    assert_eq!(
        err.get("continuation_status").and_then(|v| v.as_str()),
        Some("consumed")
    );
    assert_eq!(
        err.get("retry_safety").and_then(|v| v.as_str()),
        Some("unsafe_without_new_elicitation"),
        "an ordinary retry cannot recover a spent approval"
    );
}

/// Non-vacuity control for the test above. The SAME refusal, at the SAME point, on an
/// exchange that spent no approval carries none of those fields — so the assertions above
/// are pinning the cross-machine state and not just the wire code.
#[tokio::test]
async fn the_same_retention_outage_without_a_spent_approval_stays_an_ordinary_retry() {
    const STATE: &str = "state-token-E2";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());

    let dir = WedgedRetentionDir::new("unspent");
    let retention = Arc::new(
        mcp_re_proxy::transparency::EvidenceRetention::open(&dir.0)
            .expect("retention opens while the root is writable"),
    );
    let b = replica_with_retention(ready_signer(), Arc::clone(&store), STATE, retention);
    dir.wedge();

    // A plain request: no continuation, so nothing is at stake but the call itself.
    let (req, _e) = signed_request("nonce-plain", OPEN_BODY, None);
    let served = b.handle(served_of(&req), NOW).await;

    assert_eq!(served.status, 503);
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.evidence_retention_unavailable"
    );
    let body: serde_json::Value = serde_json::from_slice(&served.body).unwrap();
    let err = body.pointer("/error/data/mcp_re_error").unwrap();
    assert!(err.get("continuation_status").is_none(), "{err}");
    assert!(err.get("retry_safety").is_none(), "{err}");
}

// --- coexistence: a spent approval and a newly opened leg are different facts ---

/// An inner backend that elicits TWICE: the first answer opens a second leg.
///
/// This is what an ordinary multi-step approval looks like — confirm the action, then
/// confirm a parameter of it — and it is the sequence that makes `Consumed -> Recorded`
/// reachable rather than theoretical.
fn twice_eliciting_inner(first: &'static str, second: &'static str) -> Box<dyn AsyncInnerServer> {
    Box::new(move |forwarded: &[u8]| -> Vec<u8> {
        let v: serde_json::Value =
            serde_json::from_slice(forwarded).unwrap_or(serde_json::Value::Null);
        let answered = v
            .get("params")
            .and_then(|p| p.get("requestState"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_owned());
        let id = echoed_id(forwarded);
        match answered.as_deref() {
            // The answer to leg 1 opens leg 2.
            Some(state) if state == first => format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"input_required","requestState":"{second}"}}}}"#
            )
            .into_bytes(),
            // The answer to leg 2 completes the exchange.
            Some(_) => format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"complete","confirmed":true}}}}"#
            )
            .into_bytes(),
            // The original call opens leg 1.
            None => format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"input_required","requestState":"{first}"}}}}"#
            )
            .into_bytes(),
        }
    })
}

/// ADR-MCPRE-057 §4 — the coexistence question, end to end.
///
/// `ContinuationState::Consumed` latches, so that a refusal can never report a spent
/// approval as recoverable by an ordinary retry. The question that latch raises is whether
/// it also discards the fact that a NEW leg now exists.
///
/// It does not, and this proves it operationally rather than by argument: answerability
/// lives in the shared continuation store, and the latch is on a projection whose only
/// production reader is `retry_semantics`. The leg opened BY an answer leg is answered here
/// successfully, on a different replica, after its predecessor was consumed.
#[tokio::test]
async fn a_leg_opened_by_an_answer_leg_is_itself_answerable() {
    const FIRST: &str = "state-token-F1";
    const SECOND: &str = "state-token-F2";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());

    let make = || {
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
            twice_eliciting_inner(FIRST, SECOND),
            300,
            ready_signer(),
        )
        .with_continuation_store(Arc::clone(&store), TTL)
    };
    let a = make();
    let b = make();

    // Round 1 — the original call opens leg 1 on A.
    let (req1, ev1) = signed_request("nonce-r1", OPEN_BODY, None);
    let served1 = a.handle(served_of(&req1), NOW).await;
    assert_eq!(served1.status, 200, "leg 1 opened");
    let resp1 = http_response(served1);
    let r = resolver();
    let verified_req1 = Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_request(&req1, &audience(), &|_b: &ArtifactBinding| None, NOW)
        .expect("the client's own round-1 request verifies");
    let r = resolver();
    let verified1 = Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_delegated_bound_response(
            &resp1,
            &req1,
            verified_req1.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .expect("the round-1 reply verifies");

    // Round 2 — answering leg 1 CONSUMES it, and the reply opens leg 2. Served on B, which
    // never saw round 1.
    let cont1 = HttpContinuation::from_handles(
        as_digest(&ev1),
        as_digest(&verified1.signature_facts.response_signature_base_digest),
        FIRST.as_bytes(),
    );
    let (req2, ev2) = signed_request("nonce-r2", &answer_body(FIRST), Some(cont1));
    let served2 = b.handle(served_of(&req2), NOW).await;
    assert_eq!(
        served2.status, 200,
        "the answer to leg 1 is served and opens leg 2"
    );
    let resp2 = http_response(served2);
    let body2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
    assert_eq!(
        body2
            .pointer("/result/requestState")
            .and_then(|s| s.as_str()),
        Some(SECOND),
        "the answer's own reply carries a NEW requestState"
    );
    let r = resolver();
    let verified_req2 = Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_request(&req2, &audience(), &|_b: &ArtifactBinding| None, NOW)
        .expect("the client's own round-2 request verifies");
    let r = resolver();
    let verified2 = Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_delegated_bound_response(
            &resp2,
            &req2,
            verified_req2.evidence(),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .expect("the round-2 reply verifies");

    // Round 3 — the load-bearing assertion. Leg 2 was recorded by an exchange that had
    // ALREADY consumed leg 1. If the latch had discarded the new leg, this fails closed.
    let cont2 = HttpContinuation::from_handles(
        as_digest(&ev2),
        as_digest(&verified2.signature_facts.response_signature_base_digest),
        SECOND.as_bytes(),
    );
    let (req3, _ev3) = signed_request("nonce-r3", &answer_body(SECOND), Some(cont2));
    let served3 = a.handle(served_of(&req3), NOW).await;
    assert_eq!(
        served3.status, 200,
        "the leg opened BY an answer leg is itself answerable"
    );
    let body3: serde_json::Value = serde_json::from_slice(&served3.body).unwrap();
    assert_eq!(
        body3.pointer("/result/resultType").and_then(|s| s.as_str()),
        Some("complete")
    );

    // Negative control: leg 1 really was consumed, so re-answering it fails closed. Without
    // this, the test above could pass on a store that never consumes anything.
    let cont1_again = HttpContinuation::from_handles(
        as_digest(&ev1),
        as_digest(&verified1.signature_facts.response_signature_base_digest),
        FIRST.as_bytes(),
    );
    let (replay_req, _e) = signed_request("nonce-r2-again", &answer_body(FIRST), Some(cont1_again));
    let served_again = b.handle(served_of(&replay_req), NOW).await;
    assert_eq!(served_again.status, 409, "leg 1 is one-shot and was spent");
    assert_eq!(
        wire_code_of(&served_again.body),
        "mcp-re.continuation_binding_failed"
    );
}

// ===================== STAGE CONTRACT MATRIX (ADR-MCPRE-058 §9.2) =====================
//
// One test per stage obligation that the end-to-end suite would not catch, each written
// against a NAMED broken implementation. The broken version is stated in the doc comment
// before the test exists, so the test is built to detect a specific defect rather than to
// describe whatever the code currently does.
//
// Common obligation, asserted throughout: a refusal carries exactly the retry posture
// implied by the EXCHANGE state at the point of refusal, never one chosen locally by the
// stage. Since the descriptor refactor a stage cannot express a posture at all — it returns
// a `Refusal` and never sees `RequestProgress` — so these tests pin that separation from
// the outside, where a regression would be visible.

/// Assert the machine-derived retry posture on a signed refusal body.
///
/// `None` means the refusal states nothing beyond its wire code, which is the correct
/// posture for an ordinary retry-safe failure.
fn assert_retry_posture(body: &[u8], expected: Option<&str>) {
    let v: serde_json::Value = serde_json::from_slice(body).expect("a JSON-RPC error body");
    let err = v
        .pointer("/error/data/mcp_re_error")
        .expect("the rejection carries the mcp-re error object");
    let got = err.get("retry_safety").and_then(|s| s.as_str());
    assert_eq!(got, expected, "retry posture in {err}");
}

/// **replay_admission_stage** — the nonce is burned STRICTLY LAST.
///
/// Broken implementation this must catch: perform the atomic `check_and_insert` BEFORE the
/// continuation binding check, so a request that goes on to be refused has already consumed
/// its replay slot.
///
/// Why it matters: the client's corrected retry reuses its nonce, and the replay key is
/// `(profile_id, signature_label, actor_id, audience_hash, nonce)` — the body is not in it.
/// A prematurely burned nonce therefore turns a recoverable client error into a permanent
/// one, and reports it as `replay_detected`, which is a claim about the caller's honesty.
#[tokio::test]
async fn a_request_refused_on_the_continuation_binding_has_not_burned_its_nonce() {
    const STATE: &str = "state-token-G1";
    const NONCE: &str = "nonce-shared-G1";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let a = replica(ready_signer(), Arc::clone(&store), STATE);
    let b = replica(ready_signer(), Arc::clone(&store), STATE);

    let (d_prev, _d_irr, state) = open_on(&a, STATE).await;

    // A well-formed answer whose continuation digests are wrong: refused at the binding,
    // which sits BEFORE the atomic admission.
    let wrong = HttpContinuation::from_handles(d_prev.clone(), d_prev.clone(), state.as_bytes());
    let (bad, _e) = signed_request(NONCE, &answer_body(&state), Some(wrong));
    let refused = b.handle(served_of(&bad), NOW).await;
    assert_eq!(refused.status, 409);
    assert_eq!(
        wire_code_of(&refused.body),
        "mcp-re.continuation_binding_failed"
    );
    // Nothing was executed and nothing was spent — the peek is not a consume.
    assert_retry_posture(&refused.body, None);

    // The load-bearing assertion: the SAME nonce is still admissible. A different body, so
    // only the shared replay key can make these two collide.
    let (retry, _e) = signed_request(NONCE, OPEN_BODY, None);
    let served = b.handle(served_of(&retry), NOW).await;
    assert_eq!(
        served.status, 200,
        "the refused request must not have consumed the replay slot"
    );

    // Negative control for the assertion above: the nonce IS one-shot once genuinely
    // admitted, so a real replay of it is still refused. Without this, the test would pass
    // against a proxy with no replay tier at all.
    let (again, _e) = signed_request(NONCE, OPEN_BODY, None);
    let replayed = b.handle(served_of(&again), NOW).await;
    assert_eq!(replayed.status, 409);
    assert_eq!(wire_code_of(&replayed.body), "mcp-re.replay_detected");
}

/// An inner backend that counts how many times it was actually invoked.
fn counting_inner(calls: Arc<std::sync::atomic::AtomicUsize>) -> Box<dyn AsyncInnerServer> {
    Box::new(move |forwarded: &[u8]| -> Vec<u8> {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id = echoed_id(forwarded);
        format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"complete","ok":true}}}}"#)
            .into_bytes()
    })
}

/// **reserve_retention_stage** — the last refusal that is genuinely free.
///
/// Broken implementation this must catch: dispatch to the backend before the durable
/// reservation is acknowledged (or treat the reservation as advisory and continue on
/// error), so a retention outage produces a 503 AFTER the action has already run.
///
/// Why it matters: 503 is a status clients retry, and the retry carries a fresh nonce the
/// replay tier cannot stop. A post-execution 503 therefore runs the action twice.
///
/// Asserted on the BACKEND, not on the status code: the status is identical either way, so
/// only the invocation count distinguishes the correct implementation from the broken one.
#[tokio::test]
async fn a_retention_reservation_failure_leaves_the_backend_untouched() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());

    let dir = WedgedRetentionDir::new("untouched");
    let retention = Arc::new(
        mcp_re_proxy::transparency::EvidenceRetention::open(&dir.0)
            .expect("retention opens while the root is writable"),
    );
    let proxy = HttpProfileProxy::new_delegated(
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
    )
    .with_continuation_store(Arc::clone(&store), TTL)
    .with_evidence_retention(retention);
    dir.wedge();

    let (req, _e) = signed_request("nonce-H1", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(served.status, 503);
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.evidence_retention_unavailable"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the backend must not have been reached"
    );
    // No continuation was involved, so the refusal is an ordinary retry.
    assert_retry_posture(&served.body, None);

    // Non-vacuity control: the same proxy with a writable store DOES reach the backend, so
    // the count above is a consequence of the outage and not of a broken harness.
    let dir_ok = WedgedRetentionDir::new("untouched-ok");
    let retention_ok = Arc::new(
        mcp_re_proxy::transparency::EvidenceRetention::open(&dir_ok.0).expect("retention opens"),
    );
    let calls_ok = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let healthy = HttpProfileProxy::new_delegated(
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
        counting_inner(Arc::clone(&calls_ok)),
        300,
        ready_signer(),
    )
    .with_evidence_retention(retention_ok);
    let (req_ok, _e) = signed_request("nonce-H2", OPEN_BODY, None);
    let served_ok = healthy.handle(served_of(&req_ok), NOW).await;
    assert_eq!(served_ok.status, 200);
    assert_eq!(calls_ok.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// **retire_continuation_stage** — a successful consumption is irreversible.
///
/// Broken implementation this must catch: a refusal raised AFTER the consumption reports the
/// exchange as though the approval were still reusable — the state the pre-descriptor code
/// produced, because each refusal site answered the retry question from its own position and
/// no site could see the continuation machine.
///
/// The backend is asserted untouched as well, because the two facts together are the whole
/// contract: the action did NOT run, and the approval is nonetheless gone. Either one alone
/// is a true statement that misleads.
#[tokio::test]
async fn a_consumption_followed_by_a_refusal_reports_a_spent_approval_and_an_unrun_action() {
    const STATE: &str = "state-token-H3";
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let opener = replica(ready_signer(), Arc::clone(&store), STATE);
    let (d_prev, d_irr, state) = open_on(&opener, STATE).await;

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dir = WedgedRetentionDir::new("spent-unrun");
    let retention = Arc::new(
        mcp_re_proxy::transparency::EvidenceRetention::open(&dir.0).expect("retention opens"),
    );
    let answerer = HttpProfileProxy::new_delegated(
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
    )
    .with_continuation_store(Arc::clone(&store), TTL)
    .with_evidence_retention(retention);
    dir.wedge();

    let continuation = HttpContinuation::from_handles(d_prev, d_irr, state.as_bytes());
    let (answer, _e) = signed_request("nonce-H3", &answer_body(&state), Some(continuation));
    let served = answerer.handle(served_of(&answer), NOW).await;

    // The action did NOT run...
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "refused before the dispatch"
    );
    // ...and the refusal says so, while ALSO saying the approval cannot be reused.
    assert_eq!(served.status, 503);
    assert_retry_posture(&served.body, Some("unsafe_without_new_elicitation"));
    let body: serde_json::Value = serde_json::from_slice(&served.body).unwrap();
    let err = body.pointer("/error/data/mcp_re_error").unwrap();
    assert_eq!(
        err.get("execution_status").and_then(|s| s.as_str()),
        Some("not_executed")
    );

    // And the approval really is gone: re-answering fails closed rather than succeeding.
    let (retry, _e) = signed_request(
        "nonce-H4",
        &answer_body(&state),
        Some(HttpContinuation::from_handles(
            as_digest(&signed_request("nonce-open", OPEN_BODY, None).1),
            as_digest(&signed_request("nonce-open", OPEN_BODY, None).1),
            state.as_bytes(),
        )),
    );
    let refused = answerer.handle(served_of(&retry), NOW).await;
    assert_eq!(refused.status, 409);
}

// --- transport binding: absence of evidence is not satisfaction of the check ---

/// **transport_binding_stage** — a configured Mode-A binding cannot be satisfied by silence.
///
/// Broken implementation this must catch: `identity.map(check).unwrap_or(true)` — treat a
/// missing peer identity as "nothing to check, continue" instead of "the evidence this
/// configured policy requires is absent, so the binding cannot be established".
///
/// This is the fail-open shape already seen elsewhere in this codebase:
///
/// ```text
/// required evidence absent -> absence read as "nothing to check" -> condition satisfied
/// ```
///
/// Asserted on the PROTECTED PROPERTY rather than the status: when transport binding is
/// configured, a request lacking peer identity must not advance past the binding stage at
/// all. So the backend must be untouched AND the replay slot unspent — either of which a
/// later, unrelated 403 would fail to guarantee.
#[tokio::test]
async fn a_configured_transport_binding_refuses_a_request_that_presents_no_peer_identity() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let proxy = HttpProfileProxy::new_delegated(
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
    )
    .with_exact_match_transport_binding();

    // `served_of` presents no `identity` — the plain-HTTP case.
    let (req, _e) = signed_request("nonce-TB1", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(served.status, 403);
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.transport_binding_failed"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the backend must never be reached"
    );
    // The stage sits BEFORE replay admission, so the slot is untouched: proved by the same
    // nonce still being admissible on a proxy with no binding configured.
    let open = HttpProfileProxy::new_delegated(
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
        counting_inner(Arc::new(std::sync::atomic::AtomicUsize::new(0))),
        300,
        ready_signer(),
    );
    let (same_nonce, _e) = signed_request("nonce-TB1", OPEN_BODY, None);
    assert_eq!(
        open.handle(served_of(&same_nonce), NOW).await.status,
        200,
        "the refused request must not have advanced far enough to spend anything"
    );

    // Non-vacuity control: the SAME proxy admits the SAME request once the peer identity it
    // requires is actually presented. Without this the test would pass against a proxy that
    // refuses everything.
    let r = resolver();
    let verified = Verifier::new(&VerifierPolicy::default(), &move |k: &str, s| r(k, s))
        .verify_request(&req, &audience(), &|_b: &ArtifactBinding| None, NOW)
        .expect("the client's own request verifies");
    let mut with_identity = served_of(&req);
    with_identity.identity = Some(mcp_re_proxy::transport::TransportIdentity::new(
        verified.resolved_actor().actor_id(),
        mcp_re_proxy::transport::IdentitySource::UriSan,
    ));
    let admitted = proxy.handle(with_identity, NOW).await;
    assert_eq!(
        admitted.status, 200,
        "the identical request binds and is served once its peer identity is present"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

// --- answerability: a receipt may not outlive the credential authorizing it ---

/// A delegated signer whose credential expires in `ttl` seconds rather than [`TTL`].
fn signer_with_credential_ttl(ttl: i64) -> Arc<DelegatedServerSigner> {
    let signer = Arc::new(DelegatedServerSigner::new());
    let root = root_key();
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
        Some(issue_delegation_credential(&root, h, c))
    };
    let mut n = 200u8;
    let factory = move || {
        n = n.wrapping_add(1);
        SigningKey::from_seed_bytes(&[n; 32])
    };
    let cfg = CustodyConfig {
        ttl,
        ..custody_cfg()
    };
    let mut rotor = DelegatedRotor::new(
        DelegatedSigningCustody::new(cfg, issue, factory),
        Arc::clone(&signer),
    );
    rotor.rotate(NOW).expect("issue the short-lived key");
    std::mem::forget(rotor);
    signer
}

/// Read the `expires` parameter off a signed response's `signature-input` header.
fn advertised_expiry(resp: &ServedHttpResponse) -> i64 {
    let value = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
        .map(|(_, v)| v.clone())
        .expect("a signed response carries signature-input");
    let after = value
        .split("expires=")
        .nth(1)
        .expect("an expires parameter");
    after
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .expect("expires is an integer")
}

/// **answerable_stage** — the advertised signature window never outlives the credential.
///
/// ```text
/// expires = min(now + sig_ttl_secs, delegated_credential.exp)
/// ```
///
/// Broken implementation this must catch: drop the `.min(a.exp)` and advertise
/// `now + sig_ttl_secs` unconditionally. The receipt then claims a verification lifetime
/// its own credential cannot support, and a verifier refuses the whole thing as
/// `delegation_credential_expired` — the enforcement boundary emitting self-invalidating
/// evidence.
///
/// **The fixture is deliberately asymmetric**, because the obvious one proves nothing: with
/// a response TTL of 300 and a credential also 300 seconds from expiry, `min(300, 300)` and
/// an unclamped `300` are the same number. The clamp executes and decides nothing. Here the
/// credential expires in 40 seconds while the proxy is configured for 300, so correct and
/// broken implementations differ by 260.
#[tokio::test]
async fn a_signed_reply_never_advertises_validity_past_its_delegated_credential() {
    const CREDENTIAL_TTL: i64 = 40;
    const RESPONSE_SIG_TTL: i64 = 300;

    let proxy = HttpProfileProxy::new_delegated(
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
        counting_inner(Arc::new(std::sync::atomic::AtomicUsize::new(0))),
        RESPONSE_SIG_TTL,
        signer_with_credential_ttl(CREDENTIAL_TTL),
    );

    let (req, _e) = signed_request("nonce-AE1", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;
    assert_eq!(served.status, 200);

    assert_eq!(
        advertised_expiry(&served),
        NOW + CREDENTIAL_TTL,
        "the reply must be clamped to the credential, not to the configured response TTL"
    );

    // Non-vacuity control: the fixture can discriminate. The unclamped value the broken
    // implementation would produce is a different number, so this assertion is not
    // satisfied by both branches.
    assert_ne!(NOW + CREDENTIAL_TTL, NOW + RESPONSE_SIG_TTL);

    // And the other direction: when the credential outlives the configured window, the
    // configured window is what governs — the clamp is a minimum, not a substitution.
    let long = HttpProfileProxy::new_delegated(
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
        counting_inner(Arc::new(std::sync::atomic::AtomicUsize::new(0))),
        CREDENTIAL_TTL,
        signer_with_credential_ttl(RESPONSE_SIG_TTL),
    );
    let (req2, _e) = signed_request("nonce-AE2", OPEN_BODY, None);
    let served2 = long.handle(served_of(&req2), NOW).await;
    assert_eq!(served2.status, 200);
    assert_eq!(advertised_expiry(&served2), NOW + CREDENTIAL_TTL);
}

// ===================== ROUND 8: EXECUTION CERTAINTY AT THE SEAMS =====================
//
// Four seams where a fact the exchange knows was being flattened into a fact it does not:
// a store outage into a binding failure, an indeterminate `consume` into "nothing was
// spent", a free refusal into a durable execution-threshold marker, and every inner
// outcome into a signed 202. Each test names the broken implementation it must catch, and
// each asserts the MECHANISM — the wire code, the retry contract, the marker on disk, the
// backend count — rather than the status alone, which every one of these shares with the
// behaviour it replaced.

/// A continuation store whose `peek` always fails. `store`/`consume` behave normally, so
/// an answer leg fails at exactly the read the shared tier serves it from.
struct PeekFailingStore(Arc<dyn AsyncContinuationStore>);

impl AsyncContinuationStore for PeekFailingStore {
    fn store<'a>(
        &'a self,
        key: &'a str,
        bases: &'a mcp_re_proxy::continuation_store::RetainedBases,
        ttl_secs: i64,
    ) -> mcp_re_proxy::continuation_store::ContinuationFuture<'a, ()> {
        self.0.store(key, bases, ttl_secs)
    }
    fn peek<'a>(
        &'a self,
        _key: &'a str,
    ) -> mcp_re_proxy::continuation_store::ContinuationFuture<
        'a,
        Option<mcp_re_proxy::continuation_store::RetainedBases>,
    > {
        Box::pin(async {
            Err(
                mcp_re_proxy::continuation_store::ContinuationStoreError::Unavailable {
                    details: "the shared tier is down".to_string(),
                },
            )
        })
    }
    fn consume<'a>(
        &'a self,
        key: &'a str,
    ) -> mcp_re_proxy::continuation_store::ContinuationFuture<'a, bool> {
        self.0.consume(key)
    }
}

/// A continuation store that peeks normally and whose `consume` never answers — the
/// `DEL`-with-a-lost-reply case, where the entry may or may not be gone.
struct ConsumeFailingStore(Arc<dyn AsyncContinuationStore>);

impl AsyncContinuationStore for ConsumeFailingStore {
    fn store<'a>(
        &'a self,
        key: &'a str,
        bases: &'a mcp_re_proxy::continuation_store::RetainedBases,
        ttl_secs: i64,
    ) -> mcp_re_proxy::continuation_store::ContinuationFuture<'a, ()> {
        self.0.store(key, bases, ttl_secs)
    }
    fn peek<'a>(
        &'a self,
        key: &'a str,
    ) -> mcp_re_proxy::continuation_store::ContinuationFuture<
        'a,
        Option<mcp_re_proxy::continuation_store::RetainedBases>,
    > {
        self.0.peek(key)
    }
    fn consume<'a>(
        &'a self,
        _key: &'a str,
    ) -> mcp_re_proxy::continuation_store::ContinuationFuture<'a, bool> {
        Box::pin(async {
            Err(
                mcp_re_proxy::continuation_store::ContinuationStoreError::Unavailable {
                    details: "the shared tier is down".to_string(),
                },
            )
        })
    }
}

/// The `continuation_status` a signed rejection states.
fn continuation_status_of(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/data/mcp_re_error/continuation_status")
                .and_then(|w| w.as_str())
                .map(str::to_owned)
        })
}

/// **R8-C113.** A shared-tier outage on the answer leg's `peek` is reported as an outage,
/// not as a forged continuation.
///
/// Broken implementation this must catch: `store.peek(key).await.ok().flatten()` — flatten
/// `Err` into the same `None` as "no live entry", so the dispatcher mints
/// `continuation_binding_failed` (409). That code means a splice or a replayed
/// continuation, so an operator paging on it during a Redis blip investigates a forgery
/// incident, and a genuine splice attempt becomes indistinguishable from store health.
///
/// The two halves are asserted together: the outage says `replay_cache_unavailable`, and
/// the splice on a HEALTHY store still says `continuation_binding_failed`. Either alone
/// would pass against an implementation that had merely renamed the code.
#[tokio::test]
async fn a_continuation_store_outage_on_the_answer_leg_is_named_as_an_outage() {
    const STATE: &str = "state-token-R8-peek";
    let healthy: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let a = replica(ready_signer(), Arc::clone(&healthy), STATE);
    let (d_prev, d_irr, state) = open_on(&a, STATE).await;

    // Replica B shares the entry but cannot read it.
    let blind: Arc<dyn AsyncContinuationStore> = Arc::new(PeekFailingStore(Arc::clone(&healthy)));
    let b = replica(ready_signer(), blind, STATE);

    let continuation =
        HttpContinuation::from_handles(d_prev.clone(), d_irr.clone(), state.as_bytes());
    let (answer, _e) = signed_request("nonce-R8-peek", &answer_body(&state), Some(continuation));
    let served = b.handle(served_of(&answer), NOW).await;

    assert_eq!(served.status, 503, "a store outage is not a client fault");
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.replay_cache_unavailable",
        "an unreachable shared tier must not be reported as a forged continuation"
    );
    // The peek has no side effect, so nothing was spent and an ordinary retry is correct.
    assert_retry_posture(&served.body, None);

    // Non-vacuity: on a HEALTHY store the code that means "this continuation does not
    // bind" is still exactly that, so the assertion above discriminates.
    let c = replica(ready_signer(), Arc::clone(&healthy), STATE);
    let spliced = HttpContinuation::from_handles(d_prev.clone(), d_prev, state.as_bytes());
    let (bad, _e) = signed_request("nonce-R8-splice", &answer_body(&state), Some(spliced));
    let refused = c.handle(served_of(&bad), NOW).await;
    assert_eq!(refused.status, 409);
    assert_eq!(
        wire_code_of(&refused.body),
        "mcp-re.continuation_binding_failed"
    );
}

/// **R8-C011 / C012 / C049 / C084 / C101.** A `consume` that the store never answered is
/// not reported as "nothing was spent".
///
/// Broken implementation this must catch: `Ok(false) | Err(_) => Err(...)` — one refusal
/// for two different facts, with `ContinuationState::Consumed` recorded only on
/// `Ok(true)`. A Redis `DEL` whose reply was lost may well have executed, so the approval
/// may be destroyed; the exchange nonetheless reported `SafeNothingExecuted`, the client
/// read a plain retryable conflict, and its retry passed replay admission on a fresh nonce
/// and then failed permanently as already-answered.
///
/// Asserted on the BODY's retry contract, not the status: both implementations refuse.
#[tokio::test]
async fn an_indeterminate_continuation_retirement_is_never_reported_as_retry_safe() {
    const STATE: &str = "state-token-R8-consume";
    let shared: Arc<dyn AsyncContinuationStore> = Arc::new(InMemoryContinuationStore::new());
    let a = replica(ready_signer(), Arc::clone(&shared), STATE);
    let (d_prev, d_irr, state) = open_on(&a, STATE).await;

    // The answering replica reads the SAME entry the opener recorded — so the binding
    // succeeds and the exchange really does reach the retirement step — and only the
    // atomic removal fails.
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store: Arc<dyn AsyncContinuationStore> = Arc::new(ConsumeFailingStore(Arc::clone(&shared)));
    let b = HttpProfileProxy::new_delegated(
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
    )
    .with_continuation_store(store, TTL);

    let continuation = HttpContinuation::from_handles(d_prev, d_irr, state.as_bytes());
    let (answer, _e) = signed_request("nonce-R8-consume", &answer_body(&state), Some(continuation));
    let served = b.handle(served_of(&answer), NOW).await;

    // The action did not run...
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "refused before the dispatch"
    );
    // ...the fault is named as the shared tier's, not the caller's...
    assert_eq!(served.status, 503);
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.replay_cache_unavailable",
        "a store that did not answer is not evidence of a forged continuation"
    );
    // ...and the client is told the approval cannot be reused, which is the whole point:
    // an ordinary retry destroys it for nothing.
    assert_retry_posture(&served.body, Some("unsafe_without_new_elicitation"));
    assert_eq!(
        execution_status_of(&served.body),
        Some("not_executed".to_owned())
    );
    assert_eq!(
        continuation_status_of(&served.body),
        Some("consumed".to_owned())
    );
}

/// An inner plane that refuses to admit anything, and never transmits.
struct ClosedInnerPlane;

impl AsyncInnerServer for ClosedInnerPlane {
    fn admit(&self) -> Result<(), mcp_re_proxy::async_inner::NotAdmitted> {
        Err(mcp_re_proxy::async_inner::NotAdmitted(
            "every inner backend is ejected",
        ))
    }
    fn dispatch<'a>(
        &'a self,
        _request: &'a [u8],
    ) -> mcp_re_proxy::async_inner::InnerResponseFuture<'a> {
        panic!("a refused inner plane must never be dispatched to")
    }
}

/// **R8-C010 / C048 / C092.** A free refusal never runs after the retention reservation.
///
/// Broken implementation this must catch: order `reserve_retention_stage` BEFORE
/// `inner_plane_stage`. `RetentionReservation` has no `Drop` that unlinks its marker and
/// nothing sweeps `*.pending`, so every request refused at the inner-plane gate — local
/// saturation or an all-ejected backend set, both inducible by an authenticated client
/// with concurrent slow calls — leaves a permanent on-disk record whose documented meaning
/// is "this exact request crossed the execution threshold and its outcome was never
/// retained". The exchange machine reports the same request as `RefusedBeforeDispatch`.
///
/// Asserted on the FILESYSTEM. The status and wire code are identical under both
/// orderings, so only the marker count distinguishes them.
#[tokio::test]
async fn an_inner_plane_refusal_leaves_no_durable_retention_marker() {
    let dir = WedgedRetentionDir::new("no-marker");
    let retention = Arc::new(
        mcp_re_proxy::transparency::EvidenceRetention::open(&dir.0).expect("retention opens"),
    );
    let reader = Arc::clone(&retention);
    let proxy = HttpProfileProxy::new_delegated(
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
        Box::new(ClosedInnerPlane),
        300,
        ready_signer(),
    )
    .with_evidence_retention(retention);

    let (req, _e) = signed_request("nonce-R8-plane", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(served.status, 503);
    assert_eq!(wire_code_of(&served.body), "mcp-re.inner_plane_unavailable");
    // Nothing ran and nothing was spent, so the refusal is an ordinary retry.
    assert_retry_posture(&served.body, None);
    assert_eq!(
        reader
            .pending_reservations()
            .expect("the retention root is readable"),
        Vec::<String>::new(),
        "a request that provably never reached a backend must leave no execution-threshold \
         marker behind"
    );

    // Non-vacuity: the retention store IS wired and DOES write for an exchange that
    // crosses the threshold — so the zero above is the ordering, not a dead store.
    let dir_ok = WedgedRetentionDir::new("no-marker-ok");
    let retention_ok = Arc::new(
        mcp_re_proxy::transparency::EvidenceRetention::open(&dir_ok.0).expect("retention opens"),
    );
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let healthy = HttpProfileProxy::new_delegated(
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
    )
    .with_evidence_retention(retention_ok);
    let (req_ok, _e) = signed_request("nonce-R8-plane-ok", OPEN_BODY, None);
    assert_eq!(healthy.handle(served_of(&req_ok), NOW).await.status, 200);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        std::fs::read_dir(&dir_ok.0)
            .expect("readable")
            .filter_map(|e| e.ok())
            .count()
            > 0,
        "the control must actually have retained something"
    );
}

/// An inner plane that admits, then reports a fixed outcome without transmitting anything
/// the test can observe.
struct FixedOutcomeInner(InnerOutcome);

impl AsyncInnerServer for FixedOutcomeInner {
    fn dispatch<'a>(
        &'a self,
        _request: &'a [u8],
    ) -> mcp_re_proxy::async_inner::InnerResponseFuture<'a> {
        let outcome = self.0.clone();
        Box::pin(async move { outcome })
    }
}

const NOTIFICATION_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"1"}}"#;

fn notification_proxy(outcome: InnerOutcome) -> HttpProfileProxy {
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
        Box::new(FixedOutcomeInner(outcome)),
        300,
        ready_signer(),
    )
}

/// **R8-C047 / C050 / C051 / C081 / C083.** A notification the inner plane did not deliver
/// is not acknowledged with a signed 202.
///
/// Broken implementation this must catch: branch to `answer_notification` before
/// `observe_inner_stage` and drop the `InnerOutcome` unread. All four outcomes then
/// collapse into one delegated-signed bodyless 202 that the client verifies and, per the
/// SDK contract, treats as the signal to stop — so a `notifications/cancelled` the proxy
/// provably never transmitted is indistinguishable from one the backend received, under a
/// signature from the enforcement boundary. Because `observe_origin` was never called on
/// that arm, the machine's own guard against serving synthesized transport-failure bytes
/// as a success could not fire either.
///
/// RB-09's split is asserted per outcome: nothing transmitted is 503, transmitted with no
/// answer is 504, and the 504 states that the message may have been acted on.
#[tokio::test]
async fn a_notification_the_inner_plane_never_delivered_is_not_acknowledged() {
    let lost = notification_proxy(InnerOutcome::NotDispatched(
        "every inner backend is ejected",
    ));
    let (req, _e) = signed_request("nonce-R8-note-lost", NOTIFICATION_BODY, None);
    let served = lost.handle(served_of(&req), NOW).await;
    assert_ne!(
        served.status, 202,
        "a message that was never transmitted must not earn a signed acknowledgement"
    );
    assert_eq!(served.status, 503);
    assert_eq!(wire_code_of(&served.body), "mcp-re.inner_plane_unavailable");

    let timed_out = notification_proxy(InnerOutcome::Indeterminate("inner request timed out"));
    let (req2, _e) = signed_request("nonce-R8-note-timeout", NOTIFICATION_BODY, None);
    let served2 = timed_out.handle(served_of(&req2), NOW).await;
    assert_ne!(served2.status, 202);
    assert_eq!(served2.status, 504);
    assert_eq!(
        wire_code_of(&served2.body),
        "mcp-re.inner_dispatch_indeterminate"
    );
    assert_eq!(
        execution_status_of(&served2.body),
        Some("possibly_executed".to_owned()),
        "a notification transmitted with no answer may have been acted on"
    );
}

/// The other half of the split, and the non-vacuity control for it: a notification the
/// backend RECEIVED is still acknowledged with a bodyless 202.
///
/// Both accepting outcomes are exercised, and `InvalidUpstream` is the load-bearing one.
/// A conformant Streamable-HTTP backend answers a notification with `202 Accepted` and no
/// body — no `application/json` content type — which the inner client classifies as an
/// unusable answer from a backend that nevertheless received the message. Refusing it
/// would break every conformant notification, so the split is on delivery, not on
/// whether the reply was usable.
#[tokio::test]
async fn a_delivered_notification_is_still_acknowledged_with_a_202() {
    let replied = notification_proxy(InnerOutcome::Replied(Vec::new()));
    let (req, _e) = signed_request("nonce-R8-note-ok", NOTIFICATION_BODY, None);
    let served = replied.handle(served_of(&req), NOW).await;
    assert_eq!(served.status, 202, "the backend received the message");
    assert!(served.body.is_empty(), "the 202 is bodyless");

    let bodyless_202 = notification_proxy(InnerOutcome::InvalidUpstream(
        "inner backend did not answer application/json",
    ));
    let (req2, _e) = signed_request("nonce-R8-note-202", NOTIFICATION_BODY, None);
    let served2 = bodyless_202.handle(served_of(&req2), NOW).await;
    assert_eq!(
        served2.status, 202,
        "a backend that answered 202-no-body received the notification"
    );
}

/// An inner plane that retires the delegated signer mid-flight, then fails the dispatch.
struct SignerRetiringInner(Arc<DelegatedServerSigner>);

impl AsyncInnerServer for SignerRetiringInner {
    fn dispatch<'a>(
        &'a self,
        _request: &'a [u8],
    ) -> mcp_re_proxy::async_inner::InnerResponseFuture<'a> {
        self.0.retire();
        Box::pin(async { InnerOutcome::Indeterminate("inner request timed out") })
    }
}

/// **R8-C070 / C071.** A post-dispatch refusal is signed and states its execution claim
/// even when the signer is retired after the exchange snapshotted its key.
///
/// Broken implementation this must catch: `signed_rejection` re-asks `self.signer.current`
/// and falls back to `unsigned_error` when it is gone, dropping the request binding, the
/// signature AND the `ExecutionDisposition`. `current` returns `None` for a retired signer,
/// which a drain or a failed rotation can produce between ANSWERABLE and a post-dispatch
/// refusal — so during exactly those windows the 504 whose entire purpose is to say "the
/// backend may have acted" left as a bare unsigned body a client cannot distinguish from an
/// on-path forgery, and which its verifier fails closed on as a transport error, i.e. as
/// did-not-run.
#[tokio::test]
async fn a_post_dispatch_refusal_is_signed_with_the_key_the_exchange_snapshotted() {
    let signer = ready_signer();
    let proxy = HttpProfileProxy::new_delegated(
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
        Box::new(SignerRetiringInner(Arc::clone(&signer))),
        300,
        Arc::clone(&signer),
    );

    let (req, _e) = signed_request("nonce-R8-retired", OPEN_BODY, None);
    let served = proxy.handle(served_of(&req), NOW).await;

    assert_eq!(served.status, 504);
    assert!(
        served
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("signature")),
        "a post-dispatch refusal must not degrade to an unsigned body"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&served.body).expect("the refusal body is JSON");
    assert!(
        body.pointer("/_meta/se.syncom~1mcp-re.http.response")
            .and_then(|b| b.get("server_delegation"))
            .is_some(),
        "the inline delegation credential rides with the signed refusal: {body}"
    );
    assert_eq!(
        execution_status_of(&served.body),
        Some("possibly_executed".to_owned())
    );
    // The signer really is retired: a NEW exchange on the same proxy cannot be answered at
    // all, which is what makes the assertions above about the snapshot and not about a
    // signer that happened to still be live.
    let (req2, _e) = signed_request("nonce-R8-retired-2", OPEN_BODY, None);
    let served2 = proxy.handle(served_of(&req2), NOW).await;
    assert_eq!(served2.status, 503);
    assert_eq!(
        wire_code_of(&served2.body),
        "mcp-re.delegated_signing_unavailable"
    );
}

/// **R8-C053 / C054.** A body that is not a legal JSON-RPC request never reaches the
/// backend, and never earns a signed acknowledgement.
///
/// Broken implementation this must catch: the one in the tree before the validator was
/// wired — the only member ever read on the request side was `id`, by `outstanding_id`,
/// and its ABSENCE was read as "notification". So an object carrying nothing but an
/// evidence block, or a document that is simultaneously a request and a response, or one
/// whose `jsonrpc` is not `"2.0"`, was forwarded to the inner server and then acknowledged
/// with a delegated-signed 202 asserting the enforcement boundary had accepted an MCP
/// message. A `null` id was folded into the notification arm for the same reason, and the
/// two are answered differently — one with a bound signed reply, the other with a
/// bodyless 202.
///
/// Asserted on the BACKEND COUNT, which is the mechanism: every one of these bodies would
/// have produced a plausible-looking response from the proxy either way, and only the
/// dispatch count distinguishes "refused" from "refused after running it".
#[tokio::test]
async fn a_body_that_is_not_a_json_rpc_request_never_reaches_the_backend() {
    let illegal: &[(&str, &[u8])] = &[
        (
            "no method member",
            br#"{"jsonrpc":"2.0","id":1,"params":{}}"#,
        ),
        ("no jsonrpc member", br#"{"id":1,"method":"tools/call"}"#),
        (
            "wrong jsonrpc version",
            br#"{"jsonrpc":"1.0","id":1,"method":"tools/call"}"#,
        ),
        (
            "also a response",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","result":{}}"#,
        ),
        (
            "scalar params",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":7}"#,
        ),
        (
            "null id folded into a notification",
            br#"{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}"#,
        ),
        ("bare evidence carrier", br#"{"greeting":"hello"}"#),
    ];

    for (name, body) in illegal {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let proxy = HttpProfileProxy::new_delegated(
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

        let (req, _e) = signed_request(&format!("nonce-R8-env-{name}"), body, None);
        let served = proxy.handle(served_of(&req), NOW).await;

        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "{name}: a body that is not an MCP message must not be dispatched"
        );
        assert_ne!(served.status, 202, "{name}: acknowledged as a notification");
        assert_ne!(served.status, 200, "{name}: served as a successful reply");
        assert_eq!(served.status, 400, "{name}");
        assert_eq!(
            wire_code_of(&served.body),
            "mcp-re.malformed_envelope",
            "{name}"
        );
        // Refused before admission: nothing ran and nothing was spent.
        assert_retry_posture(&served.body, None);

        // The refusal is FREE, and the replay slot proves it: the same nonce is still
        // admissible for a well-formed request. Without this the test would pass against
        // an implementation that refused correctly but had already burned the nonce.
        let (retry, _e) = signed_request(&format!("nonce-R8-env-{name}"), OPEN_BODY, None);
        assert_eq!(
            proxy.handle(served_of(&retry), NOW).await.status,
            200,
            "{name}: the refused envelope must not have spent the replay slot"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

/// The non-vacuity control for the validator: the two LEGAL request shapes still pass, and
/// still reach their own terminals.
///
/// Without this, a validator that refused every body would satisfy the test above.
#[tokio::test]
async fn the_two_legal_request_shapes_still_reach_their_terminals() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bodied = HttpProfileProxy::new_delegated(
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
    let (req, _e) = signed_request("nonce-R8-env-ok", OPEN_BODY, None);
    assert_eq!(bodied.handle(served_of(&req), NOW).await.status, 200);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    let notes = notification_proxy(InnerOutcome::Replied(Vec::new()));
    let (note, _e) = signed_request("nonce-R8-env-note", NOTIFICATION_BODY, None);
    assert_eq!(notes.handle(served_of(&note), NOW).await.status, 202);
}
