// SPDX-License-Identifier: Apache-2.0
//! §7 admission currency through the production PEP (`HttpProfileProxy`) — MCPRE-493.
//!
//! ADR-MCPRE-053 built the evidence: an authority-signed admission assertion, and the
//! binding that ties a call to it. Both were verified by `check_admission`, which the
//! serving path never called. So a call carrying a fresh, correctly-bound assertion
//! was served even after its workload had been revoked — the assertion is a snapshot,
//! and nothing compared it against authoritative state.
//!
//! These are the properties that make admission actually enforced:
//!
//!   * a superseded generation is refused **before the backend runs** — the whole
//!     point of a currency check is to stop work being done on behalf of a workload
//!     whose admission has moved on, and a check after the tool call has already
//!     happened is a log line, not a control;
//!   * a REVOKED workload is refused even though its assertion is still valid;
//!   * an authority that is healthy but has never heard of the workload is a
//!     definitive negative, NOT an outage — routing it into degraded mode would serve
//!     an unknown caller on its own say-so;
//!   * an unreachable authority fails closed unless the deployment opted into a
//!     BOUNDED degraded window, and fails closed again past P;
//!   * and — the property #493 exists for — a revocation written to a SHARED source
//!     is honoured by a replica that never saw the original call.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_admission_assertion;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AdmissionBinding;
use mcp_re_http_profile::AdmissionClaims;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::AdmissionStatus;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::AuthoritativeAdmission;
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

use mcp_re_proxy::admission_enforcer::AdmissionEnforcement;
use mcp_re_proxy::admission_source::AsyncAdmissionSource;
use mcp_re_proxy::admission_source::InMemoryAdmissionSource;
use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::http_profile_serve::AdmissionAuthorityResolver;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const AUTHORITY_SEED: [u8; 32] = [44u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const AUTHORITY_KID: &str = "admission-root-1";
const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";
const TTL: i64 = 300;
const WORKLOAD: &str = "workload-7";

/// What an admission refusal looks like ON THE WIRE.
///
/// Not `mcp-re.admission_not_current`: no such token exists, deliberately. The
/// taxonomy is frozen and every wire code is a core token, so an admission failure
/// collapses onto `actor_binding_failed` — the caller is not authorized to act, which
/// is the true statement the client can act on.
///
/// The cost is real and worth naming: a revoked workload, an unknown one, and an
/// authority outage are indistinguishable to the client, and to an operator reading
/// only the wire code. That is why the propagation harness below measures the
/// TRANSITION from served to refused under a single changing variable rather than
/// keying off the code.
const ADMISSION_REFUSED: &str = "mcp-re.actor_binding_failed";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
/// The ADMISSION AUTHORITY's root — a different key from the response-signing root,
/// so "trusted to sign responses" can never be mistaken for "trusted to admit".
fn authority_key() -> SigningKey {
    SigningKey::from_seed_bytes(&AUTHORITY_SEED)
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
            (CLIENT_KEY_ID, SignerSlot::Request) => {
                ("client", "did:example:host-a", client_key().public_key())
            }
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

/// Resolves ONLY the configured admission authority. Anything else is untrusted —
/// a kid never introduces trust.
fn authority_resolver() -> AdmissionAuthorityResolver {
    Arc::new(|kid: &str| (kid == AUTHORITY_KID).then(|| authority_key().public_key()))
}

/// The actor id the PEP's verifier resolves for the signing client — the value an
/// assertion must name so it cannot be presented by anyone else.
fn client_actor_id() -> String {
    ActorIdentity {
        role: "client".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:host-a".into(),
        keyid: CLIENT_KEY_ID.into(),
    }
    .actor_id()
}

fn admission_claims(generation: u64, status: AdmissionStatus, iat: i64) -> AdmissionClaims {
    AdmissionClaims {
        iss: "did:example:admission".into(),
        iat,
        nbf: iat,
        exp: iat + 600,
        jti: format!("adm#{generation}"),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_admission_id: WORKLOAD.into(),
        mcp_re_admitted_actor: client_actor_id(),
        mcp_re_admission_generation: generation,
        mcp_re_admitted_state_digest: b64url_encode(&sha2::Sha256::digest(b"admitted-state")),
        mcp_re_admission_status: status,
        issuer_kid: AUTHORITY_KID.into(),
    }
}

fn issue_assertion(claims: &AdmissionClaims, signer: &SigningKey) -> String {
    issue_admission_assertion(claims, |input| {
        b64url_decode(&signer.sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
    })
    .expect("issue")
}

use sha2::Digest;

/// A signed call, optionally declaring the admission it acts under. `nonce` must be
/// fresh per call: the replay tier is real here.
fn signed_call(admission: Option<(&AdmissionClaims, &SigningKey)>, nonce: &str) -> HttpRequest {
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
    let evidence =
        admission.map(|(c, k)| (AdmissionBinding::opaque_from(c), issue_assertion(c, k)));
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"tok",
        )],
        continuation: None,
        admission: evidence.as_ref().map(|(b, _)| b.clone()),
        admission_assertion: evidence.as_ref().map(|(_, jws)| jws.clone()),
        authorization_decision: None,
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

/// An inner that COUNTS the calls that reached it. The count is the assertion that
/// matters for a currency check: a rejection issued after the tool ran is a record of
/// something that already happened.
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
        ttl: TTL,
        overlap: 60,
    }
}

fn ready_signer() -> Arc<DelegatedServerSigner> {
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
    rotor.rotate(NOW).expect("issue first delegated key");
    std::mem::forget(rotor);
    signer
}

/// One fleet replica: its own signer and replay tier, consulting `source` for
/// admission. Replicas share the SOURCE and nothing else, which is what makes a
/// cross-replica revocation claim meaningful.
fn replica(
    source: Arc<dyn AsyncAdmissionSource>,
    policy: AdmissionPolicy,
    enforcement: AdmissionEnforcement,
    calls: Arc<AtomicUsize>,
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
        counting_inner(calls),
        300,
        ready_signer(),
    )
    .with_admission(source, policy, enforcement, authority_resolver())
}

fn served_of(req: &HttpRequest) -> ServedHttpRequest {
    ServedHttpRequest {
        method: req.method.clone(),
        target_uri: req.target_uri.clone(),
        headers: req.headers.clone(),
        body: req.body.clone(),
        peer: None,
        assertion: None,
    }
}

fn wire_code_of(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")?
                .get("data")?
                .get("mcp_re_error")?
                .get("wire_code")?
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

/// The default enforcing policy: no degraded mode, so an unreachable authority is a
/// refusal rather than a judgement call.
fn strict_policy() -> AdmissionPolicy {
    AdmissionPolicy {
        max_assertion_age: 600,
        max_clock_skew: 30,
        degraded_propagation_bound: 0,
        allow_degraded_mode: false,
    }
}

/// A policy that refuses everything, installed to measure ONE proposition.
struct RefusesEverything;

impl mcp_re_proxy::authorization::AuthorizationEvaluator for RefusesEverything {
    fn evaluate(
        &self,
        _: &mcp_re_proxy::authorization::AuthorizationRequest,
    ) -> Result<mcp_re_proxy::authorization::AuthorizedDecision, mcp_re_policy::PolicyError> {
        Err(mcp_re_policy::PolicyError::AuthorizationScopeDenied)
    }
}

/// ADMISSION IS NOT AUTHORIZATION (ADR-MCPRE-065 §3).
///
/// The caller here is admitted on every axis §7 measures: a current generation, a genuine
/// assertion from the real authority, bound to this presenter. That is the strongest
/// admission statement this deployment can make, and it grants no application authority at
/// all. A denying policy still refuses, before the backend runs.
///
/// The inverse — an unadmitted caller reaching a granting policy — cannot happen, because
/// admission is ordered first and refuses on its own.
#[test]
fn an_admitted_workload_is_still_refused_by_a_denying_policy() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    )
    .with_authorization(Arc::new(RefusesEverything));
    let claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);
    let req = signed_call(Some((&claims, &authority_key())), "n-admitted-unauthorized");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(served.status, 403);
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.authorization_scope_denied",
        "the refusal is the POLICY's, not admission's — admission had already passed"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the backend must never have been asked"
    );
}

#[test]
fn a_current_admitted_workload_is_served() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    let claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);
    let req = signed_call(Some((&claims, &authority_key())), "n-ok");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(
        served.status,
        200,
        "{}",
        String::from_utf8_lossy(&served.body)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A BORROWED assertion does not admit its holder.
///
/// Every field of the binding is derivable from the assertion itself
/// (`AdmissionBinding::opaque_from`), and the assertion is carried in a request body
/// the caller signs — so without a presenter binding, anyone whose own key the PEP
/// resolves could copy an admitted peer's assertion into its own evidence block and
/// pass §7. The assertion here is genuine, current, and signed by the real authority:
/// the ONLY thing wrong with it is that it was issued to somebody else.
#[test]
fn an_assertion_issued_to_another_actor_does_not_admit_this_caller() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    let mut claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);
    claims.mcp_re_admitted_actor = "client:example.com:did:example:host-b:client-key-2".into();
    let req = signed_call(Some((&claims, &authority_key())), "n-borrowed");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(
        served.status, 403,
        "an assertion naming another actor must not admit this one"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the tool ran on a borrowed admission"
    );
}

/// THE case #493 exists for. The assertion is fresh, correctly bound, and says
/// admitted — but the authority has moved to generation 6. A snapshot does not confer
/// currency.
#[test]
fn a_superseded_generation_is_refused_before_the_backend_runs() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 6);
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    let claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);
    let req = signed_call(Some((&claims, &authority_key())), "n-stale");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(served.status, 403);
    assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the tool ran for a workload whose admission had been superseded"
    );
}

#[test]
fn a_revoked_workload_is_refused_though_its_assertion_is_still_valid() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    source.revoke(WORKLOAD);
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    let claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);
    let req = signed_call(Some((&claims, &authority_key())), "n-revoked");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(served.status, 403);
    assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// A healthy authority that has never heard of this workload is a definitive
/// negative. If it were treated as an outage, an unknown caller would reach the
/// degraded fork and be served on its own assertion — admitted by being unknown.
#[test]
fn an_unknown_workload_is_refused_not_routed_into_degraded_mode() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        AdmissionPolicy {
            // Degraded mode ENABLED and wide open: if the unknown workload were
            // mistaken for an outage, this policy would serve it.
            allow_degraded_mode: true,
            degraded_propagation_bound: 3600,
            ..strict_policy()
        },
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    let claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);
    let req = signed_call(Some((&claims, &authority_key())), "n-unknown");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(served.status, 403);
    assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn an_unreachable_authority_fails_closed_by_default() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    source.set_unavailable(true);
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    let claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);
    let req = signed_call(Some((&claims, &authority_key())), "n-outage");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(served.status, 403);
    assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// R7-C093: the degraded window is elapsed OUTAGE time, not assertion freshness.
///
/// Degraded mode is a BOUNDED window a deployment opts into, not a fallback — and the
/// thing P has to bound is how long this replica may serve on last-known state while the
/// authority is unreachable. Applied to the presented assertion's `iat` it bounded the
/// wrong thing: the revocation channel IS the store, so during a store outage the
/// issuer never learns of a revocation and keeps minting assertions with a current
/// `iat`, and a caller that simply keeps fetching them was served for the whole outage,
/// however long. Every assertion below is FRESH; only the outage ages.
#[test]
fn an_unreachable_authority_serves_within_p_and_fails_closed_past_it() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = AdmissionPolicy {
        allow_degraded_mode: true,
        degraded_propagation_bound: 120,
        ..strict_policy()
    };
    let proxy = replica(
        Arc::clone(&source) as Arc<dyn AsyncAdmissionSource>,
        policy,
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );

    // The authority is reachable: this call establishes last-known state to serve on.
    let confirmed = admission_claims(5, AdmissionStatus::Admitted, NOW - 30);
    let served = block_on(proxy.handle(
        served_of(&signed_call(
            Some((&confirmed, &authority_key())),
            "n-degraded-confirm",
        )),
        NOW,
    ));
    assert_eq!(served.status, 200, "a live-confirmed admission serves");

    source.set_unavailable(true);

    // 60s into the outage: inside P, and the assertion is fresh.
    let fresh = admission_claims(5, AdmissionStatus::Admitted, NOW + 55);
    let served = block_on(proxy.handle(
        served_of(&signed_call(
            Some((&fresh, &authority_key())),
            "n-degraded-in",
        )),
        NOW + 60,
    ));
    assert_eq!(served.status, 200, "within P, degraded mode serves");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // 160s into the same outage — past P + skew — with an EQUALLY FRESH assertion. A
    // revocation could have propagated by now and this replica would not know it, and no
    // assertion the caller can obtain moves this clock, which is the whole point.
    let just_issued = admission_claims(5, AdmissionStatus::Admitted, NOW + 155);
    let served = block_on(proxy.handle(
        served_of(&signed_call(
            Some((&just_issued, &authority_key())),
            "n-degraded-out",
        )),
        NOW + 160,
    ));
    assert_eq!(served.status, 403);
    assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "no third call reached the inner"
    );
}

/// R7-C093, the other half: a replica that has NEVER reached the authority has no
/// last-known state to serve on, so startup is not a confirmation. Degraded mode extends
/// a window that has to have been opened by a real read.
#[test]
fn a_replica_that_never_reached_the_authority_does_not_enter_degraded_mode() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    source.set_unavailable(true);
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = AdmissionPolicy {
        allow_degraded_mode: true,
        degraded_propagation_bound: 120,
        ..strict_policy()
    };
    let proxy = replica(
        Arc::clone(&source) as Arc<dyn AsyncAdmissionSource>,
        policy,
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );

    let fresh = admission_claims(5, AdmissionStatus::Admitted, NOW - 10);
    let served = block_on(proxy.handle(
        served_of(&signed_call(
            Some((&fresh, &authority_key())),
            "n-never-read",
        )),
        NOW,
    ));

    assert_eq!(served.status, 403);
    assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the backend must not run for a workload whose admission was never confirmed here"
    );
}

#[test]
fn a_call_without_admission_evidence_is_refused_when_required_and_served_when_optional() {
    let claims_free = signed_call(None, "n-none");

    let calls = Arc::new(AtomicUsize::new(0));
    let strict = replica(
        Arc::new(InMemoryAdmissionSource::new()),
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    let served = block_on(strict.handle(served_of(&claims_free), NOW));
    assert_eq!(served.status, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let calls = Arc::new(AtomicUsize::new(0));
    let lenient = replica(
        Arc::new(InMemoryAdmissionSource::new()),
        strict_policy(),
        AdmissionEnforcement::Optional,
        Arc::clone(&calls),
    );
    let served = block_on(lenient.handle(served_of(&claims_free), NOW));
    assert_eq!(served.status, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// An assertion signed by a key the deployment does not trust as an admission
/// authority is refused — even though the key is a perfectly good Ed25519 key and the
/// call's own request signature verifies.
#[test]
fn an_assertion_from_an_untrusted_authority_is_refused() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    let claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);
    // Signed by the RESPONSE-signing root, which is trusted — for responses.
    let req = signed_call(Some((&claims, &root_key())), "n-foreign");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(served.status, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// The cross-replica property #493 was opened for, at last testable: a revocation
/// written to the SHARED source is honoured by a replica that never saw the workload's
/// earlier traffic. The replicas share nothing else — separate signers, separate
/// replay tiers — so it is the source that carries the revocation, not shared memory
/// of the call.
#[test]
fn a_revocation_on_the_shared_source_is_honoured_by_a_replica_that_never_saw_the_workload() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    let claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);

    let calls_a = Arc::new(AtomicUsize::new(0));
    let replica_a = replica(
        Arc::clone(&source) as Arc<dyn AsyncAdmissionSource>,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls_a),
    );
    let calls_b = Arc::new(AtomicUsize::new(0));
    let replica_b = replica(
        Arc::clone(&source) as Arc<dyn AsyncAdmissionSource>,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls_b),
    );

    // A serves the workload happily.
    let served = block_on(replica_a.handle(
        served_of(&signed_call(Some((&claims, &authority_key())), "n-a-1")),
        NOW,
    ));
    assert_eq!(served.status, 200);

    // The authority revokes it. Nothing tells B; B simply consults the shared source.
    source.revoke(WORKLOAD);

    let served = block_on(replica_b.handle(
        served_of(&signed_call(Some((&claims, &authority_key())), "n-b-1")),
        NOW,
    ));
    assert_eq!(served.status, 403);
    assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
    assert_eq!(calls_b.load(Ordering::SeqCst), 0);

    // And A, which had already served it, refuses the next one too.
    let served = block_on(replica_a.handle(
        served_of(&signed_call(Some((&claims, &authority_key())), "n-a-2")),
        NOW,
    ));
    assert_eq!(served.status, 403);
    assert_eq!(
        calls_a.load(Ordering::SeqCst),
        1,
        "only the pre-revocation call ran"
    );
}

/// A generation that is NEWER than the authority's is refused too. The currency rule
/// is equality, not "at least": a call claiming a generation the authority has not
/// issued is not a fresher client, it is a client asserting an admission nobody made.
#[test]
fn a_generation_ahead_of_the_authority_is_refused() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    let claims = admission_claims(9, AdmissionStatus::Admitted, CREATED);
    let req = signed_call(Some((&claims, &authority_key())), "n-ahead");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(served.status, 403);
    assert_eq!(wire_code_of(&served.body), ADMISSION_REFUSED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// The authoritative record is consulted by ADMISSION ID, and the id comes from the
/// signed binding — so a call cannot borrow another workload's admission by naming it,
/// because the binding it names must also match the assertion it carries.
#[test]
fn a_binding_naming_another_workload_does_not_borrow_its_admission() {
    let source = Arc::new(InMemoryAdmissionSource::new());
    source.admit(WORKLOAD, 5);
    source.set(
        "workload-other",
        AuthoritativeAdmission {
            generation: 5,
            status: AdmissionStatus::Admitted,
        },
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let proxy = replica(
        source,
        strict_policy(),
        AdmissionEnforcement::Required,
        Arc::clone(&calls),
    );
    source_revoked_workload_call(&proxy, &calls);
}

fn source_revoked_workload_call(proxy: &HttpProfileProxy, calls: &Arc<AtomicUsize>) {
    // The assertion is for WORKLOAD; the binding claims `workload-other`. The two must
    // describe the same admission, so this is refused as a binding mismatch rather
    // than being looked up against the other workload's healthy record.
    let claims = admission_claims(5, AdmissionStatus::Admitted, CREATED);
    let mut binding = AdmissionBinding::opaque_from(&claims);
    binding.admission_id = "workload-other".into();

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
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"tok",
        )],
        continuation: None,
        admission: Some(binding),
        admission_assertion: Some(issue_assertion(&claims, &authority_key())),
        authorization_decision: None,
    };
    sign_request_full(
        &mut req,
        &block,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        "n-borrow",
    )
    .expect("signs");

    let served = block_on(proxy.handle(served_of(&req), NOW));
    assert_eq!(served.status, 403);
    assert_eq!(
        wire_code_of(&served.body),
        "mcp-re.request_binding_mismatch"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
