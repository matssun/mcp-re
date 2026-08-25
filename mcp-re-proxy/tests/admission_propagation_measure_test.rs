// SPDX-License-Identifier: Apache-2.0
//! MCPRE-493 — MEASURE cross-replica admission-revocation propagation against the
//! declared P bound, over a real shared store.
//!
//! This is the fourth ADR-MCPRE-053 acceptance criterion, and the reason it stayed
//! open: the bound was declared, enforced and vector-tested, but nothing had ever
//! measured a real revocation reaching a replica that did not perform it.
//!
//! **What is measured, stated precisely.** Two `HttpProfileProxy` replicas share one
//! Redis-backed admission source and nothing else — separate delegated signers,
//! separate replay tiers, separate connections. An authority revokes a workload on a
//! THIRD connection. The measurement is the wall-clock interval from the revoking
//! write returning to the first request on the *other* replica being refused.
//!
//! **What that number is and is not.** It is the propagation delay of THIS mechanism:
//! an authoritative record read live per request. There is no cached copy, so the
//! delay is the store's own write-then-read visibility plus one round trip — not a
//! cache TTL, and not a push channel's delivery time. A deployment that adds a
//! bounded cache is making a different claim and must measure it separately;
//! `RevocationTier` exists so that difference cannot be quietly elided.
//!
//! It is also a LOCAL number. Measured against a Redis on the same host, it bounds
//! the mechanism, not a production fleet: a real deployment adds network RTT and
//! replication lag between the writer and each replica's reader. What this run
//! establishes is that the mechanism propagates at all, that it does so to a replica
//! with no prior knowledge of the workload, and what the floor looks like when the
//! store is not the bottleneck.
//!
//! Skipped without `MCP_RE_TEST_REDIS_URL` (hard-failed under
//! `MCP_RE_REQUIRE_LIVE_INFRA`), mirroring `redis_trust_epoch_e2e_test.rs`.
#![cfg(feature = "redis_replay")]

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

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
use mcp_re_proxy::async_inner::AsyncInnerServer;
use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::http_profile_serve::AdmissionAuthorityResolver;
use mcp_re_proxy::redis_admission_source::RedisAdmissionSource;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::DelegatedRotor;
use mcp_re_proxy::DelegatedServerSigner;
use mcp_re_proxy::HttpProfileProxy;

use sha2::Digest;

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

/// The P bound this run is measured against, in milliseconds.
///
/// Not a universal constant: it is what a deployment DECLARES as its propagation
/// budget, and the measurement's job is to say whether the mechanism meets the one
/// declared here. Generous on purpose — a floor test that fails on an unrelated
/// machine hiccup teaches nothing, and the interesting result is the observed number,
/// which the run prints.
const DECLARED_P_MS: u128 = 2_000;

fn redis_url() -> Option<String> {
    let url = std::env::var("MCP_RE_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
        panic!("MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable");
    }
    url
}

/// A per-run workload id, so concurrent runs never observe each other's revocation.
fn unique_workload() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("workload-propagation-{now}")
}

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
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

/// The actor id the PEP's verifier resolves for the signing client — the value an
/// assertion must name so it cannot be presented by anyone else.
fn test_actor() -> String {
    ActorIdentity {
        role: "client".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:host-a".into(),
        keyid: CLIENT_KEY_ID.into(),
    }
    .actor_id()
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

fn authority_resolver() -> AdmissionAuthorityResolver {
    Arc::new(|kid: &str| (kid == AUTHORITY_KID).then(|| authority_key().public_key()))
}

fn admission_claims(workload: &str, generation: u64) -> AdmissionClaims {
    AdmissionClaims {
        iss: "did:example:admission".into(),
        iat: CREATED,
        nbf: CREATED,
        exp: CREATED + 600,
        jti: format!("adm#{generation}"),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_admission_id: workload.into(),
        mcp_re_admitted_actor: test_actor(),
        mcp_re_admission_generation: generation,
        mcp_re_admitted_state_digest: b64url_encode(&sha2::Sha256::digest(b"admitted-state")),
        mcp_re_admission_status: AdmissionStatus::Admitted,
        issuer_kid: AUTHORITY_KID.into(),
    }
}

/// A signed call under `claims`. The nonce must be fresh per call: the replay tier is
/// real, and a measurement loop that replayed one nonce would measure the replay
/// tier's refusal instead of the revocation's.
fn signed_call(claims: &AdmissionClaims, nonce: &str) -> HttpRequest {
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
    let assertion = issue_admission_assertion(claims, |input| {
        b64url_decode(&authority_key().sign(input)).map_err(|_| HttpProfileError::InvalidSignature)
    })
    .expect("issue");
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"tok",
        )],
        continuation: None,
        admission: Some(AdmissionBinding::opaque_from(claims)),
        admission_assertion: Some(assertion),
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

fn inner(calls: Arc<AtomicUsize>) -> Box<dyn AsyncInnerServer> {
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

/// One replica: its own signer, its own replay tier, its own connection to the shared
/// source. Nothing is shared but the store — which is what makes the propagation
/// claim about the store rather than about shared memory.
fn replica(source: Arc<dyn AsyncAdmissionSource>, calls: Arc<AtomicUsize>) -> HttpProfileProxy {
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
        inner(calls),
        300,
        ready_signer(),
    )
    .with_admission(
        source,
        AdmissionPolicy {
            max_assertion_age: 600,
            max_clock_skew: 30,
            // No degraded window: this measures propagation of a real revocation, and
            // a degraded fallback would let a store hiccup look like continued
            // admission and quietly inflate the measured delay.
            degraded_propagation_bound: 0,
            allow_degraded_mode: false,
        },
        AdmissionEnforcement::Required,
        authority_resolver(),
    )
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

#[test]
fn a_revocation_reaches_a_sibling_replica_within_the_declared_p_bound() {
    let Some(url) = redis_url() else {
        eprintln!(
            "SKIP a_revocation_reaches_a_sibling_replica_within_the_declared_p_bound: \
             MCP_RE_TEST_REDIS_URL unset"
        );
        return;
    };
    let workload = unique_workload();
    let claims = admission_claims(&workload, 5);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async {
        // Three independent connections: the authority that writes, and one per
        // replica that reads. A single shared connection would measure a memory write.
        let authority = RedisAdmissionSource::connect(&url)
            .await
            .expect("authority connects");
        let source_a = Arc::new(
            RedisAdmissionSource::connect(&url)
                .await
                .expect("A connects"),
        );
        let source_b = Arc::new(
            RedisAdmissionSource::connect(&url)
                .await
                .expect("B connects"),
        );

        authority
            .publish(
                &workload,
                &AuthoritativeAdmission {
                    generation: 5,
                    status: AdmissionStatus::Admitted,
                },
            )
            .await
            .expect("publish admitted");

        let calls_a = Arc::new(AtomicUsize::new(0));
        let calls_b = Arc::new(AtomicUsize::new(0));
        let replica_a = replica(
            Arc::clone(&source_a) as Arc<dyn AsyncAdmissionSource>,
            Arc::clone(&calls_a),
        );
        let replica_b = replica(
            Arc::clone(&source_b) as Arc<dyn AsyncAdmissionSource>,
            Arc::clone(&calls_b),
        );

        // Baseline: BOTH replicas serve the workload. Without this the measurement
        // below could not tell a working revocation from a replica that was never
        // admitting the call in the first place.
        let served = replica_a
            .handle(served_of(&signed_call(&claims, "n-base-a")), NOW)
            .await;
        assert_eq!(
            served.status, 200,
            "replica A must admit before the revocation"
        );
        let served = replica_b
            .handle(served_of(&signed_call(&claims, "n-base-b")), NOW)
            .await;
        assert_eq!(
            served.status, 200,
            "replica B must admit before the revocation"
        );
        assert_eq!(calls_a.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b.load(Ordering::SeqCst), 1);

        // The authority revokes. Nothing notifies either replica.
        let revoked_at = Instant::now();
        authority.revoke(&workload).await.expect("revoke");

        // Poll replica B — which performed no revocation and shares nothing with the
        // authority but the store — until it refuses. Each attempt carries a fresh
        // nonce so the replay tier never answers instead of the admission gate.
        let mut attempts = 0usize;
        let observed = loop {
            attempts += 1;
            let nonce = format!("n-poll-{attempts}");
            let served = replica_b
                .handle(served_of(&signed_call(&claims, &nonce)), NOW)
                .await;
            if served.status != 200 {
                break revoked_at.elapsed();
            }
            assert!(
                revoked_at.elapsed().as_millis() < DECLARED_P_MS,
                "replica B still served the workload {}ms after it was revoked \
                 (declared P bound {}ms); propagation did NOT meet the budget",
                revoked_at.elapsed().as_millis(),
                DECLARED_P_MS,
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        };

        // The number this test exists to produce. Printed rather than only asserted:
        // the pass/fail says the mechanism met a declared budget, the value says what
        // the budget could honestly be set to.
        println!(
            "MCPRE-493 propagation: revocation visible to a sibling replica in {}ms \
             ({} request(s)), against a declared P bound of {}ms. \
             Mechanism: live per-request read of the shared authoritative record — \
             no cached copy, so this is store visibility + one round trip, measured \
             against a LOCAL Redis. A production fleet adds network RTT and \
             replication lag.",
            observed.as_millis(),
            attempts,
            DECLARED_P_MS,
        );

        // The refusal must be the admission gate's, not a side effect: the backend
        // never ran for the revoked call.
        assert_eq!(
            calls_b.load(Ordering::SeqCst),
            1,
            "only the pre-revocation call reached the backend on replica B"
        );

        // And replica A, which served it happily a moment ago, now refuses too.
        let served = replica_a
            .handle(served_of(&signed_call(&claims, "n-after-a")), NOW)
            .await;
        assert_ne!(
            served.status, 200,
            "replica A must honour the revocation as well"
        );
        assert_eq!(calls_a.load(Ordering::SeqCst), 1);
    });
}
