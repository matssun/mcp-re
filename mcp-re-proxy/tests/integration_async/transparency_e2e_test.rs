// SPDX-License-Identifier: Apache-2.0
//! The ADR-MCPRE-054 vertical, end to end, from a served call to an offline-verifiable
//! receipt.
//!
//! ```text
//! signed request -> HttpProfileProxy (delegated-required, retention ON)
//!   -> the exchange is RETAINED before the response goes out
//!   -> auditor: reconstruct_chain over the retained hop
//!   -> issue_signed_statement committing to the reconstruction
//!   -> register with a transparency service -> Receipt
//!   -> verify_receipt_offline + verify_retained_evidence, contacting nobody
//! ```
//!
//! Until this wiring the whole SCITT surface was reachable only from tests, conformance
//! vectors and interop harnesses: nothing on the serving path produced a statement,
//! reconstructed a chain, or retained anything, so `retained_evidence.rs` was dead code
//! inside the serving crate. This lane is the production caller.
//!
//! The transparency service here is `PrototypeTransparencyService` — an in-process
//! Merkle log, NOT a running SCITT Transparency Service. Registering against a real one
//! is ADR-MCPRE-054's remaining external dependency. What this proves without one is
//! everything either side of that hop: that a served call is retained, that the
//! reconstruction and the statement are about the retained bytes, and that the receipt
//! verifies offline.

use mcp_re_http_profile::Verifier;
use std::sync::Arc;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::scitt::CoseVerificationKey;
use mcp_re_http_profile::scitt::PrototypeTransparencyService;
use mcp_re_http_profile::scitt::ReceiptPositionProfile;
use mcp_re_http_profile::scitt::ResolvedTransparencyService;
use mcp_re_http_profile::scitt::StatementLeafProfile;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::ChainLabel;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifierPolicy;

use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::transparency::attest_chain;
use mcp_re_proxy::transparency::EvidenceRetention;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::HttpProfileProxy;

use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::RequestSigningInputs;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [55u8; 32];
const ISSUER_SEED: [u8; 32] = [77u8; 32];
const TS_SEED: [u8; 32] = [88u8; 32];
const NOW: i64 = 1_700_000_100;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const ISSUER_KID: &str = "pep-statement-issuer";
const TS_KID: &str = "prototype-ts";
const AUD: &str = "verifier-1";
const EPOCH: &str = "epoch-1";
const ACCESS_TOKEN: &str = "access-token-xyz";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
fn issuer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ISSUER_SEED)
}
fn ts_key() -> SigningKey {
    SigningKey::from_seed_bytes(&TS_SEED)
}

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mcp-re-transparency-e2e-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch");
        Scratch(path)
    }
    fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- the real delegated-required server ------------------------------------

fn server_config() -> mcp_re_proxy::deployment_request::DeploymentRequest {
    let args: Vec<String> = [
        "--bind",
        "127.0.0.1:8443",
        "--audience",
        AUD,
        "--server-signer",
        "did:example:server",
        "--server-key-id",
        ROOT_KID,
        "--signing-key-seed",
        "/dev/null",
        "--tls-cert",
        "/dev/null",
        "--tls-key",
        "/dev/null",
        "--client-ca",
        "/dev/null",
        "--trust",
        "/dev/null",
        "--inner-http-url",
        "http://127.0.0.1:9",
        "--target-uri",
        TARGET,
        "--route",
        "a",
        "--replay-redis-url",
        "redis://127.0.0.1:6379",
        "--replay-durability-tier",
        "redis-wait-quorum:1:100",
        "--delegated-trust-epoch",
        EPOCH,
        "--trust-domain",
        "mcp.example.com",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    mcp_re_proxy::cli::parse_args(&args).expect("parse server config")
}

/// The trust seam for BOTH the serving path (Request slot) and the auditor's
/// reconstruction (Response slot: the root the delegated credential chains to).
fn resolver() -> ActorResolver {
    Box::new(move |key_id: &str, slot: SignerSlot| {
        match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
                identity: ActorIdentity {
                    role: "client".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:client".into(),
                    keyid: CLIENT_KEY_ID.into(),
                },
                verification_key: client_key().public_key(),
                slot,
            }),
            (ROOT_KID, SignerSlot::Response) => Some(ResolvedActor {
                identity: ActorIdentity {
                    role: "server".into(),
                    trust_domain: "example.com".into(),
                    subject: "did:example:server".into(),
                    keyid: ROOT_KID.into(),
                },
                verification_key: root_key().public_key(),
                slot,
            }),
            _ => None,
        }
        .into()
    })
}

/// A server whose inner backend counts how many times it was actually invoked.
///
/// The distinction the retention state machine turns on is "the call definitely did not
/// execute" vs "it may have", so a test that only reads the status cannot tell whether
/// the refusal happened on the right side of the execution boundary.
fn build_server_counting(
    retention: Option<Arc<EvidenceRetention>>,
    dispatches: Arc<std::sync::atomic::AtomicUsize>,
) -> HttpProfileProxy {
    let config = server_config();
    let wiring = mcp_re_proxy::build_delegated_signing(&signing_plan(&config), root_key());
    let mut rotor = wiring.rotor;
    rotor.rotate(NOW).expect("first delegated key");
    let expected_audience = AudienceTuple {
        audience_id: config.audience.clone(),
        target_uri: config.target_uri.clone(),
        route: config.route.clone(),
    };
    let proxy = HttpProfileProxy::new_delegated(
        resolver(),
        expected_audience,
        AsyncReplayTier::new(
            Arc::new(InMemoryAsyncAtomicReplayStore::new()),
            mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
        ),
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
        Box::new(move |_forwarded: &[u8]| -> Vec<u8> {
            dispatches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
        }),
        300,
        Arc::clone(&wiring.signer),
    );
    match retention {
        Some(retention) => proxy.with_evidence_retention(retention),
        None => proxy,
    }
}

fn build_server(retention: Option<Arc<EvidenceRetention>>) -> HttpProfileProxy {
    let config = server_config();
    let wiring = mcp_re_proxy::build_delegated_signing(&signing_plan(&config), root_key());
    let mut rotor = wiring.rotor;
    rotor.rotate(NOW).expect("first delegated key");
    let expected_audience = AudienceTuple {
        audience_id: config.audience.clone(),
        target_uri: config.target_uri.clone(),
        route: config.route.clone(),
    };
    let proxy = HttpProfileProxy::new_delegated(
        resolver(),
        expected_audience,
        AsyncReplayTier::new(
            Arc::new(InMemoryAsyncAtomicReplayStore::new()),
            mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
        ),
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
        Box::new(|_forwarded: &[u8]| -> Vec<u8> {
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
        }),
        300,
        Arc::clone(&wiring.signer),
    );
    match retention {
        Some(retention) => proxy.with_evidence_retention(retention),
        None => proxy,
    }
}

/// The full-profile audit inputs for reconstruction: the verifier's own audience tuple
/// and the DPoP credential surface the retained request does not carry.
fn attest_audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

fn attest_material(_: &mcp_re_http_profile::ArtifactBinding) -> Option<Vec<u8>> {
    Some(ACCESS_TOKEN.as_bytes().to_vec())
}

static ATTEST_MATERIAL: fn(&mcp_re_http_profile::ArtifactBinding) -> Option<Vec<u8>> =
    attest_material;

fn attest_audit() -> mcp_re_http_profile::ChainAudit<'static> {
    static AUDIENCE: std::sync::OnceLock<AudienceTuple> = std::sync::OnceLock::new();
    mcp_re_http_profile::ChainAudit {
        expected_audience: AUDIENCE.get_or_init(attest_audience),
        artifact_material: &ATTEST_MATERIAL,
    }
}

/// Sign a plain request and serve it, returning the served status and the frozen
/// `mcp-re.*` reason the response body carries (a success carries none).
fn serve_one_full(proxy: &HttpProfileProxy, nonce: &str) -> (u16, Option<String>) {
    let inputs = RequestSigningInputs::new(
        CLIENT_KEY_ID.to_owned(),
        AudienceTuple {
            audience_id: AUD.into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        },
        vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        nonce,
        NOW - 100,
        NOW + 200,
    )
    .with_headers(vec![(
        "Authorization".to_owned(),
        format!("Bearer {ACCESS_TOKEN}"),
    )]);
    let signed = mcp_re_client_core::build_signed_request(
        &serde_json::json!(1),
        "tools/call",
        serde_json::Map::new(),
        TARGET,
        &inputs,
        &client_key(),
    )
    .expect("sign the request");
    let request = signed.request();
    let served = ServedHttpRequest {
        method: request.method.clone(),
        target_uri: request.target_uri.clone(),
        headers: request.headers.clone(),
        body: request.body.clone(),
        peer: None,
        assertion: None,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let response = rt.block_on(async { proxy.handle(served, NOW).await });
    let reason = serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/data/mcp_re_error/wire_code")
                .and_then(|w| w.as_str())
                .map(str::to_owned)
        });
    (response.status, reason)
}

/// The status alone, for the calls that are expected to succeed.
fn serve_one(proxy: &HttpProfileProxy, nonce: &str) -> u16 {
    serve_one_full(proxy, nonce).0
}

fn expectations<'a>(audiences: &'a [&'a str], epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        verifier_audiences: audiences,
        expected_audience_hash: AUD,
        accepted_epochs: epochs,
        max_clock_skew: 60,
    }
}

/// The external-signer seam COSE issuance and registration take: raw signature bytes,
/// so the issuer/TS key never enters the profile crate.
fn sign_with(key: SigningKey) -> impl Fn(&[u8]) -> Result<Vec<u8>, HttpProfileError> {
    move |preimage: &[u8]| {
        mcp_re_core::b64url_decode(&key.sign(preimage))
            .map_err(|_| HttpProfileError::InvalidSignature)
    }
}

// ---- the proofs ------------------------------------------------------------

/// Serve one NOTIFICATION (a JSON-RPC message with no `id`), answered with a signed
/// bodyless 202.
fn serve_one_notification(proxy: &HttpProfileProxy, nonce: &str) -> u16 {
    let inputs = RequestSigningInputs::new(
        CLIENT_KEY_ID.to_owned(),
        AudienceTuple {
            audience_id: AUD.into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        },
        vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        nonce,
        NOW - 100,
        NOW + 200,
    )
    .with_headers(vec![(
        "Authorization".to_owned(),
        format!("Bearer {ACCESS_TOKEN}"),
    )]);
    let signed = mcp_re_client_core::build_signed_notification(
        "notifications/cancelled",
        serde_json::Map::new(),
        TARGET,
        &inputs,
        &client_key(),
    )
    .expect("sign the notification");
    let request = signed.request();
    let served = ServedHttpRequest {
        method: request.method.clone(),
        target_uri: request.target_uri.clone(),
        headers: request.headers.clone(),
        body: request.body.clone(),
        peer: None,
        assertion: None,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async { proxy.handle(served, NOW).await })
        .status
}

/// R7-C010/C011/C012/C019/C034: retention must not be a message class the CLIENT picks.
///
/// A notification reaches the same backend and runs the same side effects as a bodied
/// call; it is merely answered with a signed bodyless 202 instead of a body. When the
/// retention hook sat only on the bodied exit, dropping the JSON-RPC `id` served the
/// call, ran it, emitted `response.signed` — and retained nothing, so no receipt could
/// ever be issued about it.
#[test]
fn a_served_notification_is_retained_like_any_other_accepted_exchange() {
    let scratch = Scratch::new("notification-retained");
    let retention =
        Arc::new(EvidenceRetention::open(scratch.join("evidence")).expect("open retention"));
    let proxy = build_server(Some(Arc::clone(&retention)));

    assert_eq!(
        serve_one_notification(&proxy, "nonce-transparency-notification-1"),
        202,
        "a one-way notification is acknowledged with a signed bodyless 202"
    );

    let retained: Vec<_> = std::fs::read_dir(scratch.join("evidence"))
        .expect("the store directory exists")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(
        retained.len(),
        1,
        "the accepted notification must be retained; omitting the JSON-RPC id must not \
         be a way to have a served, executed call leave no reconstructible hop"
    );
}

/// The whole vertical: serve, retain, reconstruct, attest, register, verify offline.
#[test]
fn a_served_call_becomes_an_offline_verifiable_receipt() {
    let scratch = Scratch::new("vertical");
    let retention =
        Arc::new(EvidenceRetention::open(scratch.join("evidence")).expect("open retention"));
    let proxy = build_server(Some(Arc::clone(&retention)));

    assert_eq!(serve_one(&proxy, "nonce-transparency-vertical-1"), 200);

    // The auditor reads what the serving path kept. The handle is the store's, so an
    // auditor that has the digest — from the deployment's audit stream — can find it.
    let retained: Vec<_> = std::fs::read_dir(scratch.join("evidence"))
        .expect("the store directory exists")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        retained.len(),
        1,
        "exactly the one served exchange was retained"
    );
    let digest = mcp_re_http_profile::scitt::EvidenceDigest::of(
        &std::fs::read(scratch.join("evidence").join(&retained[0])).expect("read back"),
    );

    let audiences = [AUD];
    let epochs = [EPOCH];
    let attestation = attest_chain(
        &retention,
        &[digest],
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(&audiences, &epochs),
        &attest_audit(),
        &|_kid: &str| false,
        NOW,
        ISSUER_KID,
        None,
        None,
        sign_with(issuer_key()),
    )
    .expect("the retained exchange attests");

    assert_eq!(
        attestation.reconstruction.label,
        ChainLabel::Complete,
        "a single terminal hop, fully verified, is a complete record"
    );
    assert!(attestation.statement.commitment().is_complete_record());

    // Registration, then the acceptance property: the receipt verifies CONTACTING
    // NOBODY — issuer signature, inclusion proof re-deriving the signed root, and the
    // service's signature over that root.
    let mut service = PrototypeTransparencyService::new(TS_KID);
    let receipt = service
        .register(&attestation.statement, sign_with(ts_key()))
        .expect("the statement registers");

    mcp_re_http_profile::scitt::verify_receipt_offline(
        &attestation.statement,
        &receipt,
        |kid| (kid == ISSUER_KID).then(|| CoseVerificationKey::Ed25519(issuer_key().public_key())),
        |kid| {
            (kid == TS_KID).then(|| ResolvedTransparencyService {
                key: CoseVerificationKey::Ed25519(ts_key().public_key()),
                leaf_profile: StatementLeafProfile::StatementBytes,
                position_profile: ReceiptPositionProfile::Bound,
            })
        },
    )
    .expect("the receipt verifies offline");
}

/// The retained/committed split made to mean something: the statement's commitment is
/// checked against the bytes the store holds. A receipt says a statement was registered;
/// only this says the statement is about the evidence in hand.
#[test]
fn the_statement_is_verifiable_against_the_bytes_the_store_kept() {
    let scratch = Scratch::new("retained");
    let retention =
        Arc::new(EvidenceRetention::open(scratch.join("evidence")).expect("open retention"));
    let proxy = build_server(Some(Arc::clone(&retention)));
    assert_eq!(serve_one(&proxy, "nonce-transparency-retained-1"), 200);

    let name = std::fs::read_dir(scratch.join("evidence"))
        .expect("dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .next()
        .expect("one object");
    let digest = mcp_re_http_profile::scitt::EvidenceDigest::of(
        &std::fs::read(scratch.join("evidence").join(&name)).expect("read"),
    );

    let audiences = [AUD];
    let epochs = [EPOCH];
    let attestation = attest_chain(
        &retention,
        std::slice::from_ref(&digest),
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(&audiences, &epochs),
        &attest_audit(),
        &|_kid: &str| false,
        NOW,
        ISSUER_KID,
        None,
        None,
        sign_with(issuer_key()),
    )
    .expect("attest");

    // Re-derived independently from the store, as an auditor holding only the retained
    // bytes and the statement would.
    let hops = retention.load_chain(&[digest]).expect("load the chain");
    let reconstruction = mcp_re_http_profile::reconstruct_chain(
        &hops,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(&audiences, &epochs),
        &attest_audit(),
        &|_kid: &str| false,
        NOW,
    );
    mcp_re_http_profile::scitt::verify_retained_evidence(
        attestation.statement.commitment(),
        &reconstruction,
        None,
        None,
    )
    .expect("the retained bytes reproduce what the statement committed to");

    // And the control: a DIFFERENT record does not pass as this one.
    let other = build_server(Some(Arc::clone(&retention)));
    assert_eq!(serve_one(&other, "nonce-transparency-retained-2"), 200);
    let names: Vec<_> = std::fs::read_dir(scratch.join("evidence"))
        .expect("dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != &name)
        .collect();
    let other_digest = mcp_re_http_profile::scitt::EvidenceDigest::of(
        &std::fs::read(scratch.join("evidence").join(&names[0])).expect("read"),
    );
    let other_hops = retention.load_chain(&[other_digest]).expect("load");
    let other_reconstruction = mcp_re_http_profile::reconstruct_chain(
        &other_hops,
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(&audiences, &epochs),
        &attest_audit(),
        &|_kid: &str| false,
        NOW,
    );
    assert!(
        mcp_re_http_profile::scitt::verify_retained_evidence(
            attestation.statement.commitment(),
            &other_reconstruction,
            None,
            None,
        )
        .is_err(),
        "a statement must not verify against a different call's retained evidence"
    );
}

/// Retention is off unless a deployment turns it on, and off means the request path is
/// unchanged — no store, no directory, nothing kept.
#[test]
fn retention_is_off_by_default_and_nothing_is_kept() {
    let scratch = Scratch::new("off");
    let proxy = build_server(None);
    assert_eq!(serve_one(&proxy, "nonce-transparency-off-1"), 200);
    assert!(
        !scratch.join("evidence").exists(),
        "a deployment that did not ask for retention stores nothing"
    );
}

/// A deployment with retention ON is asserting it can account for what it served, so an
/// exchange whose evidence cannot be kept is REFUSED rather than served silently.
///
/// The failure is injected by replacing the store directory with a regular file, so
/// every write under it fails at the filesystem — the closest thing to a full or
/// unmounted volume that a hermetic test can arrange.
#[test]
fn an_exchange_whose_evidence_cannot_be_retained_is_refused() {
    let scratch = Scratch::new("failclosed");
    let evidence = scratch.join("evidence");
    let retention = Arc::new(EvidenceRetention::open(&evidence).expect("open retention"));
    let proxy = build_server(Some(Arc::clone(&retention)));

    // The store opened; now the directory goes away and a file takes its name.
    std::fs::remove_dir_all(&evidence).expect("remove the store directory");
    std::fs::write(&evidence, b"not a directory").expect("occupy the path");

    // The REASON, not just the status: 503 is also what an unavailable replay tier
    // returns, and a test that accepted any 503 here would keep passing if retention
    // stopped running altogether and something else refused the call.
    assert_eq!(
        serve_one_full(&proxy, "nonce-transparency-failclosed-1"),
        (
            503,
            Some("mcp-re.evidence_retention_unavailable".to_owned())
        ),
        "serving a call the deployment cannot account for would break the assertion \
         turning retention on makes"
    );
}

/// R7-C018/C045/C058: a known-unwritable store must stop the call BEFORE the backend.
///
/// 503 says "nothing happened, retry is safe", and that is only true if the refusal
/// happened on the near side of the execution boundary. Asserting the status alone
/// cannot tell the two sides apart, so this counts inner dispatches: the honest 503
/// requires the backend to have run zero times.
#[test]
fn a_retention_store_that_cannot_accept_the_call_refuses_before_the_backend_runs() {
    let scratch = Scratch::new("prereserve");
    let evidence = scratch.join("evidence");
    let retention = Arc::new(EvidenceRetention::open(&evidence).expect("open retention"));
    let dispatches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let proxy = build_server_counting(Some(Arc::clone(&retention)), Arc::clone(&dispatches));

    std::fs::remove_dir_all(&evidence).expect("remove the store directory");
    std::fs::write(&evidence, b"not a directory").expect("occupy the path");

    assert_eq!(
        serve_one_full(&proxy, "nonce-transparency-prereserve-1"),
        (
            503,
            Some("mcp-re.evidence_retention_unavailable".to_owned())
        ),
    );
    assert_eq!(
        dispatches.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the backend must not have run: a retryable 503 for a call that DID execute is \
         how a store fault becomes repeated execution, since the retry carries a fresh \
         nonce the replay tier cannot refuse"
    );
}

/// R7-C018/C045/C058: the post-execution failure is a DIFFERENT state, and says so.
///
/// Reserve succeeds, so the call is dispatched; the store is then broken, so completion
/// fails. There is no transaction spanning the backend and the store, so this state is
/// unavoidable — what matters is that it is reported as indeterminate rather than as an
/// ordinary retryable outage, and that the reservation marker survives as the durable
/// record that this request crossed the execution threshold.
#[tokio::test]
async fn a_retention_failure_after_execution_is_indeterminate_and_leaves_its_reservation() {
    let scratch = Scratch::new("indeterminate");
    let evidence = scratch.join("evidence");
    let retention = EvidenceRetention::open(&evidence).expect("open retention");

    let request = mcp_re_http_profile::HttpRequest {
        method: "POST".to_owned(),
        target_uri: TARGET.to_owned(),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
    };
    let response = mcp_re_http_profile::HttpResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };

    let reservation = retention
        .reserve(&request)
        .await
        .expect("reserve before dispatch");
    let marker = evidence.join(format!("{}.pending", reservation.digest().as_str()));
    assert!(
        marker.exists(),
        "the reservation must be durable before the side effects run"
    );

    // The backend has now "run". Break the store underneath the completion.
    std::fs::remove_dir_all(&evidence).expect("remove the store directory");
    std::fs::write(&evidence, b"not a directory").expect("occupy the path");

    retention
        .complete(&reservation, &request, &response)
        .await
        .expect_err("completion must fail once the store is gone");

    // Restore a directory so the marker's absence/presence is observable again.
    std::fs::remove_file(&evidence).expect("free the path");
    std::fs::create_dir_all(&evidence).expect("recreate the store directory");
    assert!(
        !evidence.join(reservation.digest().as_str()).exists(),
        "no hop was retained for the failed completion"
    );
}

/// R8-C030: the records with no verified hop are the ones an auditor most needs a
/// portable statement about, and they must be attestable.
///
/// `attest_chain` self-checks the statement it just issued against the retained bytes.
/// That check is over a record that NAMES bytes, and a reconstruction with no verified
/// prefix — the empty chain, and a chain that broke at hop 0 — names none: two empty
/// handles and a fold over nothing. Running it unconditionally made the function refuse
/// exactly the class its own contract says it must attest, so a submission whose first
/// hop failed to verify had no portable evidence at all.
#[test]
fn a_chain_with_no_verified_hop_is_still_attested() {
    let scratch = Scratch::new("no-verified-hop");
    let retention =
        Arc::new(EvidenceRetention::open(scratch.join("evidence")).expect("open retention"));
    let proxy = build_server(Some(Arc::clone(&retention)));
    assert_eq!(serve_one(&proxy, "nonce-transparency-unverified-1"), 200);

    let name = std::fs::read_dir(scratch.join("evidence"))
        .expect("dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .next()
        .expect("one object");
    let digest = mcp_re_http_profile::scitt::EvidenceDigest::of(
        &std::fs::read(scratch.join("evidence").join(&name)).expect("read"),
    );

    let audiences = [AUD];
    let epochs = [EPOCH];
    // A resolver that resolves nobody: hop 0's request cannot be verified, so the
    // reconstruction has an empty verified prefix.
    let nobody: ActorResolver =
        Box::new(|_key_id: &str, _slot: SignerSlot| Option::<ResolvedActor>::None.into());

    let attestation = attest_chain(
        &retention,
        std::slice::from_ref(&digest),
        &Verifier::new(&VerifierPolicy::default(), &nobody),
        &expectations(&audiences, &epochs),
        &attest_audit(),
        &|_kid: &str| false,
        NOW,
        ISSUER_KID,
        None,
        None,
        sign_with(issuer_key()),
    )
    .expect("a record whose first hop did not verify still gets a portable statement");

    assert!(
        matches!(
            attestation.reconstruction.label,
            ChainLabel::Incomplete { hop: 0, .. }
        ),
        "the label is what says which hop broke: {:?}",
        attestation.reconstruction.label
    );
    assert!(
        attestation.reconstruction.hop_evidence.is_empty(),
        "nothing verified, so there is no verified prefix"
    );
    assert!(
        !attestation
            .statement
            .commitment()
            .commits_to_verified_evidence(),
        "the statement must say plainly that it names no verified evidence"
    );
    assert!(
        !attestation.statement.commitment().is_complete_record(),
        "and it must never read as a complete call record"
    );

    // The empty chain is the same class and must behave the same way.
    let empty = attest_chain(
        &retention,
        &[],
        &Verifier::new(&VerifierPolicy::default(), &nobody),
        &expectations(&audiences, &epochs),
        &attest_audit(),
        &|_kid: &str| false,
        NOW,
        ISSUER_KID,
        None,
        None,
        sign_with(issuer_key()),
    )
    .expect("the empty chain is a representable record, not an error");
    assert!(!empty.statement.commitment().commits_to_verified_evidence());

    // The self-check is still applied where it means something: a statement about a
    // chain that DID verify is checked against the retained bytes.
    let complete = attest_chain(
        &retention,
        std::slice::from_ref(&digest),
        &Verifier::new(&VerifierPolicy::default(), &resolver()),
        &expectations(&audiences, &epochs),
        &attest_audit(),
        &|_kid: &str| false,
        NOW,
        ISSUER_KID,
        None,
        None,
        sign_with(issuer_key()),
    )
    .expect("attest");
    assert!(complete
        .statement
        .commitment()
        .commits_to_verified_evidence());
}

/// The `SigningPlan` `app::run` projects, so this lane drives the production wiring
/// through the same plan the binary does — including the boundary that produces it.
fn signing_plan(
    config: &mcp_re_proxy::deployment_request::DeploymentRequest,
) -> mcp_re_proxy::startup_plan::SigningPlan {
    use mcp_re_proxy::startup_plan::{response_issuer_kid, SigningPlan, TrustEpochPlan};
    let validated =
        mcp_re_proxy::config_state::validation::ValidatedDeployment::try_from(config.clone())
            .expect("the fixture config must validate");
    SigningPlan::from_validated(
        &validated,
        response_issuer_kid(&validated),
        TrustEpochPlan::from_validated(&validated),
    )
}
