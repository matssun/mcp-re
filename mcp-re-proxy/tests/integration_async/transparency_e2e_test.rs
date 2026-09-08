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
        retention.archive(),
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
        attestation.reconstruction.label(),
        &ChainLabel::Complete,
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
            // `stated`, not a pin: this is the in-process prototype log, so there is no
            // operator-reviewed document to resolve the profiles from and the test says so.
            (kid == TS_KID).then(|| {
                ResolvedTransparencyService::stated(
                    CoseVerificationKey::Ed25519(ts_key().public_key()),
                    StatementLeafProfile::StatementBytes,
                    ReceiptPositionProfile::Bound,
                )
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
        retention.archive(),
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
    let hops = retention
        .archive()
        .load_chain(&[digest])
        .expect("load the chain");
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
    let other_hops = retention
        .archive()
        .load_chain(&[other_digest])
        .expect("load");
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

    let reserved = retention
        .reserve(&request)
        .await
        .expect("reserve before dispatch");
    let digest = reserved.digest().as_str().to_owned();
    assert!(
        evidence.join(format!("{digest}.reserved")).exists(),
        "the obligation must be durable before anything relies on it"
    );
    let committed = retention
        .commit_to_dispatch(reserved)
        .await
        .expect("record the crossing before the side effects run");
    assert!(
        evidence.join(format!("{digest}.pending")).exists(),
        "the crossing must be durable before the side effects run"
    );

    // The backend has now "run". Break the store underneath the completion.
    std::fs::remove_dir_all(&evidence).expect("remove the store directory");
    std::fs::write(&evidence, b"not a directory").expect("occupy the path");

    retention
        .complete(&committed, &request, &response)
        .await
        .expect_err("completion must fail once the store is gone");

    // Restore a directory so the marker's absence/presence is observable again.
    std::fs::remove_file(&evidence).expect("free the path");
    std::fs::create_dir_all(&evidence).expect("recreate the store directory");
    assert!(
        !evidence.join(&digest).exists(),
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
        retention.archive(),
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
            attestation.reconstruction.label(),
            &ChainLabel::Incomplete { hop: 0, .. }
        ),
        "the label is what says which hop broke: {:?}",
        attestation.reconstruction.label()
    );
    assert!(
        attestation.reconstruction.hop_evidence().is_empty(),
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
        retention.archive(),
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
        retention.archive(),
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

// ---- the auditor BINARY -----------------------------------------------------
//
// Everything above drives `attest_chain` in-process. What an operator runs is
// `mcp-re-auditor`, and until #841's G-2 that executable did not exist: the serving half
// was a product and the auditing half was a library with no callers outside this file.
// These lanes exercise the SHIPPED PATH — a child process, real files, an exit status —
// because a composition root proved only in-process is a composition root nobody can run.

/// The documents one audit run is asserted by, written into a scratch directory.
struct AuditFixtures {
    profile: std::path::PathBuf,
    trust: std::path::PathBuf,
    pin: std::path::PathBuf,
    seed: std::path::PathBuf,
    out: std::path::PathBuf,
}

/// The audit profile matching the posture `build_server` serves under.
fn audit_profile_json() -> serde_json::Value {
    serde_json::json!({
        "schema": "mcp-re-audit-profile/v1",
        "trust_domain": "example.com",
        "expected_audience": {
            "audience_id": AUD,
            "target_uri": TARGET,
            "route": "a",
        },
        "delegation": {
            "verifier_audiences": [AUD],
            "expected_audience_hash": AUD,
            "accepted_epochs": [EPOCH],
            "max_clock_skew_secs": 60,
        },
        "response_anchor": {
            "subject": "did:example:server",
            "key_id": ROOT_KID,
            "public_key": root_key().public_key().to_b64url(),
        },
    })
}

/// A legal transparency-service trust pin. Its key is never used in this half — the
/// auditor loads it as a precondition and names the service in the artifact — so the pin
/// is the prototype log's key, which is the one a receipt from it would verify under.
fn service_pin_json() -> serde_json::Value {
    serde_json::json!({
        "schema": "mcp-re-scitt-service-trust-pin/v1",
        "service_identifier": "prototype-log",
        "discovery_method": "well-known-scitt-keys",
        "discovery_uri": "https://ts.example.test/.well-known/scitt-keys",
        "fetched_at": "2026-09-08T00:00:00Z",
        "kid": TS_KID,
        "algorithm": "EdDSA",
        "public_key": { "x": ts_key().public_key().to_b64url() },
        "public_key_thumbprint": "unused-by-this-lane",
        "discovery_document_digest": "unused-by-this-lane",
        "leaf_profile": "statement-bytes",
        "position_profile": "bound",
    })
}

impl AuditFixtures {
    fn write(scratch: &Scratch, profile: serde_json::Value, pin: serde_json::Value) -> Self {
        let trust_json = serde_json::json!([{
            "signer": "did:example:client",
            "key_id": CLIENT_KEY_ID,
            "public_key": client_key().public_key().to_b64url(),
        }]);
        let fixtures = AuditFixtures {
            profile: scratch.join("audit-profile.json"),
            trust: scratch.join("trust.json"),
            pin: scratch.join("service-pin.json"),
            seed: scratch.join("issuer.seed"),
            out: scratch.join("attestation.json"),
        };
        std::fs::write(
            &fixtures.profile,
            serde_json::to_vec(&profile).expect("json"),
        )
        .expect("write profile");
        std::fs::write(
            &fixtures.trust,
            serde_json::to_vec(&trust_json).expect("json"),
        )
        .expect("write trust");
        std::fs::write(&fixtures.pin, serde_json::to_vec(&pin).expect("json")).expect("write pin");
        std::fs::write(&fixtures.seed, mcp_re_core::b64url_encode(&ISSUER_SEED))
            .expect("write seed");
        fixtures
    }

    fn args(&self, evidence: &std::path::Path, hops: &[String]) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "--retained-evidence-dir".into(),
            evidence.display().to_string(),
            "--audit-profile".into(),
            self.profile.display().to_string(),
            "--trust-document".into(),
            self.trust.display().to_string(),
            "--service-trust-pin".into(),
            self.pin.display().to_string(),
            "--issuer-kid".into(),
            ISSUER_KID.into(),
            "--issuer-key-seed".into(),
            self.seed.display().to_string(),
            "--out".into(),
            self.out.display().to_string(),
            "--at".into(),
            NOW.to_string(),
        ];
        for hop in hops {
            args.push("--hop".into());
            args.push(hop.clone());
        }
        args
    }
}

/// Run the shipped auditor as a child process.
fn run_auditor(args: &[String]) -> std::process::Output {
    let binary = mcp_re_test_paths::resolve_runfile("MCP_RE_AUDITOR_CLI");
    std::process::Command::new(&binary)
        .args(args)
        .output()
        .expect("the auditor binary runs")
}

/// Serve one call, and return the scratch, the retention handle and the retained hop's
/// digest token — the three things every auditor lane below starts from.
fn served_archive(name: &str, nonce: &str) -> (Scratch, Arc<EvidenceRetention>, String) {
    let scratch = Scratch::new(name);
    let retention =
        Arc::new(EvidenceRetention::open(scratch.join("evidence")).expect("open retention"));
    let proxy = build_server(Some(Arc::clone(&retention)));
    assert_eq!(serve_one(&proxy, nonce), 200);

    let token = std::fs::read_dir(scratch.join("evidence"))
        .expect("the store directory exists")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .next()
        .expect("one retained object");
    (scratch, retention, token)
}

/// THE C1 property: a served call, an archive on disk, and the SHIPPED BINARY turns it
/// into an attestation whose Signed Statement registers and verifies offline.
///
/// The last step is what makes this more than "the process exited 0": the bytes the
/// artifact carries are put through a transparency log and the RFC 9942 offline
/// verification, so an artifact carrying a statement that could not be registered would
/// fail here rather than look like a success.
#[test]
fn the_auditor_binary_turns_a_served_call_into_a_verifiable_attestation() {
    let (scratch, retention, token) =
        served_archive("auditor-vertical", "nonce-transparency-auditor-vertical-1");
    // The retention handle owns a writer thread; the child process opens the same
    // directory, so drop ours first and audit what is on disk.
    drop(retention);

    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());
    let output =
        run_auditor(&fixtures.args(&scratch.join("evidence"), std::slice::from_ref(&token)));
    assert!(
        output.status.success(),
        "the auditor refused a record it should attest: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let artifact = mcp_re_proxy::transparency::auditor::AttestationArtifact::parse(
        &std::fs::read(&fixtures.out).expect("the artifact was written"),
    )
    .expect("the artifact parses");

    assert!(
        artifact.chain().is_complete(),
        "a single terminal hop, fully verified, is a complete record: {:?}",
        artifact.chain(),
    );
    assert_eq!(
        artifact.correspondence(),
        mcp_re_proxy::transparency::auditor::CorrespondenceVerdict::BoundToVerifiedCall,
        "the statement is bound to the retained bytes of a verified call",
    );
    assert_eq!(
        artifact.transparency_service().service_identifier,
        "prototype-log",
        "the artifact names the service the operator's pin selected",
    );

    // The statement the artifact carries is the real thing: register it and verify the
    // receipt offline, contacting nobody.
    let statement = mcp_re_http_profile::scitt::SignedStatement::from_cose(
        &artifact.signed_statement().expect("the statement decodes"),
    )
    .expect("the artifact carries a Signed Statement");
    assert!(statement.commitment().is_complete_record());

    let mut service = PrototypeTransparencyService::new(TS_KID);
    let receipt = service
        .register(&statement, sign_with(ts_key()))
        .expect("the statement registers");
    mcp_re_http_profile::scitt::verify_receipt_offline(
        &statement,
        &receipt,
        |kid| (kid == ISSUER_KID).then(|| CoseVerificationKey::Ed25519(issuer_key().public_key())),
        |kid| {
            (kid == TS_KID).then(|| {
                ResolvedTransparencyService::stated(
                    CoseVerificationKey::Ed25519(ts_key().public_key()),
                    StatementLeafProfile::StatementBytes,
                    ReceiptPositionProfile::Bound,
                )
            })
        },
    )
    .expect("the receipt over the binary's statement verifies offline");
}

/// MCPRE-179: the SHIPPED BINARY audits an archive it has no write access to.
///
/// This is the whole point of splitting a read projection out of the retention authority.
/// Before it, `EvidenceRetention::open` was the only way in and it proves the directory
/// writable BY WRITING a probe object — so an auditor could not run against a read-only
/// mount or a filesystem snapshot, which is the ordinary way an archive is handed to
/// somebody meant to audit it and not to add to it.
///
/// The directory is `0555` for the whole child run, so a probe write, a `create_dir_all`
/// on a missing root, or any staged object would fail. The audit succeeding is the
/// evidence that none of them is attempted.
#[test]
#[cfg(unix)]
fn the_auditor_binary_audits_an_archive_it_cannot_write_to() {
    use std::os::unix::fs::PermissionsExt;
    let (scratch, retention, token) = served_archive(
        "auditor-read-only",
        "nonce-transparency-auditor-read-only-1",
    );
    drop(retention);
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());
    let evidence = scratch.join("evidence");
    std::fs::set_permissions(&evidence, std::fs::Permissions::from_mode(0o555)).expect("chmod");

    let output = run_auditor(&fixtures.args(&evidence, std::slice::from_ref(&token)));

    // Restore before asserting, so the scratch can be removed either way.
    std::fs::set_permissions(&evidence, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(
        output.status.success(),
        "auditing must not require write access to the evidence it attests: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let artifact = mcp_re_proxy::transparency::auditor::AttestationArtifact::parse(
        &std::fs::read(&fixtures.out).expect("the artifact was written"),
    )
    .expect("the artifact parses");
    assert!(artifact.chain().is_complete());
}

/// And the SERVING constructor still refuses the same directory, at startup.
///
/// The narrowing is on the read side only. A replica that starts on a read-only volume, a
/// `0555` directory or a mismatched `fsGroup` would otherwise refuse every call it then
/// accepted, and that failure has to surface where an operator is looking.
#[test]
#[cfg(unix)]
fn the_serving_constructor_still_proves_the_archive_writable() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new("retention-writability-gate");
    let evidence = scratch.join("evidence");
    std::fs::create_dir_all(&evidence).expect("create");
    std::fs::set_permissions(&evidence, std::fs::Permissions::from_mode(0o555)).expect("chmod");

    let serving = EvidenceRetention::open(&evidence);
    let reading = mcp_re_proxy::transparency::RetainedArchive::open_read_only(&evidence);

    std::fs::set_permissions(&evidence, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(
        serving.is_err(),
        "a serving replica must not start on an archive it cannot write",
    );
    assert!(reading.is_ok(), "reading needs no write authority");
}

/// A hop the archive does not hold is a REFUSAL, and nothing is written.
///
/// The alternative — reconstructing from the hops that happen to be present — would
/// produce a `Complete` label for a record with a hole in it. The absence of the output
/// file is asserted too: a run that refused after writing would leave an artifact
/// describing an audit that did not happen.
#[test]
fn a_hop_the_archive_does_not_hold_is_refused_and_writes_nothing() {
    let (scratch, retention, token) = served_archive(
        "auditor-missing-hop",
        "nonce-transparency-auditor-missing-hop-2",
    );
    drop(retention);
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());

    let absent = mcp_re_http_profile::scitt::EvidenceDigest::of(b"a hop nobody retained")
        .as_str()
        .to_owned();
    let output = run_auditor(&fixtures.args(&scratch.join("evidence"), &[token, absent]));

    assert!(!output.status.success(), "a missing hop must refuse");
    assert!(
        !fixtures.out.exists(),
        "a refused audit must leave no artifact behind",
    );
}

/// An illegal service pin refuses the run BEFORE anything is signed.
///
/// A statement cut for a service whose pin is illegal can never be shown to have been
/// registered with that service, so producing one would produce an artifact with no
/// possible future. The pin is loaded first for exactly that reason.
#[test]
fn an_illegal_service_pin_refuses_the_audit() {
    let (scratch, retention, token) =
        served_archive("auditor-bad-pin", "nonce-transparency-auditor-bad-pin-3");
    drop(retention);

    // An EdDSA pin carrying an EC2 `y` coordinate is a mislabelled key, and never becomes
    // a pin at all.
    let mut pin = service_pin_json();
    pin["public_key"]["y"] = ts_key().public_key().to_b64url().into();
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), pin);

    let output = run_auditor(&fixtures.args(&scratch.join("evidence"), &[token]));
    assert!(!output.status.success(), "an illegal pin must refuse");
    assert!(!fixtures.out.exists(), "and must leave no artifact");
}

/// A profile asserting a posture the record was NOT served under yields an INCOMPLETE
/// attestation — not a refusal, and not a complete one.
///
/// This is the §9 seam reaching the shipped binary. The auditor asserts an audience the
/// call never had; every hop fails the full-profile comparison; and what comes out is a
/// portable statement that says so, naming the hop and the frozen wire code. An auditor
/// that refused here would leave the interesting record with no evidence, and one that
/// labelled it complete would launder it.
#[test]
fn an_audit_posture_the_call_was_not_served_under_attests_an_incomplete_record() {
    let (scratch, retention, token) = served_archive(
        "auditor-wrong-posture",
        "nonce-transparency-auditor-posture-4",
    );
    drop(retention);

    let mut profile = audit_profile_json();
    profile["expected_audience"]["audience_id"] = "some-other-verifier".into();
    let fixtures = AuditFixtures::write(&scratch, profile, service_pin_json());

    let output = run_auditor(&fixtures.args(&scratch.join("evidence"), &[token]));
    assert!(
        output.status.success(),
        "an incomplete record is attested, not refused: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let artifact = mcp_re_proxy::transparency::auditor::AttestationArtifact::parse(
        &std::fs::read(&fixtures.out).expect("an artifact was still written"),
    )
    .expect("the artifact parses");

    let mcp_re_proxy::transparency::auditor::ChainVerdict::Incomplete { hop, reason, .. } =
        artifact.chain()
    else {
        panic!("a record served under another audience is not complete");
    };
    assert_eq!(*hop, 0, "the first hop is where it broke");
    assert_eq!(
        *reason,
        mcp_re_proxy::transparency::auditor::IncompleteAt::RequestUnverifiable,
    );
    assert_eq!(
        artifact.correspondence(),
        mcp_re_proxy::transparency::auditor::CorrespondenceVerdict::BoundToSubmissionOnly,
        "nothing verified, so the statement binds the SUBMISSION and says only that",
    );

    let statement = mcp_re_http_profile::scitt::SignedStatement::from_cose(
        &artifact.signed_statement().expect("decodes"),
    )
    .expect("still a Signed Statement");
    assert!(
        !statement.commitment().is_complete_record(),
        "and the signed record can never read as whole",
    );
}

/// An archive object that was replaced on disk is refused, not reconstructed from.
///
/// The store is content-addressed, so the tamper is detectable by the name alone — and
/// this is the lane that proves the auditor consults that property rather than trusting
/// the directory it was pointed at.
#[test]
fn a_tampered_archive_object_is_refused() {
    let (scratch, retention, token) =
        served_archive("auditor-tampered", "nonce-transparency-auditor-tampered-5");
    drop(retention);
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());

    let object = scratch.join("evidence").join(&token);
    let mut bytes = std::fs::read(&object).expect("read the retained object");
    bytes.push(b' ');
    std::fs::write(&object, &bytes).expect("replace the retained object");

    let output = run_auditor(&fixtures.args(&scratch.join("evidence"), &[token]));
    assert!(
        !output.status.success(),
        "bytes that do not hash to the digest they are stored under must refuse",
    );
    assert!(!fixtures.out.exists(), "and must leave no artifact");
}

// ---- registration, over a socket, through the shipped binary -----------------
//
// Everything above stops at the artifact. This is the last hop: a transparency service on
// a loopback socket, the SHIPPED auditor pointed at it, and an artifact that comes back
// carrying a receipt — which it can only do if that receipt verified offline against the
// exact statement submitted and the pin the operator loaded.
//
// The service below is hermetic and it is not a canned-response table. It parses the
// Signed Statement it is sent, registers it in a real RFC 9162 log, and answers with a
// real RFC 9942 receipt about those exact bytes.

/// How the hermetic service answers a submission.
#[derive(Clone, Copy)]
enum ServiceMode {
    /// SCRAPI, `201 Created` with the receipt in the body.
    Synchronous,
    /// SCRAPI, `202 Accepted` + `Location`, then `n` × `204`, then `200` with the receipt.
    Asynchronous { pending: u32 },
    /// The `capsule-anchor` contract: `200` with JSON `{"receipt_b64": …}`, no polling.
    ///
    /// A separate mode rather than a status variation, because the difference is the whole
    /// reason there is a second mechanism leaf: a different resource, a different request
    /// media type, and the receipt arriving base64 inside JSON rather than as the body.
    CapsuleAnchor,
}

impl ServiceMode {
    /// The `--registration-protocol` token an operator names for this service.
    fn protocol(self) -> &'static str {
        match self {
            ServiceMode::Synchronous | ServiceMode::Asynchronous { .. } => "scrapi-11",
            ServiceMode::CapsuleAnchor => "capsule-anchor",
        }
    }
}

/// A transparency service on a loopback socket, speaking the registration exchange.
///
/// Returns the base URL and a join handle. It serves exactly the exchanges one
/// registration needs and then stops.
fn spawn_transparency_service(mode: ServiceMode) -> (String, std::thread::JoinHandle<()>) {
    use std::io::Read;
    use std::io::Write;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the service");
    let port = listener.local_addr().expect("addr").port();
    let base = format!("http://127.0.0.1:{port}");
    let operation = format!("{base}/operations/1");

    let handle = std::thread::spawn(move || {
        let mut receipt: Vec<u8> = Vec::new();
        let mut pending = match mode {
            ServiceMode::Asynchronous { pending } => pending,
            ServiceMode::Synchronous | ServiceMode::CapsuleAnchor => 0,
        };
        // One submission plus at most `pending + 1` polls; the loop ends when the receipt
        // has been handed over.
        loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut raw = Vec::new();
            let mut buf = [0_u8; 4096];
            // Read until the headers are complete, then the declared body.
            loop {
                let Ok(n) = stream.read(&mut buf) else { return };
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&raw).to_string();
                let Some(head_end) = text.find("\r\n\r\n") else {
                    continue;
                };
                let declared: usize = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse().ok())
                    })
                    .unwrap_or(0);
                if raw.len() >= head_end + 4 + declared {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            let head_end = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(raw.len());
            let is_post = text.starts_with("POST ");

            let mut delivered = false;
            let response: Vec<u8> = if is_post {
                // The two contracts put the statement in different places, and the service
                // reads it the way the contract it is speaking says to. Accepting either
                // shape on either path would let a mechanism pass this lane while sending
                // the other one's request.
                let submitted: Vec<u8> = match mode {
                    ServiceMode::CapsuleAnchor => {
                        assert!(
                            text.starts_with("POST /transparency/register-statement "),
                            "the capsule-anchor leaf must POST that contract's resource: {}",
                            text.lines().next().unwrap_or_default(),
                        );
                        let body: serde_json::Value = serde_json::from_slice(&raw[head_end..])
                            .expect("the capsule-anchor leaf submits JSON");
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD
                            .decode(
                                body["signed_statement_b64"]
                                    .as_str()
                                    .expect("signed_statement_b64"),
                            )
                            .expect("standard base64")
                    }
                    _ => raw[head_end..].to_vec(),
                };
                let statement = mcp_re_http_profile::scitt::SignedStatement::from_cose(&submitted)
                    .expect("the auditor submits a Signed Statement");
                let mut log = PrototypeTransparencyService::new(TS_KID);
                receipt = log
                    .register(&statement, sign_with(ts_key()))
                    .expect("the log registers it")
                    .to_cose()
                    .to_vec();
                match mode {
                    ServiceMode::CapsuleAnchor => {
                        delivered = true;
                        http_json_receipt(&receipt)
                    }
                    ServiceMode::Synchronous => {
                        delivered = true;
                        http_cose(201, &receipt)
                    }
                    ServiceMode::Asynchronous { .. } => format!(
                        "HTTP/1.1 202 Accepted\r\nLocation: {operation}\r\n\
                         Content-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .into_bytes(),
                }
            } else if pending > 0 {
                pending -= 1;
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec()
            } else {
                delivered = true;
                http_cose(200, &receipt)
            };

            let _ = stream.write_all(&response);
            let _ = stream.flush();
            // The service stops once it has handed the receipt over, and not before: a
            // loop that ended when the pending count reached zero would close on the poll
            // BEFORE the one that answers.
            if delivered {
                return;
            }
        }
    });
    (base, handle)
}

/// A `capsule-anchor` `200`: the receipt base64 inside this contract's JSON, beside the
/// unsigned log coordinates the leaf must NOT consume.
fn http_json_receipt(receipt: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let body = serde_json::to_vec(&serde_json::json!({
        "receipt_b64": base64::engine::general_purpose::STANDARD.encode(receipt),
        "entry_hash": "unused-by-the-leaf",
        "entry_hash_scheme": "sig_structure",
        "leaf_index": 0,
        "tree_size": 1,
    }))
    .expect("json");
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    )
    .into_bytes();
    out.extend_from_slice(&body);
    out
}

/// An HTTP response carrying COSE bytes.
fn http_cose(status: u16, body: &[u8]) -> Vec<u8> {
    let reason = if status == 201 { "Created" } else { "OK" };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/cose\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// Run one audit that also registers, and return the artifact it wrote.
fn audit_and_register(
    name: &str,
    nonce: &str,
    mode: ServiceMode,
) -> mcp_re_proxy::transparency::auditor::AttestationArtifact {
    let (scratch, retention, token) = served_archive(name, nonce);
    drop(retention);
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());
    let (base, service) = spawn_transparency_service(mode);

    let mut args = fixtures.args(&scratch.join("evidence"), &[token]);
    args.extend([
        "--register-to".to_owned(),
        base,
        "--registration-protocol".to_owned(),
        mode.protocol().to_owned(),
        "--registration-timeout-secs".to_owned(),
        "20".to_owned(),
        "--registration-poll-interval-secs".to_owned(),
        "1".to_owned(),
    ]);
    let output = run_auditor(&args);
    assert!(
        output.status.success(),
        "the registration did not succeed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let _ = service.join();

    mcp_re_proxy::transparency::auditor::AttestationArtifact::parse(
        &std::fs::read(&fixtures.out).expect("the artifact was written"),
    )
    .expect("the artifact parses")
}

/// THE C2 property, synchronously: the shipped binary registers a real attestation with a
/// service over a socket, and the artifact comes back carrying the receipt.
///
/// The receipt is then re-verified here, WITH NO NETWORK — the service thread has already
/// exited — against the previously captured pin. That is the shape the external
/// interoperability claim is earned in, run against a hermetic service.
#[test]
fn the_auditor_binary_registers_a_statement_and_keeps_a_verified_receipt() {
    let artifact = audit_and_register(
        "auditor-register",
        "nonce-transparency-auditor-register-1",
        ServiceMode::Synchronous,
    );
    assert_receipt_verifies_offline(&artifact);
}

/// The SECOND mechanism, through the same binary: the `capsule-anchor` contract.
///
/// The hermetic service refuses to read this submission the SCRAPI way — it asserts the
/// resource and parses the JSON envelope — so a leaf that sent the other contract's request
/// fails here rather than passing on a family resemblance. What comes back is a receipt
/// inside JSON, and the artifact carries it only because it verified offline.
///
/// It also records WHICH contract answered, which is what stops the claim exceeding the
/// peer: this run is external Transparency Service interoperability, not SCRAPI.
#[test]
fn the_auditor_binary_registers_over_the_second_mechanism_and_records_which_one() {
    let artifact = audit_and_register(
        "auditor-register-capsule",
        "nonce-transparency-auditor-register-capsule-1",
        ServiceMode::CapsuleAnchor,
    );
    assert_receipt_verifies_offline(&artifact);
    assert_eq!(
        artifact.registration_protocol(),
        Some("capsule-anchor /transparency"),
        "the artifact must name the contract that answered, not merely that one did",
    );
}

/// And the SCRAPI path records its own revision, so the two are distinguishable in the
/// artifact rather than only in whoever ran the command.
#[test]
fn a_scrapi_registration_records_the_draft_revision_it_spoke() {
    let artifact = audit_and_register(
        "auditor-register-names-scrapi",
        "nonce-transparency-auditor-register-names-scrapi-1",
        ServiceMode::Synchronous,
    );
    assert_eq!(
        artifact.registration_protocol(),
        Some("draft-ietf-scitt-scrapi-11"),
    );
}

// ---- the LIVE external lane, deliberately off the merge path ----------------
//
// Everything above is hermetic. This one needs a third party's service and a network, so
// it cannot be a merge gate: a red build would then mean "somebody else's server is down".
// It is opt-in, and it is the ONLY thing in this repository that earns the external
// interoperability sentence — the frozen corpus in
// `mcp-re-conformance/tests/vectors/scitt/interop/capsule-anchor-live/` is what one of its
// runs produced.
//
// The reason it is a test rather than a script: the property is about the SHIPPED BINARY
// end to end — serve a call, retain it, attest it, register it, verify the receipt — and a
// script would re-implement the half that matters.

/// The live service's base URL, when an operator asked for the live lane.
fn live_transparency_service() -> Option<(String, std::path::PathBuf)> {
    let url = std::env::var("MCP_RE_LIVE_TRANSPARENCY_SERVICE").ok()?;
    let pin = std::env::var("MCP_RE_LIVE_TRANSPARENCY_PIN").expect(
        "MCP_RE_LIVE_TRANSPARENCY_SERVICE without MCP_RE_LIVE_TRANSPARENCY_PIN: a \
                 receipt is not accepted until it verifies against a pin cut out of band, \
                 so the live lane cannot run without one",
    );
    Some((url, pin.into()))
}

/// THE external-interoperability property: the shipped auditor registers with a
/// Transparency Service SOMEBODY ELSE OPERATES, and keeps a receipt that verified offline
/// against a pin cut before the run.
///
/// Opt-in, via `MCP_RE_LIVE_TRANSPARENCY_SERVICE` and `MCP_RE_LIVE_TRANSPARENCY_PIN`. With
/// them unset this lane MEASURES NOTHING and says so on stdout rather than passing quietly
/// — a green that measured nothing is worse than a red one. With them set nothing about it
/// is tolerant: a service that will not answer, or a receipt that will not verify, fails.
///
/// What a passing run earns is *external Transparency Service interoperability* and exactly
/// that. Whether it also earns *SCRAPI interoperability* depends on which peer answered, and
/// the artifact records which — this lane asserts the artifact says so rather than assuming.
#[test]
fn the_auditor_binary_registers_with_a_live_external_service() {
    let Some((base, pin_path)) = live_transparency_service() else {
        println!(
            "SKIPPED and therefore MEASURED NOTHING: set \
             MCP_RE_LIVE_TRANSPARENCY_SERVICE=<base url> and \
             MCP_RE_LIVE_TRANSPARENCY_PIN=<pin path> to run the live external lane. \
             Do not read this lane's absence as evidence of interoperability."
        );
        return;
    };
    // Named, never guessed — the same rule the auditor itself applies. The default is the
    // contract the one operated peer this project has reached actually speaks; pointing the
    // lane at a SCRAPI peer is a matter of setting this and the pin.
    let protocol = std::env::var("MCP_RE_LIVE_TRANSPARENCY_PROTOCOL")
        .unwrap_or_else(|_| "capsule-anchor".to_owned());

    let (scratch, retention, token) =
        served_archive("auditor-live", "nonce-transparency-auditor-live-1");
    drop(retention);
    let live_pin: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pin_path).expect("the live pin is readable"))
            .expect("the live pin parses");
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), live_pin.clone());

    let mut args = fixtures.args(&scratch.join("evidence"), &[token]);
    args.extend([
        "--register-to".to_owned(),
        base.clone(),
        "--registration-protocol".to_owned(),
        protocol.clone(),
        "--registration-timeout-secs".to_owned(),
        "120".to_owned(),
        "--registration-poll-interval-secs".to_owned(),
        "2".to_owned(),
    ]);
    let output = run_auditor(&args);
    assert!(
        output.status.success(),
        "the live registration with {base} did not succeed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let artifact = mcp_re_proxy::transparency::auditor::AttestationArtifact::parse(
        &std::fs::read(&fixtures.out).expect("the artifact was written"),
    )
    .expect("the artifact parses");

    // The receipt is present ONLY because the auditor verified it offline against the pin
    // above; that is the whole meaning of the field. Re-derived here so the lane states the
    // property rather than trusting the process that just ran.
    let receipt = artifact
        .receipt()
        .expect("a live registration must carry a receipt")
        .expect("the receipt decodes");
    let statement = mcp_re_http_profile::scitt::SignedStatement::from_cose(
        &artifact.signed_statement().expect("the statement decodes"),
    )
    .expect("a Signed Statement");
    let pin: mcp_re_http_profile::scitt::ScittServiceTrustPin =
        serde_json::from_value(live_pin).expect("the pin deserializes");
    mcp_re_http_profile::scitt::verify_receipt_offline(
        &statement,
        &mcp_re_http_profile::scitt::Receipt::from_cose(&receipt).expect("a Receipt"),
        |kid| (kid == ISSUER_KID).then(|| CoseVerificationKey::Ed25519(issuer_key().public_key())),
        |kid| pin.resolve(kid),
    )
    .expect("the live service's receipt verifies offline against the pre-cut pin");

    // The claim may not exceed the peer, so the artifact has to name it.
    let recorded = artifact
        .registration_protocol()
        .expect("a registered artifact names the contract that answered");
    println!(
        "LIVE EXTERNAL RUN: {base} answered over {recorded}; receipt verified offline \
         against {}. This earns external Transparency Service interoperability; it earns \
         SCRAPI interoperability only if {recorded} is a SCRAPI revision.",
        pin_path.display(),
    );
    assert!(
        !recorded.is_empty(),
        "a registered artifact must name a contract",
    );
}

/// The asynchronous path — `202` → `204` → `204` → `200` — through the same binary.
#[test]
fn the_auditor_binary_polls_an_asynchronous_registration_to_its_receipt() {
    let artifact = audit_and_register(
        "auditor-register-async",
        "nonce-transparency-auditor-register-async-2",
        ServiceMode::Asynchronous { pending: 2 },
    );
    assert_receipt_verifies_offline(&artifact);
}

/// The receipt an artifact carries verifies offline against the statement beside it and
/// the pin the operator captured — contacting nobody.
fn assert_receipt_verifies_offline(
    artifact: &mcp_re_proxy::transparency::auditor::AttestationArtifact,
) {
    let statement = mcp_re_http_profile::scitt::SignedStatement::from_cose(
        &artifact.signed_statement().expect("the statement decodes"),
    )
    .expect("a Signed Statement");
    let receipt_bytes = artifact
        .receipt()
        .expect("a registered artifact carries a receipt")
        .expect("the receipt decodes");
    let receipt =
        mcp_re_http_profile::scitt::Receipt::from_cose(&receipt_bytes).expect("a Receipt");

    mcp_re_http_profile::scitt::verify_receipt_offline(
        &statement,
        &receipt,
        |kid| (kid == ISSUER_KID).then(|| CoseVerificationKey::Ed25519(issuer_key().public_key())),
        |kid| {
            (kid == TS_KID).then(|| {
                ResolvedTransparencyService::stated(
                    CoseVerificationKey::Ed25519(ts_key().public_key()),
                    StatementLeafProfile::StatementBytes,
                    ReceiptPositionProfile::Bound,
                )
            })
        },
    )
    .expect("the archived receipt verifies with no service running");
}

/// A registration that does not succeed does NOT cost the attestation.
///
/// The auditor writes the artifact before it submits anything, so an operator who cannot
/// reach a transparency service still holds a portable, offline-verifiable record. The
/// exit status is non-zero and the artifact is on disk with no receipt — which is the
/// honest pair of facts.
#[test]
fn a_failed_registration_leaves_the_attestation_behind() {
    let (scratch, retention, token) =
        served_archive("auditor-register-down", "nonce-transparency-auditor-down-3");
    drop(retention);
    let fixtures = AuditFixtures::write(&scratch, audit_profile_json(), service_pin_json());

    // A port nothing is listening on: bind it, learn the number, drop the listener.
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        probe.local_addr().expect("addr").port()
    };

    let mut args = fixtures.args(&scratch.join("evidence"), &[token]);
    args.extend([
        "--register-to".to_owned(),
        format!("http://127.0.0.1:{port}"),
        "--registration-timeout-secs".to_owned(),
        "2".to_owned(),
        "--registration-poll-interval-secs".to_owned(),
        "1".to_owned(),
    ]);
    let output = run_auditor(&args);

    assert!(
        !output.status.success(),
        "a registration that did not happen must not read as success",
    );
    let artifact = mcp_re_proxy::transparency::auditor::AttestationArtifact::parse(
        &std::fs::read(&fixtures.out).expect("the attestation survives a failed submission"),
    )
    .expect("the artifact parses");
    assert!(
        artifact.receipt().is_none(),
        "no receipt was verified, so the artifact must carry none",
    );
    assert!(
        artifact.chain().is_complete(),
        "and the attestation itself is unaffected",
    );

    // The message must preserve the certainty: the statement went nowhere we can prove.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("the attestation was written"),
        "an operator must be told the record survived: {stderr}",
    );
    assert!(
        stderr.contains("draft-ietf-scitt-scrapi-11"),
        "and which protocol revision was attempted: {stderr}",
    );
}
