// SPDX-License-Identifier: Apache-2.0
//! Live GCP Cloud KMS — ADR-MCPRE-052 delegated-REQUIRED serving + authority-flip
//! lanes (MCPRE-122 / #328). The local pre-GKE gate for running the delegated path
//! on a REAL Cloud KMS root.
//!
//! The sibling `gcp_kms_delegated_signing_live_test` proves the custody state
//! machine with a KMS root (issuance/rotation/verify, zero per-request KMS ops).
//! THIS lane goes two steps further, on the same KMS key:
//!
//!   * **Serving** — drives the PRODUCTION wiring `build_delegated_signing(config,
//!     kms_root)` + `HttpProfileProxy::new_delegated` — the exact path `app::run`
//!     takes for delegated-signing (the only response mode) — and serves real
//!     requests through the PEP. The KMS root is wrapped in a counting
//!     `ResponseSigner` so the load-bearing property is asserted at the SERVING
//!     altitude: N served responses invoke Cloud KMS ZERO extra times (one op per
//!     key issuance/rotation, none per request). Also proves bound rejection,
//!     rotation to a successor, and the client revocation seam (allow + deny) on a
//!     KMS-rooted credential.
//!
//!   * **Authority flip** — on ONE KMS key, demonstrates the response-signing
//!     authority cutover is a real security boundary, not cosmetic:
//!       1. the PRE-052 authority (the KMS signs the response DIRECTLY, with no
//!          delegation evidence block) is REJECTED by a delegated-required verifier
//!          (fails closed) — no downgrade to the old response authority;
//!       2. the POST-052 authority (the KMS ISSUES a credential; an in-memory
//!          delegated key signs) is ACCEPTED;
//!       3. a TRUST-EPOCH flip: a KMS-rooted credential minted under the old epoch
//!          is rejected once the accepted-epoch set advances
//!          (`delegation_trust_epoch_stale`), and accepted under a bounded-rollout
//!          `{new, old}` window;
//!       4. a KEY-authority rotation + revocation flip: after the KMS issues a
//!          successor, revoking the predecessor kid fails its responses closed
//!          (`delegation_revoked`) while the successor's still verify.
//!
//! Both lanes share the offline/live entry-point pattern of the sibling test:
//!   * `*_offline_local_seed` — NOT ignored: the feature-gated CI job runs it via
//!     `GcpKmsEd25519Backend::for_test_with_local_seed` (no network), guarding the
//!     KMS-root → serving/flip wiring on every push.
//!   * `*_live` — `#[ignore]`: the real Cloud KMS backend; run from
//!     `work/test-gcp-cloud.sh` (or `docs/security/gcp-kms-delegated-required.sh`)
//!     with `-- --ignored` and `MCP_RE_GCP_*` set. FAILS LOUDLY if unconfigured.
//!
//! Required environment for the live lanes:
//!   * `MCP_RE_GCP_KEY_VERSION`  — full `EC_SIGN_ED25519` key-version resource path.
//!   * `MCP_RE_GCP_ACCESS_TOKEN` (bearer) or `MCP_RE_GCP_USE_METADATA=1`.
//!   * `MCP_RE_GCP_KMS_ENDPOINT` — OPTIONAL emulator endpoint override.
#![cfg(feature = "gcp_kms_keysource")]

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::issue_delegation_credential_with_signer;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_with_signer;
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
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedHttpRequestEvidence;
use mcp_re_http_profile::PROFILE_TAG;

use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::async_serve::ServedHttpResponse;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::GcpKmsConfig;
use mcp_re_proxy::GcpKmsEd25519Backend;
use mcp_re_proxy::HttpProfileProxy;
use mcp_re_proxy::KeyError;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const NOW: i64 = 1_700_000_100;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";
const CLIENT_KEY_ID: &str = "client-key-1";
// The KMS root's issuer kid == the serving config's --server-key-id. The credential
// the KMS signs carries this issuer; the verifier resolves it to the KMS public key.
const ROOT_KID: &str = "gcp-kms-root-1";
const VERIFIER_AUD: &str = "verifier-1";
const EPOCH: &str = "epoch-1";
const NEW_EPOCH: &str = "epoch-2";
const TTL: i64 = 300;
const OVERLAP: i64 = 60;
// A batch comfortably larger than 1, to prove the KMS is not touched per request.
const RESPONSES_PER_KEY: usize = 8;

// --- KMS signer construction (identical policy to the sibling live test) --------

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "gcp-kms delegated-required lane: required env var {name} is not set — this lane must \
             run against a real/emulated Cloud KMS; it does not pass without verifying"
        ),
    }
}

/// The live Cloud KMS signer (root issuer), failing loudly if unconfigured.
fn live_signer() -> KmsResponseSigner {
    let config = GcpKmsConfig {
        key_version_name: require_env("MCP_RE_GCP_KEY_VERSION"),
        endpoint: std::env::var("MCP_RE_GCP_KMS_ENDPOINT").ok().filter(|s| !s.is_empty()),
    };
    let use_metadata = std::env::var("MCP_RE_GCP_USE_METADATA").is_ok_and(|v| v == "1");
    if !use_metadata {
        require_env("MCP_RE_GCP_ACCESS_TOKEN");
    }
    let backend = GcpKmsEd25519Backend::new(&config, use_metadata)
        .expect("construct GCP KMS backend (getPublicKey must succeed and be Ed25519)");
    KmsResponseSigner::new(Box::new(backend))
}

/// An offline signer over the SAME backend adapter (local seed, no network) —
/// exercises the KMS-root → serving/flip wiring hermetically in CI.
fn offline_signer() -> KmsResponseSigner {
    let backend = GcpKmsEd25519Backend::for_test_with_local_seed(&[7u8; 32])
        .expect("local-seed KMS backend");
    KmsResponseSigner::new(Box::new(backend))
}

/// A `ResponseSigner` that wraps the KMS root and counts EVERY real signing call.
/// Passing this as the root to `build_delegated_signing` lets the SERVING lane
/// assert the KMS is invoked only at issuance/rotation — never on the request path.
struct CountingRootSigner {
    inner: KmsResponseSigner,
    calls: Arc<AtomicUsize>,
}

impl ResponseSigner for CountingRootSigner {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_response(preimage)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        self.inner.response_public_key()
    }
}

// --- shared request/response/resolver/config helpers ---------------------------

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

/// Resolver: the client key for the Request slot, the KMS ROOT public key (by its
/// issuer kid) for the Response slot. The DELEGATED key is never enrolled; the
/// KMS-signed credential authorizes it.
fn resolver(root_pub: VerificationKey) -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> + Send + Sync + Clone {
    let client_pub = client_key().public_key();
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_pub.clone()),
            (ROOT_KID, SignerSlot::Response) => ("server", root_pub.clone()),
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

fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        policy: mcp_re_http_profile::VerifierPolicy::default(),
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: VERIFIER_AUD,
        accepted_epochs: epochs,
        max_clock_skew: 60,
    }
}

fn custody_cfg() -> CustodyConfig {
    CustodyConfig {
        issuer_kid: ROOT_KID.into(),
        iss: "did:example:server".into(),
        profile: PROFILE_TAG.into(),
        aud: VERIFIER_AUD.into(),
        audience_hash: VERIFIER_AUD.into(),
        trust_epoch: EPOCH.into(),
        server_role: "server".into(),
        server_trust_domain: "example.com".into(),
        server_subject: "did:example:server".into(),
        ttl: TTL,
        overlap: OVERLAP,
    }
}

/// The production serving Config in delegated-required mode (parser-produced, as the
/// binary does). Filesystem paths are placeholders — the delegated wiring reads
/// config fields, not files. `--server-key-id` becomes the credential issuer kid.
fn delegated_config() -> mcp_re_proxy::cli::Config {
    let args: Vec<String> = [
        "--bind", "127.0.0.1:8443",
        "--audience", VERIFIER_AUD,
        "--server-signer", "did:example:server",
        "--server-key-id", ROOT_KID,
        "--signing-key-seed", "/dev/null",
        "--tls-cert", "/dev/null",
        "--tls-key", "/dev/null",
        "--client-ca", "/dev/null",
        "--trust", "/dev/null",
        "--inner-http-url", "http://127.0.0.1:9",
        "--target-uri", TARGET,
        "--route", "a",
        "--replay-cache", "file",
        "--replay-path", "/tmp/mcp-re-gcp-delegated-required-replay",
        "--delegated-trust-epoch", EPOCH,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    mcp_re_proxy::cli::parse_args(&args).expect("parse delegated-required serving config")
}

fn base_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec(),
    }
}

/// A client-signed request whose freshness window brackets the serve instant `at`
/// (so serving at `at` exercises the SIGNING step, not a freshness rejection),
/// verified at `at` for the response binding. `nonce` distinguishes replays.
fn signed_request(nonce: &str, at: i64) -> (HttpRequest, RequestEvidence, VerifiedHttpRequestEvidence) {
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
    };
    let mut req = base_request();
    let evidence = sign_request_full(
        &mut req,
        &block,
        &client_key(),
        CLIENT_KEY_ID,
        at - 100,
        at + 200,
        nonce,
    )
    .expect("client signs RFC 9421 request");
    let no_material = |_b: &ArtifactBinding| None;
    let r = resolver_client_only();
    let verified = verify_request_full(&req, &audience(), &no_material, &r, at)
        .expect("client's own request verifies (for response binding)");
    (req, evidence, verified)
}

/// Request-leg resolver (client key only); the response root is resolved separately
/// against the concrete KMS public key.
fn resolver_client_only() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    let client_pub = client_key().public_key();
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:client".into(),
                keyid: CLIENT_KEY_ID.into(),
            },
            verification_key: client_pub.clone(),
            slot,
        }),
        _ => None,
    }
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

fn canned_inner() -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
    Box::new(|_forwarded: &[u8]| -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
    })
}

fn fresh_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    }
}

// ========================================================================
// LANE A — the PRODUCTION serving path on the KMS root
// ========================================================================

async fn run_kms_delegated_required_serving(root: KmsResponseSigner) {
    let root_pub = root.response_public_key().expect("KMS root public key");
    let kms_calls = Arc::new(AtomicUsize::new(0));
    let counting = CountingRootSigner { inner: root, calls: Arc::clone(&kms_calls) };

    // Build the serving proxy EXACTLY as `app::run` does in delegated-required mode:
    // `build_delegated_signing` off the KMS root, then `new_delegated`.
    let config = delegated_config();
    let wiring = mcp_re_proxy::build_delegated_signing(&config, counting)
        .expect("build delegated signing wiring from config + KMS root");
    let signer = Arc::clone(&wiring.signer);
    let mut rotor = wiring.rotor;

    let expected_audience = AudienceTuple {
        audience_id: config.audience.clone(),
        target_uri: config.target_uri.clone(),
        route: config.route.clone(),
    };
    let r = resolver(root_pub.clone());
    let actor_resolver: ActorResolver = Box::new(move |k: &str, s| r(k, s));
    let proxy = HttpProfileProxy::new_delegated(
        actor_resolver,
        expected_audience,
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig { fleet_strict: false, tier: None },
        canned_inner(),
        300,
        Arc::clone(&wiring.signer),
    );

    // Startup issuance: the KMS signs the FIRST credential (one KMS op).
    rotor.rotate(NOW).expect("startup issuance mints the first delegated key via the KMS root");
    assert_eq!(kms_calls.load(Ordering::SeqCst), 1, "startup issuance is exactly one KMS op");
    let first_kid = signer.current(NOW).expect("a key is published").delegated_kid.clone();
    assert_eq!(first_kid, format!("{ROOT_KID}/delegated/1"));

    // Serve a batch under the one delegated key; each response verifies via the
    // credential→KMS-root chain, signed by the DELEGATED key (not the root).
    for i in 0..RESPONSES_PER_KEY {
        let (req, _ev, verified_req) = signed_request(&format!("nonce-serve-{i}"), NOW);
        let served = proxy.handle(served_of(&req), NOW).await;
        assert_eq!(served.status, 200, "delegated-required request served");
        let resp = http_response(served);
        let verified = verify_delegated_response_full(
            &resp,
            &req,
            &verified_req,
            &resolver(root_pub.clone()),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .expect("served response verifies via the KMS-rooted attestation chain");
        assert_eq!(
            verified.server_signer.as_ref().unwrap().keyid,
            first_kid,
            "signed by the delegated key, not the KMS root"
        );
    }

    // THE load-bearing property at the serving altitude: N responses, KMS untouched
    // beyond the single issuance.
    assert_eq!(
        kms_calls.load(Ordering::SeqCst),
        1,
        "serving {RESPONSES_PER_KEY} responses invoked Cloud KMS ZERO extra times — no KMS on the hot path"
    );

    // Revocation seam (deny): the client denylists the active delegated kid → the
    // otherwise-valid response fails closed.
    let (req, _ev, verified_req) = signed_request("nonce-revoke", NOW);
    let resp = http_response(proxy.handle(served_of(&req), NOW).await);
    let revoked_kid = first_kid.clone();
    let deny = verify_delegated_response_full(
        &resp,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &|id: &str| id == revoked_kid,
        NOW,
    )
    .unwrap_err();
    assert_eq!(deny, HttpProfileError::DelegationRevoked, "revoked delegated kid fails closed");
    // Revocation seam (allow): a non-empty denylist that does NOT name this kid still verifies.
    verify_delegated_response_full(
        &resp,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &|id: &str| id == "some-other/delegated/9",
        NOW,
    )
    .expect("a non-matching denylist does not blanket-deny");

    // Rotation: cross into the overlap window → the KMS signs the SUCCESSOR
    // credential (one more KMS op), and the new response verifies under it.
    let after = NOW + TTL - OVERLAP + 10;
    rotor.rotate(after).expect("rotation mints a successor via the KMS root");
    assert_eq!(kms_calls.load(Ordering::SeqCst), 2, "rotation is exactly one more KMS op");
    let second_kid = signer.current(after).expect("successor published").delegated_kid.clone();
    assert_ne!(first_kid, second_kid, "rotation mints a distinct delegated key");

    let (req2, _ev2, verified_req2) = signed_request("nonce-after-rotation", after);
    let resp2 = http_response(proxy.handle(served_of(&req2), after).await);
    let verified2 = verify_delegated_response_full(
        &resp2,
        &req2,
        &verified_req2,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &|_| false,
        after,
    )
    .expect("post-rotation response verifies");
    assert_eq!(
        verified2.server_signer.as_ref().unwrap().keyid,
        second_kid,
        "post-rotation responses are signed by the successor delegated key"
    );
}

// ========================================================================
// LANE B — the authority flip, on ONE KMS key
// ========================================================================

/// A custody state machine whose ROOT issuer is the KMS `signer`, plus a shared
/// KMS-call counter. Returns the custody + counter so the flip lane can mint
/// KMS-rooted delegated responses.
fn kms_custody(
    signer: KmsResponseSigner,
    kms_calls: Arc<AtomicUsize>,
) -> DelegatedSigningCustody<
    impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
    impl FnMut() -> SigningKey,
> {
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| -> Option<String> {
        issue_delegation_credential_with_signer(h, c, |input| {
            kms_calls.fetch_add(1, Ordering::SeqCst);
            let b64 = signer.sign_response(input).map_err(|_| HttpProfileError::InvalidSignature)?;
            b64url_decode(&b64).map_err(|_| HttpProfileError::InvalidSignature)
        })
        .ok()
    };
    let mut seed = 100u8;
    let factory = move || {
        seed = seed.wrapping_add(1);
        SigningKey::from_seed_bytes(&[seed; 32])
    };
    DelegatedSigningCustody::new(custody_cfg(), issue, factory)
}

fn run_kms_authority_flip(root: KmsResponseSigner) {
    let root_pub = root.response_public_key().expect("KMS root public key");
    let (req, ev, verified_req) = signed_request("nonce-flip", NOW);

    // --- Flip 1: the PRE-052 authority (KMS signs the response DIRECTLY) is
    // rejected by a delegated-required verifier — no downgrade. The SAME KMS key
    // that (post-052) issues credentials here signs a response directly, with NO
    // inline credential, exactly as a pre-052 direct-root server would.
    let mut direct = fresh_response();
    sign_response_with_signer(
        &mut direct,
        &req,
        |base| {
            let b64 = root.sign_response(base).map_err(|_| HttpProfileError::InvalidSignature)?;
            b64url_decode(&b64).map_err(|_| HttpProfileError::InvalidSignature)
        },
        ROOT_KID,
        NOW - 100,
        NOW + 200,
    )
    .expect("the KMS signs a direct-root RFC 9421 response");
    let downgrade = verify_delegated_response_full(
        &direct,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &|_| false,
        NOW,
    )
    .unwrap_err();
    // A genuine pre-052 direct-root response carries NO delegation evidence block at
    // all (unlike a delegation block with the credential stripped), so it fails
    // closed here — the delegated-required verifier will not accept the old
    // response authority. Fail-closed rejection is the property; the exact code is
    // MissingEvidence for this shape.
    assert!(
        matches!(downgrade, HttpProfileError::MissingEvidence(_)),
        "flipping response authority to delegated-required REJECTS a pre-052 direct-root \
         response (no delegation evidence block); got {downgrade:?}"
    );

    // --- Flip 2 (post-052 authority accepted) + the KMS issues the credential.
    let kms_calls = Arc::new(AtomicUsize::new(0));
    let mut custody = kms_custody(root, Arc::clone(&kms_calls));

    let mut delegated = fresh_response();
    custody.sign_response(NOW, &mut delegated, &req, &ev).expect("KMS-rooted custody signs");
    let first_kid = custody.active_kid().expect("a key is active").to_owned();
    assert_eq!(kms_calls.load(Ordering::SeqCst), 1, "the KMS issued exactly one credential");
    verify_delegated_response_full(
        &delegated,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &|_| false,
        NOW,
    )
    .expect("the delegated (post-052) authority is accepted");

    // --- Flip 3: TRUST-EPOCH flip. The credential is bound to EPOCH. Advancing the
    // accepted set to NEW_EPOCH alone rejects it; a bounded-rollout {new, old}
    // window accepts it (ADR-MCPRE-052 §7).
    let stale = verify_delegated_response_full(
        &delegated,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[NEW_EPOCH]),
        &|_| false,
        NOW,
    )
    .unwrap_err();
    assert_eq!(
        stale,
        HttpProfileError::DelegationTrustEpochStale,
        "advancing the trust epoch rejects a credential minted under the old authority epoch"
    );
    verify_delegated_response_full(
        &delegated,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[NEW_EPOCH, EPOCH]),
        &|_| false,
        NOW,
    )
    .expect("a bounded-rollout {new, old} epoch window accepts the old-epoch credential");

    // --- Flip 4: KEY-authority rotation + revocation. The KMS issues a successor;
    // revoking the predecessor kid fails its responses closed while the successor's
    // verify. The predecessor response was minted at NOW; re-sign a fresh one so
    // both keys are simultaneously within their TTL at the overlap instant.
    let mut predecessor = fresh_response();
    custody.sign_response(NOW, &mut predecessor, &req, &ev).expect("predecessor signs");

    let after = NOW + TTL - OVERLAP + 10;
    let mut successor = fresh_response();
    custody.sign_response(after, &mut successor, &req, &ev).expect("KMS issues the successor");
    let second_kid = custody.active_kid().expect("successor active").to_owned();
    assert_ne!(first_kid, second_kid, "rotation mints a distinct delegated authority");
    assert_eq!(kms_calls.load(Ordering::SeqCst), 2, "the KMS issued exactly two credentials total");

    // Revoke the PREDECESSOR authority. The successor still verifies; the predecessor
    // fails closed — a revoked authority cannot serve even during the overlap.
    let revoke_first = |id: &str| id == first_kid;
    verify_delegated_response_full(
        &successor,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &revoke_first,
        after,
    )
    .expect("the successor (new authority) still verifies while the predecessor is revoked");
    let revoked = verify_delegated_response_full(
        &predecessor,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &revoke_first,
        after,
    )
    .unwrap_err();
    assert_eq!(
        revoked,
        HttpProfileError::DelegationRevoked,
        "revoking the predecessor authority fails its responses closed"
    );
}

// ---- offline (hermetic, runs in the feature-gated CI job) ------------------

#[tokio::test]
async fn gcp_kms_delegated_required_serving_offline_local_seed() {
    run_kms_delegated_required_serving(offline_signer()).await;
}

#[test]
fn gcp_kms_authority_flip_offline_local_seed() {
    run_kms_authority_flip(offline_signer());
}

// ---- live (real Cloud KMS; ignored) ---------------------------------------

#[tokio::test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCP_RE_GCP_* set)"]
async fn gcp_kms_delegated_required_serving_live() {
    run_kms_delegated_required_serving(live_signer()).await;
}

#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCP_RE_GCP_* set)"]
fn gcp_kms_authority_flip_live() {
    run_kms_authority_flip(live_signer());
}
