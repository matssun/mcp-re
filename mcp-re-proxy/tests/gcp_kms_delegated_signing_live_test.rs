// SPDX-License-Identifier: Apache-2.0
//! Live GCP Cloud KMS — ADR-MCPRE-052 delegated-signing custody lane
//! (MCPRE-122 / #328).
//!
//! The sibling `gcp_kms_http_profile_live_test` proves Cloud KMS can sign an
//! RFC 9421 response DIRECTLY — one KMS `asymmetricSign` PER response, i.e. the
//! root key is on the hot path. This lane proves the ADR-MCPRE-052 posture that
//! removes it from the hot path: Cloud KMS is the root ISSUER that signs only a
//! short-lived compact-JWS **delegation credential** at issuance/rotation, while
//! an in-memory Ed25519 **delegated** key signs the per-request RFC 9421
//! responses. The load-bearing property proven here:
//!
//!   **Zero remote KMS operations on the per-request signing path** — signing N
//!   responses within one delegated key's life invokes Cloud KMS exactly once
//!   (the initial issuance), and `verify_delegated_response_full` accepts each
//!   response via the credential's attestation chain back to the KMS root.
//!
//! It wires `GcpKmsEd25519Backend` as the custody root issuer through the
//! wire-identical KMS seam `issue_delegation_credential_with_signer` (the same
//! seam the in-process reference issuer uses), so the KMS is a swap of the
//! injected issuer, not a code fork.
//!
//! Two entry points share one lane body:
//!   * `*_offline_local_seed` — NOT ignored: runs in the blocking feature-gated
//!     CI job via `GcpKmsEd25519Backend::for_test_with_local_seed` (no network),
//!     guarding the KMS-backend → custody-issuer wiring on every push.
//!   * `*_live` — `#[ignore]`: the real Cloud KMS backend; run from the cloud
//!     script / nightly lane with `-- --ignored` and `MCP_RE_GCP_*` set. FAILS
//!     LOUDLY if its configuration is absent — never a silent pass.
//!
//! Required environment for the live lane:
//!   * `MCP_RE_GCP_KEY_VERSION`  — full `EC_SIGN_ED25519` key-version resource path.
//!   * `MCP_RE_GCP_ACCESS_TOKEN` (bearer) or `MCP_RE_GCP_USE_METADATA=1`.
//!   * `MCP_RE_GCP_KMS_ENDPOINT` — OPTIONAL emulator endpoint override.
#![cfg(feature = "gcp_kms_keysource")]

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential_with_signer;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::verify_delegated_response_full;
use mcp_re_http_profile::verify_request_full;
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
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::PROFILE_TAG;
use mcp_re_proxy::GcpKmsConfig;
use mcp_re_proxy::GcpKmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;
use mcp_re_proxy::ResponseSigner;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";

// The KMS root's `issuer_kid` (the identity anchor the verifier trusts). The
// delegated key ids the custody mints are `<ROOT_KID>/delegated/<n>`.
const ROOT_KID: &str = "gcp-kms-root-1";
const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";

// Custody policy: delegated-key TTL `T` and rotation-overlap window `O` (0 < O < T).
const TTL: i64 = 300;
const OVERLAP: i64 = 60;
// A batch of per-request signs comfortably larger than 1, to prove the KMS is not
// touched per request.
const RESPONSES_PER_KEY: usize = 8;

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "gcp-kms delegated-signing lane: required env var {name} is not set — this lane must \
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

/// An offline signer over the SAME backend adapter, using a local seed instead of
/// a network round-trip — exercises the KMS-backend → custody-issuer wiring
/// hermetically.
fn offline_signer() -> KmsResponseSigner {
    let backend = GcpKmsEd25519Backend::for_test_with_local_seed(&[7u8; 32])
        .expect("local-seed KMS backend");
    KmsResponseSigner::new(Box::new(backend))
}

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

fn no_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |_b: &ArtifactBinding| None
}

/// Resolver: the client key for the Request slot, and the KMS ROOT public key
/// (by its `issuer_kid`) for the Response slot — the credential's issuer is
/// resolved for the Response slot. The DELEGATED key is NEVER enrolled here; it is
/// authorized by the KMS-signed credential alone.
fn resolver(root_pub: mcp_re_core::VerificationKey) -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    let client_pub = client_key().public_key();
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            ("client-key-1", SignerSlot::Request) => ("client", client_pub.clone()),
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

fn signed_request() -> (HttpRequest, RequestEvidence, VerifiedHttpRequestEvidence) {
    let mut req = base_request();
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
            admission: None,
    };
    let ev = sign_request_full(
        &mut req,
        &block,
        &client_key(),
        "client-key-1",
        CREATED,
        EXPIRES,
        "nonce-1",
    )
    .expect("sign request");
    let verified = verify_request_full(&req, &audience(), &no_material(), &resolver_client_only(), NOW)
        .expect("verify request");
    (req, ev, verified)
}

/// The request-leg verify only needs the client key; the response root is resolved
/// later against the concrete KMS public key.
fn resolver_client_only() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    let client_pub = client_key().public_key();
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        ("client-key-1", SignerSlot::Request) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:client".into(),
                keyid: "client-key-1".into(),
            },
            verification_key: client_pub.clone(),
            slot,
        }),
        _ => None,
    }
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

fn expectations<'a>(epochs: &'a [&'a str]) -> DelegationExpectations<'a> {
    DelegationExpectations {
        policy: mcp_re_http_profile::VerifierPolicy::default(),
        verifier_audiences: &[VERIFIER_AUD],
        expected_audience_hash: AUD_SCOPE,
        accepted_epochs: epochs,
        max_clock_skew: 60,
    }
}

fn fresh_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    }
}

/// The lane body: drive the ADR-052 custody state machine with `signer` as the KMS
/// ROOT issuer and prove zero KMS ops on the per-request path, a verifiable
/// attestation chain to the KMS root, rotation overlap (no verification gap), and a
/// fail-closed body tamper.
fn run_delegated_custody_lane(signer: KmsResponseSigner) {
    let (req, ev, verified_req) = signed_request();
    let root_pub = signer.response_public_key().expect("KMS root public key");

    // Count REAL KMS invocations: the issuer closure is the ONLY place the KMS is
    // touched, so a per-request sign that hit the KMS would bump this.
    let kms_calls = Arc::new(AtomicUsize::new(0));
    let kms_calls_issuer = Arc::clone(&kms_calls);

    // Wire the KMS backend as the custody root issuer through the wire-identical
    // seam: the KMS signs the compact-JWS credential's signing input at
    // issuance/rotation; the returned base64url raw Ed25519 signature is decoded to
    // the 64 bytes the JWS carries.
    let issue = move |h: &DelegationHeader, c: &DelegationClaims| -> Option<String> {
        issue_delegation_credential_with_signer(h, c, |input| {
            kms_calls_issuer.fetch_add(1, Ordering::SeqCst);
            let b64 = signer
                .sign_response(input)
                .map_err(|_| HttpProfileError::InvalidSignature)?;
            b64url_decode(&b64).map_err(|_| HttpProfileError::InvalidSignature)
        })
        .ok()
    };
    // Deterministic in-memory delegated-key factory (a distinct key per rotation).
    let mut seed = 100u8;
    let factory = move || {
        seed = seed.wrapping_add(1);
        SigningKey::from_seed_bytes(&[seed; 32])
    };

    let mut custody = DelegatedSigningCustody::new(custody_cfg(), issue, factory);

    // --- Batch 1: N per-request signs under one delegated key -----------------
    // Keep one predecessor-signed response to re-verify across the rotation.
    let mut predecessor_rsp = fresh_response();
    custody
        .sign_response(NOW, &mut predecessor_rsp, &req, &ev)
        .expect("custody signs (issuance)");
    let first_kid = custody.active_kid().expect("a key is active").to_owned();

    for _ in 1..RESPONSES_PER_KEY {
        let mut rsp = fresh_response();
        custody
            .sign_response(NOW, &mut rsp, &req, &ev)
            .expect("custody signs (hot path)");
        verify_delegated_response_full(
            &rsp,
            &req,
            &verified_req,
            &resolver(root_pub.clone()),
            &expectations(&[EPOCH]),
            &|_| false,
            NOW,
        )
        .expect("delegated response verifies via the KMS-rooted attestation chain");
    }

    // The load-bearing assertion: N responses signed, KMS touched exactly ONCE.
    assert_eq!(
        kms_calls.load(Ordering::SeqCst),
        1,
        "the KMS root must be invoked ONLY at issuance — zero remote KMS ops on the per-request path"
    );
    assert_eq!(
        custody.root_invocations(),
        1,
        "custody must record exactly one root invocation across the whole batch"
    );
    assert_eq!(
        custody.root_invocations() as usize,
        kms_calls.load(Ordering::SeqCst),
        "every root invocation is exactly one KMS call — and no more"
    );

    // The predecessor response verifies now (before rotation).
    verify_delegated_response_full(
        &predecessor_rsp,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &|_| false,
        NOW,
    )
    .expect("predecessor response verifies before rotation");

    // --- Rotation: cross into the overlap window (now >= exp - overlap) --------
    // exp = NOW + TTL; rotation is due at NOW + TTL - OVERLAP. Sign past it.
    let after = NOW + TTL - OVERLAP + 10;
    let mut successor_rsp = fresh_response();
    custody
        .sign_response(after, &mut successor_rsp, &req, &ev)
        .expect("custody signs (rotation)");
    let second_kid = custody.active_kid().expect("a successor key is active").to_owned();

    assert_ne!(first_kid, second_kid, "rotation must mint a distinct delegated key");
    assert_eq!(
        kms_calls.load(Ordering::SeqCst),
        2,
        "rotation invokes the KMS root exactly once more (successor credential)"
    );

    // No verification gap: the successor response verifies AND the predecessor —
    // minted under the first key, still within its own TTL — is still accepted at
    // the overlap instant (both keys simultaneously valid).
    verify_delegated_response_full(
        &successor_rsp,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &|_| false,
        after,
    )
    .expect("successor response verifies after rotation");
    verify_delegated_response_full(
        &predecessor_rsp,
        &req,
        &verified_req,
        &resolver(root_pub.clone()),
        &expectations(&[EPOCH]),
        &|_| false,
        after,
    )
    .expect("predecessor response still verifies during the overlap window (no gap)");

    // --- Audited lifecycle: issue then rotate ---------------------------------
    let audit = custody.audit();
    assert_eq!(audit.len(), 2, "one issuance + one rotation audited");
    assert_eq!(audit[0].event_type, "mcp-re.delegated_key.issued");
    assert_eq!(audit[0].delegated_kid, first_kid);
    assert_eq!(audit[0].issuer_kid, ROOT_KID);
    assert_eq!(audit[1].event_type, "mcp-re.delegated_key.rotated");
    assert_eq!(audit[1].delegated_kid, second_kid);

    // --- Negative: a body tamper on a delegated response fails closed ---------
    let mut tampered = fresh_response();
    custody
        .sign_response(after, &mut tampered, &req, &ev)
        .expect("custody signs");
    let last = tampered.body.len() - 2;
    tampered.body[last] ^= 0x01;
    assert_eq!(
        verify_delegated_response_full(
            &tampered,
            &req,
            &verified_req,
            &resolver(root_pub.clone()),
            &expectations(&[EPOCH]),
            &|_| false,
            after,
        )
        .unwrap_err(),
        HttpProfileError::ContentDigestMismatch,
        "a post-signing body tamper on a delegated response must fail closed"
    );
}

// ---- offline (hermetic, runs in blocking CI) ------------------------------

#[test]
fn gcp_kms_delegated_signing_offline_local_seed() {
    run_delegated_custody_lane(offline_signer());
}

// ---- live (real Cloud KMS; ignored) ---------------------------------------

#[test]
#[ignore = "requires a live or emulated GCP Cloud KMS (run with --ignored and MCP_RE_GCP_* set)"]
fn gcp_kms_delegated_signing_live() {
    run_delegated_custody_lane(live_signer());
}
