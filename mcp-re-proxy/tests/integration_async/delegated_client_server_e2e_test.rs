// SPDX-License-Identifier: Apache-2.0
//! Full MCP-RE client↔server round-trip in delegated-required mode (MCPRE-122).
//!
//!   plain MCP client
//!     → MCP-RE client proxy  (mcp-re-client-proxy: signs RFC 9421/9530)
//!     → in-process network    (RemoteTransport)
//!     → MCP-RE server proxy    (mcp-re-proxy HttpProfileProxy, delegated-required)
//!     → backend MCP server     (canned inner)
//!     → delegated response / rejection receipt
//!     → client proxy verifies  (delegated credential chain to the root)
//!     → plain MCP back to the local client
//!
//! Both ends are the REAL production types: the server is built through the real
//! `build_delegated_signing` + `HttpProfileProxy::new_delegated` (root issuer off the
//! request path); the client is the real `ClientProxy` in `DelegatedRequired` mode.
//! The root issuer is an in-memory `SigningKey` (the KMS-root swap is proven through
//! the same seam by `gcp_kms_delegated_signing_live_test`), so this lane is hermetic.
//!
//! Proves the end-to-end contract:
//!   * a plain request round-trips to a delegated-signed success the client verifies
//!     via the credential→root chain and hands back as plain MCP;
//!   * a replay is rejected server-side with a delegated, request-BOUND rejection
//!     receipt that the client verifies and classifies (`mcp-re.replay_detected`),
//!     converting it to a plain JSON-RPC error (fail closed);
//!   * a direct-root server (wrong profile) is refused by the delegated-required
//!     client — no downgrade.

use std::sync::Arc;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve::ServedHttpRequest;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::HttpProfileProxy;

use mcp_re_client_core::verify_delegated_response;
use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::DelegatedOutcome;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::ManifestVersionFloor;
use mcp_re_client_core::ResponseExpectation;
use mcp_re_client_core::RevocationSource;
use mcp_re_client_core::StaticRevocationList;
use mcp_re_client_proxy::transport::RemoteTransport;
use mcp_re_client_proxy::transport::TransportError;
use mcp_re_client_proxy::CallParams;
use mcp_re_client_proxy::ClientProxy;
use mcp_re_client_proxy::ClientVerification;
use mcp_re_client_proxy::ResponseKind;
use mcp_re_client_proxy::Route;
use mcp_re_client_proxy::RouteRegistry;

use serde_json::json;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [55u8; 32];
const NOW: i64 = 1_700_000_100;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const AUD: &str = "verifier-1";
const EPOCH: &str = "epoch-1";
const ACCESS_TOKEN: &str = "access-token-xyz";
/// Inside the rotation-overlap window (ttl 300, overlap 60): the rotor mints a
/// successor only from `exp - overlap` onward, so an earlier `rotate` is a no-op.
const ROTATED_AT: i64 = NOW + 250;

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

// ---- server side -----------------------------------------------------------

/// The server's delegated-required serving config (parser-produced, as the binary).
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

/// The server's trust seam: the client key for the Request slot (the server verifies
/// inbound requests); the ROOT key for the Response slot (unused on the serving path
/// but resolved for symmetry).
fn server_resolver() -> ActorResolver {
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

fn canned_inner() -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
    Box::new(|_forwarded: &[u8]| -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
    })
}

/// Build the real delegated-required server proxy with an in-memory root, first key
/// issued (as the binary does before serving).
fn build_server() -> HttpProfileProxy {
    build_server_with_kid().0
}

/// Build the server AND report the delegated kid it actually issued. Profile-issued
/// kids are RFC 7638 JWK thumbprints (#415 rev 2 §1.5), so a test that needs to name
/// the server's key — revocation, for instance — must ask which key was minted rather
/// than assume a kid it can spell.
fn build_server_with_kid() -> (HttpProfileProxy, String) {
    let config = server_config();
    let wiring = mcp_re_proxy::build_delegated_signing(&signing_plan(&config), root_key());
    let mut rotor = wiring.rotor;
    rotor
        .rotate(NOW)
        .expect("server issues the first delegated key");
    let issued_kid = wiring
        .signer
        .current(NOW)
        .expect("the first delegated key is published")
        .delegated_kid
        .clone();
    let expected_audience = AudienceTuple {
        audience_id: config.audience.clone(),
        target_uri: config.target_uri.clone(),
        route: config.route.clone(),
    };
    let proxy = HttpProfileProxy::new_delegated(
        server_resolver(),
        expected_audience,
        AsyncReplayTier::new(
            Arc::new(InMemoryAsyncAtomicReplayStore::new()),
            mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
        ),
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
        canned_inner(),
        300,
        Arc::clone(&wiring.signer),
    );
    (proxy, issued_kid)
}

// ---- the in-process "network" ---------------------------------------------

/// A [`RemoteTransport`] that drives the server-side [`HttpProfileProxy`] in process:
/// it adapts the client's signed [`HttpRequest`] into a [`ServedHttpRequest`], runs
/// the async server handler on a private runtime, and adapts the reply back. This is
/// the network hop in the round-trip.
struct InProcessServer {
    server: Arc<HttpProfileProxy>,
    rt: tokio::runtime::Runtime,
    now: i64,
}

impl InProcessServer {
    fn new(server: HttpProfileProxy, now: i64) -> Self {
        InProcessServer {
            server: Arc::new(server),
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("current-thread runtime"),
            now,
        }
    }
}

impl RemoteTransport for InProcessServer {
    fn round_trip(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let served = ServedHttpRequest {
            method: request.method.clone(),
            target_uri: request.target_uri.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
            identity: None,
            assertion: None,
        };
        let server = Arc::clone(&self.server);
        let resp = self
            .rt
            .block_on(async move { server.handle(served, self.now).await });
        Ok(HttpResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        })
    }
}

// ---- client side -----------------------------------------------------------

fn delegation_policy() -> DelegationPolicy {
    // audience_hash defaults to --audience on the server, so the client expects it too.
    DelegationPolicy::new(vec![AUD.to_string()], AUD, vec![EPOCH.to_string()], 60)
}

/// The client's trust seam: the ROOT issuer key for the Response slot (the credential
/// chains to it). The delegated key is authorized by the credential, never enrolled.
fn client_resolver() -> mcp_re_client_proxy::route::RouteActorResolver {
    Box::new(move |key_id: &str, slot: SignerSlot| {
        match (key_id, slot) {
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

fn client_proxy(server: HttpProfileProxy) -> ClientProxy {
    // Default posture: an explicit empty denylist (TTL-only reliance).
    client_proxy_with_revocation(server, Box::new(StaticRevocationList::new()))
}

fn client_proxy_with_revocation(
    server: HttpProfileProxy,
    revocation: Box<dyn RevocationSource>,
) -> ClientProxy {
    let route = Route {
        route_id: "r1".into(),
        target_uri: TARGET.into(),
        audience: audience(),
        // A non-empty binding is required; the OAuth-DPoP binding digests the bearer
        // token whose `Authorization` header the client carries and covers.
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        extra_headers: vec![("Authorization".into(), format!("Bearer {ACCESS_TOKEN}"))],
        expected_server_keyid: None,
        verification: ClientVerification::DelegatedRequired(
            delegation_policy(),
            client_resolver(),
            revocation,
        ),
    };
    let registry = RouteRegistry::new().register(route);
    ClientProxy::new(
        registry,
        client_key(),
        CLIENT_KEY_ID,
        Box::new(InProcessServer::new(server, NOW)),
    )
}

/// The same client, but with its trust anchors loaded from a SIGNED trust-anchor
/// manifest against a durable rollback floor — the production path for
/// `ClientVerification::DelegatedAnchored`.
fn client_proxy_anchored(
    server: HttpProfileProxy,
    issuers: mcp_re_client_core::TrustedIssuerSet,
) -> ClientProxy {
    let route = Route {
        route_id: "r1".into(),
        target_uri: TARGET.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        extra_headers: vec![("Authorization".into(), format!("Bearer {ACCESS_TOKEN}"))],
        expected_server_keyid: None,
        verification: ClientVerification::DelegatedAnchored(
            delegation_policy(),
            std::sync::Arc::new(mcp_re_client_proxy::AnchorSnapshot::new(issuers)),
        ),
    };
    ClientProxy::new(
        RouteRegistry::new().register(route),
        client_key(),
        CLIENT_KEY_ID,
        Box::new(InProcessServer::new(server, NOW)),
    )
}

/// Publish a signed trust-anchor manifest listing the server's root, load it through a
/// FILE-BACKED rollback floor, and return the resulting anchor set. This is the whole
/// distribution chain the manifest exists for: org key signs → verifier pins the org
/// key → floor records the version → anchors feed response verification.
fn issuers_from_signed_manifest(
    floor_path: &std::path::Path,
    manifest_version: u64,
    revoke_root: bool,
) -> mcp_re_client_core::TrustedIssuerSet {
    let org = SigningKey::from_seed_bytes(&[91u8; 32]);
    let org_kid = "org-admin-1";
    let manifest = mcp_re_client_core::TrustAnchorManifest {
        profile: MANIFEST_PROFILE.into(),
        manifest_version,
        current_issuers: vec![mcp_re_client_core::ManifestIssuer {
            issuer_kid: ROOT_KID.into(),
            public_key: root_key().public_key().to_b64url(),
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:server".into(),
        }],
        retiring_issuers: vec![],
        revoked_issuers: if revoke_root {
            vec![ROOT_KID.to_string()]
        } else {
            vec![]
        },
        issued_at: NOW - 100,
        expires_at: NOW + 100_000,
    };
    let signed = mcp_re_client_core::sign_manifest(&manifest, &org, org_kid);
    let mut floor = mcp_re_client_proxy::FileManifestFloor::open(floor_path).expect("open floor");
    let org_public = org.public_key();
    mcp_re_client_core::load_signed_manifest_with_floor(
        &signed,
        |kid| (kid == org_kid).then(|| org_public.clone()),
        MANIFEST_PROFILE,
        &mut floor,
        NOW,
    )
    .expect("manifest loads")
    .issuer_set
}

const MANIFEST_PROFILE: &str = "mcp-re-http-v1";

/// A unique floor path per test, cleaned up on drop.
struct FloorPath(std::path::PathBuf);

impl FloorPath {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("mcp-re-e2e-floor-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        FloorPath(path)
    }
}

impl Drop for FloorPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("tmp"));
    }
}

/// A one-way JSON-RPC NOTIFICATION: the ABSENT `id` is what makes it one, and both the
/// signer and the serving path classify on exactly that key's absence.
fn plain_notification() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
}

fn plain_request() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read" },
    })
}

/// Test nonces are padded to the 128-bit emission floor the client core enforces —
/// the floor is a property under test elsewhere, not something to work around here.
fn params(nonce: &str) -> CallParams {
    CallParams {
        nonce: format!("{nonce}-padded-to-the-128-bit-floor"),
        created: NOW - 100,
        expires: NOW + 200,
        now_unix: NOW,
    }
}

// ---- tests -----------------------------------------------------------------

#[test]
fn plain_client_round_trips_through_delegated_required_server() {
    let proxy = client_proxy(build_server());
    let out = proxy
        .handle("r1", &plain_request(), &params("nonce-e2e-1"))
        .expect("full delegated round-trip succeeds");
    assert_eq!(out.kind, ResponseKind::Success);
    // The local client gets PLAIN MCP back — an ordinary result, no MCP-RE field.
    assert_eq!(out.plain_response["result"]["ok"], json!(true));
    assert_eq!(out.plain_response["result"]["tool"], json!("read"));
    assert!(out.plain_response.get("_meta").is_none());
    assert!(out.plain_response["result"].get("_meta").is_none());
}

#[test]
fn replayed_request_yields_a_verified_delegated_rejection() {
    // One server instance shared across both calls (its replay cache sees the repeat).
    let proxy = client_proxy(build_server());
    // Same nonce twice ⇒ the second is a byte-identical replay.
    let p = params("nonce-e2e-replay");
    let first = proxy.handle("r1", &plain_request(), &p).expect("first ok");
    assert_eq!(first.kind, ResponseKind::Success);

    let second = proxy
        .handle("r1", &plain_request(), &p)
        .expect("the replay's delegated rejection receipt still verifies");
    // The client verified a request-BOUND delegated rejection and classified it.
    assert_eq!(
        second.kind,
        ResponseKind::VerifiedRejection {
            wire_code: Some("mcp-re.replay_detected".to_string()),
            bound: true,
            // A replay is refused before the dispatch and spends nothing, so the receipt
            // states no execution hazard at all — every token absent.
            execution: mcp_re_client_core::ExecutionContract::default(),
        }
    );
    // Converted to a PLAIN JSON-RPC error for the local client (fail closed — not a
    // success result).
    assert!(second.plain_response.get("error").is_some());
    assert!(second.plain_response.get("result").is_none());
}

// ---- C004b: the server-signer pin under delegation --------------------------

/// Build the expectation the client verifies under, with an optional signer pin.
fn expectation_with_pin(
    signed: &mcp_re_client_core::SignedRequest,
    pin: Option<&str>,
) -> ResponseExpectation {
    let base = ResponseExpectation::new(signed.request().clone(), signed.evidence().clone());
    match pin {
        Some(kid) => base.with_expected_server_signer(kid),
        None => base,
    }
}

/// Drive one signed exchange against the real delegated server and return the raw
/// response plus what the client signed, so a test can verify it under its own
/// expectation.
fn one_exchange(
    server: &HttpProfileProxy,
    rt: &tokio::runtime::Runtime,
    nonce: &str,
    at: i64,
) -> (
    mcp_re_client_core::SignedRequest,
    mcp_re_http_profile::HttpResponse,
) {
    let inputs = mcp_re_client_core::RequestSigningInputs::new(
        CLIENT_KEY_ID,
        audience(),
        vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        // Padded to the 128-bit emission floor the client core enforces.
        format!("{nonce}-padded-to-the-128-bit-floor"),
        at,
        at + 60,
    )
    .with_headers(vec![(
        "Authorization".into(),
        format!("Bearer {ACCESS_TOKEN}"),
    )]);
    let signed = mcp_re_client_core::build_signed_request(
        &json!(1),
        "tools/call",
        json!({"name": "read"}).as_object().cloned().unwrap(),
        TARGET,
        &inputs,
        &client_key(),
    )
    .expect("client signs");
    let served = ServedHttpRequest {
        method: signed.request().method.clone(),
        target_uri: signed.request().target_uri.clone(),
        headers: signed.request().headers.clone(),
        body: signed.request().body.clone(),
        identity: None,
        assertion: None,
    };
    let resp = rt.block_on(async { server.handle(served, at).await });
    (
        signed,
        mcp_re_http_profile::HttpResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        },
    )
}

/// The pin binds to the credential's ROOT ISSUER kid. Before C004b any set pin was
/// refused outright on this path, so the control could not be used at all.
#[test]
fn a_pin_on_the_root_issuer_kid_verifies() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let server = build_server();
    let (signed, response) = one_exchange(&server, &rt, "nonce-pin-ok", NOW);
    let verified = verify_delegated_response(
        &response,
        client_resolver().as_ref(),
        &expectation_with_pin(&signed, Some(ROOT_KID)),
        &delegation_policy(),
        &StaticRevocationList::new(),
        NOW,
    )
    .expect("a pin on the issuer kid is the coordinate that verifies");
    assert!(matches!(verified.outcome, DelegatedOutcome::Success));
    assert_eq!(
        verified.verified.delegation_issuer_kid.as_deref(),
        Some(ROOT_KID),
        "the verified evidence reports the anchor the credential chained to"
    );
}

/// Pinning the wrong issuer fails closed — the control is load-bearing, not decorative.
#[test]
fn a_pin_on_the_wrong_issuer_kid_fails_closed() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let server = build_server();
    let (signed, response) = one_exchange(&server, &rt, "nonce-pin-wrong", NOW);
    let err = verify_delegated_response(
        &response,
        client_resolver().as_ref(),
        &expectation_with_pin(&signed, Some("some-other-root")),
        &delegation_policy(),
        &StaticRevocationList::new(),
        NOW,
    )
    .expect_err("a pin naming a different root must fail closed");
    assert_eq!(
        err,
        mcp_re_client_core::HttpProfileError::ResponseBindingMismatch
    );
}

/// THE REASON the pin binds to the issuer and not to the accepted keyid: the delegated
/// kid is an RFC 7638 thumbprint that rotates every TTL. A pin on it would break on the
/// first rotation. Rotate the server's key and the SAME issuer pin still verifies.
#[test]
fn the_issuer_pin_survives_a_delegated_key_rotation() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let config = server_config();
    let wiring = mcp_re_proxy::build_delegated_signing(&signing_plan(&config), root_key());
    let mut rotor = wiring.rotor;
    rotor.rotate(NOW).expect("first key");
    let first_kid = wiring
        .signer
        .current(NOW)
        .expect("published")
        .delegated_kid
        .clone();
    let server = HttpProfileProxy::new_delegated(
        server_resolver(),
        AudienceTuple {
            audience_id: config.audience.clone(),
            target_uri: config.target_uri.clone(),
            route: config.route.clone(),
        },
        AsyncReplayTier::new(
            Arc::new(InMemoryAsyncAtomicReplayStore::new()),
            mcp_re_proxy::config_state::FreshnessWindow::new(60).expect("bounded"),
        ),
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
        canned_inner(),
        300,
        Arc::clone(&wiring.signer),
    );

    let (signed_a, response_a) = one_exchange(&server, &rt, "nonce-pin-rot-1", NOW);
    verify_delegated_response(
        &response_a,
        client_resolver().as_ref(),
        &expectation_with_pin(&signed_a, Some(ROOT_KID)),
        &delegation_policy(),
        &StaticRevocationList::new(),
        NOW,
    )
    .expect("verifies before rotation");

    // Rotate: a NEW delegated key, a new ephemeral kid, the SAME root issuer. The
    // rotor only mints inside the overlap window (ttl 300, overlap 60), so rotating
    // earlier is correctly a no-op — hence ROTATED_AT rather than NOW + 1.
    rotor.rotate(ROTATED_AT).expect("rotates");
    let second_kid = wiring
        .signer
        .current(ROTATED_AT)
        .expect("published")
        .delegated_kid
        .clone();
    assert_ne!(
        first_kid, second_kid,
        "the delegated kid must actually rotate"
    );

    let (signed_b, response_b) = one_exchange(&server, &rt, "nonce-pin-rot-2", ROTATED_AT);
    let verified = verify_delegated_response(
        &response_b,
        client_resolver().as_ref(),
        &expectation_with_pin(&signed_b, Some(ROOT_KID)),
        &delegation_policy(),
        &StaticRevocationList::new(),
        ROTATED_AT,
    )
    .expect("the SAME issuer pin still verifies after rotation — this is why it is the coordinate");
    assert_eq!(
        verified.verified.delegation_issuer_kid.as_deref(),
        Some(ROOT_KID)
    );
}

// ---- ADR-MCPS-035 audit emission (C086) ------------------------------------

/// `security-boundary.md` S9 presents `mcp-re.request.accepted` /
/// `.rejected` and `mcp-re.response.signed` as a delivered surface. Until this was
/// wired, `HttpProfileProxy::handle` emitted NOTHING on any exit, so a deployment
/// relying on that surface for post-incident attribution got no record of which actor
/// was admitted or which wire code caused a rejection.
#[test]
fn an_accepted_request_emits_accepted_then_signed_with_the_resolved_actor() {
    let sink = Arc::new(mcp_re_proxy::CollectingAuditSink::new());
    let proxy = client_proxy(build_server().with_audit_sink(sink.clone()));
    let out = proxy
        .handle("r1", &plain_request(), &params("nonce-audit-1"))
        .expect("round trip succeeds");
    assert_eq!(out.kind, ResponseKind::Success);

    let records = sink.records();
    let types: Vec<&str> = records.iter().map(|r| r.event.event_type).collect();
    assert_eq!(
        types,
        vec!["mcp-re.request.accepted", "mcp-re.response.signed"],
        "an admitted request records exactly accept-then-sign, in order"
    );
    // Attribution is the point of the surface: the actor is the VERIFIER-RESOLVED one.
    for record in &records {
        assert!(
            record.actor_id.is_some(),
            "an admitted request's records must carry the resolved actor"
        );
        assert_eq!(
            record.event.reason, None,
            "a success event carries no rejection reason"
        );
    }
}

/// A rejection records the EXACT frozen wire code, and never also claims acceptance —
/// `accepted` and `rejected` are mutually exclusive per request, which is what makes
/// the surface usable for attribution.
#[test]
fn a_replay_emits_exactly_one_rejection_carrying_the_frozen_wire_code() {
    let sink = Arc::new(mcp_re_proxy::CollectingAuditSink::new());
    let proxy = client_proxy(build_server().with_audit_sink(sink.clone()));
    let p = params("nonce-audit-replay");
    proxy.handle("r1", &plain_request(), &p).expect("first ok");
    let before = sink.records().len();

    proxy
        .handle("r1", &plain_request(), &p)
        .expect("the rejection receipt verifies");

    let replay_records: Vec<_> = sink.records().into_iter().skip(before).collect();
    assert_eq!(
        replay_records.len(),
        1,
        "the replayed request records ONE decision, got {replay_records:?}"
    );
    let record = &replay_records[0];
    assert_eq!(record.event.event_type, "mcp-re.request.rejected");
    assert_eq!(
        record.event.reason,
        Some("mcp-re.replay_detected"),
        "the reason is the exact frozen wire code, never a parallel sub-name"
    );
    // 409 Conflict is the replay status; the record carries the status actually
    // returned, so a reader can correlate the audit line with the HTTP response.
    assert_eq!(record.status, 409);
}

/// No sink installed is the explicit no-emission posture and must not disturb serving.
#[test]
fn serving_without_an_audit_sink_still_round_trips() {
    let proxy = client_proxy(build_server());
    let out = proxy
        .handle("r1", &plain_request(), &params("nonce-audit-none"))
        .expect("round trip succeeds with no sink installed");
    assert_eq!(out.kind, ResponseKind::Success);
}

// Downgrade resistance (a delegated-required verifier refusing a pre-052 direct-root
// response) is proven at the serving, client-core, http-profile, and conformance (d10)
// altitudes. It is not re-driven through the two-proxy round trip here because a
// direct-root SERVER no longer exists as a serving mode by design.

#[test]
fn revoked_server_delegated_key_is_refused_by_client() {
    // The client's revocation source names the delegated key the server actually
    // issued, so an otherwise-valid delegated success fails closed — proving the
    // revocation seam is live, not a hardcoded never-revoked.
    let (server, issued_kid) = build_server_with_kid();
    let revoked = StaticRevocationList::new().revoke(issued_kid);
    let proxy = client_proxy_with_revocation(server, Box::new(revoked));
    let err = proxy
        .handle("r1", &plain_request(), &params("nonce-e2e-revoked"))
        .expect_err("delegated-required client refuses a revoked delegated key");
    assert_eq!(
        err.wire_code(),
        Some("mcp-re.delegation_revoked"),
        "the revoked delegated key is the fail-closed reason"
    );
}

#[test]
fn non_revoked_client_still_round_trips() {
    // A non-empty denylist that does NOT name the server's key still succeeds — the
    // seam answers, it does not blanket-deny.
    let revoked = StaticRevocationList::new()
        .revoke("some-other/delegated/9")
        .revoke("unrelated-root");
    let proxy = client_proxy_with_revocation(build_server(), Box::new(revoked));
    let out = proxy
        .handle("r1", &plain_request(), &params("nonce-e2e-allow"))
        .expect("a non-matching denylist does not block a valid delegated response");
    assert_eq!(out.kind, ResponseKind::Success);
    assert_eq!(out.plain_response["result"]["ok"], json!(true));
}

// --- Trust anchors from a SIGNED MANIFEST (C039/C075/C076) --------------------
//
// The signed trust-anchor manifest, the four-state TrustedIssuerSet, and the rollback
// floor were all built and all unreachable: nothing in the serving or client path ever
// loaded a manifest, and the accepted `manifest_version` was handed back for a caller
// to record with no caller and nowhere to record it. These drive the whole chain
// end-to-end through the real two-proxy round trip.

#[test]
fn a_manifest_published_root_verifies_a_real_round_trip() {
    // Publish → pin the org key → record the version → verify a response. The client's
    // trust anchors come from the signed document, not from a hand-written resolver.
    let floor = FloorPath::new("accept");
    let issuers = issuers_from_signed_manifest(&floor.0, 1, false);
    let proxy = client_proxy_anchored(build_server(), issuers);
    let out = proxy
        .handle("r1", &plain_request(), &params("nonce-manifest-ok"))
        .expect("a manifest-published root verifies the delegated response");
    assert_eq!(out.kind, ResponseKind::Success);
    assert_eq!(out.plain_response["result"]["ok"], json!(true));
}

#[test]
fn a_manifest_revoked_root_fails_the_round_trip_closed() {
    // The decisive action: the manifest lists the server's root as REVOKED, so every
    // descendant delegated credential is invalid at once — no per-key denylist entry,
    // and the client never had to be told the delegated kid. This is also the anchored
    // variant proving both seams are wired from the ONE set (C064/C065): the reason is
    // delegation_revoked, which only the revocation seam can produce.
    let floor = FloorPath::new("revoke");
    let issuers = issuers_from_signed_manifest(&floor.0, 1, true);
    let proxy = client_proxy_anchored(build_server(), issuers);
    let err = proxy
        .handle("r1", &plain_request(), &params("nonce-manifest-revoked"))
        .expect_err("a manifest-revoked root must fail closed");
    assert_eq!(
        err.wire_code(),
        Some("mcp-re.delegation_revoked"),
        "revoking the ROOT in the manifest invalidates the delegated credential under it"
    );
}

#[test]
fn an_anchored_route_verifies_the_signed_202_that_acknowledges_a_notification() {
    // Anchored routes used to refuse every notification: no signed-202 verifier was
    // wired for the trust-anchor set, so the mode a signed manifest distributes could
    // not carry a one-way message at all. The acknowledgement is checked against the
    // manifest-published root, exactly as a bodied reply is.
    let floor = FloorPath::new("notify-accept");
    let issuers = issuers_from_signed_manifest(&floor.0, 1, false);
    let proxy = client_proxy_anchored(build_server(), issuers);
    let out = proxy
        .handle("r1", &plain_notification(), &params("nonce-anchored-202"))
        .expect("the signed 202 verifies against the manifest-published root");
    assert_eq!(out.kind, ResponseKind::AcceptedNotification);
    assert_eq!(
        out.plain_response,
        serde_json::Value::Null,
        "a notification has no reply to hand back"
    );
}

#[test]
fn a_manifest_revoked_root_refuses_the_notification_acknowledgement_too() {
    // The control for the test above. Verifying the 202 has to be a real check against
    // the same anchors, not a formality that returns AcceptedNotification whatever the
    // trust picture says — otherwise revoking a root would still silently acknowledge
    // every one-way message sent under it.
    let floor = FloorPath::new("notify-revoke");
    let issuers = issuers_from_signed_manifest(&floor.0, 1, true);
    let proxy = client_proxy_anchored(build_server(), issuers);
    let err = proxy
        .handle(
            "r1",
            &plain_notification(),
            &params("nonce-anchored-202-rev"),
        )
        .expect_err("a revoked root must not acknowledge a notification");
    assert_eq!(err.wire_code(), Some("mcp-re.delegation_revoked"));
}

#[test]
fn a_replayed_older_manifest_cannot_un_revoke_a_root() {
    // The rollback attack the floor exists to stop, driven all the way to a round trip.
    // v2 revokes the root; an attacker then re-serves v1, which does not. With a durable
    // floor the old manifest is refused, so the revocation cannot be walked back — and
    // the floor is read from disk, so this holds across a restart rather than only
    // within one process.
    let floor = FloorPath::new("rollback");

    // v2: the root is revoked. Loading it raises the floor to 2.
    let revoked_issuers = issuers_from_signed_manifest(&floor.0, 2, true);
    let proxy = client_proxy_anchored(build_server(), revoked_issuers);
    assert_eq!(
        proxy
            .handle("r1", &plain_request(), &params("nonce-rollback-1"))
            .expect_err("v2 revoked the root")
            .wire_code(),
        Some("mcp-re.delegation_revoked"),
    );

    // The replay: v1 (root not revoked), offered to a FRESH floor handle reading the
    // same file — i.e. the state a restarted verifier would see.
    let org = SigningKey::from_seed_bytes(&[91u8; 32]);
    let manifest = mcp_re_client_core::TrustAnchorManifest {
        profile: MANIFEST_PROFILE.into(),
        manifest_version: 1,
        current_issuers: vec![mcp_re_client_core::ManifestIssuer {
            issuer_kid: ROOT_KID.into(),
            public_key: root_key().public_key().to_b64url(),
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:server".into(),
        }],
        retiring_issuers: vec![],
        revoked_issuers: vec![],
        issued_at: NOW - 100,
        expires_at: NOW + 100_000,
    };
    let signed = mcp_re_client_core::sign_manifest(&manifest, &org, "org-admin-1");
    let mut reopened = mcp_re_client_proxy::FileManifestFloor::open(&floor.0).expect("reopen");
    assert_eq!(
        reopened.min_version().expect("floor readable"),
        2,
        "the floor survived in the file, not just in the process that wrote it"
    );
    let org_public = org.public_key();
    let replayed = mcp_re_client_core::load_signed_manifest_with_floor(
        &signed,
        |kid| (kid == "org-admin-1").then(|| org_public.clone()),
        MANIFEST_PROFILE,
        &mut reopened,
        NOW,
    );
    assert_eq!(
        replayed.err(),
        Some(mcp_re_client_core::TrustManifestError::Stale {
            version: 1,
            min_version: 2
        }),
        "the superseded manifest is refused, so the root stays revoked"
    );
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
