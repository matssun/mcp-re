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

use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::DelegationPolicy;
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
fn server_config() -> mcp_re_proxy::cli::Config {
    let args: Vec<String> = [
        "--bind", "127.0.0.1:8443",
        "--audience", AUD,
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
        "--replay-path", "/tmp/mcp-re-client-server-e2e-replay",
        "--delegated-trust-epoch", EPOCH,
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
    Box::new(move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
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
    let wiring = mcp_re_proxy::build_delegated_signing(&config, root_key())
        .expect("build delegated signing wiring");
    let mut rotor = wiring.rotor;
    rotor.rotate(NOW).expect("server issues the first delegated key");
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
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig { fleet_strict: false, tier: None },
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
        let resp = self.rt.block_on(async move { server.handle(served, self.now).await });
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
    Box::new(move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
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
        resolve_actor: client_resolver(),
        verification: ClientVerification::DelegatedRequired(delegation_policy(), revocation),
    };
    let registry = RouteRegistry::new().register(route);
    ClientProxy::new(
        registry,
        client_key(),
        CLIENT_KEY_ID,
        Box::new(InProcessServer::new(server, NOW)),
    )
}

fn plain_request() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read" },
    })
}

fn params(nonce: &str) -> CallParams {
    CallParams {
        nonce: nonce.to_string(),
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
        }
    );
    // Converted to a PLAIN JSON-RPC error for the local client (fail closed — not a
    // success result).
    assert!(second.plain_response.get("error").is_some());
    assert!(second.plain_response.get("result").is_none());
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
