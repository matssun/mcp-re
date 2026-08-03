// SPDX-License-Identifier: Apache-2.0
//! The shipped client sidecar, driven over a REAL loopback socket against a REAL
//! delegated-required server.
//!
//! ```text
//! raw TCP (plain JSON-RPC) -> mcp_re_client::serve -> ClientProxy (signs RFC 9421/9530)
//!   -> HttpProfileProxy (delegated-required) -> canned backend
//!   -> delegated-signed reply -> verified against MANIFEST-PUBLISHED anchors -> plain JSON-RPC
//! ```
//!
//! The client's trust anchors come from a signed trust-anchor manifest loaded through a
//! FILE-BACKED rollback floor — the chain ADR-MCPRE-052 describes, from an org
//! publishing a document to a request being verified under it. Until the binary this
//! crate ships, that chain terminated in a test; here it terminates in the listener an
//! operator actually runs.
//!
//! The mTLS leg is deliberately NOT in this picture: it is proven by
//! `mcp-re-proxy`'s `mtls_client_leg_e2e_test`, and standing a TLS server up here would
//! test that again while telling us nothing new about the listener, the route table, or
//! the anchors.

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
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
use mcp_re_client_core::ManifestIssuer;
use mcp_re_client_core::TrustAnchorManifest;
use mcp_re_client_proxy::route::ClientVerification;
use mcp_re_client_proxy::transport::RemoteTransport;
use mcp_re_client_proxy::transport::TransportError;
use mcp_re_client_proxy::AnchorSnapshot;
use mcp_re_client_proxy::ClientProxy;
use mcp_re_client_proxy::Route;
use mcp_re_client_proxy::RouteRegistry;

use mcp_re_client::anchors::refresh_once;
use mcp_re_client::anchors::AnchorLoader;
use mcp_re_client::anchors::RefreshOutcome;
use mcp_re_client::config::FloorConfig;
use mcp_re_client::config::OrgKey;
use mcp_re_client::config::TrustConfig;
use mcp_re_client::serve::ServeContext;

const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [55u8; 32];
const ORG_SEED: [u8; 32] = [91u8; 32];
const NOW: i64 = 1_700_000_100;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const CLIENT_KEY_ID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const ORG_KID: &str = "org-admin-1";
const AUD: &str = "verifier-1";
const EPOCH: &str = "epoch-1";
const PROFILE: &str = "mcp-re-http-v1";

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
fn org_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ORG_SEED)
}

// ---- a scratch directory per test -----------------------------------------

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("mcp-re-client-e2e-{name}-{}", std::process::id()));
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

fn server_config(replay_path: &std::path::Path) -> mcp_re_proxy::cli::Config {
    let replay_path = replay_path.to_string_lossy().into_owned();
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
        "--replay-cache",
        "file",
        "--replay-path",
        &replay_path,
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

fn build_server(replay_path: &std::path::Path) -> HttpProfileProxy {
    let config = server_config(replay_path);
    let wiring = mcp_re_proxy::build_delegated_signing(&config, root_key())
        .expect("build delegated signing wiring");
    let mut rotor = wiring.rotor;
    rotor.rotate(NOW).expect("first delegated key");
    let expected_audience = AudienceTuple {
        audience_id: config.audience.clone(),
        target_uri: config.target_uri.clone(),
        route: config.route.clone(),
    };
    HttpProfileProxy::new_delegated(
        server_resolver(),
        expected_audience,
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
        Box::new(|_forwarded: &[u8]| -> Vec<u8> {
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
        }),
        300,
        Arc::clone(&wiring.signer),
    )
}

/// The network hop, in process: adapt the client's signed request into the server's
/// served form, run the async handler, adapt the reply back.
struct InProcessServer {
    server: Arc<HttpProfileProxy>,
    rt: tokio::runtime::Runtime,
    now: i64,
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
        let now = self.now;
        let resp = self
            .rt
            .block_on(async move { server.handle(served, now).await });
        Ok(HttpResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        })
    }
}

// ---- the manifest an org publishes -----------------------------------------

fn publish_manifest(path: &std::path::Path, version: u64, revoke_root: bool) {
    let manifest = TrustAnchorManifest {
        profile: PROFILE.into(),
        manifest_version: version,
        current_issuers: vec![ManifestIssuer {
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
    let signed = mcp_re_client_core::sign_manifest(&manifest, &org_key(), ORG_KID);
    std::fs::write(path, serde_json::to_vec(&signed).expect("serialize")).expect("publish");
}

fn trust_config(scratch: &Scratch) -> TrustConfig {
    TrustConfig {
        manifest_path: scratch.join("manifest.json"),
        profile: PROFILE.into(),
        org_keys: vec![OrgKey {
            kid: ORG_KID.into(),
            public_key: org_key().public_key().to_b64url(),
        }],
        floor: FloorConfig::Durable {
            dir: scratch.join("floor"),
            bootstrap_version: 0,
        },
        reload_secs: 300,
    }
}

// ---- the sidecar under test ------------------------------------------------

/// A running listener plus the handles a test needs to publish a new manifest.
struct Sidecar {
    addr: std::net::SocketAddr,
    snapshot: Arc<AnchorSnapshot>,
    loader: AnchorLoader,
    manifest_expires_at: i64,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn start_sidecar(scratch: &Scratch, default_route: Option<&str>) -> Sidecar {
    publish_manifest(&scratch.join("manifest.json"), 1, false);
    let trust = trust_config(scratch);
    let mut loader = AnchorLoader::new(&trust).expect("loader");
    let loaded = loader.load(NOW).expect("startup manifest loads");
    let snapshot = Arc::new(AnchorSnapshot::new(loaded.issuers));

    let policy = DelegationPolicy::new(vec![AUD.to_string()], AUD, vec![EPOCH.to_string()], 60);
    let route = Route {
        route_id: "r1".into(),
        target_uri: TARGET.into(),
        audience: AudienceTuple {
            audience_id: AUD.into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        },
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            b"access-token-xyz",
        )],
        extra_headers: vec![("Authorization".into(), "Bearer access-token-xyz".into())],
        expected_server_keyid: None,
        verification: ClientVerification::DelegatedAnchored(policy, Arc::clone(&snapshot)),
    };

    let transport = InProcessServer {
        server: Arc::new(build_server(&scratch.join("replay"))),
        rt: tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime"),
        now: NOW,
    };
    let proxy = ClientProxy::new(
        RouteRegistry::new().register(route),
        client_key(),
        CLIENT_KEY_ID,
        Box::new(transport),
    );

    let context = Arc::new(ServeContext {
        proxy,
        default_route: default_route.map(str::to_owned),
        request_lifetime_secs: 300,
        max_in_flight: 8,
        // A FIXED clock, matching the server's: the point of this lane is the listener
        // and the anchors, not clock skew, and a fixed pair keeps the freshness gate
        // out of the way of what is being measured.
        clock: Box::new(|| NOW),
        nonce: Box::new(mcp_re_client::next_nonce),
    });

    let listener = mcp_re_client::serve::bind("127.0.0.1:0".parse().expect("addr"))
        .expect("bind an ephemeral loopback port");
    let addr = listener.local_addr().expect("local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        mcp_re_client::serve::serve(listener, context, stop_thread);
    });

    Sidecar {
        addr,
        snapshot,
        loader,
        manifest_expires_at: loaded.expires_at,
        stop,
        handle: Some(handle),
    }
}

// ---- a raw HTTP client -----------------------------------------------------

struct Reply {
    status: u16,
    verified_kind: Option<String>,
    body: String,
}

/// Send a raw request and read the whole reply. Deliberately raw: this exercises the
/// listener's own framing rather than a client library's idea of it.
fn send(addr: std::net::SocketAddr, request: &str) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("timeout");
    stream.write_all(request.as_bytes()).expect("write");
    stream.flush().expect("flush");
    let mut raw = Vec::new();
    // The listener closes after one exchange, so read-to-end is the whole reply.
    stream.read_to_end(&mut raw).expect("read");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("a complete reply");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("status line");
    let verified_kind = head.lines().find_map(|line| {
        line.strip_prefix("Mcp-Re-Verified-Kind: ")
            .map(str::to_owned)
    });
    Reply {
        status,
        verified_kind,
        body: body.to_owned(),
    }
}

fn post(addr: std::net::SocketAddr, path: &str, body: &str) -> Reply {
    send(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

const CALL: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;
const NOTIFY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

// ---- the proofs ------------------------------------------------------------

#[test]
fn a_plain_mcp_call_round_trips_through_the_listener_and_comes_back_verified() {
    let scratch = Scratch::new("roundtrip");
    let sidecar = start_sidecar(&scratch, None);

    let reply = post(sidecar.addr, "/route/r1", CALL);
    assert_eq!(reply.status, 200, "body was {}", reply.body);
    assert_eq!(reply.verified_kind.as_deref(), Some("success"));

    let plain: serde_json::Value = serde_json::from_str(&reply.body).expect("plain JSON-RPC back");
    assert_eq!(plain["result"]["ok"], serde_json::json!(true));
    assert_eq!(plain["id"], serde_json::json!(1), "the caller's own id");
    assert!(
        plain.get("_meta").is_none() && plain["result"].get("_meta").is_none(),
        "the local client never sees an MCP-RE field"
    );
}

/// The decisive property the binary exists for: an org publishes a manifest revoking a
/// root, the refresh accepts it, and the NEXT request on the ALREADY-RUNNING listener
/// fails closed. No restart, no reconfiguration.
#[test]
fn a_published_revocation_reaches_the_running_listener() {
    let scratch = Scratch::new("revoke");
    let mut sidecar = start_sidecar(&scratch, None);

    assert_eq!(
        post(sidecar.addr, "/route/r1", CALL).status,
        200,
        "the root is live under v1"
    );

    publish_manifest(&scratch.join("manifest.json"), 2, true);
    assert_eq!(
        refresh_once(
            &mut sidecar.loader,
            &sidecar.snapshot,
            &mut sidecar.manifest_expires_at,
            NOW,
        ),
        RefreshOutcome::Published { version: 2 }
    );

    let reply = post(sidecar.addr, "/route/r1", CALL);
    assert_eq!(reply.status, 502, "an unverifiable reply is not a result");
    let error: serde_json::Value = serde_json::from_str(&reply.body).expect("error body");
    assert_eq!(
        error["error"]["data"]["mcp_re_error"]["wire_code"],
        serde_json::json!("mcp-re.delegation_revoked"),
        "revoking the ROOT invalidates every descendant delegated credential at once"
    );
    assert!(
        reply.verified_kind.is_none(),
        "a failed verification carries no verified classification"
    );
}

/// The rollback the durable floor exists to stop, driven through the running listener:
/// after v2 revoked the root, re-serving v1 must not un-revoke it.
#[test]
fn a_replayed_older_manifest_cannot_restore_service_through_the_listener() {
    let scratch = Scratch::new("rollback");
    let mut sidecar = start_sidecar(&scratch, None);

    publish_manifest(&scratch.join("manifest.json"), 2, true);
    refresh_once(
        &mut sidecar.loader,
        &sidecar.snapshot,
        &mut sidecar.manifest_expires_at,
        NOW,
    );
    assert_eq!(post(sidecar.addr, "/route/r1", CALL).status, 502);

    // The attacker re-serves v1, which does not revoke the root.
    publish_manifest(&scratch.join("manifest.json"), 1, false);
    let outcome = refresh_once(
        &mut sidecar.loader,
        &sidecar.snapshot,
        &mut sidecar.manifest_expires_at,
        NOW,
    );
    assert!(
        matches!(outcome, RefreshOutcome::KeptLastGood { .. }),
        "the floor refuses the rollback: {outcome:?}"
    );
    assert_eq!(
        post(sidecar.addr, "/route/r1", CALL).status,
        502,
        "the revocation cannot be walked back by replaying an older document"
    );
}

/// A one-way notification is answered with 202 and NO body. The 202 says the
/// enforcement boundary accepted the message — never that the action completed.
#[test]
fn a_notification_is_acknowledged_with_a_bodyless_202() {
    let scratch = Scratch::new("notify");
    let sidecar = start_sidecar(&scratch, None);

    let reply = post(sidecar.addr, "/route/r1", NOTIFY);
    assert_eq!(reply.status, 202, "body was {}", reply.body);
    assert_eq!(
        reply.verified_kind.as_deref(),
        Some("accepted-notification")
    );
    assert!(reply.body.is_empty(), "a notification has no reply");
}

#[test]
fn a_path_that_names_no_route_is_refused_rather_than_guessed() {
    let scratch = Scratch::new("noroute");
    let sidecar = start_sidecar(&scratch, None);
    assert_eq!(post(sidecar.addr, "/mcp", CALL).status, 404);
    assert_eq!(post(sidecar.addr, "/route/nope", CALL).status, 404);
}

#[test]
fn a_configured_default_route_serves_a_fixed_path() {
    let scratch = Scratch::new("default");
    let sidecar = start_sidecar(&scratch, Some("r1"));
    let reply = post(sidecar.addr, "/mcp", CALL);
    assert_eq!(reply.status, 200, "body was {}", reply.body);
    assert_eq!(reply.verified_kind.as_deref(), Some("success"));
}

/// The listener's HTTP surface is deliberately small, and each refusal is a refusal.
/// A lenient path here would let one local caller's body be read as another's.
#[test]
fn the_local_http_surface_refuses_everything_it_does_not_implement() {
    let scratch = Scratch::new("surface");
    let sidecar = start_sidecar(&scratch, None);

    assert_eq!(
        send(
            sidecar.addr,
            "GET /route/r1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
        )
        .status,
        405,
        "only POST"
    );
    assert_eq!(
        send(
            sidecar.addr,
            "POST /route/r1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .status,
        411,
        "a body with no declared length has no boundary"
    );
    assert_eq!(
        send(
            sidecar.addr,
            "POST /route/r1 HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        .status,
        411,
        "chunked is refused rather than parsed"
    );
    assert_eq!(
        send(
            sidecar.addr,
            "POST /route/r1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\nhello"
        )
        .status,
        400,
        "two lengths let a reader and a writer disagree about where the message ends"
    );
    assert_eq!(
        post(sidecar.addr, "/route/r1", "{ not json").status,
        400,
        "a malformed local body never reaches the signer"
    );
}

/// Several local callers at once. An agent issuing parallel tool calls must not have
/// them serialized by the security sidecar.
#[test]
fn concurrent_local_callers_are_served_in_parallel() {
    let scratch = Scratch::new("concurrent");
    let sidecar = start_sidecar(&scratch, None);
    let addr = sidecar.addr;

    let workers: Vec<_> = (0..4)
        .map(|_| std::thread::spawn(move || post(addr, "/route/r1", CALL).status))
        .collect();
    for worker in workers {
        assert_eq!(worker.join().expect("worker"), 200);
    }
}
