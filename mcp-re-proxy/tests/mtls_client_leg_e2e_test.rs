// SPDX-License-Identifier: Apache-2.0
//! The CLIENT LEG of Mode A end-to-end mTLS, over a REAL network hop.
//!
//!   plain MCP client
//!     → MCP-RE client proxy   (mcp-re-client-proxy: signs RFC 9421/9530)
//!     → mcp-re-transport       (verifying mTLS: presents a client cert AND
//!                               authenticates the server's cert + identity)
//!     → real TLS socket        (rustls, over loopback)
//!     → mcp-re-proxy async_serve → HttpProfileProxy (delegated-required)
//!     → delegated response / rejection receipt
//!     → client proxy verifies  (delegated credential chain to the root)
//!     → plain MCP back to the local client
//!
//! `delegated_client_server_e2e_test` proves the same pipeline over an IN-PROCESS
//! `RemoteTransport`, which never serialises a single HTTP byte. This lane replaces
//! that hop with the shipped one — `mcp_re_transport::remote::MtlsRemoteTransport`,
//! the production implementation of the `RemoteTransport` seam — so the evidence has
//! to survive real HTTP framing in BOTH directions:
//!
//!   * the request `Signature` / `Signature-Input` / `Content-Digest` must reach the
//!     server as headers on the wire, or the server cannot verify the request;
//!   * the response `Signature` / `Signature-Input` / `Content-Digest` must come back
//!     as headers, or the client cannot verify the response bound to its request;
//!   * the response STATUS must come back, or a signed rejection receipt (403) is
//!     indistinguishable from a success (200).
//!
//! A transport that returned only body bytes would fail every one of these.

#![cfg(feature = "async_serve")]

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

use mcp_re_proxy::async_replay::AsyncReplayTier;
use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
use mcp_re_proxy::async_serve;
use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
use mcp_re_proxy::tls::RustlsDirectProvider;
use mcp_re_proxy::ActorResolver;
use mcp_re_proxy::HttpProfileProxy;
use mcp_re_proxy::ServerOptions;

use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::StaticRevocationList;
use mcp_re_client_proxy::CallParams;
use mcp_re_client_proxy::ClientProxy;
use mcp_re_client_proxy::ClientVerification;
use mcp_re_client_proxy::ResponseKind;
use mcp_re_client_proxy::Route;
use mcp_re_client_proxy::RouteRegistry;

use mcp_re_transport::remote::MtlsRemoteTransport;
use mcp_re_transport::ClientTlsConfig;
use mcp_re_transport::MtlsClient;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;

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
const SERVER_NAME: &str = "proxy.internal";
const CLIENT_SPIFFE: &str = "spiffe://example.org/agent-1";

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

// ---------------------------------------------------------------------------
// rcgen CA + leaves (same idiom as mcp-re-transport/tests/mtls_client_test.rs).
// ---------------------------------------------------------------------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    /// Retained so an `Issuer` can be borrowed per signature: rcgen derives the
    /// issuer DN, key-identifier method and key usages from these, not from `cert`.
    params: CertificateParams,
}

impl Ca {
    /// The issuing state that minted `cert`, paired with the signing key.
    fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcp-re-test-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key, params }
}

fn make_leaf(
    ca: &Ca,
    sans: Vec<SanType>,
    common_name: Option<&str>,
    client_auth: bool,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params
        .signed_by(&key, &ca.issuer())
        .expect("leaf signed by ca");
    let der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (der, key_der)
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

// ---------------------------------------------------------------------------
// Server: the REAL delegated-required HttpProfileProxy behind the REAL async
// serving path, over real TLS.
// ---------------------------------------------------------------------------

fn server_config_args() -> mcp_re_proxy::cli::Config {
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
        "/tmp/mcp-re-mtls-client-leg-e2e-replay",
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

fn canned_inner() -> Box<dyn mcp_re_proxy::async_inner::AsyncInnerServer> {
    Box::new(|_forwarded: &[u8]| -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"tool":"read"}}"#.to_vec()
    })
}

fn build_server() -> HttpProfileProxy {
    let config = server_config_args();
    let wiring =
        mcp_re_proxy::build_delegated_signing(&config, root_key()).expect("delegated wiring");
    let mut rotor = wiring.rotor;
    rotor.rotate(NOW).expect("issue the first delegated key");
    HttpProfileProxy::new_delegated(
        server_resolver(),
        AudienceTuple {
            audience_id: config.audience.clone(),
            target_uri: config.target_uri.clone(),
            route: config.route.clone(),
        },
        AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
        ProxyDispatchConfig {
            fleet_strict: false,
            tier: None,
        },
        canned_inner(),
        300,
        Arc::clone(&wiring.signer),
    )
}

/// A running async server on a real TLS listener; shuts down on drop.
struct RunningServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Serve the real `HttpProfileProxy` over the real async path on a real TLS socket
/// that REQUIRES a client certificate signed by `client_ca`.
fn spawn_server(server_ca: &Ca, client_ca: &Ca) -> RunningServer {
    let (server_cert, server_key) =
        make_leaf(server_ca, vec![dns(SERVER_NAME)], Some(SERVER_NAME), false);
    let tls = RustlsDirectProvider::build_server_config(
        vec![server_cert],
        server_key,
        vec![client_ca.cert.der().clone()],
    )
    .expect("server tls config");

    let options = ServerOptions {
        target_uri: TARGET.to_string(),
        ..ServerOptions::default()
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_srv = Arc::clone(&shutdown);
    let (tx, rx) = mpsc::channel::<SocketAddr>();

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            tx.send(listener.local_addr().expect("addr"))
                .expect("send addr");
            let proxy = Arc::new(build_server());
            let handler =
                move |req: async_serve::ServedHttpRequest| -> async_serve::HandlerResponseFuture {
                    let proxy = Arc::clone(&proxy);
                    Box::pin(async move { proxy.handle(req, NOW).await })
                };
            async_serve::serve(
                listener,
                Arc::new(mcp_re_proxy::config_snapshot::ServerConfigSnapshot::new(
                    Arc::new(tls),
                )),
                Arc::new(options),
                Arc::new(handler),
                shutdown_srv,
            )
            .await;
        });
    });

    let addr = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("server bound");
    RunningServer {
        addr,
        shutdown,
        handle: Some(handle),
    }
}

// ---------------------------------------------------------------------------
// Client: the REAL ClientProxy over the SHIPPED mTLS RemoteTransport.
// ---------------------------------------------------------------------------

fn delegation_policy() -> DelegationPolicy {
    DelegationPolicy::new(vec![AUD.to_string()], AUD, vec![EPOCH.to_string()], 60)
}

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

/// The client's mTLS leg: presents a client cert signed by `client_ca` and trusts
/// ONLY `server_ca` to authenticate a server named `SERVER_NAME`.
fn mtls_transport(
    client_ca: &Ca,
    server_ca_der: CertificateDer<'static>,
    addr: SocketAddr,
) -> MtlsRemoteTransport {
    let (client_cert, client_key) = make_leaf(client_ca, vec![uri(CLIENT_SPIFFE)], None, true);
    let tls = ClientTlsConfig::from_der(vec![client_cert], client_key, vec![server_ca_der])
        .expect("client tls config");
    let client = MtlsClient::new(tls, SERVER_NAME).expect("mtls client");
    MtlsRemoteTransport::new(client, addr)
}

fn client_proxy(transport: MtlsRemoteTransport) -> ClientProxy {
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
        verification: ClientVerification::DelegatedRequired(
            delegation_policy(),
            client_resolver(),
            Box::new(StaticRevocationList::new()),
        ),
    };
    ClientProxy::new(
        RouteRegistry::new().register(route),
        client_key(),
        CLIENT_KEY_ID,
        Box::new(transport),
    )
}

/// Test nonces are padded to the 128-bit emission floor the client core enforces.
fn call_params(nonce: &str) -> CallParams {
    CallParams {
        nonce: format!("{nonce}-padded-to-the-128-bit-floor"),
        created: NOW,
        expires: NOW + 60,
        now_unix: NOW,
    }
}

fn plain_request() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read", "arguments": {}},
    })
}

// ---------------------------------------------------------------------------
// 1. The whole pipeline round-trips over a real mTLS socket.
// ---------------------------------------------------------------------------

#[test]
fn signed_request_and_bound_response_survive_a_real_mtls_hop() {
    let server_ca = make_ca();
    let client_ca = make_ca();
    let server = spawn_server(&server_ca, &client_ca);

    let transport = mtls_transport(&client_ca, server_ca.cert.der().clone(), server.addr);
    let proxy = client_proxy(transport);

    let response = proxy
        .handle("r1", &plain_request(), &call_params("nonce-mtls-1"))
        .expect("the round trip verifies end to end");

    // A VERIFIED success: the client could only reach this by verifying the response
    // signature bound to its own request — which requires the response `Signature`,
    // `Signature-Input` and `Content-Digest` headers to have survived the wire.
    assert_eq!(response.kind, ResponseKind::Success);
    assert_eq!(response.plain_response["result"]["ok"], json!(true));
    assert_eq!(response.plain_response["result"]["tool"], json!("read"));
    // Transparency: the plain client never sees an MCP-RE field.
    assert!(response.plain_response["result"].get("_meta").is_none());
}

// ---------------------------------------------------------------------------
// 2. A replay comes back as a VERIFIED REJECTION, not a success — which requires
//    the status AND the response evidence headers to survive the hop.
// ---------------------------------------------------------------------------

#[test]
fn a_replay_returns_a_verified_rejection_receipt_over_the_real_hop() {
    let server_ca = make_ca();
    let client_ca = make_ca();
    let server = spawn_server(&server_ca, &client_ca);

    let transport = mtls_transport(&client_ca, server_ca.cert.der().clone(), server.addr);
    let proxy = client_proxy(transport);

    let params = call_params("nonce-mtls-replayed");
    let first = proxy
        .handle("r1", &plain_request(), &params)
        .expect("first call verifies");
    assert_eq!(first.kind, ResponseKind::Success);

    // Byte-identical replay: same nonce, same signature.
    let replayed = proxy
        .handle("r1", &plain_request(), &params)
        .expect("the rejection receipt itself verifies");
    match replayed.kind {
        ResponseKind::VerifiedRejection {
            wire_code,
            bound,
            execution,
        } => {
            assert_eq!(wire_code.as_deref(), Some("mcp-re.replay_detected"));
            assert!(bound, "the receipt must be bound to the replayed request");
            // A replay is refused before dispatch and spends nothing, so the receipt
            // states no execution hazard. Asserted rather than ignored: an UNSTATED
            // contract must stay distinguishable from one that says the work may have
            // run, and this is the arm that says nothing.
            assert!(!execution.is_stated());
        }
        other => panic!("a replay must be a verified rejection, got {other:?}"),
    }
    assert!(
        replayed.plain_response.get("error").is_some(),
        "a rejection is a plain JSON-RPC error to the local client"
    );
}

// ---------------------------------------------------------------------------
// 3. Server authentication is not optional on the client leg: a proxy presenting
//    an untrusted certificate never receives the signed request.
// ---------------------------------------------------------------------------

#[test]
fn an_untrusted_server_certificate_stops_the_signed_request_at_the_client() {
    let server_ca = make_ca();
    let rogue_ca = make_ca();
    let client_ca = make_ca();
    // The server is real, but its certificate chains to `rogue_ca`.
    let server = spawn_server(&rogue_ca, &client_ca);

    // The client trusts only `server_ca`.
    let transport = mtls_transport(&client_ca, server_ca.cert.der().clone(), server.addr);
    let proxy = client_proxy(transport);

    let result = proxy.handle("r1", &plain_request(), &call_params("nonce-mtls-rogue"));
    match result {
        Err(mcp_re_client_proxy::transport::ProxyError::Transport(error)) => {
            assert!(
                error.detail.contains("handshake"),
                "a rejected server certificate is a failed CHANNEL, got {error:?}"
            );
        }
        other => panic!("an untrusted server cert must fail the transport, got {other:?}"),
    }
}
