//! MCPS-053 — verifying mTLS CLIENT transport: server authentication is NOT
//! optional (epic #3948, Phase 6.6).
//!
//! These tests stand up the real server side (`mcps_proxy::serve_once`) on a
//! thread and drive it with `mcps_transport::MtlsClient`. Certificates are
//! minted in-process with `rcgen` (no committed key fixtures). The client uses
//! rustls' standard `WebPkiServerVerifier` (NOT a fake accept-any verifier), so:
//!
//!   1. a trusted server cert (right CA, right name) + a valid client cert → the
//!      handshake completes and the round trip returns the response bytes;
//!   2. an untrusted server cert (DIFFERENT CA) → the client aborts the handshake
//!      before sending the request body (the server handler is never reached);
//!   3. a wrong-identity server cert (right CA, wrong SAN/name) → the client
//!      aborts;
//!   4. an expired server cert (right CA, right name, past validity) → the client
//!      aborts.
//!
//! Plus: client-cert presentation still works — the server extracts the verified
//! client identity exactly as before.

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use mcps_proxy::serve_once;
use mcps_proxy::transport::IdentitySource;
use mcps_proxy::RustlsDirectProvider;
use mcps_proxy::ServerOptions;

use mcps_transport::ClientTlsConfig;
use mcps_transport::MtlsClient;
use mcps_transport::TransportError;

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

// ---------------------------------------------------------------------------
// rcgen CA + leaves (same idiom as mcps-proxy/tests/tls_test.rs).
// ---------------------------------------------------------------------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcps-test-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
}

/// A leaf signed by `ca`, with the given SANs / CN and (client or server) EKU.
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
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("leaf signed by ca");
    let der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (der, key_der)
}

/// A SERVER leaf with an explicit validity window (day granularity) so an
/// expired server certificate can be minted deterministically.
fn make_server_leaf_with_validity(
    ca: &Ca,
    sans: Vec<SanType>,
    not_before: (i32, u8, u8),
    not_after: (i32, u8, u8),
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&key, &ca.cert, &ca.key).expect("leaf signed");
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

const SERVER_NAME: &str = "proxy.internal";
const CLIENT_SPIFFE: &str = "spiffe://example.org/agent-1";

// ---------------------------------------------------------------------------
// Harness: a server thread that serves exactly one mTLS request.
// ---------------------------------------------------------------------------

/// Build the SERVER config: server presents `server_chain`/`server_key`, and
/// requires + verifies a client cert against `client_ca`.
fn server_config(
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca: &Ca,
) -> Arc<rustls::ServerConfig> {
    let config = RustlsDirectProvider::build_server_config(
        server_chain,
        server_key,
        vec![client_ca.cert.der().clone()],
    )
    .expect("server config");
    Arc::new(config)
}

/// Spawn a one-shot server returning the verified client identity (if any). The
/// handler records that it was reached by writing a sentinel response.
fn spawn_server(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    handler_reached: Arc<std::sync::atomic::AtomicBool>,
) -> thread::JoinHandle<std::io::Result<Option<mcps_proxy::transport::TransportIdentity>>> {
    thread::spawn(move || {
        serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            move |request, identity| {
                handler_reached.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = request;
                let _ = identity;
                b"{\"ok\":true}".to_vec()
            },
        )
    })
}

/// Build the client config presenting a trusted client cert and trusting
/// `server_ca` to authenticate the proxy.
fn client_config_with_server_ca(client_ca: &Ca, server_ca_der: CertificateDer<'static>) -> ClientTlsConfig {
    let (client_cert, client_key) = make_leaf(client_ca, vec![uri(CLIENT_SPIFFE)], None, true);
    ClientTlsConfig::from_der(vec![client_cert], client_key, vec![server_ca_der])
        .expect("client config")
}

// ---------------------------------------------------------------------------
// 1. Trusted server cert + valid client cert → round trip succeeds.
// ---------------------------------------------------------------------------

#[test]
fn trusted_server_and_client_round_trip_succeeds() {
    let server_ca = make_ca();
    let client_ca = make_ca();
    let (server_cert, server_key) =
        make_leaf(&server_ca, vec![dns(SERVER_NAME)], Some(SERVER_NAME), false);
    let config = server_config(vec![server_cert], server_key, &client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = spawn_server(listener, config, reached.clone());

    let client_config =
        client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    let client = MtlsClient::new(client_config, SERVER_NAME).expect("client");
    let response = client
        .round_trip(addr, b"{\"jsonrpc\":\"2.0\"}")
        .expect("round trip succeeds");
    assert_eq!(response, b"{\"ok\":true}");

    let identity = server.join().expect("join").expect("serve ok");
    let identity = identity.expect("a verified client identity");
    assert_eq!(identity.value, CLIENT_SPIFFE);
    assert_eq!(identity.source, IdentitySource::UriSan);
    assert!(
        reached.load(std::sync::atomic::Ordering::SeqCst),
        "handler must be reached on the happy path"
    );
}

// ---------------------------------------------------------------------------
// 2. Untrusted server cert (DIFFERENT CA) → client aborts before sending body.
// ---------------------------------------------------------------------------

#[test]
fn untrusted_server_cert_is_rejected() {
    // Server presents a cert signed by `rogue_ca`, but the client trusts only
    // `server_ca`.
    let server_ca = make_ca();
    let rogue_ca = make_ca();
    let client_ca = make_ca();
    let (server_cert, server_key) =
        make_leaf(&rogue_ca, vec![dns(SERVER_NAME)], Some(SERVER_NAME), false);
    let config = server_config(vec![server_cert], server_key, &client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = spawn_server(listener, config, reached.clone());

    let client_config =
        client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    let client = MtlsClient::new(client_config, SERVER_NAME).expect("client");
    let result = client.round_trip(addr, b"{\"jsonrpc\":\"2.0\"}");

    assert!(
        matches!(result, Err(TransportError::Handshake(_))),
        "untrusted server cert must abort the handshake, got {result:?}"
    );
    let _ = server.join();
    assert!(
        !reached.load(std::sync::atomic::Ordering::SeqCst),
        "server handler must NOT be reached when the client rejects the server cert"
    );
}

// ---------------------------------------------------------------------------
// 3. Wrong server identity (right CA, wrong SAN/name) → client aborts.
// ---------------------------------------------------------------------------

#[test]
fn wrong_server_identity_is_rejected() {
    let server_ca = make_ca();
    let client_ca = make_ca();
    // Cert is signed by the trusted CA but its SAN/name is NOT `SERVER_NAME`.
    let (server_cert, server_key) = make_leaf(
        &server_ca,
        vec![dns("evil.attacker.test")],
        Some("evil.attacker.test"),
        false,
    );
    let config = server_config(vec![server_cert], server_key, &client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = spawn_server(listener, config, reached.clone());

    let client_config =
        client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    let client = MtlsClient::new(client_config, SERVER_NAME).expect("client");
    let result = client.round_trip(addr, b"{\"jsonrpc\":\"2.0\"}");

    assert!(
        matches!(result, Err(TransportError::Handshake(_))),
        "wrong-identity server cert must abort the handshake, got {result:?}"
    );
    let _ = server.join();
    assert!(
        !reached.load(std::sync::atomic::Ordering::SeqCst),
        "server handler must NOT be reached on identity mismatch"
    );
}

// ---------------------------------------------------------------------------
// 4. Expired server cert (right CA, right name, past validity) → client aborts.
// ---------------------------------------------------------------------------

#[test]
fn expired_server_cert_is_rejected() {
    let server_ca = make_ca();
    let client_ca = make_ca();
    // Right CA, right name, but the validity window is entirely in the past.
    let (server_cert, server_key) = make_server_leaf_with_validity(
        &server_ca,
        vec![dns(SERVER_NAME)],
        (2000, 1, 1),
        (2001, 1, 1),
    );
    let config = server_config(vec![server_cert], server_key, &client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = spawn_server(listener, config, reached.clone());

    let client_config =
        client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    let client = MtlsClient::new(client_config, SERVER_NAME).expect("client");
    let result = client.round_trip(addr, b"{\"jsonrpc\":\"2.0\"}");

    assert!(
        matches!(result, Err(TransportError::Handshake(_))),
        "expired server cert must abort the handshake, got {result:?}"
    );
    let _ = server.join();
    assert!(
        !reached.load(std::sync::atomic::Ordering::SeqCst),
        "server handler must NOT be reached when the server cert is expired"
    );
}

// ---------------------------------------------------------------------------
// Config-building guards: server authentication is mandatory.
// ---------------------------------------------------------------------------

#[test]
fn empty_server_ca_is_rejected_fail_closed() {
    let client_ca = make_ca();
    let (client_cert, client_key) = make_leaf(&client_ca, vec![uri(CLIENT_SPIFFE)], None, true);
    let result = ClientTlsConfig::from_der(vec![client_cert], client_key, vec![]);
    assert!(
        matches!(result, Err(TransportError::EmptyServerCa)),
        "an empty server-CA bundle must fail closed, got {result:?}"
    );
}
