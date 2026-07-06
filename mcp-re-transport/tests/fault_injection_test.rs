//! MCPS-071 — fault injection ("test of the tests").
//!
//! This is the periodic/pre-release "test of the tests": it deliberately BREAKS
//! the server-authentication control (via the `fault_accept_any_server` cargo
//! feature, which is OFF by default and never compiled by the normal build /
//! default `bazel test //...`) and proves that with the control broken the
//! server-auth property NO LONGER holds. That is exactly what proves the real
//! guard `untrusted_server_cert_is_rejected` (mtls_client_test.rs) is
//! load-bearing: if someone re-introduced accept-any-server, the round trip an
//! untrusted server cert would now SUCCEED and reach the handler, and the guard
//! test — which asserts a handshake REJECTION and a NON-reached handler — would
//! fail.
//!
//! How this stays a green, self-contained test: it does not run the guard test
//! and check it fails (that would mean shipping a red test). Instead it runs the
//! SAME untrusted-server scenario the guard runs, but compiled WITH the fault
//! active, and asserts the OPPOSITE outcome (round trip succeeds, handler
//! reached). The guard asserts (reject, not reached); this asserts (accept,
//! reached) under the fault. Demonstrating that the faulted outcome is the exact
//! negation of the guard's assertion is the proof that the guard would fire on a
//! real break.
//!
//! This target is ONLY built/run with `--features fault_accept_any_server`. It is
//! NOT part of the default-config conformance run. The mcp-re-transport crate's
//! default build is byte-for-byte the verifying transport (the fault path is
//! behind `#[cfg(feature = "fault_accept_any_server")]`).

#![cfg(feature = "fault_accept_any_server")]

use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use mcp_re_proxy::serve_once;
use mcp_re_proxy::RustlsDirectProvider;
use mcp_re_proxy::ServerOptions;

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

// The harness below mirrors mtls_client_test.rs so the faulted scenario is the
// same scenario the guard runs — only the control (and therefore the asserted
// outcome) differs. Fixtures are generated-but-deterministic-per-run via rcgen
// (no committed key material); fresh CAs/leaves and an OS-assigned ephemeral port
// each run.

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
        .push(DnType::CommonName, "mcp-re-fault-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
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
        .signed_by(&key, &ca.cert, &ca.key)
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

const SERVER_NAME: &str = "proxy.internal";
const CLIENT_SPIFFE: &str = "spiffe://example.org/agent-1";

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

fn spawn_server(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    handler_reached: Arc<AtomicBool>,
) -> thread::JoinHandle<std::io::Result<Option<mcp_re_proxy::transport::TransportIdentity>>> {
    thread::spawn(move || {
        serve_once(
            &listener,
            config,
            &ServerOptions::default(),
            move |request, identity| {
                handler_reached.store(true, Ordering::SeqCst);
                let _ = request;
                let _ = identity;
                b"{\"ok\":true}".to_vec()
            },
        )
    })
}

fn client_config_with_server_ca(
    client_ca: &Ca,
    server_ca_der: CertificateDer<'static>,
) -> ClientTlsConfig {
    let (client_cert, client_key) = make_leaf(client_ca, vec![uri(CLIENT_SPIFFE)], None, true);
    ClientTlsConfig::from_der(vec![client_cert], client_key, vec![server_ca_der])
        .expect("client config")
}

/// With the `fault_accept_any_server` control break compiled in, the SAME
/// untrusted-server scenario that the guard `untrusted_server_cert_is_rejected`
/// expects to FAIL the handshake instead SUCCEEDS and reaches the handler.
///
/// The guard asserts: `Err(Handshake)` AND handler NOT reached.
/// Here, under the fault, we assert the exact negation: `Ok(..)` AND handler
/// reached. That negation is the proof that the guard is load-bearing — if this
/// fault path ever shipped in the real transport, the guard would fire.
#[test]
fn fault_accept_any_server_makes_untrusted_server_cert_accepted() {
    // Server presents a cert signed by `rogue_ca`; the client trusts only
    // `server_ca`. A verifying client (default build) MUST reject this. The
    // faulted client accepts it.
    let server_ca = make_ca();
    let rogue_ca = make_ca();
    let client_ca = make_ca();
    let (server_cert, server_key) =
        make_leaf(&rogue_ca, vec![dns(SERVER_NAME)], Some(SERVER_NAME), false);
    let config = server_config(vec![server_cert], server_key, &client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let reached = Arc::new(AtomicBool::new(false));
    let server = spawn_server(listener, config, reached.clone());

    // Client trusts ONLY `server_ca`, but the server presented a `rogue_ca` cert.
    let client_config = client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    let client = MtlsClient::new(client_config, SERVER_NAME).expect("client");
    let result = client.round_trip(addr, b"{\"jsonrpc\":\"2.0\"}");

    let _ = server.join();

    // THE CATCH DEMONSTRATION: with the control broken, the untrusted server cert
    // is accepted, the round trip succeeds, and the handler is reached — the exact
    // OPPOSITE of what the guard asserts. The guard would therefore fail if this
    // fault were ever the real behaviour.
    assert!(
        result.is_ok(),
        "with fault_accept_any_server, an UNTRUSTED server cert must be ACCEPTED \
         (round trip succeeds) — this is the broken control the guard catches; got {result:?}"
    );
    assert_eq!(result.unwrap(), b"{\"ok\":true}");
    assert!(
        reached.load(Ordering::SeqCst),
        "with the control broken, the server handler IS reached behind an untrusted \
         server cert — the negation of the guard's 'handler NOT reached' assertion"
    );
}

/// Companion witness: under the fault, the wrong-server-IDENTITY scenario
/// (right CA, wrong SAN) is ALSO accepted — covering a second of the four
/// mandatory server-auth cases so the fault demonstrably defeats identity
/// checking too, not only CA-trust checking.
#[test]
fn fault_accept_any_server_makes_wrong_identity_server_cert_accepted() {
    let server_ca = make_ca();
    let client_ca = make_ca();
    // Signed by the trusted CA, but the SAN/name is NOT `SERVER_NAME`.
    let (server_cert, server_key) = make_leaf(
        &server_ca,
        vec![dns("evil.attacker.test")],
        Some("evil.attacker.test"),
        false,
    );
    let config = server_config(vec![server_cert], server_key, &client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let reached = Arc::new(AtomicBool::new(false));
    let server = spawn_server(listener, config, reached.clone());

    let client_config = client_config_with_server_ca(&client_ca, server_ca.cert.der().clone());
    let client = MtlsClient::new(client_config, SERVER_NAME).expect("client");
    let result = client.round_trip(addr, b"{\"jsonrpc\":\"2.0\"}");

    let _ = server.join();

    assert!(
        result.is_ok(),
        "with fault_accept_any_server, a WRONG-IDENTITY server cert must be ACCEPTED; got {result:?}"
    );
    assert!(
        reached.load(Ordering::SeqCst),
        "wrong-identity server cert reaches the handler under the fault — negation of \
         the guard's wrong_server_identity_is_rejected assertion"
    );
}
