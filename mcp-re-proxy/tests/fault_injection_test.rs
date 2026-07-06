//! MCPS-079 — fault injection ("test of the tests"), the symmetric mirror of
//! mcp-re-transport's `tests/fault_injection_test.rs`.
//!
//! This is the periodic/pre-release "test of the tests": it deliberately BREAKS
//! the proxy's CLIENT-authentication control (via the `fault_accept_any_client`
//! cargo feature, which is OFF by default and never compiled by the normal build
//! / default `bazel test //...`) and proves that with the control broken the
//! client-auth property NO LONGER holds. That is exactly what proves the real
//! guards `missing_client_certificate_is_rejected` (T1) and
//! `untrusted_client_certificate_is_rejected` (T2) in `tls_test.rs` are
//! load-bearing: if someone re-introduced accept-any-client (or dropped the
//! mandatory-client-cert requirement), a missing/untrusted client cert would now
//! complete the handshake and reach the inner handler, and those guard tests —
//! which assert a `serve_once` ERROR (handshake rejection) — would fail.
//!
//! The proxy is the MORE IMPORTANT boundary here: it guards the inner MCP server.
//! A broken client-auth control means any unauthenticated/untrusted caller can
//! reach the inner.
//!
//! How this stays a green, self-contained test: it does not run the guard tests
//! and check that they fail (that would mean shipping a red test). Instead it runs
//! the SAME missing-cert and untrusted-cert scenarios the guards run, but compiled
//! WITH the fault active, and asserts the OPPOSITE outcome (handshake completes,
//! inner handler reached, response served). The guards assert (reject, server
//! errors); this asserts (accept, handler reached, served) under the fault.
//! Demonstrating that the faulted outcome is the exact negation of the guards'
//! assertions is the proof that the guards would fire on a real break.
//!
//! This target is ONLY built/run with `--features fault_accept_any_client`. It is
//! NOT part of the default-config conformance run. The mcp-re-proxy crate's default
//! build is byte-for-byte the verifying proxy (the fault path is behind
//! `#[cfg(feature = "fault_accept_any_client")]`).

#![cfg(feature = "fault_accept_any_client")]

use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

use mcp_re_proxy::serve_once;
use mcp_re_proxy::RustlsDirectProvider;
use mcp_re_proxy::ServerOptions;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::StreamOwned;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;
use rustls_pki_types::UnixTime;

// The harness below mirrors `tls_test.rs` so the faulted scenario is the same
// scenario the guards run — only the control (and therefore the asserted outcome)
// differs. Fixtures are generated-but-deterministic-per-run via rcgen (no
// committed key material); fresh CAs/leaves and an OS-assigned ephemeral port each
// run.

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

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

/// A client-side verifier that accepts any server certificate — the test server
/// is self-presented and we are only exercising the SERVER's client-auth control.
#[derive(Debug)]
struct AcceptAnyServer;

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> ClientConfig {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer));
    match client_auth {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .expect("client auth cert"),
        None => builder.with_no_client_auth(),
    }
}

/// Connect as a TLS client, send one HTTP POST with `body`, return the response
/// body. Returns Err if the TLS handshake or IO fails (e.g. rejected client cert).
fn client_round_trip(
    addr: std::net::SocketAddr,
    config: ClientConfig,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let tcp = TcpStream::connect(addr)?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);

    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }
    let split = b"\r\n\r\n";
    let pos = response
        .windows(split.len())
        .position(|w| w == split)
        .map(|p| p + split.len())
        .unwrap_or(0);
    Ok(response[pos..].to_vec())
}

/// Build the proxy server config WITH the fault feature active. The proxy presents
/// its own server leaf; `client_ca` is still parsed for config construction, but is
/// ignored for client-auth verification (the faulted verifier accepts any client).
fn server_config_for(client_ca: &Ca) -> Arc<rustls::ServerConfig> {
    let server_ca = make_ca();
    let (server_cert, server_key) =
        make_leaf(&server_ca, vec![dns("localhost")], Some("localhost"), false);
    let config = RustlsDirectProvider::build_server_config(
        vec![server_cert],
        server_key,
        vec![client_ca.cert.der().clone()],
    )
    .expect("server config");
    Arc::new(config)
}

/// Negation of T1 (`missing_client_certificate_is_rejected`). With the
/// `fault_accept_any_client` control break compiled in, a connection that presents
/// NO client certificate — which the verifying proxy MUST reject at the handshake
/// — instead COMPLETES the handshake, reaches the inner handler, and is served.
///
/// The guard asserts: `serve_once` returns `Err` (handshake rejection).
/// Here, under the fault, we assert the exact negation: `serve_once` returns `Ok`,
/// the handler ran, and the served response came back. That negation is the proof
/// that the guard is load-bearing — if this fault path ever shipped in the real
/// proxy, the guard would fire.
#[test]
fn fault_accept_any_client_makes_missing_client_cert_accepted() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        serve_once(&listener, config, &ServerOptions::default(), |_req, _id| {
            b"{\"ok\":true}".to_vec()
        })
    });

    // Client presents NO certificate. The verifying proxy requires one (T1);
    // the faulted proxy (client_auth_mandatory = false) does not.
    let body = client_round_trip(addr, client_config(None), b"{\"jsonrpc\":\"2.0\"}")
        .expect("with the fault, the handshake completes even with no client cert");
    let served = server.join().expect("join");

    // THE CATCH DEMONSTRATION: with the control broken, the missing client cert is
    // accepted, the handshake completes, `serve_once` returns Ok, and the inner
    // handler served a response — the exact OPPOSITE of T1's `is_err()` assertion.
    assert!(
        served.is_ok(),
        "with fault_accept_any_client, a connection with NO client certificate must \
         COMPLETE (serve_once Ok) — this is the broken control T1 catches; got {served:?}"
    );
    assert_eq!(
        body, b"{\"ok\":true}",
        "the inner handler is reached and serves a response behind a MISSING client \
         cert — the negation of T1's handshake-rejection assertion"
    );
}

/// Negation of T2 (`untrusted_client_certificate_is_rejected`). With the fault
/// active, a client certificate signed by a CA the proxy does NOT trust — which
/// the verifying proxy MUST reject at the handshake — instead COMPLETES the
/// handshake, reaches the inner handler, and is served.
///
/// The guard asserts: `serve_once` returns `Err`. Here we assert the negation:
/// `serve_once` returns `Ok` and the served response came back.
#[test]
fn fault_accept_any_client_makes_untrusted_client_cert_accepted() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);

    // A client cert signed by a DIFFERENT CA than the proxy's client-CA root.
    let rogue_ca = make_ca();
    let (rogue_cert, rogue_key) =
        make_leaf(&rogue_ca, vec![uri("spiffe://evil/agent")], None, true);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        serve_once(&listener, config, &ServerOptions::default(), |_req, _id| {
            b"{\"ok\":true}".to_vec()
        })
    });

    let body = client_round_trip(
        addr,
        client_config(Some((vec![rogue_cert], rogue_key))),
        b"{\"jsonrpc\":\"2.0\"}",
    )
    .expect("with the fault, the handshake completes with an untrusted client cert");
    let served = server.join().expect("join");

    assert!(
        served.is_ok(),
        "with fault_accept_any_client, an UNTRUSTED client cert must be ACCEPTED \
         (serve_once Ok) — this is the broken control T2 catches; got {served:?}"
    );
    assert_eq!(
        body, b"{\"ok\":true}",
        "the inner handler is reached and serves a response behind an UNTRUSTED \
         client cert — the negation of T2's handshake-rejection assertion"
    );
}
