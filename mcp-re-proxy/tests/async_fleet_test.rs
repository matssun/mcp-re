// MCPRE-113 (ADR-MCPRE-051 §1, Phase 2) — per-core serving fleet suite.
//
// Proves the per-core fleet (`async_fleet::serve_fleet`) stands up N independent
// per-core tokio runtimes, each with its own SO_REUSEPORT listener, and that every
// one serves the FULL mTLS pipeline correctly (same security core as the blocking +
// single-runtime async paths), with a configurable core count and a clean bounded
// shutdown. Kernel connection DISTRIBUTION across cores is asserted only on Linux
// (the production platform, where SO_REUSEPORT load-balances); off Linux the suite
// still proves every core serves correctly. Near-linear THROUGHPUT scaling is the
// load-harness/SLO lane (MCPRE-110/123), not a deterministic unit assertion.
//
// The mTLS + HTTP client harness is the same shape as async_serve_parity_test /
// tls_test / full_stack_test.

#![cfg(feature = "async_serve")]

use std::collections::HashSet;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use mcp_re_proxy::async_fleet;
use mcp_re_proxy::async_fleet::FleetConfig;
use mcp_re_proxy::tls::RustlsDirectProvider;
use mcp_re_proxy::transport::TransportIdentity;
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

const CLIENT_URI_SAN: &str = "spiffe://example.org/agent-1";

// --- rcgen CA + leaves (same shape as async_serve_parity_test) ----------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, "mcp-re-fleet-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
}

fn make_leaf(ca: &Ca, sans: Vec<SanType>, client_auth: bool) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    let cert = params.signed_by(&key, &ca.cert, &ca.key).expect("leaf signed");
    (cert, key)
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

fn server_config_for(client_ca: &Ca) -> Arc<rustls::ServerConfig> {
    let server_ca = make_ca();
    let (server_cert, server_key) = make_leaf(&server_ca, vec![dns("localhost")], false);
    let server_der = server_cert.der().clone();
    let server_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let config = RustlsDirectProvider::build_server_config(
        vec![server_der],
        server_key_der,
        vec![client_ca.cert.der().clone()],
    )
    .expect("server config");
    Arc::new(config)
}

// --- blocking rustls client (Content-Length framed) ---------------------------

#[derive(Debug)]
struct AcceptAnyServer;
impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _t: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
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
        .expect("client versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer));
    match client_auth {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).expect("client auth"),
        None => builder.with_no_client_auth(),
    }
}

fn trusted_client(ca: &Ca) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let (leaf, key) = make_leaf(ca, vec![uri(CLIENT_URI_SAN)], true);
    let der = leaf.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (vec![der], key_der)
}

/// One mTLS request (fresh connection) returning the response body, or `Err` on a
/// failed handshake / IO.
fn single_request(addr: SocketAddr, config: &ClientConfig, body: &[u8]) -> std::io::Result<Vec<u8>> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(Arc::new(config.clone()), server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);
    let head = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    read_http_body(&mut stream)
}

fn read_http_body(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed before response headers",
            ));
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
    }
    let headers = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    let len = headers
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no content-length"))?;
    let mut out = vec![0u8; len];
    stream.read_exact(&mut out)?;
    Ok(out)
}

// --- per-core handler factory -------------------------------------------------

/// A per-core handler that records which core served each request (into a shared
/// sink) and echoes `core_index:body` so the client can also observe the serving
/// core end-to-end.
fn make_core_handler(
    core_index: usize,
    served_cores: Arc<Mutex<Vec<usize>>>,
) -> impl Fn(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8> + Send + Sync + 'static {
    move |request, _identity, _assertion| {
        served_cores.lock().expect("served sink").push(core_index);
        let mut out = format!("{core_index}:").into_bytes();
        out.extend_from_slice(request);
        out
    }
}

// --- tests --------------------------------------------------------------------

#[test]
fn fleet_serves_requests_across_per_core_runtimes() {
    let cores = 4;
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let served_cores = Arc::new(Mutex::new(Vec::<usize>::new()));
    let shutdown = Arc::new(AtomicBool::new(false));

    let served_for_factory = Arc::clone(&served_cores);
    let fleet = async_fleet::serve_fleet(
        FleetConfig {
            addr: "127.0.0.1:0".parse().expect("addr"),
            cores,
            listen_backlog: 128,
            max_in_flight_total: None,
        },
        config,
        Arc::new(ServerOptions::default()),
        move |core| Arc::new(make_core_handler(core, Arc::clone(&served_for_factory))),
        Arc::clone(&shutdown),
    )
    .expect("fleet starts");

    assert_eq!(fleet.worker_count(), cores, "one worker runtime per requested core");
    let addr = fleet.local_addr();

    // Fire many concurrent requests from independent client threads (distinct source
    // ports → the kernel SO_REUSEPORT group can spread them across per-core
    // listeners). Every request must be served correctly by SOME core.
    let request_count = 48;
    let client = client_config(Some(trusted_client(&client_ca)));
    let mut handles = Vec::new();
    for i in 0..request_count {
        let client = client.clone();
        handles.push(std::thread::spawn(move || {
            let body = format!(r#"{{"jsonrpc":"2.0","id":{i}}}"#).into_bytes();
            let response = single_request(addr, &client, &body).expect("round trip");
            // Response is `<core>:<body>` — strip the core tag and assert the body
            // round-tripped through the full pipeline.
            let colon = response.iter().position(|&b| b == b':').expect("core tag");
            assert_eq!(&response[colon + 1..], &body[..], "body round-trips");
        }));
    }
    for h in handles {
        h.join().expect("client thread");
    }

    let served = served_cores.lock().expect("served sink").clone();
    assert_eq!(served.len(), request_count, "every request was served exactly once");
    for core in &served {
        assert!(*core < cores, "a request was served by a valid core index");
    }

    // On Linux the SO_REUSEPORT group load-balances new connections across the
    // per-core listeners, so with 48 connections over 4 listeners more than one core
    // must have served. Off Linux (dev), distribution is platform-dependent, so we
    // assert only correctness above.
    #[cfg(target_os = "linux")]
    {
        let distinct: HashSet<usize> = served.iter().copied().collect();
        assert!(
            distinct.len() >= 2,
            "SO_REUSEPORT must distribute connections across at least 2 cores (got {distinct:?})",
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _: HashSet<usize> = served.iter().copied().collect();
    }

    fleet.shutdown_and_join();
}

#[test]
fn single_core_fleet_serves() {
    // The degenerate cores=1 case: still a per-core runtime + its own SO_REUSEPORT
    // listener, and it serves correctly.
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let served_cores = Arc::new(Mutex::new(Vec::<usize>::new()));
    let shutdown = Arc::new(AtomicBool::new(false));

    let served_for_factory = Arc::clone(&served_cores);
    let fleet = async_fleet::serve_fleet(
        FleetConfig {
            addr: "127.0.0.1:0".parse().expect("addr"),
            cores: 1,
            listen_backlog: 64,
            max_in_flight_total: None,
        },
        config,
        Arc::new(ServerOptions::default()),
        move |core| Arc::new(make_core_handler(core, Arc::clone(&served_for_factory))),
        Arc::clone(&shutdown),
    )
    .expect("fleet starts");
    assert_eq!(fleet.worker_count(), 1);

    let body = br#"{"jsonrpc":"2.0"}"#;
    let response = single_request(fleet.local_addr(), &client_config(Some(trusted_client(&client_ca))), body)
        .expect("round trip");
    assert_eq!(&response, b"0:{\"jsonrpc\":\"2.0\"}", "the single core (index 0) served it");

    fleet.shutdown_and_join();
}

#[test]
fn auto_core_count_starts_at_least_one_worker() {
    // cores = 0 resolves to available_parallelism (>= 1). We assert only the lower
    // bound (the exact count is machine-dependent) and that it serves.
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let served_cores = Arc::new(Mutex::new(Vec::<usize>::new()));
    let shutdown = Arc::new(AtomicBool::new(false));

    let served_for_factory = Arc::clone(&served_cores);
    let fleet = async_fleet::serve_fleet(
        FleetConfig::new("127.0.0.1:0".parse().expect("addr")),
        config,
        Arc::new(ServerOptions::default()),
        move |core| Arc::new(make_core_handler(core, Arc::clone(&served_for_factory))),
        Arc::clone(&shutdown),
    )
    .expect("fleet starts");
    assert!(fleet.worker_count() >= 1, "auto core count starts at least one worker");

    let body = br#"{"jsonrpc":"2.0"}"#;
    let response = single_request(fleet.local_addr(), &client_config(Some(trusted_client(&client_ca))), body)
        .expect("round trip");
    let colon = response.iter().position(|&b| b == b':').expect("core tag");
    assert_eq!(&response[colon + 1..], &body[..]);

    fleet.shutdown_and_join();
}

#[test]
fn missing_client_cert_fails_closed_across_the_fleet() {
    // The fleet reuses the exact mTLS ServerConfig, so a missing client cert fails
    // closed at the handshake on every core — the handler never runs.
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let served_cores = Arc::new(Mutex::new(Vec::<usize>::new()));
    let shutdown = Arc::new(AtomicBool::new(false));

    let served_for_factory = Arc::clone(&served_cores);
    let fleet = async_fleet::serve_fleet(
        FleetConfig {
            addr: "127.0.0.1:0".parse().expect("addr"),
            cores: 3,
            listen_backlog: 64,
            max_in_flight_total: None,
        },
        config,
        Arc::new(ServerOptions::default()),
        move |core| Arc::new(make_core_handler(core, Arc::clone(&served_for_factory))),
        Arc::clone(&shutdown),
    )
    .expect("fleet starts");

    // No client cert: every attempt must fail closed (handshake rejected).
    for _ in 0..6 {
        let result = single_request(fleet.local_addr(), &client_config(None), br#"{"jsonrpc":"2.0"}"#);
        assert!(result.is_err(), "a missing client cert must fail closed");
    }
    assert!(
        served_cores.lock().expect("served sink").is_empty(),
        "no core's handler runs for a rejected handshake",
    );

    fleet.shutdown_and_join();
}
