//! MCPRE-112 (ADR-MCPRE-051 §1) — async serving-path PARITY suite.
//!
//! Proves the opt-in async path (`tokio` + `tokio-rustls` + `hyper`) reproduces the
//! blocking serve loop's security behaviors, and adds what the async transport
//! makes possible (keep-alive, concurrency). The rustls `ServerConfig` and the
//! identity/rejection helpers are the SAME ones the blocking `serve_once` uses
//! (`tls_test` covers the blocking side); this file re-establishes the load-bearing
//! guarantees over the async transport:
//!
//!   * verified mTLS identity is extracted and handed to the handler (DirectTls);
//!   * a MISSING client certificate fails closed at the handshake (inner unreached);
//!   * an UNTRUSTED client certificate fails closed at the handshake;
//!   * keep-alive: N requests on ONE connection pay ONE handshake (the
//!     `Connection: close` one-request-per-connection wire is gone);
//!   * concurrency: many simultaneous connections are served by ONE shared handler
//!     (`Proxy: Send + Sync`, MCPRE-111);
//!   * `max_body_bytes` is enforced (oversized body → fail closed, inner unreached).
//!
//! The server runs on a shared tokio runtime in a background thread (dev
//! scaffolding per ADR-MCPRE-051 §1; per-core is MCPRE-113); clients are blocking
//! rustls, framing HTTP/1.1 keep-alive by `Content-Length`.

#![cfg(feature = "async_serve")]

use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_proxy::async_serve;
use mcp_re_proxy::tls::RustlsDirectProvider;
use mcp_re_proxy::transport::IdentityPolicy;
use mcp_re_proxy::transport::TransportIdentity;
use mcp_re_proxy::ServerLimits;
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

// --- rcgen CA + leaves (same shape as tls_test / full_stack_test) -------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, "mcp-re-async-ca");
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

/// A server config whose CLIENT-CA root is `client_ca` (the issuer of the client
/// certs the tests mint). Built by the SAME `RustlsDirectProvider` the blocking
/// path uses, so the mTLS verifier is identical.
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

// --- blocking rustls client (Content-Length framed; keep-alive capable) -------

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

/// Open one mTLS connection to `addr` with `config`. `Err` if the handshake fails
/// (e.g. a missing/untrusted client cert — fail closed).
fn connect(addr: SocketAddr, config: ClientConfig) -> std::io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(StreamOwned::new(conn, tcp))
}

/// Send one keep-alive request over an existing stream and read the
/// `Content-Length`-framed response body. Driving the first read completes the
/// handshake, so an unauthenticated/untrusted client surfaces as an error here.
fn request_keepalive(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let head = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    read_http_body(stream)
}

/// Read one HTTP/1.1 response: headers up to `\r\n\r\n`, then exactly
/// `Content-Length` body bytes (keep-alive safe — does not wait for EOF).
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

// --- async server harness (tokio runtime in a background thread) --------------

/// A running async server; shuts down + joins on drop.
struct AsyncServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for AsyncServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Spin up `async_serve::serve` on a background tokio runtime with the given
/// config/options/handler and return once it is bound (addr via channel).
fn spawn_server<H>(config: Arc<rustls::ServerConfig>, options: ServerOptions, handler: H) -> AsyncServer
where
    H: Fn(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8> + Send + Sync + 'static,
{
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_srv = Arc::clone(&shutdown);
    let (tx, rx) = mpsc::channel::<SocketAddr>();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            tx.send(listener.local_addr().expect("addr")).expect("send addr");
            async_serve::serve(
                listener,
                config,
                Arc::new(options),
                Arc::new(handler),
                shutdown_srv,
            )
            .await;
        });
    });
    let addr = rx.recv_timeout(Duration::from_secs(5)).expect("server bound");
    AsyncServer {
        addr,
        shutdown,
        handle: Some(handle),
    }
}

/// The identity value the handler observed, recorded per request so a test can
/// assert the async path extracted + passed the verified mTLS identity.
fn echo_recording_identity(
    sink: Arc<std::sync::Mutex<Vec<Option<String>>>>,
) -> impl Fn(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8> + Send + Sync + 'static {
    move |request, identity, _assertion| {
        sink.lock()
            .expect("sink")
            .push(identity.as_ref().map(|i| i.value.clone()));
        // Echo the request body back so the client can assert the round-trip.
        request.to_vec()
    }
}

// --- tests --------------------------------------------------------------------

#[test]
fn mtls_identity_extracted_and_request_served() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
    let server = spawn_server(
        config,
        ServerOptions {
            identity_policy: IdentityPolicy::UriSan,
            ..ServerOptions::default()
        },
        echo_recording_identity(Arc::clone(&sink)),
    );

    let mut stream = connect(server.addr, client_config(Some(trusted_client(&client_ca))))
        .expect("mTLS connect");
    let body = br#"{"jsonrpc":"2.0"}"#;
    let response = request_keepalive(&mut stream, body).expect("round trip");
    assert_eq!(response, body, "the async path serves the request body");

    let observed = sink.lock().expect("sink").clone();
    assert_eq!(
        observed,
        vec![Some(CLIENT_URI_SAN.to_string())],
        "the verified mTLS URI-SAN identity reached the handler",
    );
}

#[test]
fn missing_client_cert_fails_closed_at_handshake() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
    let server = spawn_server(config, ServerOptions::default(), echo_recording_identity(Arc::clone(&sink)));

    // No client certificate: the mTLS handshake must fail; the request never reaches
    // the handler.
    let mut stream = connect(server.addr, client_config(None)).expect("tcp+client build");
    let result = request_keepalive(&mut stream, br#"{"jsonrpc":"2.0"}"#);
    assert!(result.is_err(), "a missing client cert must fail closed");
    assert!(
        sink.lock().expect("sink").is_empty(),
        "the handler must never run for a rejected handshake",
    );
}

#[test]
fn untrusted_client_cert_fails_closed_at_handshake() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
    let server = spawn_server(config, ServerOptions::default(), echo_recording_identity(Arc::clone(&sink)));

    // A client cert issued by a DIFFERENT (untrusted) CA must be rejected.
    let rogue_ca = make_ca();
    let mut stream = connect(server.addr, client_config(Some(trusted_client(&rogue_ca))))
        .expect("tcp+client build");
    let result = request_keepalive(&mut stream, br#"{"jsonrpc":"2.0"}"#);
    assert!(result.is_err(), "an untrusted client cert must fail closed");
    assert!(sink.lock().expect("sink").is_empty(), "handler never runs on rejection");
}

#[test]
fn keep_alive_serves_many_requests_on_one_handshake() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_h = Arc::clone(&counter);
    let server = spawn_server(config, ServerOptions::default(), move |request, _id, _a| {
        counter_h.fetch_add(1, Ordering::SeqCst);
        request.to_vec()
    });

    // ONE connection (one handshake), FIVE sequential requests — the Connection:
    // close one-request-per-connection wire is gone.
    let mut stream = connect(server.addr, client_config(Some(trusted_client(&client_ca))))
        .expect("mTLS connect");
    for i in 0..5 {
        let body = format!(r#"{{"jsonrpc":"2.0","id":{i}}}"#);
        let response = request_keepalive(&mut stream, body.as_bytes()).expect("keep-alive request");
        assert_eq!(response, body.as_bytes(), "request {i} served on the kept-alive connection");
    }
    assert_eq!(counter.load(Ordering::SeqCst), 5, "all five requests served over one handshake");
}

#[test]
fn many_concurrent_connections_served_by_one_shared_handler() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let served_h = Arc::clone(&served);
    let server = Arc::new(spawn_server(config, ServerOptions::default(), move |request, _id, _a| {
        served_h.fetch_add(1, Ordering::SeqCst);
        request.to_vec()
    }));

    let client_auth = trusted_client(&client_ca);
    let n = 32usize;
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let addr = server.addr;
            let auth = (client_auth.0.clone(), client_auth.1.clone_key());
            std::thread::spawn(move || {
                let mut stream = connect(addr, client_config(Some(auth))).expect("mTLS connect");
                let body = format!(r#"{{"id":{i}}}"#);
                let resp = request_keepalive(&mut stream, body.as_bytes()).expect("round trip");
                assert_eq!(resp, body.as_bytes());
            })
        })
        .collect();
    for h in handles {
        h.join().expect("client thread");
    }
    assert_eq!(served.load(Ordering::SeqCst), n, "all concurrent connections served");
}

#[test]
fn oversized_body_is_rejected_before_the_handler() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let reached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reached_h = Arc::clone(&reached);
    // Tiny body cap so a modest request trips it.
    let options = ServerOptions {
        limits: ServerLimits {
            max_body_bytes: 16,
            ..ServerLimits::default()
        },
        ..ServerOptions::default()
    };
    let server = spawn_server(config, options, move |request, _id, _a| {
        reached_h.fetch_add(1, Ordering::SeqCst);
        request.to_vec()
    });

    let mut stream = connect(server.addr, client_config(Some(trusted_client(&client_ca))))
        .expect("mTLS connect");
    // 64 bytes > 16-byte cap → fail closed (413), the handler never runs.
    let big = vec![b'x'; 64];
    let framed = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        big.len()
    );
    stream.write_all(framed.as_bytes()).expect("write head");
    stream.write_all(&big).expect("write body");
    stream.flush().expect("flush");
    // The server responds with an empty 413 (no body); read the status line.
    let mut status = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).map(|n| n > 0).unwrap_or(false) {
        status.push(byte[0]);
        if status.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let status = String::from_utf8_lossy(&status);
    assert!(status.contains("413"), "oversized body must be rejected (413): {status:?}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "the handler must never see an over-cap body");
}
