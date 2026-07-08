// MCPRE-115 (ADR-MCPRE-051 §6, Phase 2) — bounded graceful drain (zero-abandoned).
//
// Proves the async serving path drains gracefully on shutdown: it stops accepting and
// then joins IN-FLIGHT requests within a bounded grace window, so a request already
// being served completes (zero abandoned) rather than being cut off — while a stuck
// request cannot delay process exit past the grace window (bounded exit). Idle and
// saturated drains both return, exit-clean, within the bound.
//
// Concurrency is forced deterministically by driving `async_serve::serve` on a
// MULTI-thread runtime; the drain mechanism lives in `async_serve` and the per-core
// fleet inherits it (each core's `serve` drains before its worker thread joins).

#![cfg(feature = "async_serve")]

use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mcp_re_proxy::async_serve;
use mcp_re_proxy::tls::RustlsDirectProvider;
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

// --- rcgen CA + leaves --------------------------------------------------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, "mcp-re-drain-ca");
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

// --- blocking rustls client ---------------------------------------------------

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

fn client_config(ca: &Ca) -> ClientConfig {
    let (leaf, key) = make_leaf(ca, vec![uri(CLIENT_URI_SAN)], true);
    let chain = vec![leaf.der().clone()];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let provider = Arc::new(ring::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_client_auth_cert(chain, key_der)
        .expect("client auth")
}

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

fn tls_connect(addr: SocketAddr, config: &ClientConfig) -> std::io::Result<TlsStream> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(Arc::new(config.clone()), server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(StreamOwned::new(conn, tcp))
}

/// A full request over a fresh connection; returns the HTTP status code.
fn request_status(addr: SocketAddr, config: &ClientConfig, body: &[u8]) -> std::io::Result<u16> {
    let mut stream = tls_connect(addr, config)?;
    let head = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    read_status(&mut stream)
}

fn read_status(stream: &mut impl Read) -> std::io::Result<u16> {
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
    let head = String::from_utf8_lossy(&buf);
    head.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no status line"))
}

/// Open a connection, send request headers promising `content_length` bytes but send
/// only `partial` of them, and RETURN the still-open stream. The server is left
/// awaiting the missing body bytes (an in-flight request stalled in the async
/// body-read phase). Keep the returned stream alive to hold the request open.
fn open_stalled_body(
    addr: SocketAddr,
    config: &ClientConfig,
    content_length: usize,
    partial: usize,
) -> std::io::Result<TlsStream> {
    let mut stream = tls_connect(addr, config)?;
    let head = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n",
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&vec![b'x'; partial])?;
    stream.flush()?;
    Ok(stream)
}

// --- multi-thread async server harness with explicit shutdown -----------------

struct AsyncServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl AsyncServer {
    fn trigger_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
    /// Join the server thread, returning how long the join took (i.e. how long the
    /// drain + teardown took once shutdown was already signalled).
    fn join(mut self) -> Duration {
        let start = Instant::now();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        start.elapsed()
    }
}

impl Drop for AsyncServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn spawn_server<H>(config: Arc<rustls::ServerConfig>, options: ServerOptions, handler: H) -> AsyncServer
where
    H: Fn(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8> + Send + Sync + 'static,
{
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_srv = Arc::clone(&shutdown);
    let (tx, rx) = mpsc::channel::<SocketAddr>();
    // Adapt the test's sync handler to the async seam: each call returns a boxed
    // future that runs the sync handler and yields its bytes. The `InFlightGuard`
    // in `handle_request` spans this await, so a handler holding the request (the
    // HANDLER_HOLD sleep) keeps the drain's in-flight count > 0 exactly as before.
    let handler = Arc::new(handler);
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(6)
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            tx.send(listener.local_addr().expect("addr")).expect("send addr");
            let async_handler = move |body: Vec<u8>,
                                      id: Option<TransportIdentity>,
                                      assertion: Option<String>|
                  -> async_serve::HandlerResponseFuture {
                let h = Arc::clone(&handler);
                Box::pin(async move { h(&body, id, assertion.as_deref()) })
            };
            async_serve::serve(
                listener,
                config,
                Arc::new(options),
                Arc::new(async_handler),
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

fn options_with_drain(grace: Duration, request_deadline: Duration) -> ServerOptions {
    ServerOptions {
        limits: ServerLimits {
            drain_grace: grace,
            request_deadline: Some(request_deadline),
            ..ServerLimits::default()
        },
        ..ServerOptions::default()
    }
}

/// How long a handler holds a request in flight in the drain tests. Fixed and
/// SELF-RELEASING (a plain sleep, never a blocking wait on an external signal) so a
/// runtime drop can never wedge a worker thread — the handler always returns on its
/// own within this bound. Long enough that shutdown reliably fires while the request
/// is still in flight.
const HANDLER_HOLD: Duration = Duration::from_millis(500);

fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        if start.elapsed() > timeout {
            panic!("condition not met within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// --- tests --------------------------------------------------------------------

#[test]
fn in_flight_request_completes_during_drain_zero_abandoned() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let entered = Arc::new(AtomicUsize::new(0));
    let entered_h = Arc::clone(&entered);
    // Generous grace so the drain waits for the in-flight request rather than cutting
    // it off. The handler holds the request in flight for HANDLER_HOLD then returns on
    // its own (self-releasing — no external signal, so a runtime drop can never wedge).
    let server = spawn_server(
        config,
        options_with_drain(Duration::from_secs(10), Duration::from_secs(10)),
        move |req, _id, _a| {
            entered_h.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(HANDLER_HOLD);
            req.to_vec()
        },
    );

    // Fire one request; it enters the handler and is now in flight (holding).
    let addr = server.addr;
    let client = client_config(&client_ca);
    let status = std::thread::spawn(move || request_status(addr, &client, b"drain-me"));
    wait_until(Duration::from_secs(5), || entered.load(Ordering::SeqCst) == 1);

    // Signal shutdown WHILE the request is in flight. Graceful drain must let it finish
    // (200), not abandon it — the handler is still mid-HANDLER_HOLD.
    server.trigger_shutdown();

    let result = status.join().expect("client thread");
    assert_eq!(result.expect("request completes"), 200, "the in-flight request drained cleanly (not abandoned)");
    let join_time = server.join();
    assert!(join_time < Duration::from_secs(5), "drain returns promptly once the request finished, took {join_time:?}");
}

#[test]
fn idle_drain_returns_promptly() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    // A long grace, but no in-flight requests → drain must return well under it.
    let server = spawn_server(
        config,
        options_with_drain(Duration::from_secs(30), Duration::from_secs(30)),
        move |req, _id, _a| req.to_vec(),
    );
    // One completed request, then quiescent.
    let status = request_status(server.addr, &client_config(&client_ca), b"hi").expect("request");
    assert_eq!(status, 200);

    server.trigger_shutdown();
    let join_time = server.join();
    assert!(join_time < Duration::from_secs(3), "an idle drain returns promptly, took {join_time:?}");
}

#[test]
fn saturated_drain_completes_all_in_flight_zero_abandoned() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let entered = Arc::new(AtomicUsize::new(0));
    let entered_h = Arc::clone(&entered);
    // Handlers hold their requests in flight for HANDLER_HOLD then return on their own
    // (self-releasing — no external signal, no worker wedge under any scheduling).
    let server = spawn_server(
        config,
        options_with_drain(Duration::from_secs(10), Duration::from_secs(10)),
        move |req, _id, _a| {
            entered_h.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(HANDLER_HOLD);
            req.to_vec()
        },
    );

    // Several concurrent in-flight requests.
    let n = 4;
    let addr = server.addr;
    let client = client_config(&client_ca);
    let mut clients = Vec::new();
    for i in 0..n {
        let client = client.clone();
        clients.push(std::thread::spawn(move || {
            request_status(addr, &client, format!("req-{i}").as_bytes())
        }));
    }
    // All n are in flight (entered their handlers, now holding).
    wait_until(Duration::from_secs(5), || entered.load(Ordering::SeqCst) == n);

    // Shut down WHILE all n are in flight; the drain must let every one finish (200).
    server.trigger_shutdown();

    for c in clients {
        let status = c.join().expect("client thread").expect("request completes");
        assert_eq!(status, 200, "every in-flight request drained cleanly");
    }
    let join_time = server.join();
    assert!(join_time < Duration::from_secs(5), "saturated drain completed within bound, took {join_time:?}");
}

#[test]
fn stuck_request_cannot_delay_exit_past_grace() {
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    // Short grace; request_deadline LONGER than the grace, so the stalled body read is
    // still pending when the grace expires — proving the grace (not the request
    // deadline) is what bounds exit.
    let grace = Duration::from_millis(400);
    let server = spawn_server(
        config,
        options_with_drain(grace, Duration::from_secs(30)),
        move |req, _id, _a| req.to_vec(),
    );

    // Open a request that stalls in the async body-read phase (promises 100 bytes,
    // sends 1) and hold it open — an in-flight request that will not finish on its own
    // within the grace.
    let _stalled = open_stalled_body(server.addr, &client_config(&client_ca), 100, 1).expect("stalled open");
    // Let the server enter the body-read await for this request.
    std::thread::sleep(Duration::from_millis(150));

    server.trigger_shutdown();
    let join_time = server.join();
    // Bounded exit: the process tears down within ~grace even though a request is
    // still in flight (that request is abandoned — the bounded-drain guarantee).
    assert!(
        join_time < grace + Duration::from_secs(3),
        "exit must be bounded by the grace window even with a stuck in-flight request, took {join_time:?}",
    );
}
