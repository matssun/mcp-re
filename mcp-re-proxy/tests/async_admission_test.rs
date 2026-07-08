// MCPRE-114 (ADR-MCPRE-051 §1, Phase 2) — per-core bounded admission control.
//
// Proves the async serving path enforces a per-core in-flight-request ceiling with
// FAIL-CLOSED backpressure: once `max_in_flight_requests` requests are being served,
// the next request is rejected with `503 Service Unavailable` BEFORE its body is read
// or the handler runs — never queued without bound. Also covers the unbounded default
// and the fleet-global → per-core ceiling derivation.
//
// Concurrency is forced deterministically by driving `async_serve::serve` on a
// MULTI-thread runtime with handlers that block until the test releases them; the
// admission mechanism lives in `async_serve` and is identical on the per-core fleet's
// current-thread runtimes (where "in flight" is dominated by async I/O phases).

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
use std::sync::Condvar;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use mcp_re_proxy::async_fleet::derived_per_core_ceiling;
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
    params.distinguished_name.push(DnType::CommonName, "mcp-re-admission-ca");
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

// --- blocking rustls client capturing the HTTP STATUS -------------------------

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

/// One mTLS request (fresh connection); returns the HTTP status code and body.
fn request_status(addr: SocketAddr, config: &ClientConfig, body: &[u8]) -> std::io::Result<(u16, Vec<u8>)> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
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
    read_status_and_body(&mut stream)
}

fn read_status_and_body(stream: &mut impl Read) -> std::io::Result<(u16, Vec<u8>)> {
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
    // Status line: "HTTP/1.1 <code> <reason>"
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no status line"))?;
    let lower = head.to_ascii_lowercase();
    let len = lower
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut out = vec![0u8; len];
    stream.read_exact(&mut out)?;
    Ok((status, out))
}

// --- multi-thread async server harness ----------------------------------------

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

/// Run `async_serve::serve` on a MULTI-thread runtime (so blocking handlers can be
/// concurrently in flight) in a background thread; return once bound.
fn spawn_server<H>(config: Arc<rustls::ServerConfig>, options: ServerOptions, handler: H) -> AsyncServer
where
    H: Fn(&[u8], Option<TransportIdentity>, Option<&str>) -> Vec<u8> + Send + Sync + 'static,
{
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_srv = Arc::clone(&shutdown);
    let (tx, rx) = mpsc::channel::<SocketAddr>();
    // Adapt the test's sync handler to the async seam (see async_drain_test).
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

fn options_with_in_flight(limit: Option<usize>) -> ServerOptions {
    ServerOptions {
        limits: ServerLimits {
            max_in_flight_requests: limit,
            ..ServerLimits::default()
        },
        ..ServerOptions::default()
    }
}

// --- tests --------------------------------------------------------------------

#[test]
fn over_cap_requests_are_rejected_503_fail_closed() {
    let ceiling = 2;
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);

    // Handlers increment `admitted` and then block on `gate` until the test releases
    // them, so the two admitted requests hold their in-flight permits across the
    // third request's admission attempt.
    let admitted = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let admitted_h = Arc::clone(&admitted);
    let gate_h = Arc::clone(&gate);
    let server = spawn_server(config, options_with_in_flight(Some(ceiling)), move |req, _id, _a| {
        admitted_h.fetch_add(1, Ordering::SeqCst);
        let (lock, cv) = &*gate_h;
        let mut released = lock.lock().expect("gate");
        while !*released {
            released = cv.wait(released).expect("gate wait");
        }
        req.to_vec()
    });

    // Fire three concurrent requests; each records its status into `results`.
    let results = Arc::new(Mutex::new(Vec::<u16>::new()));
    let client = client_config(&client_ca);
    let mut handles = Vec::new();
    for i in 0..3 {
        let addr = server.addr;
        let client = client.clone();
        let results = Arc::clone(&results);
        handles.push(std::thread::spawn(move || {
            let body = format!(r#"{{"id":{i}}}"#).into_bytes();
            let (status, _body) = request_status(addr, &client, &body).expect("request completes");
            results.lock().expect("results").push(status);
        }));
    }

    // Wait until exactly `ceiling` handlers are admitted and blocked (they hold their
    // permits), and the third request has recorded its rejection.
    wait_until(Duration::from_secs(10), || {
        admitted.load(Ordering::SeqCst) == ceiling && results.lock().expect("results").len() == 1
    });

    // At this point: 2 admitted (blocked, holding permits) and 1 already returned —
    // that one MUST be the 503 (fail-closed backpressure), and no 3rd handler ran.
    {
        let seen = results.lock().expect("results").clone();
        assert_eq!(seen, vec![503], "the over-cap request is rejected 503 before any handler runs");
        assert_eq!(admitted.load(Ordering::SeqCst), ceiling, "only `ceiling` requests were admitted");
    }

    // Release the two blocked handlers; they now complete with 200.
    {
        let (lock, cv) = &*gate;
        *lock.lock().expect("gate") = true;
        cv.notify_all();
    }
    for h in handles {
        h.join().expect("client thread");
    }

    let mut final_statuses = results.lock().expect("results").clone();
    final_statuses.sort_unstable();
    assert_eq!(final_statuses, vec![200, 200, 503], "two admitted (200) + one shed (503)");
    // Exactly `ceiling` handlers ran (the 503 never reached the handler).
    assert_eq!(admitted.load(Ordering::SeqCst), ceiling);
}

#[test]
fn no_ceiling_admits_all_concurrent_requests() {
    // With no ceiling (the default), many concurrent requests are all served — the
    // admission gate is disabled, not silently capping.
    let client_ca = make_ca();
    let config = server_config_for(&client_ca);
    let server = spawn_server(config, options_with_in_flight(None), move |req, _id, _a| req.to_vec());

    let client = client_config(&client_ca);
    let mut handles = Vec::new();
    for i in 0..12 {
        let addr = server.addr;
        let client = client.clone();
        handles.push(std::thread::spawn(move || {
            let body = format!(r#"{{"id":{i}}}"#).into_bytes();
            let (status, echoed) = request_status(addr, &client, &body).expect("request");
            assert_eq!(status, 200);
            assert_eq!(echoed, body, "body round-trips");
        }));
    }
    for h in handles {
        h.join().expect("client thread");
    }
}

#[test]
fn global_cap_divides_evenly_across_cores() {
    // MCPRE-114 config surface: an explicit per-core ceiling always wins; otherwise a
    // fleet-global target is divided evenly (ceil), at least 1; neither ⇒ unbounded.
    assert_eq!(derived_per_core_ceiling(Some(10), Some(1000), 4), Some(10), "explicit per-core wins");
    assert_eq!(derived_per_core_ceiling(None, Some(64), 4), Some(16), "even division");
    assert_eq!(derived_per_core_ceiling(None, Some(65), 4), Some(17), "ceil rounds up");
    assert_eq!(derived_per_core_ceiling(None, Some(2), 8), Some(1), "at least 1 per core");
    assert_eq!(derived_per_core_ceiling(None, None, 8), None, "no cap ⇒ unbounded");
    assert_eq!(derived_per_core_ceiling(None, Some(4), 0), Some(4), "cores=0 guarded (÷1)");
}

/// Spin until `cond` is true or `timeout` elapses (panicking on timeout). Used to
/// synchronize on server-side admission state without sleeping a fixed duration.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        if start.elapsed() > timeout {
            panic!("condition not met within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
