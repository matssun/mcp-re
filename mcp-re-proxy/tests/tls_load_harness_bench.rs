//! MCPRE-108 (ADR-MCPRE-051 §7) — concurrent-TLS-client load harness driving the
//! REAL listener.
//!
//! ADR-MCPRE-051 §7 makes a load harness a *prerequisite deliverable*: every
//! architectural throughput claim must be MEASURED against the real serving path,
//! not argued. Unlike `fleet_throughput_bench` — which calls `Proxy::handle`
//! directly on one thread and structurally cannot see TLS/handshake/accept cost —
//! this harness spawns the real `mcp-re-proxy` binary and drives its listener over
//! many concurrent rustls **mTLS** clients: accept → TLS/mTLS → verify → inner →
//! sign → respond. Every measured number therefore includes the full PEP path.
//!
//! It reports aggregate throughput and p50/p99/p999 added latency, measures the
//! cold-handshake and keep-alive connection modes SEPARATELY, and records the
//! declared benchmark envelope (hardware class, core count, payload, TLS/signature
//! suite, connection mode, replay backend, inner latency) alongside the numbers —
//! the envelope is pinned in `docs/bench/adr-051-load-harness-envelope.md` +
//! `adr-051-benchmark-envelope.json`. It drives the per-core async fleet
//! (`--cores` pins the worker count) and produces the baseline + per-core scaling
//! input to the SLO declaration (MCPRE-110).
//!
//! Two entry points:
//!   * [`load_harness_smoke`] — ALWAYS runs in the battery at tiny scale, so the
//!     harness itself is self-verifying and stays green: it drives the real
//!     listener end-to-end, confirms a genuinely signed+bound response, and checks
//!     the metrics compute. It is NOT an SLO gate.
//!   * [`tls_load_harness_bench`] — `#[ignore]` (the ADR-051 §7 "manual/dispatch
//!     lane, not a per-PR gate"): the full run, scaled by `MCP_RE_LOADGEN_*` env,
//!     printing the report and (optionally) writing machine-readable JSON.
//!
//! NOTE on keep-alive: the current wire is one-request-per-connection
//! (`Connection: close`, ADR-051 Context §3), so `keepalive` mode reports a
//! realised-reuse fraction ≈ 0 on the current proxy — the mode is instrumented now
//! and becomes meaningful with the Phase-2 keep-alive/H2 data plane.

use std::convert::Infallible;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;

use mcp_re_core::b64url_encode;
use mcp_re_core::request_hash;
use mcp_re_core::unix_to_rfc3339_utc;
use mcp_re_core::verify_response;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_host::HostSigner;

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

use serde_json::json;
use serde_json::Value;

const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const SIGNER_A: &str = "spiffe://example.org/agent-1"; // == client-cert URI SAN
const SIGNER_A_KEY_ID: &str = "key-a";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";

fn server_seed() -> [u8; 32] {
    [2u8; 32]
}
fn signer_a_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}

// --- rcgen certificate authority + leaves -------------------------------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, "mcp-re-loadgen-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
}

fn make_leaf(
    ca: &Ca,
    sans: Vec<SanType>,
    common_name: Option<&str>,
    client_auth: bool,
) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
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

// --- temp key material on disk ------------------------------------------------

fn tmp(name: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("mcp_re_loadgen_{}_{seq}_{name}", std::process::id()))
}

struct Material {
    seed_path: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    client_ca_path: PathBuf,
    trust_path: PathBuf,
    client_ca: Ca,
}

fn write_material() -> Material {
    let server_ca = make_ca();
    let (server_leaf, server_leaf_key) =
        make_leaf(&server_ca, vec![dns("localhost")], Some("localhost"), false);
    let client_ca = make_ca();

    let seed_path = tmp("seed");
    let server_cert_path = tmp("server_cert.pem");
    let server_key_path = tmp("server_key.pem");
    let client_ca_path = tmp("client_ca.pem");
    let trust_path = tmp("trust.json");

    std::fs::write(&seed_path, b64url_encode(&server_seed())).unwrap();
    std::fs::write(&server_cert_path, server_leaf.pem()).unwrap();
    std::fs::write(&server_key_path, server_leaf_key.serialize_pem()).unwrap();
    std::fs::write(&client_ca_path, client_ca.cert.pem()).unwrap();

    let trust = json!([
        { "signer": SIGNER_A, "key_id": SIGNER_A_KEY_ID, "public_key": signer_a_key().public_key().to_b64url() },
    ]);
    std::fs::write(&trust_path, serde_json::to_vec(&trust).unwrap()).unwrap();

    Material {
        seed_path,
        server_cert_path,
        server_key_path,
        client_ca_path,
        trust_path,
        client_ca,
    }
}

impl Drop for Material {
    fn drop(&mut self) {
        for p in [
            &self.seed_path,
            &self.server_cert_path,
            &self.server_key_path,
            &self.client_ca_path,
            &self.trust_path,
        ] {
            let _ = std::fs::remove_file(p);
        }
    }
}

// --- runfiles binary resolution + spawned CLI (killed on drop) ----------------

fn locate(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

// --- in-process HTTP echo inner backend (ADR-MCPRE-051 §3) --------------------
//
// The proxy serves on the async fleet and forwards each verified request over HTTP
// to a stateless inner backend (no more stdio echo subprocess). This is the HTTP
// analogue of the old `echo_inner` fixture: it reads the POSTed JSON-RPC request
// and answers with a JSON-RPC result echoing `params._meta` and the method, so a
// success ("no error") still corresponds to a genuinely signed inner result.
// Mirrors the in-process hyper backend in `http_inner_test.rs`.
async fn echo_inner_service(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let meta = value
        .get("params")
        .and_then(|params| params.get("_meta"))
        .cloned()
        .unwrap_or(Value::Null);
    let method = value.get("method").cloned().unwrap_or(Value::Null);

    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "echoed_meta": meta, "echoed_method": method },
    });
    let bytes = serde_json::to_vec(&response).unwrap_or_default();
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .expect("response builds"))
}

/// Start the in-process HTTP echo backend on an ephemeral `127.0.0.1` port and
/// return its bound address. Runs on its own multi-thread tokio runtime on a
/// detached daemon thread (lives for the rest of the test process), so it can
/// absorb the harness's concurrent load without starving.
fn spawn_http_echo_backend() -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("backend runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind echo backend");
            let addr = listener.local_addr().expect("backend addr");
            tx.send(addr).expect("send backend addr");
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service_fn(echo_inner_service))
                        .await;
                });
            }
        });
    });
    rx.recv().expect("echo backend did not report its address")
}

struct ProxyProcess {
    child: std::process::Child,
    addr: SocketAddr,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_proxy(material: &Material, inner_http_url: &str, cores: usize) -> ProxyProcess {
    let cli = locate("MCP_RE_PROXY_CLI");

    // ADR-MCPRE-051 §1/§7: PIN the per-core worker count so `declared_cores` in the
    // report is the count actually served (not a label divorced from the auto-sized
    // fleet), and so the 1→N linear-scaling curve is reproducible — run the bench at
    // MCP_RE_LOADGEN_CORES=1 then =N. `0` is passed through as auto (one per core).
    let cores_str = cores.to_string();

    // Bind an EPHEMERAL port and read the resolved address back from the CLI's own
    // `async fleet serving on <addr>` stderr line — race-free (the fleet owns the
    // port from bind onward), unlike a bind-release-rebind `free_port()`.
    let mut child = Command::new(&cli)
        .args([
            "--bind", "127.0.0.1:0",
            "--audience", AUDIENCE,
            "--server-signer", SERVER,
            "--server-key-id", SERVER_KEY_ID,
            "--key-source", "file",
            "--signing-key-seed", &material.seed_path.to_string_lossy(),
            "--tls-cert", &material.server_cert_path.to_string_lossy(),
            "--tls-key", &material.server_key_path.to_string_lossy(),
            "--client-ca", &material.client_ca_path.to_string_lossy(),
            "--trust", &material.trust_path.to_string_lossy(),
            "--transport-binding", "exact",
            "--transport-identity-source", "uri_san",
            "--max-client-cert-lifetime", "175200h",
            "--cores", &cores_str,
            // ADR-MCPRE-051 §3: serve on the async fleet forwarding to the
            // stateless in-process HTTP echo backend (was `--inner-command <echo>`).
            "--inner-http-url", inner_http_url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp_re_proxy_cli");

    let stderr_buf = Arc::new(Mutex::new(String::new()));
    let mut pipe = child.stderr.take().expect("piped stderr");
    let sink = Arc::clone(&stderr_buf);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut buf) = sink.lock() {
                        buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
                Err(_) => break,
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    let addr = loop {
        if let Some(a) = stderr_buf.lock().ok().and_then(|b| parse_serving_addr(&b)) {
            break a;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let captured = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
            panic!("mcp_re_proxy_cli exited before serving (status {status}):\n{captured}");
        }
        if Instant::now() > deadline {
            let captured = stderr_buf.lock().map(|b| b.clone()).unwrap_or_default();
            let _ = child.kill();
            panic!("mcp_re_proxy_cli did not report a serving address within budget:\n{captured}");
        }
        std::thread::sleep(Duration::from_millis(25));
    };

    let mut up = false;
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(up, "mcp_re_proxy_cli listening address {addr} is not accepting connections");

    ProxyProcess { child, addr }
}

/// Parse the CLI's `... async fleet serving on <addr> (...)` stderr line into the
/// bound [`SocketAddr`].
fn parse_serving_addr(stderr: &str) -> Option<SocketAddr> {
    let marker = "async fleet serving on ";
    let start = stderr.find(marker)? + marker.len();
    let rest = &stderr[start..];
    let end = rest.find(char::is_whitespace)?;
    rest[..end].parse::<SocketAddr>().ok()
}

// --- TLS client ---------------------------------------------------------------

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

/// Build the client mTLS config ONCE (the trusted URI-SAN leaf) and share it via
/// `Arc` across every connection, so the measured latency is the handshake +
/// request cost, not repeated config/cert construction.
fn build_client_config(ca: &Ca) -> Arc<ClientConfig> {
    let (leaf, key) = make_leaf(ca, vec![uri(SIGNER_A)], None, true);
    let chain = vec![leaf.der().clone()];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let provider = Arc::new(ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_client_auth_cert(chain, key_der)
        .expect("client auth");
    Arc::new(config)
}

/// Read one HTTP/1.1 response off `stream`: consume the header block up to
/// `\r\n\r\n`, parse `Content-Length`, then read exactly that many body bytes.
/// Returns `(body, server_keeps_alive)` where `server_keeps_alive` is false when
/// the response carried `Connection: close` (the current proxy always does).
fn read_http_response(stream: &mut impl Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    // Read until the end of the header block.
    let header_end = loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before response headers completed",
            ));
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break buf.len();
        }
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let content_length = header_text
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "no Content-Length in response")
        })?;
    let keeps_alive = !header_text.contains("connection: close");

    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body)?;
    Ok((body, keeps_alive))
}

/// Open a fresh mTLS connection, send one signed request, and read the response
/// body (cold-handshake path). Returns the response body bytes.
fn cold_round_trip(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let tcp = TcpStream::connect(addr)?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(config, server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);

    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    let (resp, _keeps_alive) = read_http_response(&mut stream)?;
    Ok(resp)
}

// --- signed requests (real clock) ---------------------------------------------

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Sign a `tools/call` as `SIGNER_A`, timestamped at the real clock (the CLI runs
/// on its own uninjected system clock) and carrying a UNIQUE `nonce` so replay
/// never fires across the load run.
fn signed_request(nonce: &str) -> Vec<u8> {
    let now = now_unix();
    let issued_at = unix_to_rfc3339_utc(now);
    let expires_at = unix_to_rfc3339_utc(now + 300);
    HostSigner::new(signer_a_key(), SIGNER_A, SIGNER_A_KEY_ID)
        .sign_tool_call(
            &Value::String("req-1".to_string()),
            "echo",
            json!({ "text": "hello" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            nonce,
            &issued_at,
            &expires_at,
        )
        .expect("host signs")
}

fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, SigningKey::from_seed_bytes(&server_seed()).public_key());
    r
}

/// A response is a SUCCESS iff it parses as a JSON object with no `error` — the
/// proxy fails closed with a JSON-RPC error object, so "no error" means the inner
/// result was signed and returned.
fn is_success(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .map(|v| v.get("error").is_none() && v.get("result").is_some())
        .unwrap_or(false)
}

// --- load generation + metrics ------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Cold,
    KeepAlive,
}

impl Mode {
    fn as_str(&self) -> &'static str {
        match self {
            Mode::Cold => "cold",
            Mode::KeepAlive => "keepalive",
        }
    }
}

struct LoadConfig {
    concurrency: usize,
    requests: usize,
    mode: Mode,
    hw_class: String,
    cores: usize,
}

impl LoadConfig {
    /// The full-bench config, scaled from `MCP_RE_LOADGEN_*` env with the envelope
    /// defaults (concurrency 64, 2000 requests, cold).
    fn from_env() -> Self {
        let env_usize = |k: &str, default: usize| {
            std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
        };
        let mode = match std::env::var("MCP_RE_LOADGEN_MODE").ok().as_deref() {
            Some("keepalive") => Mode::KeepAlive,
            _ => Mode::Cold,
        };
        LoadConfig {
            concurrency: env_usize("MCP_RE_LOADGEN_CONCURRENCY", 64),
            requests: env_usize("MCP_RE_LOADGEN_REQUESTS", 2000),
            mode,
            hw_class: std::env::var("MCP_RE_LOADGEN_HW_CLASS")
                .unwrap_or_else(|_| "unspecified".to_string()),
            cores: env_usize(
                "MCP_RE_LOADGEN_CORES",
                std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            ),
        }
    }
}

#[derive(Default)]
struct Report {
    successes: usize,
    failures: usize,
    reconnects: usize,
    wall: Duration,
    p50_us: u128,
    p99_us: u128,
    p999_us: u128,
    min_us: u128,
    mean_us: u128,
    max_us: u128,
    throughput_rps: f64,
    reuse_fraction: f64,
}

/// `q`-quantile (0.0..=1.0) of a SORTED slice, by nearest-rank.
fn quantile(sorted: &[u128], q: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Drive the workload: `concurrency` worker threads pull request indices off a
/// shared counter until `requests` are done, each timing one round-trip against
/// the real listener. Returns the aggregated [`Report`].
fn run_load(addr: SocketAddr, config: Arc<ClientConfig>, cfg: &LoadConfig) -> Report {
    let next = Arc::new(AtomicUsize::new(0));
    let latencies: Arc<Mutex<Vec<u128>>> = Arc::new(Mutex::new(Vec::with_capacity(cfg.requests)));
    let failures = Arc::new(AtomicUsize::new(0));
    let reconnects = Arc::new(AtomicUsize::new(0));

    let start = Instant::now();
    let handles: Vec<_> = (0..cfg.concurrency)
        .map(|_| {
            let next = Arc::clone(&next);
            let latencies = Arc::clone(&latencies);
            let failures = Arc::clone(&failures);
            let reconnects = Arc::clone(&reconnects);
            let config = Arc::clone(&config);
            let addr = addr;
            let mode = cfg.mode;
            let total = cfg.requests;
            std::thread::spawn(move || {
                let mut local: Vec<u128> = Vec::new();
                // Keep-alive mode threads a single live stream across requests and
                // reconnects when the server closes it (the current proxy always
                // sends Connection: close, so this reconnects every request — the
                // realised-reuse fraction the report exposes).
                let mut kept: Option<StreamOwned<ClientConnection, TcpStream>> = None;
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    let body = signed_request(&format!("loadgen-nonce-{i}"));
                    let t0 = Instant::now();
                    let outcome = match mode {
                        Mode::Cold => cold_round_trip(addr, Arc::clone(&config), &body),
                        Mode::KeepAlive => keepalive_round_trip(
                            addr,
                            Arc::clone(&config),
                            &body,
                            &mut kept,
                            &reconnects,
                        ),
                    };
                    let dt = t0.elapsed();
                    match outcome {
                        Ok(resp) if is_success(&resp) => local.push(dt.as_micros()),
                        _ => {
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                latencies.lock().expect("latencies mutex").extend(local);
            })
        })
        .collect();

    for h in handles {
        h.join().expect("load worker panicked");
    }
    let wall = start.elapsed();

    let mut samples = Arc::try_unwrap(latencies)
        .expect("sole owner")
        .into_inner()
        .expect("latencies mutex");
    samples.sort_unstable();

    let successes = samples.len();
    let failures = failures.load(Ordering::Relaxed);
    let reconnects = reconnects.load(Ordering::Relaxed);
    let sum: u128 = samples.iter().sum();
    let throughput_rps = if wall.as_secs_f64() > 0.0 {
        successes as f64 / wall.as_secs_f64()
    } else {
        0.0
    };
    let reuse_fraction = if cfg.mode == Mode::KeepAlive && cfg.requests > 0 {
        1.0 - (reconnects as f64 / cfg.requests as f64)
    } else {
        0.0
    };

    Report {
        successes,
        failures,
        reconnects,
        wall,
        p50_us: quantile(&samples, 0.50),
        p99_us: quantile(&samples, 0.99),
        p999_us: quantile(&samples, 0.999),
        min_us: samples.first().copied().unwrap_or(0),
        mean_us: if successes > 0 { sum / successes as u128 } else { 0 },
        max_us: samples.last().copied().unwrap_or(0),
        throughput_rps,
        reuse_fraction,
    }
}

/// Keep-alive round-trip: reuse `kept` if present, else open a new connection
/// (counting it as a reconnect once the first request has been served). Drops the
/// stream when the server signals `Connection: close`.
fn keepalive_round_trip(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    body: &[u8],
    kept: &mut Option<StreamOwned<ClientConnection, TcpStream>>,
    reconnects: &AtomicUsize,
) -> std::io::Result<Vec<u8>> {
    if kept.is_none() {
        let tcp = TcpStream::connect(addr)?;
        let server_name = ServerName::try_from("localhost").expect("server name");
        let conn = ClientConnection::new(config, server_name)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        *kept = Some(StreamOwned::new(conn, tcp));
    } else {
        // Reusing a live stream is the point of keep-alive; count only genuine
        // reconnects (the else-branch above) — but the current proxy forces a
        // reconnect every request, so `is_none()` is true each time and this
        // branch is effectively unreached on the current wire.
    }
    let stream = kept.as_mut().expect("stream present");

    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    let (resp, keeps_alive) = read_http_response(stream)?;
    if !keeps_alive {
        // Server closed: the NEXT request will reconnect — record it.
        *kept = None;
        reconnects.fetch_add(1, Ordering::Relaxed);
    }
    Ok(resp)
}

fn print_report(cfg: &LoadConfig, report: &Report) {
    println!("=== ADR-MCPRE-051 §7 load-harness report (envelope v1) ===");
    println!("hardware_class     : {}", cfg.hw_class);
    println!(
        "declared_cores     : {} (per-core async fleet, SO_REUSEPORT; pinned via --cores, {})",
        cfg.cores,
        if cfg.cores == 0 { "0 = auto/one-per-core" } else { "workers served == this count" }
    );
    println!("connection_mode    : {}", cfg.mode.as_str());
    println!("concurrency        : {}", cfg.concurrency);
    println!("requests           : {}", cfg.requests);
    println!("successes/failures : {}/{}", report.successes, report.failures);
    println!("wall_clock         : {:.3}s", report.wall.as_secs_f64());
    println!("throughput         : {:.1} req/s", report.throughput_rps);
    println!(
        "added_latency (us) : p50={} p99={} p999={} min={} mean={} max={}",
        report.p50_us, report.p99_us, report.p999_us, report.min_us, report.mean_us, report.max_us
    );
    if cfg.mode == Mode::KeepAlive {
        println!(
            "keepalive_reuse    : {:.3} ({} reconnects; ~0 expected on the current Connection: close wire)",
            report.reuse_fraction, report.reconnects
        );
    }
    println!("per_core_scaling   : single point at {} core(s); drive MCP_RE_LOADGEN_CORES=1 then =N for the 1→N linear-scaling curve", cfg.cores);
}

/// Emit the report as machine-readable JSON to `MCP_RE_LOADGEN_OUT` when set, so a
/// run's numbers are attributable to the envelope that produced them.
fn maybe_write_json(cfg: &LoadConfig, report: &Report) {
    let Some(path) = std::env::var("MCP_RE_LOADGEN_OUT").ok().filter(|p| !p.is_empty()) else {
        return;
    };
    let doc = json!({
        "schema": "mcp-re-load-harness-report/v1",
        "envelope_version": 1,
        "envelope_ref": "docs/bench/adr-051-benchmark-envelope.json",
        "config": {
            "hardware_class": cfg.hw_class,
            "declared_cores": cfg.cores,
            "connection_mode": cfg.mode.as_str(),
            "concurrency": cfg.concurrency,
            "requests": cfg.requests,
            "replay_backend": "memory",
            "tls_mode": "TLS1.3-mTLS",
        },
        "results": {
            "successes": report.successes,
            "failures": report.failures,
            "wall_clock_secs": report.wall.as_secs_f64(),
            "throughput_rps": report.throughput_rps,
            "added_latency_us": {
                "p50": report.p50_us, "p99": report.p99_us, "p999": report.p999_us,
                "min": report.min_us, "mean": report.mean_us, "max": report.max_us,
            },
            "keepalive_reuse_fraction": report.reuse_fraction,
        }
    });
    if let Err(e) = std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()) {
        eprintln!("load harness: could not write MCP_RE_LOADGEN_OUT={path}: {e}");
    }
}

// --- entry points -------------------------------------------------------------

/// Always-on self-verification: drive the REAL listener at tiny scale, confirm a
/// genuinely signed+bound response, and check the metrics compute. Keeps the
/// harness green in the per-PR battery without being an SLO gate.
#[test]
fn load_harness_smoke() {
    let material = write_material();
    let backend = spawn_http_echo_backend();
    // Smoke pins a single worker (matches cfg.cores below) so declared == served.
    let proxy = spawn_proxy(&material, &format!("http://{backend}/mcp"), 1);
    let config = build_client_config(&material.client_ca);

    // 1. One explicit VERIFIED round-trip proves the success criterion (`no error`)
    //    corresponds to a real Ed25519-signed response bound to the request hash —
    //    i.e. the harness is measuring genuine serving, not error responses.
    {
        let request = signed_request("smoke-verified");
        let expected_hash =
            request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).unwrap();
        let body = cold_round_trip(proxy.addr, Arc::clone(&config), &request)
            .expect("valid mTLS round trip");
        assert!(is_success(&body), "smoke request must succeed: {:?}", String::from_utf8_lossy(&body));
        let verified = verify_response(&body, &server_resolver(), &expected_hash)
            .expect("signed response verifies and binds to the request hash");
        assert_eq!(verified.server_signer(), SERVER);
    }

    // 2. Tiny concurrent load: every request must succeed and the metrics populate.
    let cfg = LoadConfig {
        concurrency: 8,
        requests: 32,
        mode: Mode::Cold,
        hw_class: "smoke".to_string(),
        cores: 1,
    };
    let report = run_load(proxy.addr, Arc::clone(&config), &cfg);
    print_report(&cfg, &report);
    assert_eq!(report.failures, 0, "every smoke request must succeed");
    assert_eq!(report.successes, cfg.requests, "all requests accounted for");
    assert!(report.throughput_rps > 0.0, "throughput must be positive");
    assert!(report.p50_us > 0, "p50 latency must be measured");
    assert!(report.p999_us >= report.p50_us, "percentiles must be monotonic");
}

/// The full ADR-051 §7 load run — the manual/dispatch lane (`#[ignore]`), scaled
/// by `MCP_RE_LOADGEN_*`. Not a per-PR gate; run explicitly to produce the
/// baseline/SLO numbers (MCPRE-110):
///
/// ```text
/// bazel test //mcp-re-proxy:tls_load_harness_bench --test_arg=--ignored \
///   --test_env=MCP_RE_LOADGEN_CONCURRENCY=256 --test_env=MCP_RE_LOADGEN_REQUESTS=20000 \
///   --test_env=MCP_RE_LOADGEN_HW_CLASS=... --test_env=MCP_RE_LOADGEN_OUT=/tmp/report.json \
///   --test_output=all
/// ```
#[test]
#[ignore = "ADR-051 §7 load benchmark — manual/dispatch lane, not a per-PR gate"]
fn tls_load_harness_bench() {
    let cfg = LoadConfig::from_env();
    let material = write_material();
    let backend = spawn_http_echo_backend();
    // Pin the served worker count to cfg.cores (MCP_RE_LOADGEN_CORES) so the report
    // is honest and the 1→N scaling curve is reproducible (run at cores=1 then =N).
    let proxy = spawn_proxy(&material, &format!("http://{backend}/mcp"), cfg.cores);
    let config = build_client_config(&material.client_ca);

    let report = run_load(proxy.addr, config, &cfg);
    print_report(&cfg, &report);
    maybe_write_json(&cfg, &report);

    // Even in the manual lane, a run that could not drive the listener at all is a
    // harness failure, not a benchmark result.
    assert!(report.successes > 0, "load run produced zero successful requests");
    assert_eq!(
        report.successes + report.failures,
        cfg.requests,
        "every issued request must be accounted for",
    );
}
