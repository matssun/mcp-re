//! Full-stack CI smoke test for the production `mcp_re_proxy_cli` binary
//! (Phase 6.1 hardening — ADR-MCPS-014 follow-up).
//!
//! This proves the EXECUTABLE end to end, not just library behavior: it spawns
//! the real `mcp_re_proxy_cli` process (TLS-terminating PEP) wired over HTTP to a
//! real in-process Streamable-HTTP inner MCP echo backend (ADR-MCPRE-051 §3;
//! MCP-RE is HTTP-profile only), with real client certificates over real mTLS, and
//! drives the security matrix the review requires:
//!
//!   * valid client cert + signed request → inner receives the injected verified
//!     context AND the response is signed and binds to the request hash;
//!   * NO client certificate → rejected at the handshake (fail closed);
//!   * UNTRUSTED client certificate → rejected at the handshake (fail closed);
//!   * valid cert + TAMPERED object signature → `mcp-re.invalid_signature`
//!     (mTLS never downgrades object verification);
//!   * valid cert + WRONG transport binding (signer ≠ cert identity) →
//!     `mcp-re.transport_binding_failed`.
//!
//! Certificates are minted in-process with `rcgen` (no committed key fixtures).
//! The proxy CLI binary is delivered via runfiles (`$(rlocationpath ...)`), the
//! same scheme the conformance harnesses use; the inner backend is in-process.

use std::convert::Infallible;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
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
use mcp_re_core::VERIFIED_META_KEY;
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

// --- identities ---------------------------------------------------------------

const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const SIGNER_A: &str = "spiffe://example.org/agent-1"; // == client-cert URI SAN
const SIGNER_A_KEY_ID: &str = "key-a";
const SIGNER_B: &str = "spiffe://example.org/agent-2"; // trusted, but NOT the cert identity
const SIGNER_B_KEY_ID: &str = "key-b";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";

fn server_seed() -> [u8; 32] {
    [2u8; 32]
}
fn signer_a_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn signer_b_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[3u8; 32])
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
    params.distinguished_name.push(DnType::CommonName, "mcp-re-fullstack-ca");
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
    // A bounded, currently-valid window (≈15y) so the cert passes the handshake
    // date check; the matrix proxy runs with a generous max-lifetime, and a
    // dedicated case runs with a tiny max to exercise lifetime enforcement.
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
    // Per-call sequence so two Material sets minted in the SAME test process (e.g.
    // two #[test]s running concurrently in this binary) get distinct paths and do
    // not clobber — or Drop-delete — each other's key files. Process id alone is
    // not unique across concurrent same-binary tests.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("mcp_re_fullstack_{}_{seq}_{name}", std::process::id()))
}

/// Write all key material the CLI needs and return their paths.
/// Returns `(seed, server_cert, server_key, client_ca, trust)` and keeps the
/// minted client-CA so the test can issue both a trusted and a rogue client cert.
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

    // Trust BOTH request signers (object verification passes for either); the
    // transport binding is what distinguishes them.
    let trust = json!([
        { "signer": SIGNER_A, "key_id": SIGNER_A_KEY_ID, "public_key": signer_a_key().public_key().to_b64url() },
        { "signer": SIGNER_B, "key_id": SIGNER_B_KEY_ID, "public_key": signer_b_key().public_key().to_b64url() },
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

// --- runfiles binary resolution (same scheme as the stdio harness) ------------

fn locate(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

// --- in-process HTTP echo inner backend (ADR-MCPRE-051 §3) --------------------
//
// The proxy now serves on the async fleet and forwards each verified request over
// HTTP to a stateless inner backend (no more stdio echo subprocess). This is the
// HTTP analogue of the old `echo_inner` fixture: it reads the POSTed JSON-RPC
// request and answers with a JSON-RPC result that echoes back `params._meta` (and
// the method), so the test can still prove the proxy injected a fresh verified-
// context block before forwarding. Mirrors the in-process hyper backend in
// `http_inner_test.rs` (hyper_util `auto` server + `service_fn` + `TokioIo`).

/// The inner echo service: parse the forwarded JSON-RPC request and answer with a
/// `{"jsonrpc":"2.0","id":<id>,"result":{"echoed_meta":<params._meta>,
/// "echoed_method":<method>}}` result — the exact response shape the stdio
/// `echo_inner` fixture returned, so every downstream assertion is preserved.
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
/// return its bound address. The backend runs on its own tokio runtime on a
/// detached daemon thread that lives for the rest of the (short-lived) test
/// process — the proxy's async fleet forwards verified requests to it over HTTP.
fn spawn_http_echo_backend() -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
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

// --- spawned CLI process (killed on drop) -------------------------------------

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

/// Spawn the CLI on an EPHEMERAL port (`--bind 127.0.0.1:0`) and learn the actual
/// bound address from the CLI's own `async fleet serving on <addr>` stderr line.
///
/// This is race-free: the CLI's fleet owns the port from `bind` onward, with no
/// bind-release-rebind window. The previous approach (bind `:0`, read the port,
/// drop the listener, then hand the number to the CLI) left a TOCTOU gap in which a
/// concurrent test in this binary — or any process under a parallel
/// `bazel test //...` — could grab the port before the CLI bound it, causing a
/// spurious "did not start listening" failure.
fn spawn_proxy(material: &Material, max_cert_lifetime: &str, inner_http_url: &str) -> ProxyProcess {
    let cli = locate("MCP_RE_PROXY_CLI");

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
            "--max-client-cert-lifetime", max_cert_lifetime,
            // ADR-MCPRE-051 §3: serve on the async fleet forwarding to the
            // stateless in-process HTTP echo backend (was `--inner-command <echo>`).
            "--inner-http-url", inner_http_url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // Capture stderr: it carries the resolved `serving on <addr>` line AND the
        // CLI's startup diagnostics, which we surface on any readiness failure.
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

    // Wait for the CLI to report its resolved bound address, failing fast if it
    // exits before serving.
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

    // Confirm the socket is actually accepting now that we know the real port.
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
/// bound [`SocketAddr`]. Requires the trailing space so a partially-captured line
/// never yields a truncated address.
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

/// POST `body` over a fresh mTLS connection and return the response BODY bytes.
/// `Err` when the TLS handshake or IO fails (e.g. a rejected client certificate).
fn round_trip(
    addr: SocketAddr,
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

/// A trusted client certificate whose URI SAN is `SIGNER_A`.
fn trusted_client_cert(ca: &Ca) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let (leaf, key) = make_leaf(ca, vec![uri(SIGNER_A)], None, true);
    let der = leaf.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (vec![der], key_der)
}

// --- signed requests (real clock) ---------------------------------------------

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Sign a tools/call as `signer` using `key`, timestamped at the real clock so it
/// is fresh against the CLI's (uninjected) system clock.
fn signed_request(signer: &str, key_id: &str, key: SigningKey, nonce: &str) -> Vec<u8> {
    let now = now_unix();
    let issued_at = unix_to_rfc3339_utc(now);
    let expires_at = unix_to_rfc3339_utc(now + 300);
    HostSigner::new(key, signer, key_id)
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

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse response");
    value["error"]["message"]
        .as_str()
        .unwrap_or("<no error message>")
        .to_string()
}

// --- the matrix (one running CLI, sequential connections) ---------------------

#[test]
fn full_stack_cli_security_matrix() {
    let material = write_material();
    // The inner MCP server is reached over HTTP (async fleet inner plane); one
    // in-process echo backend serves both the matrix proxy and the cert-lifetime
    // proxy below.
    let backend = spawn_http_echo_backend();
    let inner_http_url = format!("http://{backend}/mcp");
    // Matrix proxy runs with a generous cert-lifetime ceiling (≈20y) so the
    // bounded test certs (≈15y) pass; cert-lifetime ENFORCEMENT is exercised by
    // its own case (a second proxy with a tiny ceiling) below.
    let proxy = spawn_proxy(&material, "175200h", &inner_http_url);
    let addr = proxy.addr;

    // 1. Happy path: valid cert (identity == SIGNER_A) + request signed by A.
    {
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-ok-1");
        let expected_hash =
            request_hash(&serde_json::from_slice::<Value>(&request).unwrap()).unwrap();
        let cert = trusted_client_cert(&material.client_ca);
        let body = round_trip(addr, client_config(Some(cert)), &request)
            .expect("valid mTLS round trip");

        let response: Value = serde_json::from_slice(&body).expect("parse response body");
        assert!(
            response.get("error").is_none(),
            "valid request must not error: {response}"
        );
        // The inner subprocess received the proxy-injected verified-context block.
        let echoed_meta = &response["result"]["echoed_meta"];
        assert!(
            echoed_meta.get(VERIFIED_META_KEY).is_some(),
            "inner must receive the injected verified-context block; got: {echoed_meta}"
        );
        // The signed response verifies and binds to the request hash.
        let verified = verify_response(&body, &server_resolver(), &expected_hash)
            .expect("signed response verifies and binds");
        assert_eq!(verified.server_signer(), SERVER);
    }

    // 2. No client certificate → rejected at the handshake.
    {
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-nocert");
        let result = round_trip(addr, client_config(None), &request);
        assert!(result.is_err(), "a connection with no client cert must fail closed");
    }

    // 3. Untrusted client certificate (rogue CA) → rejected at the handshake.
    {
        let rogue_ca = make_ca();
        let (leaf, key) = make_leaf(&rogue_ca, vec![uri(SIGNER_A)], None, true);
        let chain = vec![leaf.der().clone()];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-rogue");
        let result = round_trip(addr, client_config(Some((chain, key_der))), &request);
        assert!(result.is_err(), "an untrusted client cert must fail closed");
    }

    // 4. Valid cert + TAMPERED object signature → invalid_signature (no downgrade).
    {
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-tamper");
        let mut value: Value = serde_json::from_slice(&request).unwrap();
        value["params"]["arguments"]["text"] = Value::String("tampered".to_string());
        let tampered = serde_json::to_vec(&value).unwrap();
        let cert = trusted_client_cert(&material.client_ca);
        let body = round_trip(addr, client_config(Some(cert)), &tampered)
            .expect("handshake ok, app-level rejection");
        assert_eq!(error_message(&body), "mcp-re.invalid_signature");
    }

    // 5. Valid cert (identity A) + request signed by B → transport_binding_failed.
    {
        let request = signed_request(SIGNER_B, SIGNER_B_KEY_ID, signer_b_key(), "nonce-bind");
        let cert = trusted_client_cert(&material.client_ca); // identity == SIGNER_A
        let body = round_trip(addr, client_config(Some(cert)), &request)
            .expect("handshake ok, app-level rejection");
        assert_eq!(error_message(&body), "mcp-re.transport_binding_failed");
    }

    drop(proxy); // kill the matrix CLI

    // 6. Cert-lifetime enforcement: a second CLI with a 60s ceiling rejects the
    //    (≈15y) client cert even though signer, signature, and binding are all
    //    valid — the ONLY reason for rejection is the over-long certificate.
    {
        let proxy2 = spawn_proxy(&material, "60", &inner_http_url);
        let request = signed_request(SIGNER_A, SIGNER_A_KEY_ID, signer_a_key(), "nonce-life");
        let cert = trusted_client_cert(&material.client_ca);
        let body = round_trip(proxy2.addr, client_config(Some(cert)), &request)
            .expect("handshake ok, app-level rejection");
        assert_eq!(error_message(&body), "mcp-re.transport_binding_failed");
        drop(proxy2);
    }
}

/// MCPS-88 (ADR-MCPS-049 W3): SIGTERM triggers a GRACEFUL shutdown — the proxy
/// stops accepting and exits 0 (a clean rollout stop), rather than being left
/// running or dying by signal. After the signal the listening port stops
/// accepting. In-flight completion is guaranteed BY CONSTRUCTION and so is not
/// separately asserted here: the serve loop is single-threaded and inline, so at
/// most one request is ever in flight and it always runs to completion (bounded by
/// the per-request read/response deadlines) before the loop re-checks the shutdown
/// flag.
#[cfg(unix)]
#[test]
fn sigterm_drains_gracefully_and_exits_zero() {
    let material = write_material();
    let backend = spawn_http_echo_backend();
    let inner_http_url = format!("http://{backend}/mcp");
    let mut proxy = spawn_proxy(&material, "60", &inner_http_url);
    let addr = proxy.addr;

    // The port is accepting before the signal.
    assert!(
        TcpStream::connect(addr).is_ok(),
        "proxy should be accepting before SIGTERM"
    );

    // Send SIGTERM (no libc dev-dep — shell out to `kill`).
    let pid = proxy.child.id();
    let killed = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("run kill -TERM");
    assert!(killed.success(), "kill -TERM should succeed");

    // The process must exit CLEANLY (code 0) within a bounded drain window — not be
    // left running, and not die by signal (which would yield code() == None).
    let mut status = None;
    for _ in 0..100 {
        match proxy.child.try_wait().expect("try_wait") {
            Some(s) => {
                status = Some(s);
                break;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let status = status.expect("proxy must exit within the drain window after SIGTERM");
    assert_eq!(
        status.code(),
        Some(0),
        "graceful shutdown must exit 0 (not be killed), got {status:?}"
    );

    // After exit the listening socket is gone: new connections are refused. Poll
    // briefly to avoid racing the OS teardown right at process exit.
    let mut refused = false;
    for _ in 0..40 {
        if TcpStream::connect(addr).is_err() {
            refused = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(refused, "after graceful shutdown the port must stop accepting");

    drop(proxy); // Drop re-kills/waits — harmless on an already-reaped child.
    drop(material);
}
