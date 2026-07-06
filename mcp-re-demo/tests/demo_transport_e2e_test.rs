//! Multi-process TRANSPORT-tier NEGATIVE suite over REAL mTLS (MCPS-058,
//! Phase 6.6, epic #3948) — the transport counterpart of the application-layer
//! negative suite (`demo_negative_e2e_test.rs`).
//!
//! Each case is driven against the REAL, separately-spawned `mcp_re_proxy_cli` OS
//! process (the PEP) wrapping `mcp_re_demo_fileserver_bin` as its inner stdio
//! server, over a REAL mTLS socket. They prove the transport-tier protections
//! the demo topology must enforce:
//!
//!   * T1 — NO client certificate presented → the mTLS handshake is rejected;
//!     the request body never reaches the wire and the inner is never spawned.
//!   * T2 — UNTRUSTED client CA (a client cert from a CA the proxy's `--client-ca`
//!     does not trust) → the handshake is rejected; inner never spawned.
//!   * T3 — mTLS identity != request signer (the proxy runs `--transport-binding
//!     exact`): a TRUSTED client cert whose URI SAN differs from the request
//!     signer completes the handshake but the binding check denies it with
//!     `mcp-re.transport_binding_failed`; deny-before-dispatch.
//!   * T4 — OVER-LIFETIME client cert: the (~15y) fixture client cert is rejected
//!     by a proxy run with a tiny `--max-client-cert-lifetime`, even though
//!     signer, signature, and binding are all valid.
//!   * T5 — UNTRUSTED server cert: the verifying `mcp-re-transport` client (which
//!     authenticates the proxy's server cert against a configured server CA)
//!     refuses a proxy whose server cert is NOT signed by that CA — the client
//!     aborts the handshake BEFORE sending the request body (server
//!     authentication, the mandatory other half of mTLS).
//!
//! The CENTRAL invariant: a TLS or transport-binding failure must NOT reach the
//! inner fileserver. For T1/T2/T4 (handshake / cert-posture rejection) and T3
//! (binding deny-before-dispatch) we assert ZERO `inner_spawned` lines on the
//! proxy's diagnostic stderr; for T5 the failure is entirely client-side (the
//! client never even connects to a valid proxy with that material), so "inner
//! not reached" is structural.
//!
//! HONEST failure-mode note: T1, T2, and T5 fail at the TLS handshake, which is a
//! generic transport error (a closed connection / rustls alert), NOT a structured
//! `mcp-re.*` reason code on the wire — the proxy rejects the peer before any
//! JSON-RPC body is exchanged, so there is no body to carry a code. We assert the
//! honest signal: the client's connect/handshake errors (and the proxy logged no
//! `inner_spawned`). Only T3 (which DOES complete the handshake) and T4 (a
//! cert-posture check applied to a connection that authenticated) carry a
//! response; T3 carries `mcp-re.transport_binding_failed`.
//!
//! Each case spawns its OWN proxy process so its stderr capture and durable
//! replay cache are isolated. Readiness is the same TCP port probe as the
//! positive harness (#3943); each proxy is killed + reaped and its replay dir
//! removed on Drop.
//!
//! Proxy binary + inner binary + `demo_root/` fixture are delivered via Bazel
//! runfiles (`data` deps), resolved via `$(rlocationpath …)` — no hardcoded
//! path, no cargo.

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
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcp_re_core::unix_to_rfc3339_utc;
use mcp_re_core::McpReError;
use mcp_re_core::SigningKey;
use mcp_re_demo::mint_demo_grant;
use mcp_re_demo::DemoFixtureFiles;
use mcp_re_demo::DemoFixtures;
use mcp_re_demo::DemoGrant;
use mcp_re_demo::DemoGrantSpec;
use mcp_re_demo::DemoHostClient;
use mcp_re_demo::E2E_ON_BEHALF_OF;
use mcp_re_demo::E2E_PATH;
use mcp_re_demo::E2E_TOOL;
use mcp_re_host::HostSigner;
use mcp_re_host::SystemClock;
use mcp_re_host::SystemNonceSource;
use mcp_re_transport::ClientTlsConfig;
use mcp_re_transport::MtlsClient;
use mcp_re_transport::TransportError;

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

const SKEW_SECS: i64 = 300;
const REQUEST_LIFETIME_SECS: i64 = 600;
/// A generous client-cert lifetime ceiling (~20y) so the bounded (~15y) fixture
/// client cert passes — used by every case EXCEPT T4 (which uses a tiny ceiling).
const GENEROUS_CERT_LIFETIME: &str = "175200h";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Runfiles resolution (identical scheme to the positive / negative harness).
// ---------------------------------------------------------------------------

fn resolve_runfile(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

fn proxy_cli() -> PathBuf {
    resolve_runfile("MCP_RE_PROXY_CLI")
}
fn inner_binary() -> String {
    resolve_runfile("INNER_FILESERVER_BIN")
        .to_string_lossy()
        .into_owned()
}
fn demo_root() -> String {
    resolve_runfile("DEMO_ROOT_README")
        .parent()
        .expect("readme.txt has a parent")
        .to_string_lossy()
        .into_owned()
}

/// Parse the proxy's OS-resolved listen address from its startup marker
/// `mcp-re-proxy: listening on <addr> (PEP; …)`. Requires the trailing space so a
/// partially-captured line never yields a truncated address.
fn parse_listening_addr(stderr: &str) -> Option<SocketAddr> {
    let marker = "mcp-re-proxy: listening on ";
    let start = stderr.find(marker)? + marker.len();
    let rest = &stderr[start..];
    let end = rest.find(' ')?;
    rest[..end].parse().ok()
}

// ---------------------------------------------------------------------------
// The spawned proxy, with its stderr captured so "inner not reached" is
// observable over the wire (no `inner_spawned` line => the inner never ran).
// ---------------------------------------------------------------------------

/// A spawned `mcp_re_proxy_cli` OS process whose stderr is drained into a shared
/// buffer. Killed (and reaped) on drop; its durable replay dir is removed.
struct ProxyProcess {
    child: std::process::Child,
    addr: SocketAddr,
    stderr: Arc<Mutex<String>>,
    _files: DemoFixtureFiles,
    _replay_dir: PathBuf,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self._replay_dir);
    }
}

impl ProxyProcess {
    /// The number of times the proxy launched the inner subprocess, read from its
    /// diagnostic stderr (`inner-event inner_spawned …`). Zero proves the inner
    /// fileserver was never reached.
    fn inner_spawn_count(&self) -> usize {
        self.stderr
            .lock()
            .expect("stderr lock")
            .matches("inner_spawned")
            .count()
    }

    /// True iff the inner subprocess was launched at all (any spawn line).
    fn inner_was_reached(&self) -> bool {
        self.inner_spawn_count() > 0
    }
}

/// Spawn the real `mcp_re_proxy_cli` with the full P1 flag set (mTLS, `--authz
/// reference`, durable `--replay-cache file`, `--transport-binding exact`, inner
/// = the demo fileserver over `demo_root`), draining its stderr, then poll the
/// port until it accepts. `material` supplies the server cert/key + client-CA the
/// proxy serves/trusts (normally the SAME `fixtures`, but T5 deliberately serves
/// material the VERIFYING client will reject). `max_cert_lifetime` is the
/// `--max-client-cert-lifetime` ceiling. Panics if it never listens.
fn spawn_proxy(
    fixtures: &DemoFixtures,
    material: &DemoFixtures,
    max_cert_lifetime: &str,
) -> ProxyProcess {
    let files = material.write_files().expect("materialize fixture files");
    let cli = proxy_cli();
    let inner = inner_binary();
    let root = demo_root();

    // Let the PROXY pick the port (bind :0, read it back from the startup
    // marker) — deletes the free_port() bind-after-free TOCTOU (MCPS-087).
    let bind = "127.0.0.1:0".to_string();

    static SPAWN_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SPAWN_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let replay_dir = std::env::temp_dir().join(format!(
        "mcp_re_transport_e2e_replay_{}_{}",
        std::process::id(),
        seq,
    ));
    std::fs::create_dir_all(&replay_dir).expect("mkdir replay dir");
    let replay_path = replay_dir.join("replay.json");

    let mut child = Command::new(&cli)
        .args([
            "--bind",
            &bind,
            "--audience",
            fixtures.audience(),
            "--server-signer",
            fixtures.server_signer(),
            "--server-key-id",
            fixtures.server_key_id(),
            "--max-clock-skew",
            &SKEW_SECS.to_string(),
            "--key-source",
            "file",
            "--signing-key-seed",
            &files.signing_seed_path().to_string_lossy(),
            "--tls-cert",
            &files.server_cert_path().to_string_lossy(),
            "--tls-key",
            &files.server_key_path().to_string_lossy(),
            "--client-ca",
            &files.client_ca_path().to_string_lossy(),
            "--trust",
            &files.trust_path().to_string_lossy(),
            "--replay-cache",
            "file",
            "--replay-path",
            &replay_path.to_string_lossy(),
            "--transport-binding",
            "exact",
            "--transport-identity-source",
            "uri_san",
            "--authz",
            "reference",
            "--allow-reference-authz",
            "--allow-empty-revocation",
            "--max-client-cert-lifetime",
            max_cert_lifetime,
            "--inner-working-dir",
            &root,
            "--inner-command",
            &inner,
            "--demo-root",
            &root,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp_re_proxy_cli");

    // Drain stderr on a dedicated thread into a shared buffer: the proxy emits
    // `inner-event inner_spawned …` here the instant it launches the inner, so
    // the buffer is the wire-observable "inner reached?" signal.
    let stderr = Arc::new(Mutex::new(String::new()));
    let mut pipe = child.stderr.take().expect("piped stderr");
    let sink = Arc::clone(&stderr);
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

    // Readiness without a connection-consuming probe: wait for the proxy's
    // startup marker (printed after bind) and read the OS-resolved address from
    // it; fail fast if the proxy exits before listening. See MCPS-087.
    let mut addr: Option<SocketAddr> = None;
    for _ in 0..1200 {
        if let Some(parsed) = stderr.lock().ok().and_then(|buf| parse_listening_addr(&buf)) {
            addr = Some(parsed);
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let captured = stderr.lock().map(|b| b.clone()).unwrap_or_default();
            panic!("mcp_re_proxy_cli exited before listening (status {status}):\n{captured}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let addr = addr.expect("mcp_re_proxy_cli did not report a listening address within budget");

    ProxyProcess {
        child,
        addr,
        stderr,
        _files: files,
        _replay_dir: replay_dir,
    }
}

/// The common case: the proxy serves/trusts the SAME material the client uses,
/// with the generous cert-lifetime ceiling.
fn spawn_proxy_default(fixtures: &DemoFixtures) -> ProxyProcess {
    spawn_proxy(fixtures, fixtures, GENEROUS_CERT_LIFETIME)
}

// ---------------------------------------------------------------------------
// Signing helpers (delegating to mcp-re-host + mcp-re-policy via the demo crate).
// ---------------------------------------------------------------------------

fn signer_key(fixtures: &DemoFixtures) -> SigningKey {
    SigningKey::from_seed_bytes(&fixtures.signer_seed())
}

/// Mint the reference grant authorizing `list_files` on [`E2E_PATH`], sized
/// around the real clock so a SYSTEM-clock request signed now falls inside the
/// window. Self-issued by the signer.
fn build_grant(fixtures: &DemoFixtures, now: i64) -> DemoGrant {
    let spec = DemoGrantSpec {
        issuer: fixtures.signer().to_string(),
        grantee: fixtures.signer().to_string(),
        subject: E2E_ON_BEHALF_OF.to_string(),
        audience: fixtures.audience().to_string(),
        allowed_path: E2E_PATH.to_string(),
        not_before: unix_to_rfc3339_utc(now - SKEW_SECS),
        expires_at: unix_to_rfc3339_utc(now + REQUEST_LIFETIME_SECS),
        revocation_id: "demo-transport-e2e".to_string(),
    };
    mint_demo_grant(&spec, &signer_key(fixtures), fixtures.signer_key_id()).expect("mint demo grant")
}

/// `params` for an authorized `list_files` on [`E2E_PATH`], carrying the grant.
fn list_files_params(grant: &DemoGrant) -> serde_json::Map<String, Value> {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), Value::String(E2E_TOOL.to_string()));
    params.insert("arguments".to_string(), json!({ "path": E2E_PATH }));
    let mut meta = serde_json::Map::new();
    meta.insert(DemoGrant::meta_key().to_string(), grant.authorization_block());
    params.insert("_meta".to_string(), Value::Object(meta));
    params
}

/// Sign ONE authorized `list_files` as the fixture signer on the SYSTEM clock,
/// returning the raw signed JSON-RPC bytes. The body is fully valid — the only
/// thing the transport cases vary is HOW it is presented over mTLS (or whether
/// it is presented at all).
fn signed_authorized_request(fixtures: &DemoFixtures, request_id: &str) -> Vec<u8> {
    let now = now_unix();
    let grant = build_grant(fixtures, now);
    let auth_hash = grant.authorization_hash().expect("authorization_hash");
    let mut cl = DemoHostClient::with_defaults(
        HostSigner::new(
            signer_key(fixtures),
            fixtures.signer().to_string(),
            fixtures.signer_key_id().to_string(),
        ),
        SystemClock,
        SystemNonceSource,
    );
    let id = Value::String(request_id.to_string());
    cl.sign_request(
        &id,
        "tools/call",
        list_files_params(&grant),
        E2E_ON_BEHALF_OF,
        fixtures.audience(),
        &auth_hash,
    )
    .expect("client signs the authorized list_files")
}

/// Parse the JSON-RPC denial reason (`error.message`) from a proxy response, if
/// any. `None` for a success (or a response with no `error` object).
fn denial_reason(response: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(response).ok()?;
    let error = value.get("error")?;
    error["message"].as_str().map(str::to_string)
}

// ---------------------------------------------------------------------------
// A RAW rustls client used ONLY by the handshake-rejection cases (T1/T2), which
// must vary client-auth presentation in ways the production `MtlsClient` cannot
// (it always presents a cert and always verifies the server). It accepts ANY
// server cert so the failure is ISOLATED to the client-auth side — the only
// thing under test in T1/T2. (T5 uses the REAL verifying client instead.)
// ---------------------------------------------------------------------------

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

/// Build a raw client config that accepts any server, optionally presenting a
/// client-auth cert chain + key.
fn raw_client_config(
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

/// Drive a raw mTLS POST. `Err` when the handshake or IO fails (e.g. a rejected
/// or missing client certificate — fail-closed at the transport layer).
fn raw_round_trip(addr: SocketAddr, config: ClientConfig, body: &[u8]) -> std::io::Result<Vec<u8>> {
    let tcp = TcpStream::connect(addr)?;
    let server_name = ServerName::try_from("proxy.internal").expect("server name");
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);
    // Drive the handshake explicitly so a rejected/missing client cert surfaces
    // here, before any body is sent.
    stream.conn.complete_io(&mut stream.sock)?;

    let request = format!(
        "POST / HTTP/1.1\r\nHost: proxy.internal\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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

/// A rogue (untrusted) CA + a client-auth leaf signed by it, carrying the given
/// URI-SAN identity. Used by T2 — the leaf identity matches the signer, so the
/// ONLY reason for rejection is that the CA is not in the proxy's `--client-ca`.
fn rogue_client_cert(uri_san: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let ca_key = KeyPair::generate().expect("rogue ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("rogue ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mcp-re-transport-rogue-ca");
    let ca_cert = ca_params.self_signed(&ca_key).expect("rogue ca self-signed");

    let leaf_key = KeyPair::generate().expect("rogue leaf key");
    let mut leaf_params = CertificateParams::new(Vec::new()).expect("rogue leaf params");
    leaf_params.subject_alt_names = vec![SanType::URI(uri_san.try_into().expect("ia5 uri"))];
    leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("rogue leaf signed");

    let chain = vec![leaf.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (chain, key)
}

/// The verifying mTLS client built from `material`'s POSITIVE client cert (URI
/// SAN == signer) and verifying the proxy against `material`'s server CA.
fn verifying_client(material: &DemoFixtures) -> MtlsClient {
    let tls = ClientTlsConfig::from_pem(
        material.client_cert_pem().as_bytes(),
        material.client_key_pem().as_bytes(),
        material.server_ca_pem().as_bytes(),
    )
    .expect("client TLS config from fixture PEM");
    MtlsClient::new(tls, material.server_name()).expect("verifying mTLS client")
}

// ===========================================================================
// T1 — NO client certificate → mTLS handshake rejected; inner NOT reached.
// ===========================================================================

#[test]
fn t1_no_client_cert_rejected_at_handshake() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy_default(&fixtures);

    // A fully valid signed body — but presented with NO client cert. The proxy
    // requires client-auth, so the handshake is rejected before the body lands.
    let request = signed_authorized_request(&fixtures, "req-t1-nocert");
    let result = raw_round_trip(proxy.addr, raw_client_config(None), &request);

    assert!(
        result.is_err(),
        "a connection presenting NO client cert must fail closed at the handshake; got {result:?}"
    );
    assert!(
        !proxy.inner_was_reached(),
        "a rejected handshake must NOT reach the inner fileserver"
    );
}

// ===========================================================================
// T2 — UNTRUSTED client CA → mTLS handshake rejected; inner NOT reached.
// ===========================================================================

#[test]
fn t2_untrusted_client_ca_rejected_at_handshake() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy_default(&fixtures);

    // A client cert whose URI SAN == the signer (so binding would pass) but issued
    // by a CA the proxy does NOT trust (`--client-ca` is the fixture client CA).
    // The handshake is rejected purely because the chain is untrusted.
    let cert = rogue_client_cert(fixtures.signer());
    let request = signed_authorized_request(&fixtures, "req-t2-rogueca");
    let result = raw_round_trip(proxy.addr, raw_client_config(Some(cert)), &request);

    assert!(
        result.is_err(),
        "a client cert from an untrusted CA must fail closed at the handshake; got {result:?}"
    );
    assert!(
        !proxy.inner_was_reached(),
        "a rejected handshake must NOT reach the inner fileserver"
    );
}

// ===========================================================================
// T3 — mTLS identity != request signer (binding `exact`) →
//      transport_binding_failed; deny-before-dispatch, inner NOT reached.
// ===========================================================================

#[test]
fn t3_identity_not_signer_transport_binding_failed() {
    let fixtures = DemoFixtures::generate_default();
    let proxy = spawn_proxy_default(&fixtures);

    // Present the MISMATCHED client cert (URI SAN == mismatched_identity, a
    // TRUSTED cert chaining to the same client CA so the handshake succeeds) while
    // the request is signed by the real signer. With `--transport-binding exact`
    // the proxy denies because the mTLS identity != the request signer.
    let tls = ClientTlsConfig::from_pem(
        fixtures.mismatched_client_cert_pem().as_bytes(),
        fixtures.mismatched_client_key_pem().as_bytes(),
        fixtures.server_ca_pem().as_bytes(),
    )
    .expect("mismatched client TLS config");
    let client = MtlsClient::new(tls, fixtures.server_name()).expect("verifying mTLS client");

    let request = signed_authorized_request(&fixtures, "req-t3-binding");
    let response = client
        .round_trip(proxy.addr, &request)
        .expect("handshake succeeds (trusted cert); the binding check denies at app layer");

    assert_eq!(
        denial_reason(&response).as_deref(),
        Some(McpReError::TransportBindingFailed.wire_code()),
        "mismatched mTLS identity must be denied by transport-binding exact"
    );
    assert!(
        !proxy.inner_was_reached(),
        "a transport-binding denial is pre-dispatch: the inner must NOT be reached"
    );
}

// ===========================================================================
// T4 — OVER-LIFETIME client cert → rejected by the cert-lifetime ceiling.
// ===========================================================================

#[test]
fn t4_over_lifetime_client_cert_rejected() {
    let fixtures = DemoFixtures::generate_default();
    // A proxy whose `--max-client-cert-lifetime` is 60s: the (~15y) fixture client
    // cert is far over the ceiling. Signer, signature, and binding are all valid —
    // the ONLY reason for rejection is the over-long client certificate.
    let proxy = spawn_proxy(&fixtures, &fixtures, "60");
    let client = verifying_client(&fixtures);

    let request = signed_authorized_request(&fixtures, "req-t4-lifetime");
    let response = client
        .round_trip(proxy.addr, &request)
        .expect("handshake completes; the cert-lifetime posture check rejects at app layer");

    // The proxy surfaces the over-lifetime cert as a transport-binding failure
    // (the cert-posture gate sits in the same transport-binding stage); it is the
    // honest wire signal the proxy carries — the same code full_stack_test asserts.
    assert_eq!(
        denial_reason(&response).as_deref(),
        Some(McpReError::TransportBindingFailed.wire_code()),
        "an over-lifetime client cert must be rejected by the cert-lifetime ceiling"
    );
    assert!(
        !proxy.inner_was_reached(),
        "an over-lifetime client cert must NOT reach the inner fileserver"
    );
}

// ===========================================================================
// T5 — UNTRUSTED server cert → the CLIENT refuses (server authentication). The
//      verifying client aborts the handshake BEFORE sending the request body.
// ===========================================================================

#[test]
fn t5_untrusted_server_cert_refused_by_client() {
    // Two INDEPENDENT material sets: `client_fixtures` is the one the verifying
    // client trusts (its server CA is the client's trust anchor); the proxy is
    // spawned with `proxy_material`, a DIFFERENT set whose server leaf is signed
    // by a DIFFERENT server CA. Both share the SAME identities/seeds/server-name
    // (the default spec is deterministic), so the ONLY thing that differs is the
    // freshly-minted server CA — exactly the server-authentication failure under
    // test. The proxy still serves a syntactically valid mTLS endpoint.
    let client_fixtures = DemoFixtures::generate_default();
    let proxy_material = DemoFixtures::generate_default();

    // Sanity: the two server CAs really are different, so the client's trust
    // anchor cannot validate the proxy's server cert.
    assert_ne!(
        client_fixtures.server_ca_pem(),
        proxy_material.server_ca_pem(),
        "the two fixture sets must have independent server CAs"
    );

    let proxy = spawn_proxy(&proxy_material, &proxy_material, GENEROUS_CERT_LIFETIME);

    // The client presents its (valid) client cert and verifies the server against
    // ITS server CA — which did NOT sign the proxy's server cert. Server
    // authentication fails: the handshake is aborted before the body is sent.
    let client = verifying_client(&client_fixtures);
    let request = signed_authorized_request(&client_fixtures, "req-t5-untrusted-server");
    let result = client.round_trip(proxy.addr, &request);

    match result {
        Err(TransportError::Handshake(_)) => {}
        other => panic!(
            "an untrusted server cert must be refused by the verifying client at the handshake \
             (server authentication); got {other:?}"
        ),
    }
    assert!(
        !proxy.inner_was_reached(),
        "the client aborted before sending: the inner fileserver must NOT be reached"
    );
}
