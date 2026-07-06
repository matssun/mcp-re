//! Black-box end-to-end test for the PKCS#11-backed response signer + delegated
//! TLS signer (issue #4034 / issue #59), exercised against a HERMETIC in-tree MOCK
//! PKCS#11 provider (`tests/mock-pkcs11/`).
//!
//! This proves the real device path with NO external token or tooling: the test
//! builds the mock `cdylib`, points the PKCS#11 client at it, and drives the full
//! Cryptoki surface (`C_Initialize` … `C_Sign` (`CKM_EDDSA`) … `C_GetAttributeValue`
//! (`CKA_EC_POINT`)). The mock holds deterministic in-memory Ed25519 keys, so a
//! signature it produces verifies under the public point it exports — exactly what a
//! relying party checks. Because the mock is a real, dynamically-loaded PKCS#11
//! module, the client's libloading / function-list / FFI dispatch is genuinely
//! exercised; only the token is a controllable fake.
//!
//! # How the mock is provisioned
//! `mock_module()` runs a nested `cargo build` of `tests/mock-pkcs11` (into that
//! crate's OWN target dir, so it never contends the workspace build lock) and
//! returns the resulting library path. Objects are seeded per test through two env
//! vars the mock reads at `C_Initialize` (`MOCK_PKCS11_TOKEN_LABEL`,
//! `MOCK_PKCS11_OBJECTS`) — see [`MockToken`]. When the mock cannot be built here —
//! e.g. under the Bazel test sandbox, which has no `cargo` — the test self-skips
//! (honoring `MCP_RE_REQUIRE_LIVE_INFRA`: set → a skip becomes a hard failure). A
//! `cargo`-present build FAILURE, by contrast, panics loudly and is never skipped.
//!
//! The keygen-on-token flow (never import a private key) that the delegated-TLS
//! tests rely on is preserved: the mock GENERATES the key, the test reads its public
//! key back off the token and mints the matching leaf from it via a rcgen
//! [`rcgen::RemoteKeyPair`] ([`TokenPublicKey`] / [`remote_subject_key_from_spki`]),
//! so the private key never leaves the token.
#![cfg(feature = "pkcs11_keysource")]

use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::thread;

use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_proxy::build_server_config_delegated_validated;
use mcp_re_proxy::serve_once;
use mcp_re_proxy::KeySource;
use mcp_re_proxy::Pkcs11KeySource;
use mcp_re_proxy::ResponseSigner;
use mcp_re_proxy::ServerOptions;
use mcp_re_proxy::TlsError;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::RootCertStore;
use rustls::StreamOwned;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;

// ===========================================================================
// Hermetic mock PKCS#11 provider: build once, seed per test.
// ===========================================================================

/// Build the mock provider `cdylib` once per test process and cache its path.
/// `None` means the mock could not be built HERE (no `cargo` / source absent — e.g.
/// the Bazel sandbox), which self-skips. A `cargo`-present build error panics.
fn mock_module() -> Option<String> {
    static MODULE: OnceLock<Option<String>> = OnceLock::new();
    MODULE.get_or_init(build_mock_module).clone()
}

fn build_mock_module() -> Option<String> {
    let mock_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mock-pkcs11");
    let manifest = mock_dir.join("Cargo.toml");
    if !manifest.exists() {
        eprintln!(
            "SKIP: mock PKCS#11 provider source not present at {} (sandboxed build); \
             the PKCS#11 client logic is still covered by the unit tests.",
            manifest.display()
        );
        return None;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest)
        .output();
    match output {
        // `cargo` not spawnable (e.g. Bazel sandbox): self-skip cleanly.
        Err(e) => {
            eprintln!("SKIP: cannot spawn `{cargo}` to build the mock PKCS#11 provider: {e}");
            return None;
        }
        // `cargo` present but the mock failed to COMPILE: a real regression — fail loud.
        Ok(o) if !o.status.success() => panic!(
            "mock PKCS#11 provider failed to build:\n{}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Ok(_) => {}
    }
    let lib_name = if cfg!(target_os = "macos") {
        "libmock_pkcs11.dylib"
    } else {
        "libmock_pkcs11.so"
    };
    let path = mock_dir.join("target/debug").join(lib_name);
    path.exists()
        .then(|| path.to_string_lossy().into_owned())
}

/// The decision for every test: a built mock module path, or `None` to self-skip.
/// Honors `MCP_RE_REQUIRE_LIVE_INFRA` (set → a skip becomes a hard failure, so CI
/// cannot silently lose the coverage).
fn require_mock_or_skip(test: &str) -> Option<String> {
    match mock_module() {
        Some(m) => Some(m),
        None => {
            if std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
                panic!(
                    "MCP_RE_REQUIRE_LIVE_INFRA is set but the mock PKCS#11 provider could not be \
                     built — the PKCS#11 e2e MUST run under CI, not skip"
                );
            }
            eprintln!("SKIP {test}: mock PKCS#11 provider unavailable in this environment.");
            None
        }
    }
}

/// Serializes the tests. Each sets the PROCESS-wide `MOCK_PKCS11_*` env that the
/// mock reads at `C_Initialize`, so they must NOT run concurrently (cargo runs tests
/// multi-threaded by default). Holding this lock for the whole test body makes each
/// "seed token → open → use" sequence atomic w.r.t. the others. A poisoned lock (a
/// prior test panicked) is recovered — the panic is already the reported failure.
fn provisioning_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// A seeded mock token: owns the object spec and exports the `MOCK_PKCS11_*` env the
/// mock reads. Provisioning is pure in-process env seeding — no external token or
/// tooling and no on-disk key store.
struct MockToken {
    token_label: String,
    pin: String,
    /// `label,keytype,id` object entries, mirrored into `MOCK_PKCS11_OBJECTS`.
    objects: Vec<String>,
}

impl MockToken {
    /// Seed a fresh, empty token and point the mock's env at it. The label is unique
    /// per token so successive tests never observe a stale object set.
    fn init() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let token_label = format!(
            "mcp-re-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        // SAFETY: every test holds `provisioning_lock()` for its whole body, so only
        // one token's env is live at a time — these set_var calls never race.
        std::env::set_var("MOCK_PKCS11_TOKEN_LABEL", &token_label);
        std::env::set_var("MOCK_PKCS11_OBJECTS", "");
        MockToken {
            token_label,
            pin: "1234".to_string(),
            objects: Vec::new(),
        }
    }

    /// Generate a key pair of `key_type` ON the token under `label`/`id`. `key_type`
    /// takes the standard PKCS#11 `--key-type` spellings (`EC:edwards25519`,
    /// `EC:prime256v1`), mapped to the mock's object model. The private key is never
    /// extractable and never imported: the mock generates it.
    fn keygen(&mut self, key_type: &str, label: &str, id: &str) {
        let kt = match key_type {
            "EC:edwards25519" | "ed25519" => "ed25519",
            "EC:prime256v1" | "ec" => "ec",
            other => panic!("unsupported mock key type {other:?}"),
        };
        self.objects.push(format!("{label},{kt},{id}"));
        // SAFETY: see `init` — serialized by `provisioning_lock()`.
        std::env::set_var("MOCK_PKCS11_OBJECTS", self.objects.join(";"));
    }

    /// Convenience: generate an Ed25519 key pair on the token.
    fn keygen_ed25519(&mut self, label: &str, id: &str) {
        self.keygen("ed25519", label, id);
    }
}

/// The TLS material paths are not exercised by the response-signing test (the token
/// custodies only the response-signing key), but `Pkcs11KeySource::open` takes them;
/// point them at this crate's own `Cargo.toml` (a file that always exists) so `open`
/// does not need real TLS fixtures. The TLS accessors are NOT called there, so the
/// file contents are never parsed.
const PLACEHOLDER_TLS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

#[test]
fn pkcs11_sign_verifies_against_token_public_key() {
    let Some(module) = require_mock_or_skip("pkcs11_sign_verifies_against_token_public_key") else {
        return;
    };
    let _guard = provisioning_lock();
    let mut token = MockToken::init();
    token.keygen_ed25519("mcp-re-response-signing", "01");

    let source = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcp-re-response-signing",
        PLACEHOLDER_TLS_PATH,
        PLACEHOLDER_TLS_PATH,
        PLACEHOLDER_TLS_PATH,
        None,
    )
    .expect("open PKCS#11 token + locate Ed25519 key");

    let preimage = b"test-preimage-mcp-re-4034-pkcs11-response-signing";
    let signature = source
        .sign_response(preimage)
        .expect("sign_response over the token (CKM_EDDSA)");
    let public_key = source
        .response_public_key()
        .expect("read the token's exported Ed25519 public key");

    // A signature produced ON the token must verify under its exported public key
    // using the SAME verifier a relying party uses.
    verify_ed25519_with(
        preimage,
        &signature,
        &public_key,
        McpReError::ResponseSigInvalid,
    )
    .expect("token signature must verify under the token's public key");

    // Negative: a tampered preimage must NOT verify under the same signature.
    let tampered = b"test-preimage-mcp-re-4034-pkcs11-response-signing-XXX";
    let tampered_result = verify_ed25519_with(
        tampered,
        &signature,
        &public_key,
        McpReError::ResponseSigInvalid,
    );
    assert!(
        tampered_result.is_err(),
        "a tampered preimage must NOT verify under the token signature"
    );
}

// ===========================================================================
// Issue #59 (ADR-MCPS-028 §G): PKCS#11-DELEGATED TLS signing.
//
// These prove the real device path for the TLS key: a SECOND Ed25519 token object
// (distinct label from the response-signing key) custodies the TLS server key, the
// proxy reads NO TLS key from disk, and a real rustls client completing an mTLS
// handshake verifies a CertificateVerify signature the token produced over the
// transcript. Keys are GENERATED on the token (never imported): the flow reads each
// public key back off the token and mints the matching leaf from it.
// ===========================================================================

/// A freshly generated LOCAL Ed25519 key pair (rcgen). Used ONLY where a cert must be
/// minted from a key that is DELIBERATELY DIFFERENT from the token's TLS key (the
/// cert↔signer mismatch test). Token-resident keys are never generated here — they are
/// generated ON the token (see [`MockToken::keygen_ed25519`]) and their public key is
/// read back for cert minting via [`remote_subject_key_from_spki`].
fn gen_ed25519() -> KeyPair {
    KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 key")
}

/// A rcgen [`rcgen::RemoteKeyPair`] carrying ONLY the token's Ed25519 PUBLIC key.
///
/// Minting a CA-signed leaf (`CertificateParams::signed_by`) signs the leaf with the
/// ISSUER key and uses the subject key solely for its public key — it NEVER calls the
/// subject key's `sign()`. So this holds only the owned 32-byte public key read off the
/// token; `sign()` is unreachable. This is what lets a leaf's SPKI match the token TLS
/// object WITHOUT importing a private key: the flow is keygen-on-token, read the public
/// key, mint the cert from it. The private key never leaves the token.
struct TokenPublicKey {
    /// 32-byte raw Edwards point — the format rcgen's `public_key_raw` expects.
    raw: Vec<u8>,
}

impl rcgen::RemoteKeyPair for TokenPublicKey {
    fn public_key(&self) -> &[u8] {
        &self.raw
    }
    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        // Unreachable: a CA-signed leaf is signed by the ISSUER key, never the subject
        // key. Fail loudly if a future rcgen ever changes that contract.
        Err(rcgen::Error::RemoteKeyError)
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// Build a rcgen SUBJECT `KeyPair` from the token's exported 44-byte RFC 8410 Ed25519
/// SPKI (12-byte prefix + 32-byte point). The minted leaf's SPKI then equals the token
/// TLS object, so the validated delegated build's cert↔signer match succeeds — with the
/// private key never leaving the token.
fn remote_subject_key_from_spki(spki: &[u8]) -> KeyPair {
    assert_eq!(spki.len(), 44, "RFC 8410 Ed25519 SPKI is 12 + 32 bytes");
    KeyPair::from_remote(Box::new(TokenPublicKey {
        raw: spki[12..].to_vec(),
    }))
    .expect("build a rcgen KeyPair from the token's exported public key")
}

/// A self-signed CA (rcgen) used to issue the client + server leaves below.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params =
        CertificateParams::new(vec!["mcp-re-pkcs11-tls-test-ca".to_string()]).expect("ca params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).expect("self-signed CA");
    Ca { cert, key }
}

/// Mint an Ed25519 server leaf for `localhost` from the SAME key resident on the
/// token, signed by `ca`. The leaf's `SubjectPublicKeyInfo` therefore equals the
/// token TLS object's public point.
fn make_server_leaf_for(ca: &Ca, server_key: &KeyPair) -> CertificateDer<'static> {
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().expect("dns"))];
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .signed_by(server_key, &ca.cert, &ca.key)
        .expect("server leaf signed")
        .der()
        .clone()
}

/// Mint a client leaf with a URI SAN, signed by `ca`; returns (chain, key).
fn make_client_leaf(ca: &Ca, uri: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("client key");
    let mut params = CertificateParams::new(Vec::new()).expect("client params");
    params.subject_alt_names = vec![SanType::URI(uri.try_into().expect("uri"))];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("client leaf signed");
    (
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// A rustls client that FULLY validates the server: chain to `server_ca_root`,
/// hostname, AND the CertificateVerify signature. The handshake completes only if
/// the TOKEN produced a cryptographically valid Ed25519 signature over the
/// transcript — nothing is bypassed, so this is genuinely load-bearing.
fn validating_client(
    server_ca_root: CertificateDer<'static>,
    client_auth: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(server_ca_root).expect("add server CA root");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (chain, key) = client_auth;
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .expect("client auth cert")
}

/// One mTLS POST round trip; returns the response body.
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

/// A path GUARANTEED not to exist — used as the `--tls-key` argument to prove the
/// delegated path NEVER reads it from disk.
fn nonexistent_tls_key_path() -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("THIS-TLS-KEY-MUST-NEVER-BE-READ.pem");
    p.to_string_lossy().into_owned()
}

/// (a) Without a TLS-key label, `tls_delegated_signer()` is `None` (file-backed TLS);
/// with one it is `Some` and its exported public key is a well-formed RFC 8410
/// Ed25519 SPKI matching the token object.
#[test]
fn pkcs11_tls_delegated_signer_none_then_some() {
    let Some(module) = require_mock_or_skip("pkcs11_tls_delegated_signer_none_then_some") else {
        return;
    };
    let _guard = provisioning_lock();
    let mut token = MockToken::init();
    token.keygen_ed25519("mcp-re-sign", "01");
    token.keygen_ed25519("mcp-re-tls", "02");

    // No TLS label → None (file-backed TLS path preserved). Scoped so this source
    // (and its module `C_Initialize`) is fully DROPPED before opening the next one —
    // PKCS#11 allows a single `C_Initialize` per module per process.
    {
        let no_label = Pkcs11KeySource::open(
            &module,
            &token.pin,
            &token.token_label,
            "mcp-re-sign",
            PLACEHOLDER_TLS_PATH,
            PLACEHOLDER_TLS_PATH,
            PLACEHOLDER_TLS_PATH,
            None,
        )
        .expect("open without a TLS label");
        assert!(
            no_label.tls_delegated_signer().is_none(),
            "no TLS-key label must yield NO delegated signer"
        );
    }

    // TLS label → Some; the exported SPKI is well-formed and matches the cert minted
    // from the same key (proves it is the token object's public key).
    let with_label = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcp-re-sign",
        PLACEHOLDER_TLS_PATH,
        &nonexistent_tls_key_path(),
        PLACEHOLDER_TLS_PATH,
        Some("mcp-re-tls"),
    )
    .expect("open with a TLS label");
    let signer = with_label
        .tls_delegated_signer()
        .expect("a TLS-key label must yield a delegated signer");
    let spki = signer
        .tls_public_key_spki_der()
        .expect("export token TLS public key");
    assert_eq!(spki.len(), 44, "RFC 8410 Ed25519 SPKI is 12 + 32 bytes");

    // A leaf minted from the TOKEN's OWN public key (read back from the token, never
    // imported) validates against the signer (cert↔signer match) under the #58 build
    // path — the private key stays on the token.
    let server_key = remote_subject_key_from_spki(&spki);
    let ca = make_ca();
    let server_cert = make_server_leaf_for(&ca, &server_key);
    build_server_config_delegated_validated(
        vec![server_cert],
        signer,
        vec![ca.cert.der().clone()],
        Vec::new(),
        false,
    )
    .expect("matching cert must build the validated delegated config");
}

/// (b) The validated build path (#58) FAILS CLOSED for the PKCS#11 signer when the
/// presented leaf certificate's key does NOT match the token's TLS key.
#[test]
fn pkcs11_tls_cert_signer_mismatch_fails_closed() {
    let Some(module) = require_mock_or_skip("pkcs11_tls_cert_signer_mismatch_fails_closed") else {
        return;
    };
    let _guard = provisioning_lock();
    let mut token = MockToken::init();
    token.keygen_ed25519("mcp-re-sign", "01");
    token.keygen_ed25519("mcp-re-tls", "02");

    let source = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcp-re-sign",
        PLACEHOLDER_TLS_PATH,
        &nonexistent_tls_key_path(),
        PLACEHOLDER_TLS_PATH,
        Some("mcp-re-tls"),
    )
    .expect("open with a TLS label");
    let signer = source.tls_delegated_signer().expect("delegated signer");

    // A cert minted from a DIFFERENT (local) Ed25519 key than the token's TLS key.
    let other = gen_ed25519();
    let ca = make_ca();
    let mismatching_cert = make_server_leaf_for(&ca, &other);
    let result = build_server_config_delegated_validated(
        vec![mismatching_cert],
        signer,
        vec![ca.cert.der().clone()],
        Vec::new(),
        false,
    );
    assert!(
        matches!(result, Err(TlsError::DelegatedKeyMismatch(_))),
        "a cert whose key differs from the token TLS key must fail closed, got {result:?}"
    );
}

/// (c) A TLS label resolving to a NON-Ed25519 key fails closed at `open` (the token
/// has no Ed25519 object under that label).
#[test]
fn pkcs11_tls_non_ed25519_fails_closed() {
    let Some(module) = require_mock_or_skip("pkcs11_tls_non_ed25519_fails_closed") else {
        return;
    };
    let _guard = provisioning_lock();
    let mut token = MockToken::init();
    token.keygen_ed25519("mcp-re-sign", "01");
    // A non-Ed25519 (EC P-256) object under the TLS label; `open` must reject a TLS
    // key that is not Ed25519 (the Ed25519-typed find never matches it).
    token.keygen("EC:prime256v1", "mcp-re-tls", "02");

    let result = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcp-re-sign",
        PLACEHOLDER_TLS_PATH,
        &nonexistent_tls_key_path(),
        PLACEHOLDER_TLS_PATH,
        Some("mcp-re-tls"),
    );
    assert!(
        result.is_err(),
        "a non-Ed25519 TLS key object must fail closed at open"
    );
}

/// (d) If MULTIPLE objects match the TLS label, `open` fails closed (refuses to
/// guess which key is the TLS credential).
#[test]
fn pkcs11_tls_multiple_objects_fails_closed() {
    let Some(module) = require_mock_or_skip("pkcs11_tls_multiple_objects_fails_closed") else {
        return;
    };
    let _guard = provisioning_lock();
    let mut token = MockToken::init();
    token.keygen_ed25519("mcp-re-sign", "01");
    // Two DISTINCT Ed25519 keypairs (different ids) sharing the SAME TLS label.
    token.keygen_ed25519("mcp-re-tls", "02");
    token.keygen_ed25519("mcp-re-tls", "03");

    let result = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcp-re-sign",
        PLACEHOLDER_TLS_PATH,
        &nonexistent_tls_key_path(),
        PLACEHOLDER_TLS_PATH,
        Some("mcp-re-tls"),
    );
    assert!(
        result.is_err(),
        "multiple objects under the TLS label must fail closed at open"
    );
}

/// (e) FULL mTLS handshake with the TLS key resident on the token and NO TLS key
/// read from disk: a real validating rustls client completes the handshake only if
/// the token signed the CertificateVerify over the transcript. The `--tls-key`
/// argument points at a guaranteed-missing file to prove the delegated path never
/// touches it.
#[test]
fn pkcs11_tls_full_mtls_handshake_token_resident_no_disk_read() {
    let Some(module) =
        require_mock_or_skip("pkcs11_tls_full_mtls_handshake_token_resident_no_disk_read")
    else {
        return;
    };
    let _guard = provisioning_lock();
    let mut token = MockToken::init();
    token.keygen_ed25519("mcp-re-sign", "01");
    token.keygen_ed25519("mcp-re-tls", "02");

    let server_ca = make_ca();
    let client_ca = make_ca();

    let source = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcp-re-sign",
        PLACEHOLDER_TLS_PATH,
        // GUARANTEED-MISSING TLS key file: if the delegated path ever read it, open
        // or the handshake would fail. It must not be touched.
        &nonexistent_tls_key_path(),
        PLACEHOLDER_TLS_PATH,
        Some("mcp-re-tls"),
    )
    .expect("open with a TLS label");

    let signer = source
        .tls_delegated_signer()
        .expect("delegated TLS signer present");
    // The TLS server cert is minted from the token's OWN public key (read back off the
    // token, never imported), so its SPKI matches the token object — the delegated
    // handshake signature the token produces verifies against it.
    let spki = signer
        .tls_public_key_spki_der()
        .expect("export token TLS public key");
    let server_key = remote_subject_key_from_spki(&spki);
    let server_cert = make_server_leaf_for(&server_ca, &server_key);
    let server_config = Arc::new(
        build_server_config_delegated_validated(
            vec![server_cert],
            signer,
            vec![client_ca.cert.der().clone()],
            Vec::new(),
            false,
        )
        .expect("validated delegated server config (cert matches token key)"),
    );

    let (client_chain, client_key) = make_client_leaf(&client_ca, "spiffe://example.org/agent-1");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        serve_once(
            &listener,
            server_config,
            &ServerOptions::default(),
            |request, _identity| {
                assert_eq!(request, b"{\"jsonrpc\":\"2.0\"}");
                b"{\"ok\":true}".to_vec()
            },
        )
    });

    let response = client_round_trip(
        addr,
        validating_client(server_ca.cert.der().clone(), (client_chain, client_key)),
        b"{\"jsonrpc\":\"2.0\"}",
    )
    .expect("mTLS round trip over a TOKEN-signed (no-disk-read) handshake");
    assert_eq!(response, b"{\"ok\":true}");

    let identity = server.join().expect("join").expect("serve ok");
    assert_eq!(
        identity.expect("verified client identity").value,
        "spiffe://example.org/agent-1"
    );
}
