//! Black-box end-to-end test for the PKCS#11-backed response signer (issue
//! #4034), exercised against an INDEPENDENT SoftHSM2 token.
//!
//! This proves the real device path: open a token, sign a preimage with the
//! Ed25519 key that NEVER leaves the token (`CKM_EDDSA` / `C_Sign`), then verify
//! the returned signature against the token's exported public key using
//! `mcps_core`'s ordinary verifier — exactly what a relying party does. It also
//! proves a tampered preimage does NOT verify.
//!
//! # Environment gating
//! The test runs ONLY when `MCPS_TEST_PKCS11_MODULE` is set; otherwise it prints
//! a skip notice and returns success (not every environment has SoftHSM2
//! provisioned, and this build does not bundle a token). When run, it reads:
//!   * `MCPS_TEST_PKCS11_MODULE`      — path to the PKCS#11 provider module
//!     (e.g. `/usr/lib/softhsm/libsofthsm2.so` or
//!     `/opt/homebrew/lib/softhsm/libsofthsm2.so`).
//!   * `MCPS_TEST_PKCS11_PIN`         — the token User PIN.
//!   * `MCPS_TEST_PKCS11_TOKEN_LABEL` — the token label.
//!   * `MCPS_TEST_PKCS11_KEY_LABEL`   — the CKA_LABEL of the Ed25519 key pair.
//!
//! # Provisioning a test token (run once by a human / CI, NOT by this test)
//! ```sh
//! # 1. Point SoftHSM2 at a scratch token directory (so this never touches a
//! #    host/production token store):
//! export SOFTHSM2_CONF="$PWD/softhsm2.conf"
//! mkdir -p "$PWD/softhsm-tokens"
//! printf 'directories.tokendir = %s/softhsm-tokens\n' "$PWD" > "$SOFTHSM2_CONF"
//!
//! # 2. Initialise a fresh token:
//! softhsm2-util --init-token --free \
//!     --label mcps-test --so-pin 0000 --pin 1234
//!
//! # 3. Generate an Ed25519 key pair ON the token (private key non-extractable),
//! #    labelled so the key source can find it. Using pkcs11-tool (OpenSC):
//! softhsm2-util --show-slots   # note the assigned slot id, e.g. 12345
//! pkcs11-tool --module "$MCPS_TEST_PKCS11_MODULE" \
//!     --login --pin 1234 --slot <SLOT_ID> \
//!     --keypairgen --key-type EC:edwards25519 \
//!     --label mcps-response-signing --id 01
//!
//! # 4. Export the env vars this test reads:
//! export MCPS_TEST_PKCS11_MODULE="$MCPS_TEST_PKCS11_MODULE"
//! export MCPS_TEST_PKCS11_PIN=1234
//! export MCPS_TEST_PKCS11_TOKEN_LABEL=mcps-test
//! export MCPS_TEST_PKCS11_KEY_LABEL=mcps-response-signing
//!
//! # 5. Run the feature-gated test:
//! cargo test -p mcps-proxy --features pkcs11_keysource \
//!     --test pkcs11_keysource_e2e_test
//! ```
//! SoftHSM2 is an INDEPENDENT software token; nothing here references any host
//! security system.
#![cfg(feature = "pkcs11_keysource")]

use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use mcps_core::verify_ed25519_with;
use mcps_core::McpsError;
use mcps_proxy::build_server_config_delegated_validated;
use mcps_proxy::serve_once;
use mcps_proxy::KeySource;
use mcps_proxy::Pkcs11KeySource;
use mcps_proxy::ResponseSigner;
use mcps_proxy::ServerOptions;
use mcps_proxy::TlsError;
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

/// Read all four env vars; `None` (skip) unless `MCPS_TEST_PKCS11_MODULE` is set.
/// The other three default to the values used by the provisioning recipe above so
/// a minimal `MCPS_TEST_PKCS11_MODULE=... cargo test` works against a token built
/// with those labels/PIN.
fn pkcs11_env() -> Option<(String, String, String, String)> {
    let Ok(module) = std::env::var("MCPS_TEST_PKCS11_MODULE") else {
        if std::env::var("MCPS_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
            panic!(
                "MCPS_REQUIRE_LIVE_INFRA is set but MCPS_TEST_PKCS11_MODULE is unavailable \
                 — this live e2e MUST run under CI, not skip"
            );
        }
        return None;
    };
    let pin = std::env::var("MCPS_TEST_PKCS11_PIN").unwrap_or_else(|_| "1234".to_string());
    let token_label =
        std::env::var("MCPS_TEST_PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "mcps-test".to_string());
    let key_label = std::env::var("MCPS_TEST_PKCS11_KEY_LABEL")
        .unwrap_or_else(|_| "mcps-response-signing".to_string());
    Some((module, pin, token_label, key_label))
}

/// The TLS material paths are not exercised by this signing test (the token
/// custodies only the response-signing key), but `Pkcs11KeySource::open` takes
/// them; point them at this crate's own `Cargo.toml` (a file that always exists)
/// so `open` does not need real TLS fixtures. The TLS accessors are NOT called
/// here, so the file contents are never parsed.
const PLACEHOLDER_TLS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

#[test]
fn pkcs11_sign_verifies_against_token_public_key() {
    let Some((module, pin, token_label, key_label)) = pkcs11_env() else {
        eprintln!(
            "SKIP pkcs11_sign_verifies_against_token_public_key: \
             MCPS_TEST_PKCS11_MODULE is unset (no SoftHSM2 token provisioned). \
             See this test's module doc for softhsm2-util provisioning commands."
        );
        return;
    };

    let source = Pkcs11KeySource::open(
        &module,
        &pin,
        &token_label,
        &key_label,
        PLACEHOLDER_TLS_PATH,
        PLACEHOLDER_TLS_PATH,
        PLACEHOLDER_TLS_PATH,
        None,
    )
    .expect("open PKCS#11 token + locate Ed25519 key");

    let preimage = b"test-preimage-mcps-4034-pkcs11-response-signing";
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
        McpsError::ResponseSigInvalid,
    )
    .expect("token signature must verify under the token's public key");

    // Negative: a tampered preimage must NOT verify under the same signature.
    let tampered = b"test-preimage-mcps-4034-pkcs11-response-signing-XXX";
    let tampered_result = verify_ed25519_with(
        tampered,
        &signature,
        &public_key,
        McpsError::ResponseSigInvalid,
    );
    assert!(
        tampered_result.is_err(),
        "a tampered preimage must NOT verify under the token signature"
    );
}

// ===========================================================================
// Issue #59 (ADR-MCPS-028 §G): PKCS#11-DELEGATED TLS signing — live SoftHSM2 lane.
//
// These prove the real device path for the TLS key: a SECOND Ed25519 token object
// (distinct label from the response-signing key) custodies the TLS server key, the
// proxy reads NO TLS key from disk, and a real rustls client completing an mTLS
// handshake verifies a CertificateVerify signature the token produced over the
// transcript. The lane is SELF-PROVISIONING: when `softhsm2-util` and `openssl`-free
// rcgen key material are available it builds a fresh SCRATCH token (its own tokendir
// via `SOFTHSM2_CONF`, never a host/production store) with the two objects. It
// SELF-SKIPS when SoftHSM2 is not installed, honoring `MCPS_REQUIRE_LIVE_INFRA`
// (set → a skip becomes a hard failure, so CI cannot silently lose the coverage).
// ===========================================================================

/// Serializes the #59 live tests. Each provisions its own scratch token and sets
/// the PROCESS-wide `SOFTHSM2_CONF`, so they must NOT run concurrently (cargo runs
/// tests multi-threaded by default). Holding this lock for the whole test body makes
/// each "init token → import → open → handshake" sequence atomic w.r.t. the others.
/// A poisoned lock (a prior test panicked) is recovered — the panic is already the
/// reported failure; we still want the remaining tests to run serially.
fn provisioning_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Canonical SoftHSM2 module locations probed when `MCPS_TEST_PKCS11_MODULE` is
/// unset (Homebrew on macOS, common Linux package paths).
const SOFTHSM2_MODULE_CANDIDATES: &[&str] = &[
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
];

/// Resolve the SoftHSM2 module path: explicit env override, else the first existing
/// canonical candidate.
fn softhsm2_module() -> Option<String> {
    if let Ok(m) = std::env::var("MCPS_TEST_PKCS11_MODULE") {
        return Path::new(&m).exists().then_some(m);
    }
    SOFTHSM2_MODULE_CANDIDATES
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|p| p.to_string())
}

/// `true` if `softhsm2-util` is on PATH (needed to provision the scratch token).
fn softhsm2_util_available() -> bool {
    Command::new("softhsm2-util")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The decision for every #59 live test: a resolved module path + a usable
/// `softhsm2-util`, or `None` to self-skip. Honors `MCPS_REQUIRE_LIVE_INFRA`.
fn require_softhsm2_or_skip(test: &str) -> Option<String> {
    let module = softhsm2_module();
    let ok = module.is_some() && softhsm2_util_available();
    if !ok {
        if std::env::var("MCPS_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
            panic!(
                "MCPS_REQUIRE_LIVE_INFRA is set but SoftHSM2 (module + softhsm2-util) is \
                 unavailable — the #59 delegated-TLS live lane MUST run under CI, not skip"
            );
        }
        eprintln!(
            "SKIP {test}: SoftHSM2 not available (set MCPS_TEST_PKCS11_MODULE or install \
             softhsm2-util). The #59 delegated-TLS path is exercised by the unit tests; this \
             lane needs a live token."
        );
        return None;
    }
    module
}

/// A provisioned scratch SoftHSM2 token: owns the temp dir (best-effort cleaned on
/// drop) and exports the `SOFTHSM2_CONF` that points the module at it. The PROCESS
/// env `SOFTHSM2_CONF` is set so the in-process module load finds this token.
struct ScratchToken {
    dir: PathBuf,
    token_label: String,
    pin: String,
}

impl ScratchToken {
    /// Initialise a fresh token in a unique temp dir and point `SOFTHSM2_CONF` at it.
    fn init() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("mcps-pkcs11-tls-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("tokens")).expect("create tokendir");
        let conf = dir.join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!("directories.tokendir = {}/tokens\n", dir.display()),
        )
        .expect("write softhsm2.conf");
        // SAFETY: the module reads SOFTHSM2_CONF at C_Initialize. The #59 live tests
        // hold `provisioning_lock()` for their whole body, so only ONE scratch token
        // is being provisioned/opened at a time — this set_var never races a
        // concurrent token in another test thread.
        std::env::set_var("SOFTHSM2_CONF", &conf);

        // SoftHSM2 caps the token label at 32 chars; keep it short + unique (the low
        // bits of the nanosecond clock plus the pid suffice for in-run uniqueness).
        let token_label = format!("mcps-{}-{}", std::process::id(), (nanos as u64) % 1_000_000);
        let pin = "1234".to_string();
        let out = Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                &token_label,
                "--so-pin",
                "0000",
                "--pin",
                &pin,
            ])
            .output()
            .expect("run softhsm2-util --init-token");
        assert!(
            out.status.success(),
            "softhsm2-util --init-token failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ScratchToken {
            dir,
            token_label,
            pin,
        }
    }

    /// Import an Ed25519 keypair (PKCS#8 PEM) under `label`/`id` onto the token.
    fn import_ed25519(&self, pkcs8_pem: &str, label: &str, id: &str) {
        let key_path = self.dir.join(format!("{label}.pem"));
        std::fs::write(&key_path, pkcs8_pem).expect("write key pem");
        let out = Command::new("softhsm2-util")
            .args([
                "--import",
                key_path.to_str().expect("key path utf8"),
                "--token",
                &self.token_label,
                "--label",
                label,
                "--id",
                id,
                "--pin",
                &self.pin,
            ])
            .output()
            .expect("run softhsm2-util --import");
        assert!(
            out.status.success(),
            "softhsm2-util --import ({label}) failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

impl Drop for ScratchToken {
    fn drop(&mut self) {
        // Best-effort cleanup of the scratch tokendir; failure to remove a temp dir
        // is not a test failure (it lives under the OS temp dir).
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A freshly generated Ed25519 credential: the rcgen `KeyPair` (so a matching cert
/// can be minted) plus its PKCS#8 PEM (for token import). The token object and any
/// cert minted from `key` therefore share the SAME public key — which is exactly
/// what the validated delegated-build cert↔signer match requires.
struct Ed25519Cred {
    key: KeyPair,
    pkcs8_pem: String,
}

fn gen_ed25519() -> Ed25519Cred {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 key");
    let pkcs8_pem = key.serialize_pem();
    Ed25519Cred { key, pkcs8_pem }
}

/// A self-signed CA (rcgen) used to issue the client + server leaves below.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params =
        CertificateParams::new(vec!["mcps-pkcs11-tls-test-ca".to_string()]).expect("ca params");
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

/// A path under the scratch dir that is GUARANTEED not to exist — used as the
/// `--tls-key` argument to prove the delegated path NEVER reads it from disk.
fn nonexistent_tls_key_path(token: &ScratchToken) -> String {
    token
        .dir
        .join("THIS-TLS-KEY-MUST-NEVER-BE-READ.pem")
        .to_string_lossy()
        .into_owned()
}

/// (a) Without a TLS-key label, `tls_delegated_signer()` is `None` (file-backed TLS);
/// with one it is `Some` and its exported public key is a well-formed RFC 8410
/// Ed25519 SPKI matching the token object.
#[test]
fn pkcs11_tls_delegated_signer_none_then_some() {
    let Some(module) = require_softhsm2_or_skip("pkcs11_tls_delegated_signer_none_then_some")
    else {
        return;
    };
    let _guard = provisioning_lock();
    let token = ScratchToken::init();
    let signing = gen_ed25519();
    let tls = gen_ed25519();
    token.import_ed25519(&signing.pkcs8_pem, "mcps-sign", "01");
    token.import_ed25519(&tls.pkcs8_pem, "mcps-tls", "02");

    // No TLS label → None (file-backed TLS path preserved). Scoped so this source
    // (and its module `C_Initialize`) is fully DROPPED before opening the next one —
    // PKCS#11 allows a single `C_Initialize` per module per process.
    {
        let no_label = Pkcs11KeySource::open(
            &module,
            &token.pin,
            &token.token_label,
            "mcps-sign",
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
        "mcps-sign",
        PLACEHOLDER_TLS_PATH,
        &nonexistent_tls_key_path(&token),
        PLACEHOLDER_TLS_PATH,
        Some("mcps-tls"),
    )
    .expect("open with a TLS label");
    let signer = with_label
        .tls_delegated_signer()
        .expect("a TLS-key label must yield a delegated signer");
    let spki = signer
        .tls_public_key_spki_der()
        .expect("export token TLS public key");
    assert_eq!(spki.len(), 44, "RFC 8410 Ed25519 SPKI is 12 + 32 bytes");

    // The token TLS key equals the rcgen key, so a cert minted from that key
    // validates against the signer (cert↔signer match) under the #58 build path.
    let ca = make_ca();
    let server_cert = make_server_leaf_for(&ca, &tls.key);
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
    let Some(module) = require_softhsm2_or_skip("pkcs11_tls_cert_signer_mismatch_fails_closed")
    else {
        return;
    };
    let _guard = provisioning_lock();
    let token = ScratchToken::init();
    let signing = gen_ed25519();
    let tls = gen_ed25519();
    token.import_ed25519(&signing.pkcs8_pem, "mcps-sign", "01");
    token.import_ed25519(&tls.pkcs8_pem, "mcps-tls", "02");

    let source = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcps-sign",
        PLACEHOLDER_TLS_PATH,
        &nonexistent_tls_key_path(&token),
        PLACEHOLDER_TLS_PATH,
        Some("mcps-tls"),
    )
    .expect("open with a TLS label");
    let signer = source.tls_delegated_signer().expect("delegated signer");

    // A cert minted from a DIFFERENT Ed25519 key than the token's TLS key.
    let other = gen_ed25519();
    let ca = make_ca();
    let mismatching_cert = make_server_leaf_for(&ca, &other.key);
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
    let Some(module) = require_softhsm2_or_skip("pkcs11_tls_non_ed25519_fails_closed") else {
        return;
    };
    let _guard = provisioning_lock();
    let token = ScratchToken::init();
    let signing = gen_ed25519();
    token.import_ed25519(&signing.pkcs8_pem, "mcps-sign", "01");

    // Import an ECDSA P-256 key (a NON-Ed25519 key) under the TLS label.
    let ecdsa = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ecdsa key");
    token.import_ed25519(&ecdsa.serialize_pem(), "mcps-tls", "02");

    let result = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcps-sign",
        PLACEHOLDER_TLS_PATH,
        &nonexistent_tls_key_path(&token),
        PLACEHOLDER_TLS_PATH,
        Some("mcps-tls"),
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
    let Some(module) = require_softhsm2_or_skip("pkcs11_tls_multiple_objects_fails_closed") else {
        return;
    };
    let _guard = provisioning_lock();
    let token = ScratchToken::init();
    let signing = gen_ed25519();
    token.import_ed25519(&signing.pkcs8_pem, "mcps-sign", "01");
    // Two DISTINCT Ed25519 keypairs sharing the SAME TLS label.
    token.import_ed25519(&gen_ed25519().pkcs8_pem, "mcps-tls", "02");
    token.import_ed25519(&gen_ed25519().pkcs8_pem, "mcps-tls", "03");

    let result = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcps-sign",
        PLACEHOLDER_TLS_PATH,
        &nonexistent_tls_key_path(&token),
        PLACEHOLDER_TLS_PATH,
        Some("mcps-tls"),
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
        require_softhsm2_or_skip("pkcs11_tls_full_mtls_handshake_token_resident_no_disk_read")
    else {
        return;
    };
    let _guard = provisioning_lock();
    let token = ScratchToken::init();
    let signing = gen_ed25519();
    let tls = gen_ed25519();
    token.import_ed25519(&signing.pkcs8_pem, "mcps-sign", "01");
    token.import_ed25519(&tls.pkcs8_pem, "mcps-tls", "02");

    // The TLS server cert is minted from the SAME key now resident on the token, so
    // its SPKI matches the token object — the delegated handshake signature verifies.
    let server_ca = make_ca();
    let server_cert = make_server_leaf_for(&server_ca, &tls.key);
    let client_ca = make_ca();

    let source = Pkcs11KeySource::open(
        &module,
        &token.pin,
        &token.token_label,
        "mcps-sign",
        PLACEHOLDER_TLS_PATH,
        // GUARANTEED-MISSING TLS key file: if the delegated path ever read it, open
        // or the handshake would fail. It must not be touched.
        &nonexistent_tls_key_path(&token),
        PLACEHOLDER_TLS_PATH,
        Some("mcps-tls"),
    )
    .expect("open with a TLS label");

    let signer = source
        .tls_delegated_signer()
        .expect("delegated TLS signer present");
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
