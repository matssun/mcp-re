//! MCPS-027 — KeySource (File + Env) loads signing key + TLS cert/key + client-CA.

use std::fs;
use std::path::PathBuf;

use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
// MCPS-076 (audit gap G-3): EnvKeySource is dev/CI-only — compiled only under the
// non-default `dev_env_key_source` feature (the `dev_env_key_source_test` target).
use mcp_re_proxy::capability_materialization::key_file_custody::CheckedKeyFile;
use mcp_re_proxy::config_state::KeyFileAccessPolicy;
#[cfg(feature = "dev_env_key_source")]
use mcp_re_proxy::key_source::EnvKeySource;
use mcp_re_proxy::key_source::FileKeySource;
use mcp_re_proxy::key_source::KeyError;
use mcp_re_proxy::key_source::KeySource;
use mcp_re_proxy::key_source::ResponseSigner;

use rcgen::CertificateParams;
use rcgen::Issuer;
use rcgen::KeyPair;

const SEED: [u8; 32] = [7u8; 32];

/// (signing-seed b64url, server cert PEM, server key PEM, client-CA PEM).
fn material() -> (String, String, String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let ca_params = CertificateParams::new(Vec::new()).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
        .unwrap();
    (
        b64url_encode(&SEED),
        leaf.pem(),
        leaf_key.serialize_pem(),
        ca.pem(),
    )
}

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mcp_re_ks_{}_{name}", std::process::id()))
}

/// Write `content` owner-only and admit it — the only way to hand a key file to a
/// `FileKeySource`.
fn admitted(path: &PathBuf, content: &str) -> CheckedKeyFile {
    fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    CheckedKeyFile::open(&path.to_string_lossy(), KeyFileAccessPolicy::OwnerOnly).unwrap()
}

fn expected_pubkey() -> String {
    SigningKey::from_seed_bytes(&SEED).public_key().to_b64url()
}

#[test]
fn file_source_loads_all_material() {
    let (seed, cert, key, ca) = material();
    let seed_p = tmp("file_seed");
    let cert_p = tmp("file_cert");
    let key_p = tmp("file_key");
    let ca_p = tmp("file_ca");
    fs::write(&cert_p, &cert).unwrap();
    fs::write(&ca_p, &ca).unwrap();

    let source = FileKeySource::from_checked(
        admitted(&seed_p, &seed),
        &cert_p.to_string_lossy(),
        Some(admitted(&key_p, &key)),
        &ca_p.to_string_lossy(),
    )
    .unwrap();

    assert_eq!(
        source.response_public_key().unwrap().to_b64url(),
        expected_pubkey()
    );
    assert!(!source.tls_server_cert_chain().unwrap().is_empty());
    let _ = source.tls_server_key().unwrap();
    assert!(!source.client_ca_roots().unwrap().is_empty());

    for p in [seed_p, cert_p, key_p, ca_p] {
        let _ = fs::remove_file(p);
    }
}

/// A missing key file never reaches the source: the check that produces its material
/// refuses it, naming the file.
#[test]
fn file_source_missing_file_is_refused_at_the_check() {
    let err = CheckedKeyFile::open("/nonexistent/mcp-re/seed", KeyFileAccessPolicy::OwnerOnly)
        .unwrap_err();
    assert!(err.contains("/nonexistent/mcp-re/seed"), "{err}");
}

#[test]
fn file_source_bad_seed_is_malformed() {
    let seed_p = tmp("bad_seed");
    let err = FileKeySource::from_checked(admitted(&seed_p, "not-base64-!!!"), "x", None, "x")
        .unwrap_err();
    assert!(matches!(err, KeyError::Malformed(_)));
    let _ = fs::remove_file(seed_p);
}

#[cfg(feature = "dev_env_key_source")]
#[test]
fn env_source_loads_all_material() {
    let (seed, cert, key, ca) = material();
    // Unique var names avoid races with other (parallel) tests.
    let seed_v = "MCP_RE_TEST_SEED_ENV";
    let cert_v = "MCP_RE_TEST_CERT_ENV";
    let key_v = "MCP_RE_TEST_KEY_ENV";
    let ca_v = "MCP_RE_TEST_CA_ENV";
    std::env::set_var(seed_v, &seed);
    std::env::set_var(cert_v, &cert);
    std::env::set_var(key_v, &key);
    std::env::set_var(ca_v, &ca);

    let source = EnvKeySource {
        signing_key_seed_var: seed_v.to_string(),
        tls_cert_var: cert_v.to_string(),
        tls_key_var: key_v.to_string(),
        client_ca_var: ca_v.to_string(),
    };

    assert_eq!(
        source.response_public_key().unwrap().to_b64url(),
        expected_pubkey()
    );
    assert!(!source.tls_server_cert_chain().unwrap().is_empty());
    let _ = source.tls_server_key().unwrap();
    assert!(!source.client_ca_roots().unwrap().is_empty());
}

#[cfg(feature = "dev_env_key_source")]
#[test]
fn env_source_missing_var_is_not_found() {
    let source = EnvKeySource {
        signing_key_seed_var: "MCP_RE_TEST_DEFINITELY_UNSET_VAR".to_string(),
        tls_cert_var: "x".to_string(),
        tls_key_var: "x".to_string(),
        client_ca_var: "x".to_string(),
    };
    assert!(matches!(
        source.response_public_key().unwrap_err(),
        KeyError::NotFound(_)
    ));
}

#[test]
fn key_errors_never_leak_secret_material() {
    // A malformed but secret-looking seed must not appear in the error (Display
    // or Debug) — errors are logged, secrets must not be.
    let secret = "SUPER_SECRET_SEED_VALUE_THAT_MUST_NOT_BE_LOGGED";
    let seed_p = tmp("leak_seed");
    let err = FileKeySource::from_checked(admitted(&seed_p, secret), "x", None, "x").unwrap_err();
    let rendered = format!("{err} | {err:?}");
    assert!(
        !rendered.contains(secret),
        "KeyError must not contain the secret seed value; got: {rendered}"
    );
    let _ = fs::remove_file(seed_p);
}
