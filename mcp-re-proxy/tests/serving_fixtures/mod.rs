// SPDX-License-Identifier: Apache-2.0
//! Startup material for tests that drive `app::run`: an rcgen CA, a server leaf, and
//! the on-disk key/trust files the proxy reads before it can serve.
//!
//! Shared rather than copied because these fixtures encode SECURITY properties the
//! proxy enforces — the seed and TLS-key files are written `0600` because the proxy
//! refuses to start on a group- or world-readable key file, and the trust file's shape
//! is what the RFC 9421 resolver reads. A second copy of that reasoning is a second
//! place for it to drift out of agreement with the guard it exists to satisfy.
//!
//! Deliberately NARROW: only what a startup test needs. Client-leaf minting, CRLs and
//! the mTLS client stack stay with the serving harness that uses them — pulling them
//! here would drag `time` and the whole rustls client surface into every consumer.
//!
//! Not a test target of its own: a directory under `tests/` with no `main.rs` is not
//! auto-discovered by Cargo, so this compiles only into the binaries that declare it.

#![allow(dead_code)] // each test binary uses a subset

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;
use serde_json::json;

pub const SERVER: &str = "did:example:server-1";
pub const SERVER_KEY_ID: &str = "server-key-1";
pub const AUDIENCE: &str = "did:example:server-1";
pub const TRUST_DOMAIN: &str = "example.org";
/// A DID request-signer (subject) with colons: the real-world shape, and the one whose
/// colons force `%3A` escaping in the resolved actor_id.
pub const SUBJECT_A: &str = "did:example:agent-1";
pub const SIGNER_A_KEY_ID: &str = "key-a";
pub const TARGET_URI: &str = "https://localhost/";

pub fn server_seed() -> [u8; 32] {
    [2u8; 32]
}

pub fn signer_a_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}

// --- rcgen certificate authority + leaves -------------------------------------

pub struct Ca {
    pub cert: rcgen::Certificate,
    pub key: KeyPair,
    /// Retained so an `Issuer` can be borrowed per signature: rcgen derives the issuer
    /// DN, key-identifier method and key usages from these, not from `cert`.
    pub params: CertificateParams,
}

impl Ca {
    /// The issuing state that minted `cert`, paired with the signing key.
    pub fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
}

pub fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcp-re-test-ca");
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key, params }
}

pub fn make_leaf(
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
    let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
    (cert, key)
}

pub fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

// --- temp key material on disk ------------------------------------------------

pub fn tmp(name: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "mcp_re_fixture_{}_{seq}_{name}",
        std::process::id()
    ))
}

/// The five files `app::run` reads at startup, removed when this drops.
pub struct Material {
    pub seed_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub client_ca_path: PathBuf,
    pub trust_path: PathBuf,
    pub client_ca: Ca,
}

pub fn write_material() -> Material {
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
    // The proxy refuses to start on a group/world-accessible sensitive key file, so the
    // fixture must restrict the signing-key seed and the TLS server key to 0600
    // (owner-only) — the same posture a production deployment uses.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&seed_path, &server_key_path] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    // The RFC 9421 trust file maps the request-signer keyid → (signer, public_key).
    let trust = json!([
        { "signer": SUBJECT_A, "key_id": SIGNER_A_KEY_ID, "public_key": signer_a_key().public_key().to_b64url() },
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
