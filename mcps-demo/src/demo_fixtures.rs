//! Shared demo security-material fixtures (MCPS-055, Phase 6.6, epic #3948).
//!
//! ONE source of truth for ALL the security material the multi-process mTLS demo
//! needs, so the hermetic multi-process test (#3943–#3946) and the human-facing
//! `bazel run` demonstration mint the SAME, internally-consistent set:
//!
//!   * a server CA + server leaf cert/key (the server identity is the expected
//!     server name the client verifies — e.g. `proxy.internal`);
//!   * a client CA + client leaf cert/key carrying the `clientAuth` EKU and a URI
//!     SAN identity that EQUALS the request signer (the positive / transport-
//!     binding-match path);
//!   * a SECOND client identity whose URI SAN does NOT equal the signer (the T3
//!     transport-binding-mismatch case), issued by the SAME client CA so it still
//!     passes the mTLS handshake and is rejected only by the binding check;
//!   * a `trust.json` for the proxy's `TrustResolver` (the request signers it
//!     trusts at the object layer);
//!   * the Ed25519 signing seed (Base64URL-no-pad, the byte-for-byte content the
//!     proxy's `--signing-key-seed` file and the client's `--signing-key-seed-file`
//!     expect).
//!
//! The material lines up with BOTH consumers:
//!
//!   * the `mcps_proxy_cli` flags — `--tls-cert` / `--tls-key` (server leaf),
//!     `--client-ca` (client CA), `--trust` (trust.json), `--signing-key-seed`
//!     (the SERVER signing seed the proxy signs responses with),
//!     `--audience` / `--server-signer` ([`Self::audience`] / [`Self::server_signer`]);
//!   * the `mcps-transport` client config — `ClientTlsConfig::from_pem` takes the
//!     client cert PEM + client key PEM + server-CA PEM, and the expected server
//!     name is [`Self::server_name`]; the client's signing seed is the SIGNER
//!     seed and the response public key is [`Self::server_public_key_b64url`].
//!
//! Boundary (LOCKED): this is test/demo SUPPORT only. It produces material and
//! NOTHING else — no signing, policy, or transport logic. It reuses the proven
//! `rcgen` idiom from `mcps-proxy/tests`; `rcgen` is a NORMAL dependency of this
//! demo crate (the demo bin generates certs at runtime for `bazel run`), kept OUT
//! of `mcps-core` / `mcps-host`, which stay pure / transport-free.

use std::path::PathBuf;

use mcps_core::b64url_encode;
use mcps_core::SigningKey;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use serde_json::json;

/// The deterministic identities + seeds the demo material is minted around. The
/// defaults match the rest of the demo (`did:example:*`), but every field is
/// explicit so a caller can mint a fresh, isolated set.
#[derive(Debug, Clone)]
pub struct DemoFixtureSpec {
    /// The request signer identity (the LLM caller). This EQUALS the positive
    /// client cert's URI SAN, so the proxy's `exact` transport binding matches.
    pub signer: String,
    /// The signer's key id (object-layer key id in `trust.json`).
    pub signer_key_id: String,
    /// The 32-byte Ed25519 seed for the signer's signing key.
    pub signer_seed: [u8; 32],
    /// The server (proxy) signer identity that signs responses; the proxy's
    /// `--server-signer`, and the client's response-signer trust anchor.
    pub server_signer: String,
    /// The server signer's key id.
    pub server_key_id: String,
    /// The 32-byte Ed25519 seed for the SERVER signing key (the proxy's
    /// `--signing-key-seed`).
    pub server_seed: [u8; 32],
    /// The audience the request is signed for (the proxy's `--audience`).
    pub audience: String,
    /// The expected server NAME the client verifies (a DNS SAN on the server leaf
    /// and the `ServerName` the transport client checks).
    pub server_name: String,
    /// A SECOND client identity (URI SAN) that does NOT equal `signer` — drives
    /// the T3 transport-binding-mismatch case.
    pub mismatched_identity: String,
}

impl Default for DemoFixtureSpec {
    fn default() -> Self {
        DemoFixtureSpec {
            signer: "did:example:agent-1".to_string(),
            signer_key_id: "key-1".to_string(),
            signer_seed: [1u8; 32],
            server_signer: "did:example:server-1".to_string(),
            server_key_id: "server-key-1".to_string(),
            server_seed: [2u8; 32],
            audience: "did:example:server-1".to_string(),
            server_name: "proxy.internal".to_string(),
            mismatched_identity: "spiffe://example.org/agent-2".to_string(),
        }
    }
}

/// A minted certificate authority (self-signed root) and its key.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca(common_name: &str) -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // Emit an Authority Key Identifier (referencing this CA's own SubjectKeyId,
    // which `IsCa::Ca` already writes). rustls tolerates its absence, but OpenSSL
    // 3.x — used by the Python/Node SDK clients — fails chain building without it.
    params.use_authority_key_identifier_extension = true;
    params.distinguished_name.push(DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key }
}

/// A leaf signed by `ca`, with the given SANs / CN and (client or server) EKU.
/// Uses a bounded, currently-valid window (≈15y) matching the proxy test idiom so
/// the cert passes the handshake date check and a generous `--max-client-cert-
/// lifetime` ceiling.
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
    // Emit the Authority Key Identifier (referencing the issuing CA's SubjectKeyId)
    // so OpenSSL-based clients (the Python/Node SDKs) can build the chain; rustls
    // does not require it, which is why the Rust tiers passed without it.
    params.use_authority_key_identifier_extension = true;
    let cert = params.signed_by(&key, &ca.cert, &ca.key).expect("leaf signed");
    (cert, key)
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}
fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

/// The complete, internally-consistent demo security material, as PEM strings +
/// identities. Mint it once with [`DemoFixtures::generate`] and feed it to the
/// transport client (PEM directly) or write it to files with
/// [`DemoFixtures::write_files`] for the proxy CLI flags.
///
/// Consistency guarantees (proven by this crate's unit test):
///   * the positive client leaf chains to `client_ca_pem`;
///   * the mismatched client leaf chains to the SAME `client_ca_pem`;
///   * the server leaf chains to `server_ca_pem`;
///   * the positive client URI-SAN identity EQUALS `signer` (binding match);
///   * the mismatched client URI-SAN identity differs from `signer`.
#[derive(Debug, Clone)]
pub struct DemoFixtures {
    spec: DemoFixtureSpec,

    server_ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,

    client_ca_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
    mismatched_client_cert_pem: String,
    mismatched_client_key_pem: String,

    trust_json: String,
    signing_seed_b64url: String,
}

impl DemoFixtures {
    /// Mint the full material set from `spec`. Pure in-memory generation (no I/O);
    /// use [`Self::write_files`] to materialize the proxy CLI's file inputs.
    pub fn generate(spec: DemoFixtureSpec) -> Self {
        let server_ca = make_ca("mcps-demo-server-ca");
        let (server_leaf, server_leaf_key) = make_leaf(
            &server_ca,
            vec![dns(&spec.server_name)],
            Some(&spec.server_name),
            false,
        );

        let client_ca = make_ca("mcps-demo-client-ca");
        let (client_leaf, client_leaf_key) =
            make_leaf(&client_ca, vec![uri(&spec.signer)], None, true);
        let (mismatched_leaf, mismatched_leaf_key) = make_leaf(
            &client_ca,
            vec![uri(&spec.mismatched_identity)],
            None,
            true,
        );

        // trust.json: the request signer the proxy trusts at the OBJECT layer.
        // The server signs responses with the server seed; the client trusts that
        // separately via `server_public_key_b64url`.
        let signer_public = SigningKey::from_seed_bytes(&spec.signer_seed)
            .public_key()
            .to_b64url();
        let trust = json!([
            {
                "signer": spec.signer,
                "key_id": spec.signer_key_id,
                "public_key": signer_public,
            }
        ]);
        let trust_json = serde_json::to_string_pretty(&trust).expect("trust json");

        DemoFixtures {
            server_ca_pem: server_ca.cert.pem(),
            server_cert_pem: server_leaf.pem(),
            server_key_pem: server_leaf_key.serialize_pem(),
            client_ca_pem: client_ca.cert.pem(),
            client_cert_pem: client_leaf.pem(),
            client_key_pem: client_leaf_key.serialize_pem(),
            mismatched_client_cert_pem: mismatched_leaf.pem(),
            mismatched_client_key_pem: mismatched_leaf_key.serialize_pem(),
            trust_json,
            signing_seed_b64url: b64url_encode(&spec.server_seed),
            spec,
        }
    }

    /// Mint the full material set with the default identities/seeds.
    pub fn generate_default() -> Self {
        Self::generate(DemoFixtureSpec::default())
    }

    // --- identities / scalars (proxy CLI + client flags) ---------------------

    /// The audience the request is signed for (`mcps_proxy_cli --audience`).
    pub fn audience(&self) -> &str {
        &self.spec.audience
    }
    /// The server (proxy) signer identity (`mcps_proxy_cli --server-signer`; the
    /// client's response-signer trust anchor).
    pub fn server_signer(&self) -> &str {
        &self.spec.server_signer
    }
    /// The server signer's key id (`--server-key-id`; the client's response key id).
    pub fn server_key_id(&self) -> &str {
        &self.spec.server_key_id
    }
    /// The request signer identity (the LLM caller; equals the positive client
    /// cert's URI SAN).
    pub fn signer(&self) -> &str {
        &self.spec.signer
    }
    /// The request signer's key id.
    pub fn signer_key_id(&self) -> &str {
        &self.spec.signer_key_id
    }
    /// The 32-byte Ed25519 SIGNER seed — the LLM caller's signing key material.
    /// The multi-process flow (#3943) builds the client's `HostSigner` from this
    /// so the request signer, the mTLS client-cert URI SAN, and the (self-issued)
    /// grant grantee are ONE identity, satisfying `--transport-binding exact`.
    pub fn signer_seed(&self) -> [u8; 32] {
        self.spec.signer_seed
    }
    /// The 32-byte Ed25519 SERVER seed — the proxy's response-signing key
    /// material. The client derives the response trust anchor (the server signer
    /// public key) from this to verify the signed response.
    pub fn server_seed(&self) -> [u8; 32] {
        self.spec.server_seed
    }
    /// The expected server NAME the transport client verifies against the server
    /// cert's SAN.
    pub fn server_name(&self) -> &str {
        &self.spec.server_name
    }
    /// The SECOND client identity (URI SAN) that does NOT equal the signer (T3).
    pub fn mismatched_identity(&self) -> &str {
        &self.spec.mismatched_identity
    }

    // --- PEM / encoded material ----------------------------------------------

    /// The server CA certificate PEM — the only root the client trusts to
    /// authenticate the proxy (`ClientTlsConfig::from_pem`'s `server_ca_pem`).
    pub fn server_ca_pem(&self) -> &str {
        &self.server_ca_pem
    }
    /// The server leaf certificate PEM (`mcps_proxy_cli --tls-cert`).
    pub fn server_cert_pem(&self) -> &str {
        &self.server_cert_pem
    }
    /// The server leaf private-key PEM (`mcps_proxy_cli --tls-key`).
    pub fn server_key_pem(&self) -> &str {
        &self.server_key_pem
    }
    /// The client CA certificate PEM — the root the proxy requires inbound client
    /// certs to chain to (`mcps_proxy_cli --client-ca`).
    pub fn client_ca_pem(&self) -> &str {
        &self.client_ca_pem
    }
    /// The POSITIVE client leaf certificate PEM (URI SAN == signer); the client's
    /// `--client-cert-file` for the binding-match path.
    pub fn client_cert_pem(&self) -> &str {
        &self.client_cert_pem
    }
    /// The POSITIVE client leaf private-key PEM (the client's `--client-key-file`).
    pub fn client_key_pem(&self) -> &str {
        &self.client_key_pem
    }
    /// The MISMATCHED client leaf certificate PEM (URI SAN != signer); drives T3.
    pub fn mismatched_client_cert_pem(&self) -> &str {
        &self.mismatched_client_cert_pem
    }
    /// The MISMATCHED client leaf private-key PEM (T3 partner of
    /// [`Self::mismatched_client_cert_pem`]).
    pub fn mismatched_client_key_pem(&self) -> &str {
        &self.mismatched_client_key_pem
    }
    /// The `trust.json` content for the proxy's `TrustResolver`
    /// (`mcps_proxy_cli --trust`).
    pub fn trust_json(&self) -> &str {
        &self.trust_json
    }
    /// The SERVER signing seed, Base64URL-no-pad — the content of the proxy's
    /// `--signing-key-seed` file (the key the proxy signs responses with).
    pub fn signing_seed_b64url(&self) -> &str {
        &self.signing_seed_b64url
    }
    /// The SIGNER (client/LLM) signing seed, Base64URL-no-pad — the content of the
    /// client bin's `--signing-key-seed-file`.
    pub fn signer_seed_b64url(&self) -> String {
        b64url_encode(&self.spec.signer_seed)
    }
    /// The SERVER public key, Base64URL-no-pad — the client's
    /// `--response-public-key` (its trust anchor for the signed response).
    pub fn server_public_key_b64url(&self) -> String {
        SigningKey::from_seed_bytes(&self.spec.server_seed)
            .public_key()
            .to_b64url()
    }

    /// Materialize the proxy CLI's file inputs into a fresh temp directory and
    /// return their paths (cleaned up when the returned [`DemoFixtureFiles`] is
    /// dropped). The same `DemoFixtures` can also be consumed directly as PEM by
    /// the in-process transport client without ever touching disk.
    pub fn write_files(&self) -> std::io::Result<DemoFixtureFiles> {
        let dir = std::env::temp_dir().join(format!(
            "mcps_demo_fixtures_{}_{}",
            std::process::id(),
            next_counter(),
        ));
        std::fs::create_dir_all(&dir)?;

        let server_cert_path = dir.join("server_cert.pem");
        let server_key_path = dir.join("server_key.pem");
        let server_ca_path = dir.join("server_ca.pem");
        let client_ca_path = dir.join("client_ca.pem");
        let client_cert_path = dir.join("client_cert.pem");
        let client_key_path = dir.join("client_key.pem");
        let mismatched_client_cert_path = dir.join("mismatched_client_cert.pem");
        let mismatched_client_key_path = dir.join("mismatched_client_key.pem");
        let trust_path = dir.join("trust.json");
        let signing_seed_path = dir.join("signing_seed");
        let signer_seed_path = dir.join("signer_seed");

        std::fs::write(&server_cert_path, &self.server_cert_pem)?;
        std::fs::write(&server_key_path, &self.server_key_pem)?;
        std::fs::write(&server_ca_path, &self.server_ca_pem)?;
        std::fs::write(&client_ca_path, &self.client_ca_pem)?;
        std::fs::write(&client_cert_path, &self.client_cert_pem)?;
        std::fs::write(&client_key_path, &self.client_key_pem)?;
        std::fs::write(&mismatched_client_cert_path, &self.mismatched_client_cert_pem)?;
        std::fs::write(&mismatched_client_key_path, &self.mismatched_client_key_pem)?;
        std::fs::write(&trust_path, &self.trust_json)?;
        std::fs::write(&signing_seed_path, &self.signing_seed_b64url)?;
        std::fs::write(&signer_seed_path, self.signer_seed_b64url())?;

        Ok(DemoFixtureFiles {
            dir,
            server_cert_path,
            server_key_path,
            server_ca_path,
            client_ca_path,
            client_cert_path,
            client_key_path,
            mismatched_client_cert_path,
            mismatched_client_key_path,
            trust_path,
            signing_seed_path,
            signer_seed_path,
        })
    }
}

/// A monotonic counter so two `write_files` calls in the same process land in
/// distinct temp directories.
fn next_counter() -> u64 {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The on-disk materialization of [`DemoFixtures`]: PEM/seed/trust files under a
/// private temp directory, whose paths line up with the `mcps_proxy_cli` flags
/// and the `mcps-demo` client bin flags. The directory and all files are removed
/// when this is dropped.
#[derive(Debug)]
pub struct DemoFixtureFiles {
    dir: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    server_ca_path: PathBuf,
    client_ca_path: PathBuf,
    client_cert_path: PathBuf,
    client_key_path: PathBuf,
    mismatched_client_cert_path: PathBuf,
    mismatched_client_key_path: PathBuf,
    trust_path: PathBuf,
    signing_seed_path: PathBuf,
    signer_seed_path: PathBuf,
}

impl DemoFixtureFiles {
    /// The temp directory holding every file (removed on drop).
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }
    /// Server leaf cert path (`mcps_proxy_cli --tls-cert`).
    pub fn server_cert_path(&self) -> &std::path::Path {
        &self.server_cert_path
    }
    /// Server leaf key path (`mcps_proxy_cli --tls-key`).
    pub fn server_key_path(&self) -> &std::path::Path {
        &self.server_key_path
    }
    /// Server CA path (the client bin's `--server-ca-file`).
    pub fn server_ca_path(&self) -> &std::path::Path {
        &self.server_ca_path
    }
    /// Client CA path (`mcps_proxy_cli --client-ca`).
    pub fn client_ca_path(&self) -> &std::path::Path {
        &self.client_ca_path
    }
    /// Positive client leaf cert path (the client bin's `--client-cert-file`).
    pub fn client_cert_path(&self) -> &std::path::Path {
        &self.client_cert_path
    }
    /// Positive client leaf key path (the client bin's `--client-key-file`).
    pub fn client_key_path(&self) -> &std::path::Path {
        &self.client_key_path
    }
    /// Mismatched client leaf cert path (T3 `--client-cert-file`).
    pub fn mismatched_client_cert_path(&self) -> &std::path::Path {
        &self.mismatched_client_cert_path
    }
    /// Mismatched client leaf key path (T3 `--client-key-file`).
    pub fn mismatched_client_key_path(&self) -> &std::path::Path {
        &self.mismatched_client_key_path
    }
    /// trust.json path (`mcps_proxy_cli --trust`).
    pub fn trust_path(&self) -> &std::path::Path {
        &self.trust_path
    }
    /// SERVER signing-seed file path (`mcps_proxy_cli --signing-key-seed`).
    pub fn signing_seed_path(&self) -> &std::path::Path {
        &self.signing_seed_path
    }
    /// SIGNER (client) signing-seed file path (the client bin's
    /// `--signing-key-seed-file`).
    pub fn signer_seed_path(&self) -> &std::path::Path {
        &self.signer_seed_path
    }
}

impl Drop for DemoFixtureFiles {
    fn drop(&mut self) {
        // Best-effort cleanup of the private temp directory and its contents.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
