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
//!   * the `mcp_re_proxy_cli` flags — `--tls-cert` / `--tls-key` (server leaf),
//!     `--client-ca` (client CA), `--trust` (trust.json), `--signing-key-seed`
//!     (the SERVER signing seed the proxy signs responses with),
//!     `--audience` / `--server-signer` ([`Self::audience`] / [`Self::server_signer`]);
//!   * the `mcp-re-transport` client config — `ClientTlsConfig::from_pem` takes the
//!     client cert PEM + client key PEM + server-CA PEM, and the expected server
//!     name is [`Self::server_name`]; the client's signing seed is the SIGNER
//!     seed and the response public key is [`Self::server_public_key_b64url`].
//!
//! Boundary (LOCKED): this is test/demo SUPPORT only. It produces material and
//! NOTHING else — no signing, policy, or transport logic. It reuses the proven
//! `rcgen` idiom from `mcp-re-proxy/tests`; `rcgen` is a NORMAL dependency of this
//! demo crate (the demo bin generates certs at runtime for `bazel run`), kept OUT
//! of `mcp-re-core` / `mcp-re-host`, which stay pure / transport-free.

use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;

/// Validity (window duration) of the short-lived client leaf, in seconds. Kept
/// safely under the proxy's strict `--max-client-cert-lifetime` ceiling of 3600s
/// with margin, while long enough to run a validation pass.
const SHORT_LIVED_CLIENT_CERT_SECS: i64 = 3000;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;

use serde_json::json;
use time::OffsetDateTime;

/// The deterministic identities + seeds the demo material is minted around. The
/// defaults match the rest of the demo (`did:example:*`), but every field is
/// explicit so a caller can mint a fresh, isolated set.
#[derive(Debug, Clone)]
pub struct DemoFixtureSpec {
    /// The request signer identity (the LLM caller) — the `signer` in `trust.json`, and
    /// the SUBJECT the proxy resolves for it. The `exact` binding relates the
    /// authenticated peer to this subject (ADR-MCPRE-064 Slice 4), so the positive client
    /// leaf carries it as its URI SAN.
    pub signer: String,
    /// The signer's key id (the key id in `trust.json`).
    pub signer_key_id: String,
    /// The trust domain the proxy resolves the request actor under (its
    /// `--trust-domain`). Request-side resolution CONTEXT, and deliberately NOT part of
    /// the transport binding: the channel established no corresponding fact.
    pub trust_domain: String,
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
            trust_domain: "example.com".to_string(),
            mismatched_identity: "spiffe://example.org/agent-2".to_string(),
        }
    }
}

impl DemoFixtureSpec {
    /// The SUBJECT the proxy's trust resolver resolves for this signer — and the URI SAN
    /// the positive client leaves carry.
    ///
    /// **This deliberately is not the composite actor id.** `ActorIdentity::actor_id()` is
    /// the injective `role:trust_domain:subject:keyid` join used for replay keys, audit
    /// records and trusted-key identity. These fixtures once minted THAT into the client
    /// certificate SAN, because the transport binding compared against it — the fixtures
    /// conformed to the defect, and the tests went green.
    ///
    /// Slice 4 corrected the relation to the subject, removing two couplings: a
    /// certificate no longer has to be reissued when the signing key rotates, nor name a
    /// trust domain the channel never established.
    pub fn subject(&self) -> String {
        self.signer.clone()
    }
}

/// A minted certificate authority (self-signed root) and its key.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    /// Retained so an `Issuer` can be borrowed per signature: rcgen derives the
    /// issuer DN, key-identifier method and key usages from these, not from `cert`.
    params: CertificateParams,
}

impl Ca {
    /// The issuing state that minted `cert`, paired with the signing key.
    fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
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
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("ca self-signed");
    Ca { cert, key, params }
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
    make_leaf_windowed(
        ca,
        sans,
        common_name,
        client_auth,
        rcgen::date_time_ymd(2020, 1, 1),
        rcgen::date_time_ymd(2035, 1, 1),
    )
}

/// A leaf signed by `ca` with an EXPLICIT validity window — used to mint a
/// SHORT-LIVED client cert (lifetime ≤ the proxy's strict 3600s ceiling) that a
/// `--strict` fleet accepts, unlike the ≈15y [`make_leaf`] default.
fn make_leaf_windowed(
    ca: &Ca,
    sans: Vec<SanType>,
    common_name: Option<&str>,
    client_auth: bool,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    params.not_before = not_before;
    params.not_after = not_after;
    params.extended_key_usages = vec![if client_auth {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    // Emit the Authority Key Identifier (referencing the issuing CA's SubjectKeyId)
    // so OpenSSL-based clients (the Python/Node SDKs) can build the chain; rustls
    // does not require it, which is why the Rust tiers passed without it.
    params.use_authority_key_identifier_extension = true;
    let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
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
/// Consistency guarantees (proven by `tests/demo_fixtures_test.rs`, an integration test;
/// `generate` refuses a spec that breaks the last one):
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
    // A SHORT-LIVED (≤ strict 3600s ceiling) client leaf with the SAME URI-SAN
    // identity, chaining to the SAME client CA — so a `--strict` fleet (which
    // refuses long-lived certs) can be driven live. Minted `now`-relative, so it
    // expires ~50min after `generate()`; regenerate before a strict validation run.
    short_lived_client_cert_pem: String,
    short_lived_client_key_pem: String,
    mismatched_client_cert_pem: String,
    mismatched_client_key_pem: String,

    trust_json: String,
    signing_seed_b64url: String,
}

impl DemoFixtures {
    /// Mint the full material set from `spec`. Pure in-memory generation (no I/O);
    /// use [`Self::write_files`] to materialize the proxy CLI's file inputs.
    pub fn generate(spec: DemoFixtureSpec) -> Self {
        assert!(
            spec.mismatched_identity != spec.subject() && spec.signer_seed != spec.server_seed,
            "the T3 mismatched identity must differ from the signer subject and the signer and server seeds must differ"
        );
        let server_ca = make_ca("mcp-re-demo-server-ca");
        let (server_leaf, server_leaf_key) = make_leaf(
            &server_ca,
            vec![dns(&spec.server_name)],
            Some(&spec.server_name),
            false,
        );

        let client_ca = make_ca("mcp-re-demo-client-ca");
        // The positive leaves carry the bare subject, which is what the `exact` binding compares.
        let client_subject = spec.subject();
        let (client_leaf, client_leaf_key) =
            make_leaf(&client_ca, vec![uri(&client_subject)], None, true);
        // A short-lived (< strict 3600s ceiling) client leaf, same identity + CA,
        // valid from ~1min ago to +50min so it is currently valid AND its lifetime
        // (window duration) is ≤ 3600s. `now`-relative — expires ~50min out.
        let now = OffsetDateTime::now_utc();
        let (short_client_leaf, short_client_leaf_key) = make_leaf_windowed(
            &client_ca,
            vec![uri(&client_subject)],
            None,
            true,
            now.checked_sub(time::Duration::seconds(60))
                .expect("not_before in range"),
            now.checked_add(time::Duration::seconds(SHORT_LIVED_CLIENT_CERT_SECS))
                .expect("not_after in range"),
        );
        let (mismatched_leaf, mismatched_leaf_key) =
            make_leaf(&client_ca, vec![uri(&spec.mismatched_identity)], None, true);

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
            short_lived_client_cert_pem: short_client_leaf.pem(),
            short_lived_client_key_pem: short_client_leaf_key.serialize_pem(),
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

    /// The audience the request is signed for (`mcp_re_proxy_cli --audience`).
    pub fn audience(&self) -> &str {
        &self.spec.audience
    }
    /// The server (proxy) signer identity (`mcp_re_proxy_cli --server-signer`; the
    /// client's response-signer trust anchor).
    pub fn server_signer(&self) -> &str {
        &self.spec.server_signer
    }
    /// The server signer's key id (`--server-key-id`; the client's response key id).
    pub fn server_key_id(&self) -> &str {
        &self.spec.server_key_id
    }
    /// The request signer identity (the LLM caller; the `signer` in `trust.json`).
    pub fn signer(&self) -> &str {
        &self.spec.signer
    }
    /// The trust domain the proxy resolves the request actor under (`--trust-domain`).
    pub fn trust_domain(&self) -> &str {
        &self.spec.trust_domain
    }
    /// The bare subject the positive/short-lived client URI SAN carries and the
    /// `exact` binding compares, see [`DemoFixtureSpec::subject`].
    pub fn subject(&self) -> String {
        self.spec.subject()
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
    /// The server leaf certificate PEM (`mcp_re_proxy_cli --tls-cert`).
    pub fn server_cert_pem(&self) -> &str {
        &self.server_cert_pem
    }
    /// The server leaf private-key PEM (`mcp_re_proxy_cli --tls-key`).
    pub fn server_key_pem(&self) -> &str {
        &self.server_key_pem
    }
    /// The client CA certificate PEM — the root the proxy requires inbound client
    /// certs to chain to (`mcp_re_proxy_cli --client-ca`).
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
    /// A SHORT-LIVED client leaf certificate PEM (URI SAN == signer, lifetime ≤ the
    /// strict 3600s ceiling), chaining to the same client CA — for driving a
    /// `--strict` fleet, which refuses the ≈15y [`Self::client_cert_pem`]. Minted
    /// `now`-relative in [`Self::generate`]; expires ~50min out, so regenerate
    /// before a strict validation run.
    pub fn short_lived_client_cert_pem(&self) -> &str {
        &self.short_lived_client_cert_pem
    }
    /// The private-key PEM partner of [`Self::short_lived_client_cert_pem`].
    pub fn short_lived_client_key_pem(&self) -> &str {
        &self.short_lived_client_key_pem
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
    /// (`mcp_re_proxy_cli --trust`).
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "must differ")]
    fn generate_refuses_a_mismatched_identity_equal_to_the_subject() {
        DemoFixtures::generate(DemoFixtureSpec {
            mismatched_identity: DemoFixtureSpec::default().signer,
            ..DemoFixtureSpec::default()
        });
    }

    #[test]
    #[should_panic(expected = "must differ")]
    fn generate_refuses_equal_signer_and_server_seeds() {
        DemoFixtures::generate(DemoFixtureSpec {
            server_seed: [1u8; 32],
            ..DemoFixtureSpec::default()
        });
    }
}
