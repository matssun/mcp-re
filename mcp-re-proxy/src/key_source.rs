//! `KeySource` — loads the proxy's key material (MCPS-027, ADR-MCPS-014).
//!
//! A sidecar needs three pieces of material: the Ed25519 **signing key** (for
//! signing responses), the **TLS server certificate chain + private key** (to
//! terminate TLS), and the **client-CA trust anchors** (to verify mTLS client
//! certificates). `FileKeySource` loads them from disk; `EnvKeySource` from
//! environment variables. The PKCS#11 and KMS adapters keep their keys in a device.
//!
//! The Ed25519 signing key is a 32-byte seed encoded Base64URL-no-pad (consistent
//! with the rest of MCP-RE); `mcp-re-core` exposes only seed-based construction. The
//! TLS materials are PEM (parsed with rustls-pki-types' `PemObject`).

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use crate::delegated_tls::RawEd25519TlsSigner;

mod file_key_source;
pub use file_key_source::FileKeySource;

/// Errors loading key material.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// A source (file/env var) was missing or unreadable.
    #[error("key material not found: {0}")]
    NotFound(String),
    /// Material was present but malformed (bad Base64URL seed, wrong length, no
    /// PEM key, ...).
    #[error("key material malformed: {0}")]
    Malformed(String),
}

/// Response-signing DELEGATION seam (issue #3838, ADR-MCPS-014).
///
/// The proxy signs every response on the way back, but it must NEVER require the
/// raw private key in order to do so. A non-exporting HSM/KMS fundamentally cannot
/// hand out its private key; the only operation it offers is "sign these bytes".
/// `ResponseSigner` is exactly that operation, so a non-exporting backend can drive
/// the full proxy response-signing path:
///
///   * [`sign_response`](ResponseSigner::sign_response) takes the canonical
///     response preimage and returns the Base64URL-no-pad Ed25519 signature —
///     identical to what [`SigningKey::sign`] produces — WITHOUT ever exposing the
///     private seed. The seed (or HSM key handle) stays inside the implementation.
///   * [`response_public_key`](ResponseSigner::response_public_key) returns the
///     PUBLIC verification key, which IS exportable even from an HSM (it is what
///     relying parties verify against). It is derived from / paired with the same
///     private key that `sign_response` uses, so a signature produced by
///     `sign_response` always verifies under this key.
///
/// In-memory implementations ([`SigningKey`], [`FileKeySource`], [`EnvKeySource`])
/// satisfy this by holding the key PRIVATE and signing internally; the HSM/KMS
/// follow-up satisfies it by forwarding to the device. Either way the trait does
/// NOT demand export.
///
/// The non-exporting implementations exist: `pkcs11_keysource`, `aws_kms_keysource` and
/// `gcp_kms_keysource` are feature-gated adapters behind this trait, and each also supplies
/// a [`KeySource::tls_delegated_signer`] so the TLS key stays inside the device too. What
/// this trait guarantees is unchanged by that: it demands the signing OPERATION and never
/// the key, so which custody a deployment runs is a selection below this seam.
pub trait ResponseSigner {
    /// Sign the canonical response `preimage`, returning the Base64URL-no-pad
    /// Ed25519 signature. The private key never leaves the implementation.
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError>;
    /// The public verification key paired with the signing key. Exportable even
    /// from a non-exporting HSM/KMS; a signature from [`Self::sign_response`]
    /// verifies under it.
    fn response_public_key(&self) -> Result<VerificationKey, KeyError>;
}

/// A raw in-memory [`SigningKey`] is itself a response signer that never surrenders
/// its seed at the trait boundary: it owns the Ed25519 key and signs internally;
/// the seam never asks it to export the seed. This is what keeps every existing
/// `Proxy::new(signing_key, ...)` call site working after `KeySource` stopped
/// exporting the key.
impl ResponseSigner for SigningKey {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        Ok(self.sign(preimage))
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        Ok(self.public_key())
    }
}

/// Loads the proxy's key material. Each accessor is fallible and never panics.
///
/// Issue #3838: the response-signing key is exposed ONLY through the
/// [`ResponseSigner`] supertrait ([`sign_response`](ResponseSigner::sign_response)
/// / [`response_public_key`](ResponseSigner::response_public_key)) — there is no
/// `signing_key()` export on the trait, so a non-exporting HSM/KMS backend can
/// implement `KeySource` with NO stub methods. The TLS server key
/// ([`tls_server_key`](KeySource::tls_server_key)) serves the exported-key TLS path;
/// a device-held TLS key is served through [`tls_delegated_signer`](KeySource::tls_delegated_signer).
pub trait KeySource: ResponseSigner + Send + Sync {
    /// The TLS server certificate chain (leaf first).
    fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError>;
    /// The TLS server private key. (Export accessor — see the trait note.)
    fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError>;
    /// The client-CA trust anchors used to verify mTLS client certificates.
    fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError>;

    /// Optional DELEGATED TLS handshake signer (issue #58, ADR-MCPS-028 §G).
    ///
    /// When `Some(signer)`, the proxy terminates TLS via the DELEGATED path: the TLS
    /// server private key never leaves the device/KMS — rustls drives the handshake
    /// signature through `signer` (a [`RawEd25519TlsSigner`]) paired with the
    /// (public) [`tls_server_cert_chain`](Self::tls_server_cert_chain), and
    /// [`tls_server_key`](Self::tls_server_key) is NOT consulted. The TLS key is a
    /// SEPARATE credential from the response-signing key, and delegated TLS is
    /// Ed25519-only.
    ///
    /// The DEFAULT is `None` (no delegation): the proxy uses the existing
    /// exported-key TLS path verbatim. `FileKeySource` / `EnvKeySource` keep the
    /// default, so the default build is byte-unchanged. A non-exporting backend
    /// (#59–#61: PKCS#11 / AWS-KMS / GCP-KMS) overrides this to return its TLS
    /// signer.
    fn tls_delegated_signer(&self) -> Option<std::sync::Arc<dyn RawEd25519TlsSigner>> {
        None
    }
}

/// A boxed `dyn KeySource` is itself a [`ResponseSigner`] (issue #3838): it forwards
/// to the contained source, which signs internally. This lets the production wiring
/// hand the proxy a `Box<dyn KeySource>` AS the response signer WITHOUT ever calling
/// an export accessor — the boxed source's `sign_response` is the delegation. (The
/// stdlib does not auto-upcast `Box<dyn KeySource>` to `Box<dyn ResponseSigner>` on
/// stable Rust, so this explicit forward is what bridges the supertrait at the boxed
/// trait object.)
impl ResponseSigner for Box<dyn KeySource + Send + Sync> {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        (**self).sign_response(preimage)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        (**self).response_public_key()
    }
}

/// Decode a Base64URL-no-pad 32-byte Ed25519 seed into a [`SigningKey`].
///
/// `pub(crate)` for one further consumer — `transparency::auditor`, whose statement-issuing
/// key is a seed file too. A second copy would be a second copy of the MCPS-076 hygiene
/// below, the one thing here that must not drift: every OWNED temporary holding the raw
/// seed is [`zeroize::Zeroizing`] and scrubbed on drop, and `from_seed_bytes` only BORROWS
/// it, so the key is built first and those temporaries drop scrubbed afterwards.
pub(crate) fn signing_key_from_seed_b64url(seed_b64url: &str) -> Result<SigningKey, KeyError> {
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        b64url_decode(seed_b64url.trim())
            .map_err(|_| KeyError::Malformed("signing-key seed is not Base64URL".to_string()))?,
    );
    if bytes.len() != 32 {
        return Err(KeyError::Malformed(
            "signing-key seed is not 32 bytes".to_string(),
        ));
    }
    let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_seed_bytes(&seed))
}

/// Parse a PEM certificate chain from bytes.
fn certs_from_pem(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>, KeyError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KeyError::Malformed(format!("{what}: {e}")))?;
    if certs.is_empty() {
        return Err(KeyError::Malformed(format!(
            "{what}: no certificates in PEM"
        )));
    }
    Ok(certs)
}

/// Parse a single PEM private key from bytes.
fn key_from_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>, KeyError> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| KeyError::Malformed(format!("tls key: {e}")))
}

/// Loads key material from environment variables. Each field is the NAME of the
/// env var to read (the signing-key var holds the Base64URL seed; the others hold
/// PEM text).
///
/// MCPS-076 (audit gap G-3): DEV / CI ONLY, and gated behind the NON-DEFAULT
/// `dev_env_key_source` crate feature — this type does NOT exist in a production
/// build. Environment variables are visible to the whole process tree, can leak
/// via crash dumps, `ps e`, `/proc/<pid>/environ`, and container/orchestrator
/// inspection, and are easy to log accidentally. Production deployments must use
/// [`FileKeySource`] (read once, scrubbed), or a future stdin/fd-injection or
/// non-exporting HSM/KMS source. In the dev build the seed value is held in
/// [`zeroize::Zeroizing`], so it is scrubbed from the heap on drop — but the env
/// var itself is deliberately NOT removed and stays readable in
/// `/proc/<pid>/environ` for the process lifetime; see [`EnvKeySource::read`] for
/// why, and why nothing depended on the removal. `KeyError` values carry only the
/// env-var NAME and the parse failure — never the secret bytes — so they are safe
/// to log.
#[cfg(feature = "dev_env_key_source")]
#[derive(Debug, Clone)]
pub struct EnvKeySource {
    /// Env var holding the Base64URL-no-pad Ed25519 signing-key seed.
    pub signing_key_seed_var: String,
    /// Env var holding the PEM TLS server certificate chain.
    pub tls_cert_var: String,
    /// Env var holding the PEM TLS server private key.
    pub tls_key_var: String,
    /// Env var holding the PEM client-CA trust anchors.
    pub client_ca_var: String,
}

#[cfg(feature = "dev_env_key_source")]
impl EnvKeySource {
    /// Read an env var's value, returned in [`zeroize::Zeroizing`] so it is
    /// scrubbed when the caller drops it.
    ///
    /// This does NOT mutate the process environment (issue #25). `std::env::remove_var`
    /// is unsound in a multi-threaded program — the standard library now documents
    /// it as `unsafe` for exactly this reason (a concurrent `getenv`/`setenv` in
    /// another thread is a data race). Child-process secret isolation is NOT this
    /// function's job and never relied on the global removal: the inner server is
    /// launched with [`crate::inner_launch::InnerLaunchConfig`], which by default
    /// inherits NO environment and passes only an explicit allowlist, so a key in
    /// the proxy's own env is never forwarded regardless of whether it is removed
    /// here. (`EnvKeySource` is `dev_env_key_source`-gated — dev/CI only — and a
    /// production deployment uses a file/PKCS#11 source.)
    fn read(&self, var: &str) -> Result<Zeroizing<String>, KeyError> {
        let value = std::env::var(var).map_err(|e| match e {
            std::env::VarError::NotPresent => KeyError::NotFound(format!("env var {var}")),
            std::env::VarError::NotUnicode(_) => KeyError::Malformed(format!("env var {var}")),
        })?;
        Ok(Zeroizing::new(value))
    }

    /// Load the Ed25519 signing key from the seed env var. INHERENT (non-trait)
    /// helper — see [`FileKeySource::signing_key`] for why key export is not on the
    /// [`KeySource`]/[`ResponseSigner`] contract. The env source owns the var, so it
    /// CAN load the key; its [`ResponseSigner`] impl routes through here.
    fn signing_key(&self) -> Result<SigningKey, KeyError> {
        signing_key_from_seed_b64url(&self.read(&self.signing_key_seed_var)?)
    }
}

/// `EnvKeySource` (dev/CI only) signs internally just like [`FileKeySource`]:
/// it loads its seed-backed [`SigningKey`] and forwards to that key's signer, so
/// the seed is never exported across the trait boundary.
#[cfg(feature = "dev_env_key_source")]
impl ResponseSigner for EnvKeySource {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        self.signing_key()?.sign_response(preimage)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        self.signing_key()?.response_public_key()
    }
}

#[cfg(feature = "dev_env_key_source")]
impl KeySource for EnvKeySource {
    fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        certs_from_pem(self.read(&self.tls_cert_var)?.as_bytes(), "tls cert chain")
    }
    fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError> {
        key_from_pem(self.read(&self.tls_key_var)?.as_bytes())
    }
    fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        certs_from_pem(self.read(&self.client_ca_var)?.as_bytes(), "client CA")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A non-exporting source: it signs, and every export accessor REFUSES.
    ///
    /// It is the shape the seam exists for — a device that can sign and cannot hand out a
    /// key — so a test that drives the seam through it proves the seam never took the
    /// export route, rather than proving it happened not to this time.
    struct NonExportingSource {
        key: SigningKey,
        /// How many times an EXPORT was attempted through this source.
        ///
        /// Shared rather than owned, so a battery can still read it after the source has
        /// been boxed as a `dyn KeySource` — which is the whole scenario under test, and
        /// the reason the counter previously could not be asserted at all.
        exports_attempted: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }

    impl NonExportingSource {
        fn new() -> Self {
            NonExportingSource {
                key: SigningKey::from_seed_bytes(&[9u8; 32]),
                exports_attempted: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            }
        }

        fn refuse_export<T>(&self) -> Result<T, KeyError> {
            self.exports_attempted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(KeyError::NotFound(
                "this device does not export key material".to_string(),
            ))
        }
    }

    impl ResponseSigner for NonExportingSource {
        fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
            Ok(self.key.sign(preimage))
        }

        fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
            Ok(self.key.public_key())
        }
    }

    impl KeySource for NonExportingSource {
        fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
            self.refuse_export()
        }

        fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError> {
            self.refuse_export()
        }

        fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
            self.refuse_export()
        }
    }

    // No `unsafe impl Sync` any more: the counter is an `AtomicU32`, so the `Send + Sync`
    // that `KeySource` requires is derived rather than asserted. The previous form needed
    // the escape hatch only because a `Cell` is not `Sync`, and an escape hatch in a test
    // support type is a place where a real concurrency bug could hide.

    /// **The seam's own proposition.** Boxing a source and using it AS the response signer
    /// signs through the source; it does not reach for an exported key.
    ///
    /// This is what lets the composition root hand the proxy a `Box<dyn KeySource>` as its
    /// signer. The counter is the evidence: a forward that quietly went through
    /// `tls_server_key` would show up here even though the signature would still verify.
    #[test]
    fn a_boxed_source_signs_by_delegation_and_never_by_export() {
        let source = NonExportingSource::new();
        let expected = source.key.public_key();
        let exports = std::sync::Arc::clone(&source.exports_attempted);
        let boxed: Box<dyn KeySource + Send + Sync> = Box::new(source);

        let preimage = b"the canonical response preimage";
        let signature = boxed.sign_response(preimage).expect("the device signs");
        let public = boxed
            .response_public_key()
            .expect("the public key is exportable");

        // The signature verifies under the key the same seam advertises — the two
        // accessors are paired, which is what a relying party depends on.
        mcp_re_core::verify_ed25519(preimage, &signature, &public)
            .expect("a delegated signature verifies under the advertised key");
        assert_eq!(public.to_bytes(), expected.to_bytes());

        // THE DISTINGUISHING ASSERTION, and the one this test's own doc comment named
        // while the body never made it. A forward that quietly went through
        // `tls_server_key` would produce a signature that verifies under the advertised
        // key just as well — the two clauses above cannot tell the two implementations
        // apart. The counter can: it is incremented by every export refusal, so zero is
        // the statement that no export was reached for.
        assert_eq!(
            exports.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "signing through the seam must not reach for an exported key"
        );
    }

    /// The counter is load-bearing, so it has to be able to move. A source asked for an
    /// export DOES register one — otherwise the zero above is satisfied by a counter
    /// nothing ever increments, which is the same vacuity one layer along.
    #[test]
    fn an_export_attempt_registers_on_the_counter() {
        let source = NonExportingSource::new();
        let exports = std::sync::Arc::clone(&source.exports_attempted);
        let boxed: Box<dyn KeySource + Send + Sync> = Box::new(source);

        assert!(
            boxed.tls_server_key().is_err(),
            "this device exports nothing"
        );
        assert_eq!(
            exports.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "an export attempt must be observable, or the zero asserted above proves \
             nothing about the delegation path"
        );
    }

    /// A source that says nothing about delegation is on the EXPORTED-key TLS path.
    ///
    /// The default matters more than it looks: if it were `Some`, a source that had not
    /// thought about delegated TLS would claim its key never leaves the device.
    #[test]
    fn the_default_is_no_delegated_tls_signer() {
        assert!(NonExportingSource::new().tls_delegated_signer().is_none());
    }

    /// The seed must be exactly 32 bytes; any other length is refused as malformed.
    #[test]
    fn a_seed_that_is_not_32_bytes_is_malformed() {
        for len in [31usize, 33] {
            let seed = mcp_re_core::b64url_encode(&vec![7u8; len]);
            assert!(matches!(
                signing_key_from_seed_b64url(&seed),
                Err(KeyError::Malformed(_))
            ));
        }
        let ok = signing_key_from_seed_b64url(&mcp_re_core::b64url_encode(&[7u8; 32]))
            .expect("a 32-byte seed");
        assert_eq!(
            ok.public_key().to_b64url(),
            SigningKey::from_seed_bytes(&[7u8; 32])
                .public_key()
                .to_b64url()
        );
    }
}
