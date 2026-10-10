// SPDX-License-Identifier: Apache-2.0
//! The file-backed key source: key material read ONCE, from the objects the custody check
//! admitted.
//!
//! One fact: **the private-key bytes this source signs and handshakes with are the bytes of
//! the filesystem objects whose access posture was checked.** It is built from
//! [`CheckedKeyFile`]s — the only way to hold one is to have opened, `fstat`ed and read the
//! file under the key-file access policy — and it keeps no key path, so there is nothing
//! to reopen and no second resolution of a name that could land on a different file
//! (r12 R12-630, R12-634).
//!
//! The seed is parsed at construction, so a malformed seed refuses startup instead of the
//! first signed response. The TLS certificate chain and client-CA anchors are public
//! material outside the key-file custody scope and are still read by path.

use std::fmt;
use std::fs;

use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use super::{certs_from_pem, key_from_pem, signing_key_from_seed_b64url};
use super::{KeyError, KeySource, ResponseSigner};
use crate::capability_materialization::key_file_custody::CheckedKeyFile;

/// Key material loaded from admitted key files, plus the paths of the public TLS material.
///
/// Fields private: the only constructors take [`CheckedKeyFile`]s, so an inhabitant holds
/// key material read from a checked object and never a path to one.
pub struct FileKeySource {
    /// The response-signing key, parsed from the admitted seed. `None` in a TLS-only source,
    /// whose signing key lives in a device.
    signing_key: Option<SigningKey>,
    /// Path to the PEM TLS server certificate chain.
    tls_cert_path: String,
    /// The exported TLS server private key, as read from its admitted file. `None` where
    /// custody keeps the TLS key on a device.
    tls_key: Option<Zeroizing<Vec<u8>>>,
    /// Path to the PEM client-CA trust anchors.
    client_ca_path: String,
}

impl FileKeySource {
    /// A source whose signing key is the admitted seed file.
    ///
    /// MCPS-076: the file holds the raw private seed (Base64URL text). The bytes stay in
    /// `Zeroizing` and are borrowed as `&str` — never copied into an owned `String`, whose
    /// UTF-8 error would drop an unscrubbed copy — and `signing_key_from_seed_b64url` wraps
    /// its own decoded bytes the same way. Only the dalek key (`ZeroizeOnDrop`) outlives
    /// them.
    pub fn from_checked(
        seed: CheckedKeyFile,
        tls_cert_path: &str,
        tls_key: Option<CheckedKeyFile>,
        client_ca_path: &str,
    ) -> Result<Self, KeyError> {
        let bytes = seed.into_bytes();
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| KeyError::Malformed("signing-key seed is not UTF-8".to_string()))?;
        let signing_key = signing_key_from_seed_b64url(text)?;
        let mut source = Self::tls_only(tls_cert_path, tls_key, client_ca_path)?;
        source.signing_key = Some(signing_key);
        Ok(source)
    }

    /// The TLS and client-CA half only, for a source whose SIGNING key lives elsewhere.
    ///
    /// `KmsKeySource` and `Pkcs11KeySource` wrap one of these to serve
    /// `tls_server_cert_chain`, `tls_server_key` and `client_ca_roots`; their own
    /// `ResponseSigner` impls route to the device. A present TLS key is parsed here, so a
    /// malformed one refuses construction.
    pub fn tls_only(
        tls_cert_path: &str,
        tls_key: Option<CheckedKeyFile>,
        client_ca_path: &str,
    ) -> Result<Self, KeyError> {
        let tls_key = tls_key.map(CheckedKeyFile::into_bytes);
        if let Some(pem) = &tls_key {
            key_from_pem(pem)?;
        }
        Ok(FileKeySource {
            signing_key: None,
            tls_cert_path: tls_cert_path.to_string(),
            tls_key,
            client_ca_path: client_ca_path.to_string(),
        })
    }

    /// Whether this source holds an exported TLS server key.
    ///
    /// `pub(crate)` for the two device-backed sources, which wrap one of these and must
    /// refuse to be built over a key-bearing one when their handshake is delegated: a
    /// delegated source that also held the file key would carry a second, exportable TLS
    /// credential beside the custodied one.
    pub(crate) fn holds_tls_key(&self) -> bool {
        self.tls_key.is_some()
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, KeyError> {
        fs::read(path).map_err(|e| KeyError::NotFound(format!("{path}: {e}")))
    }

    /// The loaded Ed25519 signing key. An INHERENT helper, NOT part of the
    /// [`KeySource`]/[`ResponseSigner`] contract — issue #3838 removed key export from the
    /// trait so a non-exporting HSM/KMS backend can satisfy it. This source signs through
    /// it internally.
    fn signing_key(&self) -> Result<&SigningKey, KeyError> {
        self.signing_key.as_ref().ok_or_else(|| {
            KeyError::NotFound("this file source holds TLS material only".to_string())
        })
    }
}

impl fmt::Debug for FileKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileKeySource")
            .field("signing_key", &self.signing_key.is_some())
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key", &self.tls_key.is_some())
            .field("client_ca_path", &self.client_ca_path)
            .finish()
    }
}

/// `FileKeySource` signs internally (issue #3838): it forwards to its loaded
/// [`SigningKey`]'s [`ResponseSigner`] impl, so the seed is never exported across the
/// trait boundary.
impl ResponseSigner for FileKeySource {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        self.signing_key()?.sign_response(preimage)
    }
    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        self.signing_key()?.response_public_key()
    }
}

impl KeySource for FileKeySource {
    fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        certs_from_pem(&self.read(&self.tls_cert_path)?, "tls cert chain")
    }
    fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError> {
        let pem = self.tls_key.as_ref().ok_or_else(|| {
            KeyError::NotFound("no exported TLS server key: custody keeps it on a device".into())
        })?;
        key_from_pem(pem)
    }
    fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        certs_from_pem(&self.read(&self.client_ca_path)?, "client CA")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config_state::KeyFileAccessPolicy;
    use std::os::unix::fs::PermissionsExt;

    /// An admitted key file holding `content`, per-process named.
    fn checked(name: &str, content: &[u8]) -> CheckedKeyFile {
        let path = std::env::temp_dir().join(format!("mcp_re_fks_{}_{name}", std::process::id()));
        std::fs::write(&path, content).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let file = CheckedKeyFile::open(&path.to_string_lossy(), KeyFileAccessPolicy::OwnerOnly)
            .expect("a 0600 file is admitted");
        let _ = std::fs::remove_file(&path);
        file
    }

    fn tls_key_pem() -> String {
        rcgen::KeyPair::generate().expect("keypair").serialize_pem()
    }

    /// The seed is loaded once, from the admitted object: the source signs with the key
    /// that seed names, and the file is gone by the time it is asked — nothing reopens it.
    #[test]
    fn the_signing_key_is_the_admitted_seed() {
        let seed = [7u8; 32];
        let source = FileKeySource::from_checked(
            checked("seed", mcp_re_core::b64url_encode(&seed).as_bytes()),
            "/cert",
            Some(checked("tls", tls_key_pem().as_bytes())),
            "/ca",
        )
        .expect("a well-formed seed and TLS key");
        assert_eq!(
            source
                .signing_key()
                .expect("a signing key")
                .public_key()
                .to_b64url(),
            SigningKey::from_seed_bytes(&seed).public_key().to_b64url()
        );
        source
            .tls_server_key()
            .expect("the admitted TLS key parses");
    }

    /// Parsing happens at construction: a malformed seed or TLS key refuses STARTUP, not
    /// the first signed response or handshake — and the refusal never carries the secret.
    #[test]
    fn malformed_material_refuses_construction_without_leaking_it() {
        let secret = "SUPER_SECRET_SEED_VALUE_THAT_MUST_NOT_BE_LOGGED";
        let err =
            FileKeySource::from_checked(checked("bad_seed", secret.as_bytes()), "/c", None, "/a")
                .expect_err("not a Base64URL seed");
        assert!(matches!(err, KeyError::Malformed(_)), "{err:?}");
        assert!(
            !format!("{err} | {err:?}").contains(secret),
            "the error leaked the seed"
        );

        let err = FileKeySource::tls_only("/c", Some(checked("bad_tls", b"not pem")), "/a")
            .expect_err("not a PEM key");
        assert!(matches!(err, KeyError::Malformed(_)), "{err:?}");
    }

    /// A TLS-only source holds no signing seed: the device holds the signing key, and this
    /// source cannot be asked to sign. Nor does it claim a delegated TLS signer — it is the
    /// exported-key path.
    #[test]
    fn a_tls_only_source_holds_no_signing_seed() {
        let source = FileKeySource::tls_only("/cert", None, "/ca").expect("no key to parse");
        assert!(matches!(source.signing_key(), Err(KeyError::NotFound(_))));
        assert!(source.tls_delegated_signer().is_none());
        assert!(matches!(
            source.tls_server_key(),
            Err(KeyError::NotFound(_))
        ));
    }

    /// The refusal vocabulary separates absent from malformed: an unreadable public-material
    /// path is `NotFound`, never `Malformed`.
    #[test]
    fn the_refusal_vocabulary_separates_absent_from_malformed() {
        let absent = FileKeySource::tls_only("/nonexistent/cert", None, "/nonexistent/ca")
            .expect("no key to parse");
        assert!(matches!(
            absent.tls_server_cert_chain(),
            Err(KeyError::NotFound(_))
        ));
        assert!(matches!(
            absent.client_ca_roots(),
            Err(KeyError::NotFound(_))
        ));
    }
}
