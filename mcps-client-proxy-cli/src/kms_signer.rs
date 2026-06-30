//! Client-side GCP Cloud KMS object signer (ADR-MCPS-045 Phase 4 / Tier T4;
//! ADR-MCPS-028 §C key custody).
//!
//! This is the MODE-SPECIFIC adapter the pure `mcps-client-core` deliberately
//! leaves to its consumers: it binds the version-neutral [`ClientSigner`] trait to
//! a non-exporting Cloud KMS key. The Ed25519 private key lives in GCP Cloud KMS
//! (`EC_SIGN_ED25519`) and is NEVER exported — every signature is produced by the
//! cloud `asymmetricSign` op and (in the reused backend) re-verified locally
//! against the advertised public key before it is returned.
//!
//! It reuses the live-tested backend from `mcps-proxy`
//! (`GcpKmsEd25519Backend`, implementing the SDK-free [`KmsEd25519Backend`] seam)
//! rather than re-deriving the REST/`ureq` signing path. The only new logic here
//! is the thin trait bridge and the `KeyError → McpsError` mapping (a delegated
//! signer that cannot sign fails closed; it never returns a placeholder).
//!
//! Custody is reported as [`CustodyClass::NonExporting`], so this signer is the
//! only class that satisfies the hardening profile
//! (`SignerPolicy::require_non_exporting`) — exactly T4's "key custody in cloud
//! KMS" property.

use mcps_client_core::ClientSigner;
use mcps_client_core::CustodyClass;
use mcps_core::b64url_encode;
use mcps_core::McpsError;
use mcps_proxy::kms_keysource::KmsEd25519Backend;
use mcps_proxy::GcpKmsConfig;
use mcps_proxy::GcpKmsEd25519Backend;

/// A [`ClientSigner`] whose private key is held in GCP Cloud KMS (non-exporting).
pub struct KmsClientSigner {
    backend: GcpKmsEd25519Backend,
    signer_id: String,
    key_id: String,
}

impl KmsClientSigner {
    /// Build a production Cloud KMS client signer over the given key version.
    ///
    /// `use_metadata_server` selects the GCE/GKE workload-identity token source;
    /// otherwise an operator-supplied `MCPS_GCP_ACCESS_TOKEN` is used. Construction
    /// fetches and validates the public key once (Ed25519 SPKI + `EC_SIGN_ED25519`
    /// algorithm), failing closed on any non-Ed25519 key — so a misconfigured key
    /// version is rejected here, before a single request is signed.
    pub fn new(
        config: &GcpKmsConfig,
        use_metadata_server: bool,
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Result<Self, String> {
        let backend = GcpKmsEd25519Backend::new(config, use_metadata_server)
            .map_err(|e| format!("gcp-kms client signer: {e}"))?;
        Ok(KmsClientSigner {
            backend,
            signer_id: signer_id.into(),
            key_id: key_id.into(),
        })
    }

    /// TEST-ONLY: build over an in-memory FAKE Cloud KMS transport backed by the
    /// local Ed25519 key with the given 32-byte seed — no network, no credentials.
    /// Used to prove the trait bridge end-to-end (a KMS-signed preimage verifies
    /// under the unmodified `mcps-core` verifier) offline.
    #[cfg(test)]
    fn for_test_with_local_seed(
        seed: &[u8; 32],
        signer_id: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        let backend = GcpKmsEd25519Backend::for_test_with_local_seed(seed)
            .expect("fake KMS backend builds");
        KmsClientSigner {
            backend,
            signer_id: signer_id.into(),
            key_id: key_id.into(),
        }
    }
}

impl ClientSigner for KmsClientSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn custody(&self) -> CustodyClass {
        // The private key never leaves Cloud KMS — the only class the hardening
        // profile admits.
        CustodyClass::NonExporting
    }

    fn sign_preimage(&self, preimage: &[u8]) -> Result<String, McpsError> {
        // The backend returns the raw 64-byte Ed25519 signature (already
        // verify-before-return); the envelope wants Base64URL-no-pad. A KMS that
        // cannot sign (token expired, network down, key disabled) fails closed —
        // there is no usable signing binding — never a placeholder signature.
        self.backend
            .sign_raw_ed25519(preimage)
            .map(|raw| b64url_encode(&raw))
            .map_err(|_| McpsError::ActorBindingFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcps_core::verify_ed25519;
    use mcps_core::VerificationKey;

    const SEED: [u8; 32] = [7u8; 32];
    const SIGNER: &str = "did:example:kms-client";
    const KEY_ID: &str = "kms-client-key-1";

    #[test]
    fn reports_non_exporting_custody_and_identity() {
        let s = KmsClientSigner::for_test_with_local_seed(&SEED, SIGNER, KEY_ID);
        assert_eq!(s.signer_id(), SIGNER);
        assert_eq!(s.key_id(), KEY_ID);
        assert_eq!(s.custody(), CustodyClass::NonExporting);
    }

    #[test]
    fn kms_signed_preimage_verifies_under_mcps_core() {
        // The whole point: a signature produced through the KMS client-signer
        // bridge verifies under the unmodified mcps-core Ed25519 verifier, with no
        // network. (Mirrors the server-side kms_signature_verifies_under_mcps_core
        // proof, now on the client seam.)
        let s = KmsClientSigner::for_test_with_local_seed(&SEED, SIGNER, KEY_ID);
        let preimage = b"the canonical draft-02 request preimage";
        let sig_b64url = s.sign_preimage(preimage).expect("kms sign");
        let pubkey = VerificationKey::from_bytes(
            &mcps_core::SigningKey::from_seed_bytes(&SEED).public_key().to_bytes(),
        )
        .expect("verify key");
        assert!(
            verify_ed25519(preimage, &sig_b64url, &pubkey).is_ok(),
            "a KMS-bridge signature must verify under mcps-core"
        );
    }

    #[test]
    fn passes_the_non_exporting_hardening_profile() {
        use mcps_client_core::authorize_signer;
        use mcps_client_core::Environment;
        use mcps_client_core::SignerPolicy;
        let s = KmsClientSigner::for_test_with_local_seed(&SEED, SIGNER, KEY_ID);
        let policy =
            SignerPolicy::new(SIGNER, Environment::Production, true).require_non_exporting();
        assert!(
            authorize_signer(&policy, &s).is_ok(),
            "a Cloud KMS signer must satisfy the hardening (non-exporting) profile"
        );
    }
}
