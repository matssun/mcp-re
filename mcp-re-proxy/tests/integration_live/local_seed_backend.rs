// SPDX-License-Identifier: Apache-2.0
//! The offline signer for the cloud-KMS lanes' `*_offline_local_seed` cases.
//!
//! A [`KmsEd25519Backend`] over a LOCAL Ed25519 key. It is not a provider adapter: the AWS
//! and GCP adapters' own wire, parsing and verify-before-return controls run in the crate
//! (`aws_kms_keysource::tests`, `gcp_kms_keysource::tests`) over their fake transports.
//! What these lanes measure offline is the KMS-root to serving/flip wiring above
//! [`KmsResponseSigner`], which sees only the [`KmsEd25519Backend`] trait.
#![cfg(any(feature = "aws_kms_keysource", feature = "gcp_kms_keysource"))]

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_proxy::kms_keysource::Ed25519SpkiDer;
use mcp_re_proxy::kms_keysource::RawEd25519Message;
use mcp_re_proxy::kms_keysource::RawEd25519Signature;
use mcp_re_proxy::KeyError;
use mcp_re_proxy::KmsEd25519Backend;
use mcp_re_proxy::KmsResponseSigner;

/// The fixed 12-byte RFC 8410 Ed25519 `SubjectPublicKeyInfo` prefix.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

struct LocalSeedBackend {
    key: SigningKey,
}

impl KmsEd25519Backend for LocalSeedBackend {
    fn sign_raw_ed25519(
        &self,
        message: RawEd25519Message<'_>,
    ) -> Result<RawEd25519Signature, KeyError> {
        let raw = b64url_decode(&self.key.sign(message.bytes()))
            .map_err(|e| KeyError::Malformed(format!("local seed: signature encoding: {e}")))?;
        RawEd25519Signature::interpret(&raw, "local-seed")
    }

    fn public_key_spki_der(&self) -> Result<Ed25519SpkiDer, KeyError> {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&self.key.public_key().to_bytes());
        Ed25519SpkiDer::interpret(&der)
    }
}

/// A response signer whose KMS custody is a local key derived from `[7; 32]`.
pub(crate) fn offline_signer() -> KmsResponseSigner {
    KmsResponseSigner::new(Box::new(LocalSeedBackend {
        key: SigningKey::from_seed_bytes(&[7u8; 32]),
    }))
}

#[cfg(test)]
mod tests {
    use mcp_re_proxy::ResponseSigner;

    use super::*;

    /// The offline signer is a working response signer: what it signs verifies under the
    /// key it advertises, so the lanes built on it measure the wiring and not the double.
    #[test]
    fn the_offline_signer_signs_under_its_advertised_key() {
        let signer = offline_signer();
        let preimage = b"offline preimage";
        let signature = signer.sign_response(preimage).expect("sign");
        let key = signer.response_public_key().expect("advertised key");
        mcp_re_core::verify_ed25519(preimage, &signature, &key).expect("verifies");
    }
}
