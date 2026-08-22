// SPDX-License-Identifier: Apache-2.0
//! The public key a signer claims — the other input to correspondence.
//!
//! A signing key's public half is exportable even from a device or KMS that will never
//! release the private half, and that export is what this authority interprets. It
//! establishes what key the signer claims and that the key is of the required profile. It
//! establishes nothing about whether the signer can actually sign, is reachable, is
//! authorized, or is the same party as any credential.
//!
//! The export can FAIL — a device that is unreachable, a KMS call that is refused, a signer
//! that has no exportable key at all — and that failure is evidence, not a missing
//! argument. [`SigningKeyExportEvidence::unavailable`] gives it an inhabitant, so the
//! authority reports it rather than the caller having to.

use super::ed25519_public_key::Ed25519PublicKeyValue;
use super::ed25519_public_key::Rfc8410SpkiRefusal;

/// What a signer yielded when asked for its public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningKeyExportEvidence<'a> {
    exported_spki_der: Option<&'a [u8]>,
}

impl<'a> SigningKeyExportEvidence<'a> {
    /// The signer exported these `SubjectPublicKeyInfo` bytes.
    pub fn exported(spki_der: &'a [u8]) -> Self {
        SigningKeyExportEvidence {
            exported_spki_der: Some(spki_der),
        }
    }

    /// The signer yielded no public key.
    ///
    /// The reason is deliberately not carried: it belongs to the signer's own error
    /// vocabulary, and nothing in this authority may branch on it. What matters here is
    /// that there is no key to compare, which is a different fact from having one that is
    /// unusable.
    pub fn unavailable() -> Self {
        SigningKeyExportEvidence {
            exported_spki_der: None,
        }
    }

    /// Interpret the exported key.
    pub fn interpret_signing_key(
        self,
    ) -> Result<CryptographicSigningKeyEvidence, SigningKeyRefusal> {
        let spki_der = self
            .exported_spki_der
            .ok_or(SigningKeyRefusal::Unavailable)?;
        let key = Ed25519PublicKeyValue::interpret_rfc8410_spki(spki_der)
            .map_err(SigningKeyRefusal::Key)?;
        Ok(CryptographicSigningKeyEvidence { key })
    }
}

/// Why no signing key could be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningKeyRefusal {
    /// The signer yielded no public key.
    Unavailable,
    /// The signer yielded bytes that are not a canonical Ed25519 key.
    Key(Rfc8410SpkiRefusal),
}

/// The public key a signer claims, of the required profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptographicSigningKeyEvidence {
    key: Ed25519PublicKeyValue,
}

impl CryptographicSigningKeyEvidence {
    /// The public key the signer claims.
    pub fn key(&self) -> Ed25519PublicKeyValue {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::Rfc8410SpkiRefusal;
    use super::SigningKeyExportEvidence;
    use super::SigningKeyRefusal;

    #[test]
    fn a_signer_that_exported_nothing_is_not_a_signer_that_exported_rubbish() {
        assert_eq!(
            SigningKeyExportEvidence::unavailable().interpret_signing_key(),
            Err(SigningKeyRefusal::Unavailable)
        );
        assert_ne!(
            SigningKeyExportEvidence::unavailable().interpret_signing_key(),
            Err(SigningKeyRefusal::Key(Rfc8410SpkiRefusal::Uninterpretable)),
            "an unreachable signer and a misconfigured one are different incidents"
        );
    }

    #[test]
    fn an_exported_key_of_another_algorithm_is_refused_on_the_profile_rule() {
        let mut p256 = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        p256.extend_from_slice(&[0x11u8; 64]);
        assert_eq!(
            SigningKeyExportEvidence::exported(&p256).interpret_signing_key(),
            Err(SigningKeyRefusal::Key(
                Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                    oid: "1.2.840.10045.2.1".to_string()
                }
            ))
        );
    }
}
