// SPDX-License-Identifier: Apache-2.0
//! The public key a credential presents — one of the two inputs to correspondence.
//!
//! A credential here is the certificate chain a party serves. This authority establishes
//! what public key its leaf presents, and that the key is of the required profile. It
//! establishes nothing else: not that the chain is trusted, not that it is valid now, not
//! that it is unrevoked, not that the party holds the private half.
//!
//! The input is [`CertificateChainEvidence`] — the same evidence product the identity
//! authority consumes. Two authorities reading one evidence class is the composition the
//! architecture is for; what must not happen is either of them reconstructing the other's
//! fact from the representation.

use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

use super::certificate_chain_evidence::CertificateChainEvidence;
use super::ed25519_public_key::Ed25519PublicKeyValue;
use super::ed25519_public_key::Rfc8410SpkiRefusal;

/// Why no credential public key could be established.
///
/// Absence, unreadability of the credential, and unreadability or wrong profile of the KEY
/// are four different operator problems: nothing was configured, the file is corrupt, the
/// certificate is corrupt, or the certificate holds a key of the wrong type. The
/// implementation this replaces reported all four as one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKeyRefusal {
    /// No credential was presented at all.
    Absent,
    /// A credential was presented and could not be interpreted as a certificate.
    UninterpretableCredential,
    /// The certificate was read; its public key is not a canonical Ed25519 key.
    Key(Rfc8410SpkiRefusal),
}

/// The public key a credential presents, of the required profile.
///
/// Sealed: the key and the fact that it came from a credential are set together, by the
/// adapter, and a caller cannot pair one party's key with another party's provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialPublicKeyEvidence {
    key: Ed25519PublicKeyValue,
}

impl CredentialPublicKeyEvidence {
    /// The public key the credential presents.
    pub fn key(&self) -> Ed25519PublicKeyValue {
        self.key
    }
}

impl<'a> CertificateChainEvidence<'a> {
    /// Interpret the public key this credential's leaf presents.
    ///
    /// The mechanism adapter for the credential side: it is the only code here that knows
    /// certificates are DER, and the profile rule it applies is the one owned by
    /// [`Ed25519PublicKeyValue`], not a second copy of it.
    pub fn interpret_credential_public_key(
        self,
    ) -> Result<CredentialPublicKeyEvidence, CredentialKeyRefusal> {
        let leaf_der = self.leaf_der().ok_or(CredentialKeyRefusal::Absent)?;
        let (_, certificate) = X509Certificate::from_der(leaf_der)
            .map_err(|_| CredentialKeyRefusal::UninterpretableCredential)?;
        // The SPKI bytes verbatim from the parsed certificate — never re-encoded, because
        // re-encoding would make this code a second opinion on what the credential says.
        let key = Ed25519PublicKeyValue::interpret_rfc8410_spki(certificate.public_key().raw)
            .map_err(CredentialKeyRefusal::Key)?;
        Ok(CredentialPublicKeyEvidence { key })
    }
}

#[cfg(test)]
mod tests {
    use super::CertificateChainEvidence;
    use super::CredentialKeyRefusal;
    use super::Rfc8410SpkiRefusal;

    #[test]
    fn no_credential_is_absence_not_an_unreadable_one() {
        assert_eq!(
            CertificateChainEvidence::absent().interpret_credential_public_key(),
            Err(CredentialKeyRefusal::Absent)
        );
    }

    #[test]
    fn an_unreadable_credential_is_not_reported_as_a_key_problem() {
        let garbage = [0x30u8, 0x82, 0xff, 0xff, 0x00];
        assert_eq!(
            CertificateChainEvidence::from_leaf_der(&garbage).interpret_credential_public_key(),
            Err(CredentialKeyRefusal::UninterpretableCredential),
            "a corrupt certificate and a certificate holding a corrupt key send an operator \
             to different places"
        );
        assert_ne!(
            CertificateChainEvidence::from_leaf_der(&garbage).interpret_credential_public_key(),
            Err(CredentialKeyRefusal::Key(
                Rfc8410SpkiRefusal::Uninterpretable
            ))
        );
    }
}
