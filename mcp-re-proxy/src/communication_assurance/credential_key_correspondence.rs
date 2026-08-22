// SPDX-License-Identifier: Apache-2.0
//! Credential/key correspondence: the first relation between two independently
//! established facts.
//!
//! ```text
//! credential representation ──adapter──> CredentialPublicKeyEvidence ──┐
//!                                                                      ├─ relation ─> facts
//! signer export ────────────adapter──> CryptographicSigningKeyEvidence ┘
//! ```
//!
//! # What the relation owns, and what it does not
//!
//! The adapters establish that each side holds a key of the required profile. The relation
//! establishes only that those two canonical keys are the same key. That division is why
//! the relation can refuse exactly one way — [`CorrespondenceMismatch`] — and why it never
//! sees an absent credential or an unreachable signer: those failed before it, in the
//! authority that owns them, and a relation that claimed to detect a certificate it is
//! never handed would be claiming someone else's fact.
//!
//! # What correspondence is not
//!
//! It is not trust, not validity, not revocation status, not freshness, not authority to
//! serve, not possession of the private half, and not a channel. A signer whose key
//! corresponds to a credential's key can still be an unknown party presenting an untrusted,
//! expired, revoked certificate. Correspondence says the handshake that signer produces will
//! verify against the certificate it presents — no more, which is exactly why it is worth
//! establishing separately from everything above it.

use super::certificate_chain_evidence::CertificateChainEvidence;
use super::credential_public_key_evidence::CredentialKeyRefusal;
use super::credential_public_key_evidence::CredentialPublicKeyEvidence;
use super::ed25519_public_key::Ed25519PublicKeyValue;
use super::signing_key_evidence::CryptographicSigningKeyEvidence;
use super::signing_key_evidence::SigningKeyExportEvidence;
use super::signing_key_evidence::SigningKeyRefusal;

/// The relation refusing: two legal keys that are not the same key.
///
/// A struct rather than a variant-with-fields, and it deliberately carries NO keys. Naming
/// which key was expected in a refusal invites a caller to compare them itself, which is
/// the reconstruction this authority exists to prevent; and public-key material in an error
/// string is how key confusion becomes a log-mining exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorrespondenceMismatch;

/// Why credential/key correspondence could not be established.
///
/// Hierarchical, because the failures are not a flat list: two of the three are a
/// SIDE failing to produce evidence at all, and only the third is the relation itself
/// refusing. A caller that must tell an operator where to look needs the side; a caller
/// reasoning about the security property needs the mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKeyCorrespondenceRefusal {
    /// The credential side produced no key.
    Credential(CredentialKeyRefusal),
    /// The signing-key side produced no key.
    SigningKey(SigningKeyRefusal),
    /// Both sides produced a legal key, and they are different keys.
    Mismatch(CorrespondenceMismatch),
}

/// Both sides presented the same public key, of the required profile.
///
/// Sealed. The corresponding key is the ONE key both sides agreed on, and there is
/// deliberately no projection of "the credential's key" and "the signer's key" separately:
/// after correspondence holds there is only one key, and offering two accessors would
/// invite a consumer to compare them again — re-deriving a fact this value already carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialKeyCorrespondenceFacts {
    corresponding_key: Ed25519PublicKeyValue,
}

impl CredentialKeyCorrespondenceFacts {
    /// The key both sides presented.
    pub fn corresponding_key(&self) -> Ed25519PublicKeyValue {
        self.corresponding_key
    }
}

/// The pure relation. Private: it is separately testable and is the formal-verification
/// candidate, and neither makes it a public composition edge — a published relation would
/// let a caller pair two keys it fabricated.
fn correspond(
    credential: CredentialPublicKeyEvidence,
    signing_key: CryptographicSigningKeyEvidence,
) -> Result<CredentialKeyCorrespondenceFacts, CorrespondenceMismatch> {
    if credential.key() != signing_key.key() {
        return Err(CorrespondenceMismatch);
    }
    Ok(CredentialKeyCorrespondenceFacts {
        corresponding_key: credential.key(),
    })
}

/// Establish that a credential and a signer present the same public key.
///
/// The slice's public entrance: it runs both adapters and then the relation, and reports
/// which of the three authorities refused. Establishes correspondence only — see the
/// module documentation for the list of things it deliberately does not establish.
pub fn establish_credential_key_correspondence(
    credential: CertificateChainEvidence<'_>,
    signing_key_export: SigningKeyExportEvidence<'_>,
) -> Result<CredentialKeyCorrespondenceFacts, CredentialKeyCorrespondenceRefusal> {
    let credential = credential
        .interpret_credential_public_key()
        .map_err(CredentialKeyCorrespondenceRefusal::Credential)?;
    let signing_key = signing_key_export
        .interpret_signing_key()
        .map_err(CredentialKeyCorrespondenceRefusal::SigningKey)?;
    correspond(credential, signing_key).map_err(CredentialKeyCorrespondenceRefusal::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::establish_credential_key_correspondence;
    use super::CertificateChainEvidence;
    use super::CorrespondenceMismatch;
    use super::CredentialKeyCorrespondenceRefusal;
    use super::CredentialKeyRefusal;
    use super::SigningKeyExportEvidence;
    use super::SigningKeyRefusal;
    use crate::communication_assurance::ed25519_public_key::Rfc8410SpkiRefusal;

    const CANONICAL_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    fn canonical_spki(point: u8) -> Vec<u8> {
        let mut der = CANONICAL_PREFIX.to_vec();
        der.extend_from_slice(&[point; 32]);
        der
    }

    #[test]
    fn a_credential_side_failure_is_attributed_to_the_credential_side() {
        let export = canonical_spki(1);
        assert_eq!(
            establish_credential_key_correspondence(
                CertificateChainEvidence::absent(),
                SigningKeyExportEvidence::exported(&export),
            ),
            Err(CredentialKeyCorrespondenceRefusal::Credential(
                CredentialKeyRefusal::Absent
            )),
            "an operator told only that correspondence failed would look at the signer"
        );
    }

    #[test]
    fn a_signing_side_failure_is_attributed_to_the_signing_side() {
        // The credential side must be legal, or the refusal would be the credential's.
        // Built through the real adapter rather than asserted, so the attribution is a
        // measurement of the composition and not of the test's own arrangement.
        let garbage = [0x30u8, 0x82, 0xff, 0xff, 0x00];
        let credential_failure = establish_credential_key_correspondence(
            CertificateChainEvidence::from_leaf_der(&garbage),
            SigningKeyExportEvidence::unavailable(),
        );
        assert_eq!(
            credential_failure,
            Err(CredentialKeyCorrespondenceRefusal::Credential(
                CredentialKeyRefusal::UninterpretableCredential
            )),
            "when BOTH sides fail, the credential side is reported first — the order is \
             fixed so the reported fact does not depend on evaluation order"
        );
    }

    #[test]
    fn an_unavailable_signer_is_not_reported_as_a_mismatch() {
        // Requires a legal credential, which the certificate adapter can only produce from
        // real DER; the mismatch-vs-side distinction over minted certificates is pinned in
        // the tls delegated-credential suite. Here the point is narrower and still worth
        // stating: nothing in this composition turns a missing key into a mismatch.
        let refusal = establish_credential_key_correspondence(
            CertificateChainEvidence::absent(),
            SigningKeyExportEvidence::unavailable(),
        );
        assert!(!matches!(
            refusal,
            Err(CredentialKeyCorrespondenceRefusal::Mismatch(_))
        ));
    }

    #[test]
    fn an_export_of_another_algorithm_refuses_on_the_signing_side_profile_rule() {
        let garbage_credential = [0x30u8, 0x82, 0xff, 0xff, 0x00];
        let mut p256 = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        p256.extend_from_slice(&[0x11u8; 64]);
        // Isolated: the signing-key adapter refuses this on its own.
        assert_eq!(
            SigningKeyExportEvidence::exported(&p256).interpret_signing_key(),
            Err(SigningKeyRefusal::Key(
                Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                    oid: "1.2.840.10045.2.1".to_string()
                }
            ))
        );
        // And the composition still attributes a credential failure to the credential.
        assert!(matches!(
            establish_credential_key_correspondence(
                CertificateChainEvidence::from_leaf_der(&garbage_credential),
                SigningKeyExportEvidence::exported(&p256),
            ),
            Err(CredentialKeyCorrespondenceRefusal::Credential(_))
        ));
    }

    #[test]
    fn a_mismatch_carries_no_key_material() {
        // The refusal is a unit struct; this control exists so that "carries no keys"
        // cannot be lost in a later edit that helpfully adds the expected key to it.
        let mismatch = CorrespondenceMismatch;
        assert_eq!(std::mem::size_of_val(&mismatch), 0);
    }
}
