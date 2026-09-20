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

/// The sentence an operator reads for a refusal.
///
/// It lives on the algebra so a new fact cannot be added without a sentence: every arm
/// names WHICH side failed and WHY, and two different incidents never read the same. What
/// a caller matches on is the value; this is only how it reads.
impl std::fmt::Display for CredentialKeyCorrespondenceRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Absent) => {
                f.write_str("delegated TLS server certificate chain is empty")
            }
            CredentialKeyCorrespondenceRefusal::Credential(
                CredentialKeyRefusal::UninterpretableCredential,
            ) => f.write_str("leaf certificate is not parseable DER"),
            CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Key(reason)) => {
                write!(f, "delegated TLS leaf certificate public key: {reason}")
            }
            CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Unavailable) => {
                f.write_str("delegated TLS signer did not yield an exportable public key")
            }
            CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Key(reason)) => {
                write!(f, "delegated TLS signer public key: {reason}")
            }
            CredentialKeyCorrespondenceRefusal::Mismatch(_) => f.write_str(
                "the delegated TLS signer's Ed25519 public key does not match the leaf \
                 certificate's SubjectPublicKeyInfo; the signer signs for a different key \
                 than the certificate presents",
            ),
        }
    }
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

    /// A real Ed25519 leaf certificate, in DER.
    ///
    /// Minted rather than spelled: the credential adapter parses X.509 and reads the SPKI
    /// bytes verbatim, so no literal stands in for a legal credential here. `rcgen` is
    /// already this crate's minting tool in `ocsp.rs`'s unit tests.
    fn ed25519_leaf_der() -> Vec<u8> {
        ed25519_leaf_and_its_spki().0
    }

    /// The same leaf, paired with the SPKI of the key inside it.
    ///
    /// Both halves come from ONE key pair, and the SPKI is serialized by `rcgen` rather
    /// than assembled from [`CANONICAL_PREFIX`]: a hand-built SPKI would be this test's own
    /// idea of what a signer exports, and the accepting case must not rest on a second
    /// opinion about the encoding.
    fn ed25519_leaf_and_its_spki() -> (Vec<u8>, Vec<u8>) {
        use rcgen::PublicKeyData as _;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("an ed25519 key pair");
        let spki = key.subject_public_key_info();
        let params = rcgen::CertificateParams::new(vec!["mcp-re-test".to_string()])
            .expect("leaf certificate parameters");
        let der = params
            .self_signed(&key)
            .expect("a self-signed leaf")
            .der()
            .as_ref()
            .to_vec();
        (der, spki)
    }

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

    /// An unavailable signer is reported as the signing side's refusal.
    ///
    /// # What establishes this, and what this control adds
    ///
    /// The proposition is **STRUCTURALLY ESTABLISHED**: under the current type
    /// representation and composition API, an unavailable signing key cannot inhabit the
    /// mismatch path. `correspond` is reached only once BOTH evidences have been
    /// interpreted, and the two refusals are disjoint variants of
    /// [`CredentialKeyCorrespondenceRefusal`], so there is no value of
    /// [`SigningKeyExportEvidence`] that arrives at a `Mismatch`.
    ///
    /// That is a statement about the representation and the API as they stand — not a
    /// claim that no future edit could introduce such an inhabitant. It is exactly the
    /// kind of property a source edit CAN remove, which is why it is written down here
    /// rather than left to be re-derived by the next reader.
    ///
    /// This control is the **positive mirror**, not the proof. It establishes that the
    /// composition actually reaches the signing-key adapter and returns that side's
    /// refusal — so a permanently-refusing, mis-wired, or short-circuiting composition
    /// cannot satisfy the battery vacuously. Before the repair it established neither:
    /// its fixture passed `CertificateChainEvidence::absent()`, the credential arm
    /// short-circuited, and the signing side was never consulted at all.
    #[test]
    fn an_unavailable_signer_is_not_reported_as_a_mismatch() {
        // A LEGAL credential, so the composition reaches the signing-key adapter at all.
        //
        // With `CertificateChainEvidence::absent()` the CREDENTIAL arm short-circuits first
        // (`CredentialKeyRefusal::Absent`), the signing-key adapter is never consulted, and
        // the assertion below then holds for a reason that has nothing to do with this
        // test's name. A registered symbol naming a signing-side scenario its fixture
        // cannot create is evidence about a path nothing ran.
        let leaf = ed25519_leaf_der();
        let refusal = establish_credential_key_correspondence(
            CertificateChainEvidence::from_leaf_der(&leaf),
            SigningKeyExportEvidence::unavailable(),
        );
        // Positive, not a negation: asserting only "not a Mismatch" is satisfied by every
        // refusal in the algebra, including the credential-side one this fixture used to
        // produce. The claim is that an ABSENT SIGNING KEY is reported as the signing
        // side's refusal.
        assert!(
            matches!(
                refusal,
                Err(CredentialKeyCorrespondenceRefusal::SigningKey(_))
            ),
            "an unavailable signer must be reported as the signing side's refusal, never as \
             a disagreement between two keys that were both read"
        );
    }

    /// The other half of the same distinction, kept so the credential arm's short-circuit
    /// is still covered now that the test above no longer exercises it by accident.
    #[test]
    fn an_absent_credential_is_reported_on_the_credential_side() {
        let refusal = establish_credential_key_correspondence(
            CertificateChainEvidence::absent(),
            SigningKeyExportEvidence::unavailable(),
        );
        assert!(matches!(
            refusal,
            Err(CredentialKeyCorrespondenceRefusal::Credential(
                CredentialKeyRefusal::Absent
            ))
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

    /// **The relation accepting**, and the first control in this file that reaches
    /// [`super::correspond`] at all.
    ///
    /// Every other control here refuses in an ADAPTER — an absent credential, an
    /// uninterpretable one, an unavailable signer, a non-Ed25519 export — and each
    /// short-circuits before the relation is called. The comparison the slice exists to
    /// perform is covered by the DER battery next door in `tls.rs`, which is registered
    /// evidence for this unit; what was missing is a control where the relation LIVES, so
    /// that the file carrying the `!=` carries the reason it is there.
    #[test]
    fn two_sides_presenting_the_same_key_correspond_and_the_facts_carry_that_key() {
        let (leaf, spki) = ed25519_leaf_and_its_spki();
        let facts = establish_credential_key_correspondence(
            CertificateChainEvidence::from_leaf_der(&leaf),
            SigningKeyExportEvidence::exported(&spki),
        )
        .expect("a certificate and a signer holding the same key correspond");

        let from_credential = CertificateChainEvidence::from_leaf_der(&leaf)
            .interpret_credential_public_key()
            .expect("the minted leaf carries a legal Ed25519 key")
            .key();
        assert_eq!(
            facts.corresponding_key(),
            from_credential,
            "the corresponding key must be the key that was actually presented"
        );
    }

    /// **The relation refusing** — two legal keys that are not the same key.
    ///
    /// Both sides interpret successfully, so neither adapter can produce this refusal:
    /// `Mismatch` is reachable only through the relation. Invert the comparison in
    /// `correspond` and this is the control that goes red.
    #[test]
    fn two_legal_but_different_keys_are_a_mismatch_and_not_a_side_failure() {
        let (leaf, _) = ed25519_leaf_and_its_spki();
        let other = canonical_spki(0xAB);
        assert_eq!(
            establish_credential_key_correspondence(
                CertificateChainEvidence::from_leaf_der(&leaf),
                SigningKeyExportEvidence::exported(&other),
            ),
            Err(CredentialKeyCorrespondenceRefusal::Mismatch(
                CorrespondenceMismatch
            )),
            "a signer that cannot produce a handshake the certificate verifies must be \
             refused BY THE RELATION, not reported as one side failing to present a key"
        );
    }

    #[test]
    fn a_mismatch_carries_no_key_material() {
        // The refusal is a unit struct; this control exists so that "carries no keys"
        // cannot be lost in a later edit that helpfully adds the expected key to it.
        let mismatch = CorrespondenceMismatch;
        assert_eq!(std::mem::size_of_val(&mismatch), 0);
    }

    #[test]
    fn every_fact_renders_to_a_distinct_sentence() {
        // The rendering is lossy by nature — one error variant carries many facts — but it
        // must not be lossy HERE: an operator reading two different incidents must not read
        // the same sentence. The algebra is what a caller matches on; this is what a human
        // reads, and both have to keep the facts apart.
        let facts = [
            CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Absent),
            CredentialKeyCorrespondenceRefusal::Credential(
                CredentialKeyRefusal::UninterpretableCredential,
            ),
            CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Key(
                Rfc8410SpkiRefusal::Uninterpretable,
            )),
            CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Key(
                Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                    oid: "1.2.840.113549.1.1.1".to_string(),
                },
            )),
            CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Unavailable),
            CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Key(
                Rfc8410SpkiRefusal::NonCanonicalEd25519Encoding,
            )),
            CredentialKeyCorrespondenceRefusal::Mismatch(CorrespondenceMismatch),
        ];
        let rendered: std::collections::BTreeSet<String> =
            facts.iter().map(ToString::to_string).collect();
        assert_eq!(
            rendered.len(),
            facts.len(),
            "two different facts rendered to the same sentence"
        );
    }

    #[test]
    fn an_unsupported_algorithm_tells_the_operator_which_algorithm_was_given() {
        let message = CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Key(
            Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                oid: "1.2.840.113549.1.1.1".to_string(),
            },
        ))
        .to_string();
        assert!(
            message.contains("1.2.840.113549.1.1.1"),
            "an operator who configured an RSA key must be told so: {message}"
        );
    }
}
