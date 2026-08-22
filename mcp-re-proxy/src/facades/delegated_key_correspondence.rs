// SPDX-License-Identifier: Apache-2.0
//! The delegated-TLS error vocabulary, as a facade over the credential/key correspondence
//! authority.
//!
//! `TlsError::DelegatedKeyMismatch(String)` predates the authority. It is one variant
//! carrying a sentence, and before ADR-MCPRE-063 Slice 2 it was the ONLY place six
//! different security facts existed — an empty chain, an unreadable certificate, a
//! credential key of the wrong algorithm, an unreachable signer, a signing key of the wrong
//! algorithm, and a genuine key mismatch were distinguishable only by reading the prose.
//!
//! The facts now live in the authority's algebra. What survives here is the RENDERING: the
//! sentence an operator reads, derived from the fact rather than being the fact. Nothing in
//! this file decides anything, and its callers keep the error type they already match on
//! until they are migrated one at a time.
//!
//! Keeping the rendering out of `tls.rs` is deliberate. A message table that lives beside
//! the code it describes tends to grow back into the decision it replaced.

use crate::communication_assurance::credential_key_correspondence::CredentialKeyCorrespondenceRefusal;
use crate::communication_assurance::credential_public_key_evidence::CredentialKeyRefusal;
use crate::communication_assurance::signing_key_evidence::SigningKeyRefusal;

/// Render a credential/key correspondence refusal in the historical error vocabulary.
///
/// The authority's algebra is the contract; this is the sentence an operator reads. Every
/// arm names WHICH side failed and WHY, which the single message it replaces could only do
/// as prose that nothing could match on.
pub(crate) fn correspondence_message(refusal: &CredentialKeyCorrespondenceRefusal) -> String {
    match refusal {
        CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Absent) => {
            "delegated TLS server certificate chain is empty".to_string()
        }
        CredentialKeyCorrespondenceRefusal::Credential(
            CredentialKeyRefusal::UninterpretableCredential,
        ) => "leaf certificate is not parseable DER".to_string(),
        CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Key(reason)) => {
            format!("delegated TLS leaf certificate public key: {reason}")
        }
        CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Unavailable) => {
            "delegated TLS signer did not yield an exportable public key".to_string()
        }
        CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Key(reason)) => {
            format!("delegated TLS signer public key: {reason}")
        }
        CredentialKeyCorrespondenceRefusal::Mismatch(_) => {
            "the delegated TLS signer's Ed25519 public key does not match the leaf \
             certificate's SubjectPublicKeyInfo; the signer signs for a different key than \
             the certificate presents"
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::correspondence_message;
    use crate::communication_assurance::credential_key_correspondence::CorrespondenceMismatch;
    use crate::communication_assurance::credential_key_correspondence::CredentialKeyCorrespondenceRefusal;
    use crate::communication_assurance::credential_public_key_evidence::CredentialKeyRefusal;
    use crate::communication_assurance::ed25519_public_key::Rfc8410SpkiRefusal;
    use crate::communication_assurance::signing_key_evidence::SigningKeyRefusal;

    #[test]
    fn every_fact_renders_to_a_distinct_sentence() {
        // The rendering is lossy by nature — one error variant, many facts — but it must
        // not be lossy HERE: an operator reading two different incidents must not read the
        // same sentence. The algebra is what a caller matches on; this is what a human
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
            facts.iter().map(correspondence_message).collect();
        assert_eq!(
            rendered.len(),
            facts.len(),
            "two different facts rendered to the same sentence"
        );
    }

    #[test]
    fn an_unsupported_algorithm_tells_the_operator_which_algorithm_was_given() {
        let message = correspondence_message(&CredentialKeyCorrespondenceRefusal::Credential(
            CredentialKeyRefusal::Key(Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                oid: "1.2.840.113549.1.1.1".to_string(),
            }),
        ));
        assert!(
            message.contains("1.2.840.113549.1.1.1"),
            "an operator who configured an RSA key must be told so: {message}"
        );
    }
}
