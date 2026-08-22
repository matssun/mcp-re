// SPDX-License-Identifier: Apache-2.0
//! Why certificate identity interpretation refused.
//!
//! Refusal is part of the contract, not the absence of a result. `Option` would collapse
//! five security-relevant facts — no certificate was presented, the certificate could not
//! be read, the configured field's representation could not be interpreted, the configured
//! field was not there, and the configured field held something that is not an identity —
//! into one `None` that a test, an operator, or an audit trail cannot tell apart. The first
//! is a client that sent nothing; the last is a client whose issuer minted a smuggling
//! payload. Those are different incidents.
//!
//! The variants are ordered by the refusal precedence of ADR-MCPRE-063 §9: existence,
//! then local validity, then the selected field's presence, then its shape. A refusal
//! names the first rule that failed, so the reason never depends on evaluation order.

use super::certificate_identity_policy::CertificateIdentityPolicy;
use super::peer_identity_value::PeerIdentityValueRefusal;

/// Why no peer-identity evidence was produced from a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateIdentityRefusal {
    /// No leaf certificate was presented. Produced by the mechanism adapter.
    NoLeaf,
    /// A leaf was presented but could not be interpreted as a certificate. Produced by
    /// the mechanism adapter; the foreign parser's reason is deliberately not carried,
    /// because nothing in this authority may branch on it.
    MalformedCertificate,
    /// The certificate parsed, but the representation carrying the configured field could
    /// not be interpreted: a malformed or (per the parser's contract) duplicated SAN
    /// extension, or a Common Name whose string encoding cannot be represented.
    ///
    /// This is NOT absence and must never be reported as absence. A peer that presented a
    /// broken field and a peer that presented no field are different incidents, and only
    /// the first says something about the issuer that minted the certificate. Both refuse,
    /// so nothing is admitted either way — what is at stake is which fact the refusal
    /// records, and an authority whose algebra is more precise than its adapter reports
    /// the wrong one.
    SelectedFieldUninterpretable {
        /// The configured field whose representation could not be read.
        selected: CertificateIdentityPolicy,
    },
    /// The certificate does not carry the configured identity field. Another field may
    /// well be present — reading it is the fallback this authority disclaims.
    SelectedFieldAbsent {
        /// The configured field that was looked for and was not there.
        selected: CertificateIdentityPolicy,
    },
    /// The configured field's authoritative (first) value is not a well-formed identity.
    /// A later value of the same field may be well-formed; using it is also a fallback.
    SelectedFieldMalformed {
        /// The configured field whose first value was refused.
        selected: CertificateIdentityPolicy,
        /// Which identity-value rule the value broke.
        reason: PeerIdentityValueRefusal,
    },
}

#[cfg(test)]
mod tests {
    use super::CertificateIdentityPolicy;
    use super::CertificateIdentityRefusal;
    use super::PeerIdentityValueRefusal;

    #[test]
    fn absent_and_malformed_are_distinguishable_for_the_same_field() {
        let absent = CertificateIdentityRefusal::SelectedFieldAbsent {
            selected: CertificateIdentityPolicy::UriSan,
        };
        let malformed = CertificateIdentityRefusal::SelectedFieldMalformed {
            selected: CertificateIdentityPolicy::UriSan,
            reason: PeerIdentityValueRefusal::ControlCharacter,
        };
        assert_ne!(
            absent, malformed,
            "a client that presented no URI SAN and a client whose URI SAN carried a CR \
             are different incidents and must not report the same refusal"
        );
    }

    #[test]
    fn an_unreadable_field_and_an_absent_one_are_different_refusals() {
        assert_ne!(
            CertificateIdentityRefusal::SelectedFieldUninterpretable {
                selected: CertificateIdentityPolicy::UriSan,
            },
            CertificateIdentityRefusal::SelectedFieldAbsent {
                selected: CertificateIdentityPolicy::UriSan,
            },
            "a broken SAN extension is evidence about the issuer; a missing one is not"
        );
    }

    #[test]
    fn a_refusal_names_the_configured_field_not_the_field_that_was_present() {
        let refusal = CertificateIdentityRefusal::SelectedFieldAbsent {
            selected: CertificateIdentityPolicy::UriSan,
        };
        let CertificateIdentityRefusal::SelectedFieldAbsent { selected } = refusal else {
            panic!("expected an absence refusal");
        };
        assert_eq!(selected, CertificateIdentityPolicy::UriSan);
    }
}
