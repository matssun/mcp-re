// SPDX-License-Identifier: Apache-2.0
//! Peer-identity evidence derived from a certificate: the product of this slice.
//!
//! # What this value means
//!
//! Under the deployment's identity-selection policy, the selected field of the presented
//! leaf certificate denoted this well-formed identity value, read from this field.
//!
//! # What it does not mean
//!
//! It is evidence, not a conclusion. Holding one does NOT establish that the certificate
//! chain is trusted, that it is unrevoked, that it is fresh, that the peer is
//! authenticated, admitted, or authorized, or that a channel to that peer exists. Those
//! are the propositions of authorities that do not exist yet, and the name of this type
//! stops where its evidence stops — which is why it is not called `AuthenticatedPeer`.
//!
//! # Why the fields are private
//!
//! The value carries its own invariant ([`PeerIdentityValue`]), and the source is the
//! field the interpreter actually read. Public fields would let any caller pair a value
//! with a source naming a different field — a provenance substitution that no downstream
//! consumer could detect, because the only record of where an identity came from is this
//! field. Construction is therefore restricted to this module tree, and the only
//! constructor is the interpreter's.

use super::certificate_identity_policy::CertificateIdentitySource;
use super::peer_identity_value::PeerIdentityValue;

/// A peer identity interpreted from certificate evidence, with the field it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePeerIdentityEvidence {
    value: PeerIdentityValue,
    source: CertificateIdentitySource,
}

impl CertificatePeerIdentityEvidence {
    /// Pair an interpreted value with the field it was read from.
    ///
    /// Visible only inside `communication_assurance`, so the source is written exactly
    /// once, by the interpreter, from the policy it was given.
    pub(super) fn new(value: PeerIdentityValue, source: CertificateIdentitySource) -> Self {
        CertificatePeerIdentityEvidence { value, source }
    }

    /// The interpreted identity value.
    pub fn value(&self) -> &PeerIdentityValue {
        &self.value
    }

    /// The certificate field the value was read from.
    pub fn source(&self) -> CertificateIdentitySource {
        self.source
    }
}

#[cfg(test)]
mod tests {
    use super::CertificateIdentitySource;
    use super::CertificatePeerIdentityEvidence;
    use super::PeerIdentityValue;

    #[test]
    fn the_projections_report_what_was_constructed() {
        let value = PeerIdentityValue::interpret("spiffe://example.org/agent-1").expect("value");
        let evidence =
            CertificatePeerIdentityEvidence::new(value, CertificateIdentitySource::UriSan);
        assert_eq!(evidence.value().as_str(), "spiffe://example.org/agent-1");
        assert_eq!(evidence.source(), CertificateIdentitySource::UriSan);
    }

    #[test]
    fn two_evidences_differing_only_in_source_are_not_equal() {
        // Provenance is part of the fact, not a label on it: the same string read from a
        // legacy CN is different evidence from the same string read from a URI SAN.
        let value = PeerIdentityValue::interpret("agent.example.org").expect("value");
        let from_dns =
            CertificatePeerIdentityEvidence::new(value.clone(), CertificateIdentitySource::DnsSan);
        let from_cn =
            CertificatePeerIdentityEvidence::new(value, CertificateIdentitySource::CommonName);
        assert_ne!(from_dns, from_cn);
    }
}
