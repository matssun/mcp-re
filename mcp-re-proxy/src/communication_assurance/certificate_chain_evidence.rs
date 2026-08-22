// SPDX-License-Identifier: Apache-2.0
//! Certificate-chain evidence, and the X.509 adapter that interprets its identity fields.
//!
//! This module is the mechanism boundary. It is the only place in the authority that knows
//! DER exists, and the only place that touches the foreign X.509 parser. Everything above
//! it works on [`CertificateIdentityFields`], an ordinary Rust value.
//!
//! The parser is a foreign, unverified dependency: it is recorded as an ADR-MCPRE-059
//! ASSUMED boundary (ASM-0010), not proved. What is claimed here is only the composition —
//! bytes that the parser interprets yield the field set it reports, and that field set is
//! what the selector sees. A theorem about the selector says nothing about the parser, and
//! this split is the reason it can say anything at all.
//!
//! # Scope
//!
//! `CertificateChainEvidence` is the evidence a peer presented. This slice interprets its
//! LEAF only, because identity is a property of the leaf. Presented intermediates are
//! deliberately absent from the representation rather than carried unused: they are the
//! input of chain verification, an authority that does not exist yet, and a field nothing
//! consumes is a claim about ownership that no code backs.

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

use super::certificate_identity_fields::CertificateIdentityFields;
use super::certificate_identity_interpreter::interpret_certificate_identity;
use super::certificate_identity_policy::CertificateIdentityPolicy;
use super::certificate_identity_refusal::CertificateIdentityRefusal;
use super::certificate_peer_identity_evidence::CertificatePeerIdentityEvidence;

/// The certificate evidence a peer presented, as far as identity interpretation needs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CertificateChainEvidence<'a> {
    leaf_der: Option<&'a [u8]>,
}

impl<'a> CertificateChainEvidence<'a> {
    /// Evidence consisting of the leaf certificate the peer presented, in DER.
    pub fn from_leaf_der(leaf_der: &'a [u8]) -> Self {
        CertificateChainEvidence {
            leaf_der: Some(leaf_der),
        }
    }

    /// Evidence from a peer that presented no certificate at all.
    ///
    /// An explicit inhabitant rather than an `Option` at every call site: "the peer sent
    /// nothing" is a fact the refusal algebra reports, and it should enter the authority
    /// as evidence, not as a missing argument.
    pub fn absent() -> Self {
        CertificateChainEvidence { leaf_der: None }
    }

    /// Evidence built from an optional leaf, for callers holding one.
    pub fn from_optional_leaf_der(leaf_der: Option<&'a [u8]>) -> Self {
        CertificateChainEvidence { leaf_der }
    }

    /// Interpret the leaf's identity fields through the foreign X.509 parser.
    ///
    /// The two representation-level refusals originate here and nowhere else.
    fn identity_fields(self) -> Result<CertificateIdentityFields, CertificateIdentityRefusal> {
        let leaf_der = self.leaf_der.ok_or(CertificateIdentityRefusal::NoLeaf)?;
        let (_, certificate) = X509Certificate::from_der(leaf_der)
            .map_err(|_| CertificateIdentityRefusal::MalformedCertificate)?;

        // An unreadable SAN extension is an absent SAN list, not a malformed certificate:
        // the certificate parsed, and the fields it presents are the fields it presents.
        let general_names = certificate
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|san| san.value.general_names.clone())
            .unwrap_or_default();

        // Presentation order is preserved: the FIRST value of the selected field is the
        // authoritative one, so a reordering here would change which identity a peer has.
        let uri_sans = general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::URI(uri) => Some((*uri).to_string()),
                _ => None,
            })
            .collect();
        let dns_sans = general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(dns) => Some((*dns).to_string()),
                _ => None,
            })
            .collect();
        let common_name = certificate
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_string);

        Ok(CertificateIdentityFields::new(
            uri_sans,
            dns_sans,
            common_name,
        ))
    }

    /// Interpret this evidence's identity under `policy`: the composition of the X.509
    /// adapter above with the pure selector.
    ///
    /// Establishes peer-identity evidence only — not trust, revocation status, freshness,
    /// authentication, admission, authorization, or the existence of a channel.
    pub fn interpret_identity(
        self,
        policy: CertificateIdentityPolicy,
    ) -> Result<CertificatePeerIdentityEvidence, CertificateIdentityRefusal> {
        let fields = self.identity_fields()?;
        interpret_certificate_identity(&fields, policy)
    }
}

#[cfg(test)]
mod tests {
    use super::CertificateChainEvidence;
    use super::CertificateIdentityPolicy;
    use super::CertificateIdentityRefusal;

    #[test]
    fn absent_evidence_refuses_as_no_leaf_under_every_policy() {
        for policy in [
            CertificateIdentityPolicy::UriSan,
            CertificateIdentityPolicy::DnsSan,
            CertificateIdentityPolicy::CommonNameLegacy,
        ] {
            assert_eq!(
                CertificateChainEvidence::absent().interpret_identity(policy),
                Err(CertificateIdentityRefusal::NoLeaf),
                "a peer that presented nothing is not a peer whose URI SAN is missing"
            );
        }
    }

    #[test]
    fn an_optional_leaf_that_is_none_is_the_same_evidence_as_absent() {
        assert_eq!(
            CertificateChainEvidence::from_optional_leaf_der(None),
            CertificateChainEvidence::absent()
        );
    }

    #[test]
    fn bytes_that_are_not_a_certificate_refuse_as_malformed_not_as_absent() {
        let garbage = [0x30u8, 0x82, 0xff, 0xff, 0x00, 0x01, 0x02];
        assert_eq!(
            CertificateChainEvidence::from_leaf_der(&garbage)
                .interpret_identity(CertificateIdentityPolicy::UriSan),
            Err(CertificateIdentityRefusal::MalformedCertificate),
            "unreadable evidence and readable evidence without the configured field are \
             different incidents"
        );
    }

    #[test]
    fn empty_bytes_are_a_malformed_certificate_rather_than_an_absent_one() {
        // Presenting zero bytes is presenting something: `NoLeaf` is reserved for a peer
        // that presented no certificate, and conflating them would let a peer that sent
        // an empty certificate be reported as one that sent none.
        assert_eq!(
            CertificateChainEvidence::from_leaf_der(&[])
                .interpret_identity(CertificateIdentityPolicy::UriSan),
            Err(CertificateIdentityRefusal::MalformedCertificate)
        );
    }
}
