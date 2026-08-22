// SPDX-License-Identifier: Apache-2.0
//! The interpreted identity fields of one certificate — the seam between the X.509
//! mechanism and the semantic selector.
//!
//! This is the whole of what the selector is allowed to see. It is a representation, not a
//! conclusion: nothing here is validated, trusted, or known to be well-formed, and the
//! type deliberately cannot express a chain, a signature, a validity window, or a trust
//! anchor. Everything the selector needs is here, and nothing else is, which is what lets
//! the selector be a pure total function over an ordinary Rust value while the ASN.1
//! parsing that produced it stays an explicitly assumed foreign boundary
//! (ADR-MCPRE-059 / ASM-0010).
//!
//! **Order is semantic.** The SAN lists are in the order the certificate presents them,
//! because the FIRST value of the selected field is the authoritative one. A producer that
//! sorts, deduplicates, or filters these lists changes which identity the peer has.

/// The identity-bearing fields interpreted out of one certificate, in presentation order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateIdentityFields {
    uri_sans: Vec<String>,
    dns_sans: Vec<String>,
    common_name: Option<String>,
}

impl CertificateIdentityFields {
    /// Build the interpreted field set. Called by the mechanism adapter that parsed the
    /// certificate, and by tests that need a field set the X.509 encoder cannot express.
    pub fn new(uri_sans: Vec<String>, dns_sans: Vec<String>, common_name: Option<String>) -> Self {
        CertificateIdentityFields {
            uri_sans,
            dns_sans,
            common_name,
        }
    }

    /// The first URI SAN, if the certificate presents any.
    ///
    /// First, not "first acceptable": a later value is a different identity, and reaching
    /// for it after this one fails is the fallback the policy disclaims.
    pub(super) fn first_uri_san(&self) -> Option<&str> {
        self.uri_sans.first().map(String::as_str)
    }

    /// The first DNS SAN, if the certificate presents any.
    pub(super) fn first_dns_san(&self) -> Option<&str> {
        self.dns_sans.first().map(String::as_str)
    }

    /// The subject Common Name, if the certificate carries one.
    pub(super) fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::CertificateIdentityFields;

    #[test]
    fn the_first_value_of_each_san_list_is_the_one_projected() {
        let fields = CertificateIdentityFields::new(
            vec![
                "spiffe://example.org/first".to_string(),
                "spiffe://example.org/second".to_string(),
            ],
            vec![
                "first.example.org".to_string(),
                "second.example.org".to_string(),
            ],
            Some("cn.example.org".to_string()),
        );
        assert_eq!(fields.first_uri_san(), Some("spiffe://example.org/first"));
        assert_eq!(fields.first_dns_san(), Some("first.example.org"));
        assert_eq!(fields.common_name(), Some("cn.example.org"));
    }

    #[test]
    fn an_absent_field_projects_as_absent_rather_than_as_an_empty_value() {
        let fields = CertificateIdentityFields::default();
        assert_eq!(fields.first_uri_san(), None);
        assert_eq!(fields.first_dns_san(), None);
        assert_eq!(fields.common_name(), None);
    }

    #[test]
    fn a_malformed_first_value_is_still_the_projected_one() {
        // The representation does not judge: an unusable first value is reported as the
        // first value, and refusing it is the selector's decision to make.
        let fields = CertificateIdentityFields::new(
            vec!["\r".to_string(), "spiffe://example.org/valid".to_string()],
            Vec::new(),
            None,
        );
        assert_eq!(
            fields.first_uri_san(),
            Some("\r"),
            "the representation must not hide a malformed first value; hiding it here is \
             how a fallback becomes invisible to the selector's tests"
        );
    }
}
