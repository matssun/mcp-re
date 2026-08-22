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
//! (ADR-MCPRE-059 / ASM-0030).
//!
//! Private to the authority. It is unit-tested and is a formal-verification candidate;
//! neither is a reason to publish it, because a public field set is a second entrance into
//! the block that bypasses the certificate adapter.
//!
//! **Order is semantic.** The SAN lists are in the order the certificate presents them,
//! because the FIRST value of the selected field is the authoritative one. A producer that
//! sorts, deduplicates, or filters these lists changes which identity the peer has.
//!
//! **Absence is semantic too, which is why it is not the only way to have no value.** A
//! field the certificate does not carry and a field whose representation the parser could
//! not interpret are different facts about the peer's evidence, and the seam has to be able
//! to say both — otherwise the adapter is forced to report the second as the first, and the
//! refusal algebra above it becomes more precise than the representation beneath it.

/// What the mechanism adapter was able to read for one identity field.
///
/// The `Uninterpretable` case exists because a query against the certificate can fail
/// rather than come back empty: a SAN extension that is malformed or (per the parser's
/// contract) duplicated, or a Common Name whose string encoding cannot be represented.
/// Those are present-but-unreadable, and collapsing them into `Read(None)` would report a
/// peer that presented a broken field as a peer that presented no field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FieldReadout<T> {
    /// The representation was interpreted; this is what it holds, which may be nothing.
    Read(T),
    /// The representation is there and could not be interpreted.
    Uninterpretable,
}

/// The identity-bearing fields interpreted out of one certificate, in presentation order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CertificateIdentityFields {
    uri_sans: FieldReadout<Vec<String>>,
    dns_sans: FieldReadout<Vec<String>>,
    common_name: FieldReadout<Option<String>>,
}

impl CertificateIdentityFields {
    /// Build the interpreted field set from three readouts.
    pub(super) fn new(
        uri_sans: FieldReadout<Vec<String>>,
        dns_sans: FieldReadout<Vec<String>>,
        common_name: FieldReadout<Option<String>>,
    ) -> Self {
        CertificateIdentityFields {
            uri_sans,
            dns_sans,
            common_name,
        }
    }

    /// A field set every one of whose fields was readable.
    ///
    /// Test-only, and deliberately so: in production every readout comes from the adapter,
    /// which decides per field whether the representation could be interpreted. A
    /// production constructor that assumed readability would be a way to lose the
    /// distinction this type exists to carry.
    #[cfg(test)]
    pub(super) fn readable(
        uri_sans: Vec<String>,
        dns_sans: Vec<String>,
        common_name: Option<String>,
    ) -> Self {
        CertificateIdentityFields::new(
            FieldReadout::Read(uri_sans),
            FieldReadout::Read(dns_sans),
            FieldReadout::Read(common_name),
        )
    }

    /// The first URI SAN, if the representation was readable and carries any.
    ///
    /// First, not "first acceptable": a later value is a different identity, and reaching
    /// for it after this one fails is the fallback the policy disclaims.
    pub(super) fn first_uri_san(&self) -> FieldReadout<Option<&str>> {
        first_of(&self.uri_sans)
    }

    /// The first DNS SAN, if the representation was readable and carries any.
    pub(super) fn first_dns_san(&self) -> FieldReadout<Option<&str>> {
        first_of(&self.dns_sans)
    }

    /// The subject Common Name, if its representation was readable.
    pub(super) fn common_name(&self) -> FieldReadout<Option<&str>> {
        match &self.common_name {
            FieldReadout::Read(value) => FieldReadout::Read(value.as_deref()),
            FieldReadout::Uninterpretable => FieldReadout::Uninterpretable,
        }
    }
}

/// The first value of a readable list, preserving unreadability.
fn first_of(readout: &FieldReadout<Vec<String>>) -> FieldReadout<Option<&str>> {
    match readout {
        FieldReadout::Read(values) => FieldReadout::Read(values.first().map(String::as_str)),
        FieldReadout::Uninterpretable => FieldReadout::Uninterpretable,
    }
}

#[cfg(test)]
mod tests {
    use super::CertificateIdentityFields;
    use super::FieldReadout;

    #[test]
    fn the_first_value_of_each_san_list_is_the_one_projected() {
        let fields = CertificateIdentityFields::readable(
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
        assert_eq!(
            fields.first_uri_san(),
            FieldReadout::Read(Some("spiffe://example.org/first"))
        );
        assert_eq!(
            fields.first_dns_san(),
            FieldReadout::Read(Some("first.example.org"))
        );
        assert_eq!(
            fields.common_name(),
            FieldReadout::Read(Some("cn.example.org"))
        );
    }

    #[test]
    fn an_absent_field_projects_as_read_nothing_rather_than_as_unreadable() {
        let fields = CertificateIdentityFields::readable(Vec::new(), Vec::new(), None);
        assert_eq!(fields.first_uri_san(), FieldReadout::Read(None));
        assert_eq!(fields.first_dns_san(), FieldReadout::Read(None));
        assert_eq!(fields.common_name(), FieldReadout::Read(None));
    }

    #[test]
    fn an_unreadable_field_never_projects_as_an_absent_one() {
        // The distinction this seam exists to preserve. A representation the parser could
        // not interpret must not reach the selector wearing the shape of a certificate
        // that simply had no such field.
        let fields = CertificateIdentityFields::new(
            FieldReadout::Uninterpretable,
            FieldReadout::Read(Vec::new()),
            FieldReadout::Uninterpretable,
        );
        assert_eq!(fields.first_uri_san(), FieldReadout::Uninterpretable);
        assert_ne!(fields.first_uri_san(), FieldReadout::Read(None));
        assert_eq!(fields.common_name(), FieldReadout::Uninterpretable);
        assert_eq!(
            fields.first_dns_san(),
            FieldReadout::Read(None),
            "unreadability is per field: one broken representation does not make the \
             others unreadable"
        );
    }

    #[test]
    fn a_malformed_first_value_is_still_the_projected_one() {
        // The representation does not judge: an unusable first value is reported as the
        // first value, and refusing it is the selector's decision to make.
        let fields = CertificateIdentityFields::readable(
            vec!["\r".to_string(), "spiffe://example.org/valid".to_string()],
            Vec::new(),
            None,
        );
        assert_eq!(
            fields.first_uri_san(),
            FieldReadout::Read(Some("\r")),
            "the representation must not hide a malformed first value; hiding it here is \
             how a fallback becomes invisible to the selector's tests"
        );
    }
}
