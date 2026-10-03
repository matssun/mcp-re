// SPDX-License-Identifier: Apache-2.0
//! What the §7 gate said about one exchange: its verdict and, when it refused, why.
//!
//! The two coordinates are one value because one of them is only meaningful beside the other.
//! A refusal cause beside an admission that was not refused would be a record contradicting
//! itself, so the value owns the pairing: the only way to name a cause is
//! [`AdmissionStatement::refused`], which fixes the verdict to `Refused`, and the fields are
//! private so no other pairing can be written.

use crate::audit_record::text::AuditField;

use super::AdmissionFacet;
use super::AdmissionRefusalClass;

/// The gate's statement about one exchange, as the record carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmissionStatement {
    facet: AdmissionFacet,
    refusal: Option<AdmissionRefusalClass>,
}

impl AdmissionStatement {
    /// A verdict with no refusal cause: every outcome but a gate refusal, and a refusal
    /// recorded before a cause existed to name.
    pub(crate) fn of(facet: AdmissionFacet) -> Self {
        AdmissionStatement {
            facet,
            refusal: None,
        }
    }

    /// The gate refused, for this reason.
    pub(crate) fn refused(class: AdmissionRefusalClass) -> Self {
        AdmissionStatement {
            facet: AdmissionFacet::Refused,
            refusal: Some(class),
        }
    }

    /// The gate's verdict.
    pub(crate) fn facet(self) -> AdmissionFacet {
        self.facet
    }

    /// Why the gate refused, when it did and said so.
    pub(crate) fn refusal(self) -> Option<AdmissionRefusalClass> {
        self.refusal
    }

    /// The coordinates this statement contributes to a request record: the facet's one token,
    /// then the refusal cause when there is one.
    pub(crate) fn audit_fields(self) -> Vec<AuditField<'static>> {
        let mut fields = self.facet.audit_fields();
        fields.extend(self.refusal.map(AdmissionRefusalClass::audit_field));
        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal names its cause and is `Refused`; every other statement names none. The
    /// facet's own token is the first field in both, unchanged.
    #[test]
    fn a_cause_is_only_ever_paired_with_a_refusal() {
        let refused = AdmissionStatement::refused(AdmissionRefusalClass::NoRecord);
        assert_eq!(refused.facet(), AdmissionFacet::Refused);
        assert_eq!(refused.refusal(), Some(AdmissionRefusalClass::NoRecord));
        let fields = refused.audit_fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], AdmissionFacet::Refused.audit_fields().remove(0));
        assert_eq!(fields[1].name, "admission_refusal");

        let plain = AdmissionStatement::of(AdmissionFacet::LiveConfirmed);
        assert_eq!(plain.refusal(), None);
        assert_eq!(plain.audit_fields().len(), 1);
    }
}
