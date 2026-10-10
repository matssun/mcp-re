// SPDX-License-Identifier: Apache-2.0
//! WHY the §7 gate refused, as a record coordinate.
//!
//! A SECOND, separate coordinate beside [`AdmissionFacet`](super::AdmissionFacet), whose
//! vocabulary stays one token per verdict. The wire code of an admission refusal is frozen
//! and nearly uniform — a forged record, an absent one, a revoked workload and a closed
//! window are all a 403 the client cannot tell apart — so the only place an operator can
//! learn which one fired is the durable record. That is what this carries, and it is
//! rendered only on a request record the gate refused.
//!
//! The classes are the gate's own facts. The store-side ones come from the source's answer
//! rather than from the error that answer became: an absent record and a record that fails
//! its signature both refuse as "not current", and only the class says which.

use mcp_re_http_profile::authoritative_admission::record::AdmissionRecordRefusal;
use mcp_re_http_profile::HttpProfileError;

use crate::audit_record::text::AuditField;

/// Which fact made the §7 gate refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRefusalClass {
    /// The deployment requires admission and the call presented none.
    NoEvidence,
    /// The assertion is malformed, signed by no configured authority, or fails its
    /// signature, type or audience.
    AssertionInvalid,
    /// The assertion is outside its window or older than the verifier's own budget.
    AssertionExpired,
    /// The assertion was issued to another actor, or the call's binding does not describe it.
    BindingMismatch,
    /// An authentic statement says this workload is not admitted now: a superseded
    /// generation, or a status other than admitted.
    NotCurrent,
    /// The store answered and holds no record for the workload.
    NoRecord,
    /// The store answered with a record this deployment will not act on, and which class of
    /// record it was.
    RecordRefused(AdmissionRecordRefusal),
    /// No current state could be established: the authority was unreachable and degraded
    /// serving was off, closed, or unavailable to this call.
    StateUnavailable,
}

impl AdmissionRefusalClass {
    /// The refusal class of an error [`authenticate_admission`] returned.
    ///
    /// Total: every refusal not named here is the assertion failing to authenticate.
    ///
    /// [`authenticate_admission`]: mcp_re_http_profile::authenticate_admission
    pub(super) fn of_authentication(error: &HttpProfileError) -> Self {
        match error {
            HttpProfileError::AdmissionBindingMismatch => Self::BindingMismatch,
            HttpProfileError::AdmissionAssertionExpired => Self::AssertionExpired,
            HttpProfileError::AdmissionNotCurrent => Self::NotCurrent,
            _ => Self::AssertionInvalid,
        }
    }

    /// The refusal class of an error [`check_admission`] returned.
    ///
    /// Total: the currency check refuses with `AdmissionNotCurrent` or, for every other
    /// reason, because it has no state it may act on.
    ///
    /// [`check_admission`]: mcp_re_http_profile::check_admission
    pub(super) fn of_currency(error: &HttpProfileError) -> Self {
        match error {
            HttpProfileError::AdmissionNotCurrent => Self::NotCurrent,
            _ => Self::StateUnavailable,
        }
    }

    /// The closed token the record renders.
    pub fn token(self) -> &'static str {
        match self {
            Self::NoEvidence => "no-evidence",
            Self::AssertionInvalid => "assertion-invalid",
            Self::AssertionExpired => "assertion-expired",
            Self::BindingMismatch => "binding-mismatch",
            Self::NotCurrent => "not-current",
            Self::NoRecord => "no-record",
            Self::RecordRefused(AdmissionRecordRefusal::Malformed) => "record-malformed",
            Self::RecordRefused(AdmissionRecordRefusal::IssuerUntrusted) => {
                "record-issuer-untrusted"
            }
            Self::RecordRefused(AdmissionRecordRefusal::SignatureInvalid) => {
                "record-signature-invalid"
            }
            Self::RecordRefused(AdmissionRecordRefusal::ProfileMismatch) => {
                "record-profile-mismatch"
            }
            Self::RecordRefused(AdmissionRecordRefusal::SubjectMismatch) => {
                "record-subject-mismatch"
            }
            Self::RecordRefused(AdmissionRecordRefusal::Expired) => "record-expired",
            Self::RecordRefused(AdmissionRecordRefusal::WindowExceedsBudget) => {
                "record-window-exceeds-budget"
            }
            Self::RecordRefused(AdmissionRecordRefusal::RevisionRewound) => {
                "record-revision-rewound"
            }
            Self::StateUnavailable => "state-unavailable",
        }
    }

    /// The coordinate this class contributes to a request record.
    pub(crate) fn audit_field(self) -> AuditField<'static> {
        AuditField::token("admission_refusal", self.token())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD_REFUSALS: [AdmissionRecordRefusal; AdmissionRecordRefusal::COUNT] = [
        AdmissionRecordRefusal::Malformed,
        AdmissionRecordRefusal::IssuerUntrusted,
        AdmissionRecordRefusal::SignatureInvalid,
        AdmissionRecordRefusal::ProfileMismatch,
        AdmissionRecordRefusal::SubjectMismatch,
        AdmissionRecordRefusal::Expired,
        AdmissionRecordRefusal::WindowExceedsBudget,
        AdmissionRecordRefusal::RevisionRewound,
    ];

    fn every_class() -> Vec<AdmissionRefusalClass> {
        let mut all = vec![
            AdmissionRefusalClass::NoEvidence,
            AdmissionRefusalClass::AssertionInvalid,
            AdmissionRefusalClass::AssertionExpired,
            AdmissionRefusalClass::BindingMismatch,
            AdmissionRefusalClass::NotCurrent,
            AdmissionRefusalClass::NoRecord,
            AdmissionRefusalClass::StateUnavailable,
        ];
        all.extend(
            RECORD_REFUSALS
                .into_iter()
                .map(AdmissionRefusalClass::RecordRefused),
        );
        all
    }

    /// Every class renders its own token. A forged record and an absent one are the pair this
    /// coordinate exists to separate, and a vocabulary that spelled two classes alike would
    /// restore the collapse one layer further out, where the record looks populated.
    #[test]
    fn every_class_renders_its_own_token() {
        let mut seen = std::collections::BTreeSet::new();
        for class in every_class() {
            assert!(seen.insert(class.token()), "{class:?} reuses a token");
            assert_eq!(class.audit_field().name, "admission_refusal");
        }
        assert_eq!(seen.len(), 7 + AdmissionRecordRefusal::COUNT);
        assert_ne!(
            AdmissionRefusalClass::NoRecord.token(),
            AdmissionRefusalClass::RecordRefused(AdmissionRecordRefusal::SignatureInvalid).token(),
        );
    }

    /// The error-to-class maps are total and name the facts the gate can distinguish.
    #[test]
    fn the_authentication_and_currency_errors_map_to_their_own_classes() {
        let auth = AdmissionRefusalClass::of_authentication;
        assert_eq!(
            auth(&HttpProfileError::AdmissionBindingMismatch),
            AdmissionRefusalClass::BindingMismatch
        );
        assert_eq!(
            auth(&HttpProfileError::AdmissionAssertionExpired),
            AdmissionRefusalClass::AssertionExpired
        );
        assert_eq!(
            auth(&HttpProfileError::AdmissionIssuerUntrusted),
            AdmissionRefusalClass::AssertionInvalid
        );
        let currency = AdmissionRefusalClass::of_currency;
        assert_eq!(
            currency(&HttpProfileError::AdmissionNotCurrent),
            AdmissionRefusalClass::NotCurrent
        );
        assert_eq!(
            currency(&HttpProfileError::AdmissionStateUnavailable),
            AdmissionRefusalClass::StateUnavailable
        );
    }
}
