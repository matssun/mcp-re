// SPDX-License-Identifier: Apache-2.0
//! What the request-side authorities established for one exchange, as independent
//! coordinates.
//!
//! ADR-MCPRE-066's algebra — two authorities, one record — given a type. They were two
//! fields on [`Exchange`](super::Exchange) until the §7 admission verdict joined the
//! authorization one (R11-106) and the pair became a concept rather than a coincidence:
//! same shape, same lifetime, same single writer, same single reader.
//!
//! `None` on either is not missing data. It states that **no verdict was reached**, which is
//! the thing a refusal named before that authority ran has to report — and a fact no refusal
//! CAUSE can derive from its own kind, because the same Core verdict is reachable on both
//! sides of a policy. A stage refusing after a PERMIT would otherwise record that nothing
//! decided.

use crate::admission_enforcer::AdmissionFacet;
use crate::admission_enforcer::AdmissionRefusalClass;
use crate::authorization::AuthorizationFacet;

/// The two request-side verdicts, each in its own authority's vocabulary.
///
/// Written by the admission region, which is the authority that obtains them, and read by
/// the refusal composition. The slots are private: a recorded verdict is the authority's, and
/// a later write neither restates nor clears it. No operation sets a slot back to `None`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct AuthorityVerdicts {
    /// What this deployment's authorization authority established.
    authorization: Option<AuthorizationFacet>,
    /// What the §7 admission gate established. Rendered `not-reached` when absent, never as
    /// a guess at one of its four verdicts.
    admission: Option<AdmissionFacet>,
    /// Which fact made the gate refuse. `Some` only where `admission` is `Refused` — the one
    /// way to set it is [`Self::refused_at_admission`], which sets both or neither, so the
    /// pair cannot disagree.
    admission_refusal: Option<AdmissionRefusalClass>,
}

impl AuthorityVerdicts {
    /// Records the admission verdict unless one is already recorded.
    pub(super) fn record_admission(&mut self, facet: AdmissionFacet) {
        self.admission.get_or_insert(facet);
    }

    /// Records the authorization verdict unless one is already recorded.
    pub(super) fn record_authorization(&mut self, facet: AuthorizationFacet) {
        self.authorization.get_or_insert(facet);
    }

    /// The §7 gate refused, for this reason. Ignored when an admission verdict is already
    /// recorded.
    pub(super) fn refused_at_admission(&mut self, class: AdmissionRefusalClass) {
        if self.admission.is_none() {
            self.admission = Some(AdmissionFacet::Refused);
            self.admission_refusal = Some(class);
        }
    }

    /// The recorded admission verdict, if the gate reached one.
    pub(super) fn admission(&self) -> Option<AdmissionFacet> {
        self.admission
    }

    /// The recorded authorization verdict, if that authority reached one.
    pub(super) fn authorization(&self) -> Option<&AuthorizationFacet> {
        self.authorization.as_ref()
    }

    /// The fact that made the gate refuse, where it did.
    pub(super) fn admission_refusal(&self) -> Option<AdmissionRefusalClass> {
        self.admission_refusal
    }

    /// The admission coordinate as the record states it: an unrecorded slot is `NotReached`.
    pub(super) fn admission_facet(&self) -> AdmissionFacet {
        self.admission.unwrap_or(AdmissionFacet::NotReached)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh exchange has reached NEITHER authority, and the two are separately settable.
    ///
    /// The property that matters is that they do not move together: an exchange can refuse
    /// after admission and before authorization, and the record has to say exactly that. A
    /// single "verdicts reached" flag — the shape this type exists instead of — could not.
    #[test]
    fn the_two_verdicts_start_absent_and_are_set_independently() {
        let mut v = AuthorityVerdicts::default();
        assert_eq!(v.authorization(), None);
        assert_eq!(v.admission(), None);
        v.record_admission(AdmissionFacet::LiveConfirmed);
        assert_eq!(
            v.authorization(),
            None,
            "admission does not settle authorization"
        );
        v.record_authorization(AuthorizationFacet::NotConfigured);
        assert_eq!(v.admission(), Some(AdmissionFacet::LiveConfirmed));
    }

    #[test]
    fn an_unrecorded_admission_projects_not_reached_and_a_recorded_one_itself() {
        let mut v = AuthorityVerdicts::default();
        assert_eq!(v.admission_facet(), AdmissionFacet::NotReached);
        v.record_admission(AdmissionFacet::Refused);
        assert_eq!(v.admission_facet(), AdmissionFacet::Refused);
    }

    /// A refusal at the gate sets the facet and the class together, so a record can never
    /// carry a refusal cause beside an admission that was not refused.
    #[test]
    fn a_gate_refusal_records_the_facet_and_its_class_together() {
        let mut v = AuthorityVerdicts::default();
        assert_eq!(v.admission_refusal(), None);
        v.refused_at_admission(AdmissionRefusalClass::NoRecord);
        assert_eq!(v.admission(), Some(AdmissionFacet::Refused));
        assert_eq!(v.admission_refusal(), Some(AdmissionRefusalClass::NoRecord));
    }

    /// A recorded verdict stands: `record_admission`, `refused_at_admission` and
    /// `record_authorization` each keep the first write.
    #[test]
    fn a_recorded_verdict_is_not_restated_or_cleared_by_a_later_write() {
        let mut v = AuthorityVerdicts::default();
        v.record_admission(AdmissionFacet::LiveConfirmed);
        v.record_admission(AdmissionFacet::Degraded);
        v.refused_at_admission(AdmissionRefusalClass::NoRecord);
        assert_eq!(v.admission(), Some(AdmissionFacet::LiveConfirmed));
        assert_eq!(v.admission_refusal(), None);

        v.record_authorization(AuthorizationFacet::NotConfigured);
        v.record_authorization(AuthorizationFacet::Refused(
            crate::authorization::AuthorizationRefusalFacet::BeforePolicy,
        ));
        assert_eq!(v.authorization(), Some(&AuthorizationFacet::NotConfigured));
    }
}
