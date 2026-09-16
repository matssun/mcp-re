// SPDX-License-Identifier: Apache-2.0
//! What the §7 admission authority decided about one exchange, as a record coordinate.
//!
//! An INDEPENDENT typed coordinate, on the same terms ADR-MCPRE-066 gives authorization —
//! and for the same reason. Live, degraded and not-configured admission are not Core
//! lifecycle events: they are this authority's verdict, and ADR-MCPS-035 §3 freezes the
//! success-event allowlist precisely so a deployment cannot mint a third success token to
//! carry one. The allowlist constrains the VOCABULARY, not the requirement.
//!
//! Before this, `decide` returned `Result<(), _>` and every distinction below was discarded
//! (R11-106). A serve on a stale snapshot inside P was indistinguishable in audit from a
//! live-confirmed one, and *admission was checked and passed* produced the same trace as
//! *the call declared no admission and this deployment tolerates that.*

use crate::audit_record::text::AuditField;

/// The admission authority's own statement about one exchange.
///
/// A CLOSED vocabulary owned by this crate, like [`AuthorizationFacet`]. It is not a Core
/// token and never appears in an `event_type` or a `reason`; it is a coordinate beside them.
///
/// [`AuthorizationFacet`]: crate::authorization::AuthorizationFacet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionFacet {
    /// The exchange ended before the admission gate was consulted.
    ///
    /// Distinct from every answer below, and the distinction is the point: a refusal that
    /// happened earlier says nothing about admission, and a record that reported one of the
    /// other four would be claiming a decision nobody took.
    NotReached,
    /// No admission authority is deployed for this call.
    ///
    /// NOT an allow, and not an examination. The call declared no admission and this
    /// deployment tolerates that — which is a different fact from having been checked.
    NotConfigured,
    /// The authoritative current-state relation held: the state was about this workload, at
    /// the bound generation, and admitted.
    LiveConfirmed,
    /// Served on a last-known snapshot while the authority was unreachable, inside this
    /// replica's own degraded window.
    ///
    /// The one an operator most needs to find. A degraded serve is a serve the deployment
    /// chose to make without confirmation, and it is bounded by elapsed outage time this
    /// replica measured — never by the age of the assertion the caller presented.
    Degraded,
    /// No admission was established, so the exchange was refused.
    Refused,
}

impl AdmissionFacet {
    /// The record fields this authority contributes, in its own vocabulary.
    ///
    /// One token, and deliberately only one. Which workload, which generation and which
    /// authority are the ADMISSION EVIDENCE's facts and belong to whatever records that;
    /// what this coordinate answers is *what did the admission gate decide about this
    /// exchange*, and a coordinate that also restated the evidence would make two owners'
    /// statements indistinguishable on one line.
    pub(crate) fn audit_fields(self) -> Vec<AuditField<'static>> {
        vec![AuditField::token(
            "admission",
            match self {
                AdmissionFacet::NotReached => "not-reached",
                AdmissionFacet::NotConfigured => "not-configured",
                AdmissionFacet::LiveConfirmed => "live-confirmed",
                AdmissionFacet::Degraded => "degraded",
                AdmissionFacet::Refused => "refused",
            },
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five answers are five values, and each renders its own token.
    ///
    /// Stated as a control because the property that matters is exactly that none of them
    /// collapses into another. R11-106 was three distinctions being dropped at once, and a
    /// vocabulary that rendered two of these alike would reintroduce the defect one layer
    /// further out — where it is harder to see, because the record would look populated.
    #[test]
    fn every_verdict_renders_its_own_token() {
        let all = [
            AdmissionFacet::NotReached,
            AdmissionFacet::NotConfigured,
            AdmissionFacet::LiveConfirmed,
            AdmissionFacet::Degraded,
            AdmissionFacet::Refused,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for f in all {
            let fields = f.audit_fields();
            assert_eq!(
                fields.len(),
                1,
                "one coordinate, not a restated evidence set"
            );
            assert_eq!(fields[0].name, "admission");
            assert!(
                seen.insert(format!("{:?}", fields[0].value)),
                "{f:?} renders a token another verdict already used"
            );
        }
        assert_eq!(seen.len(), 5);
    }

    /// `NotConfigured` is not `LiveConfirmed`, and `NotReached` is neither.
    ///
    /// The three the old `Result<(), _>` folded together. An unconfigured deployment reads
    /// as *nobody asked*; a live-confirmed one as *asked, and the authority said yes*; and
    /// an exchange that never got there as *this record says nothing about admission*.
    #[test]
    fn the_three_the_discarded_result_folded_together_are_distinct() {
        assert_ne!(AdmissionFacet::NotConfigured, AdmissionFacet::LiveConfirmed);
        assert_ne!(AdmissionFacet::NotReached, AdmissionFacet::NotConfigured);
        assert_ne!(AdmissionFacet::NotReached, AdmissionFacet::LiveConfirmed);
        assert_ne!(AdmissionFacet::Degraded, AdmissionFacet::LiveConfirmed);
    }
}
