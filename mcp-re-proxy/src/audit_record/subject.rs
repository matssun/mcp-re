// SPDX-License-Identifier: Apache-2.0
//! WHICH HALF of an exchange a record is about, and therefore which authorities may speak.
//!
//! The structural half of ADR-MCPRE-066: a request record always states an authorization
//! outcome and a response record has none to carry. Separate from [`super::AuditRecord`]
//! because they own different things — the record carries the exchange-wide facts, and
//! this decides what a record of that kind is ENTITLED to say. Two things a reviewer must
//! be able to check independently, and only one of them is a closed algebra.
//!
//! # No entry point takes an `AuditEvent` (R11-161)
//!
//! The variant said which half a record was about, and so did the event's own `event_type`
//! — two representations of one fact, and they could disagree:
//! `AuditSubject::request(AuditEvent::response_signed(), NotConfigured)` compiled and was a
//! legal inhabitant. Deleting the correct pairing at either emitter brought an invalid one
//! into existence immediately, so the constructors were REMEMBERING the invariant rather
//! than owning it.
//!
//! It is owned now because there is nothing left to remember: **no public constructor
//! accepts an event.** Each of the four produces its own, so a mismatched inhabitant is not
//! refused — it cannot be named. That shape is available because it was MEASURED to be: not
//! one of the six production call sites passed an event that was a variable, and the two
//! that branched kept both arms on the same half.
//!
//! It mints no vocabulary. Each constructor calls exactly one `mcp-re-core` constructor, or
//! picks between a verdict and its `_elsewhere` sibling on a fact the emitter already holds.
//! Which events EXIST stays Core's, pinned by the ADR-MCPS-035 drift guard, and
//! [`AuditEvent::half`] is what lets this file be checked against that rather than against a
//! list of its own.

use mcp_re_core::audit::AuditEvent;
use mcp_re_core::McpReError;

use crate::audit_record::text::AuditField;
use crate::authorization::AuthorizationFacet;

/// Which half of the exchange a record is about — and therefore which authorities may speak.
///
/// OPAQUE. The arms are private because a public one is a public constructor: a caller could
/// name `Request { event, authorization }` with a response-half event and rebuild the exact
/// inhabitant the four constructors exist to prevent. Downstream gets named projections —
/// [`event`](Self::event), [`authorization`](Self::authorization),
/// [`audit_fields`](Self::audit_fields) — which is all any consumer was reading anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSubject(Subject);

/// The representation. Private to this module, which is the only lever that binds a consumer
/// living in this crate — `#[non_exhaustive]` and `pub(crate)` bind other crates, and every
/// consumer here is in this one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Subject {
    /// The request half: a Core lifecycle outcome and this deployment's authorization
    /// outcome, as two separately-typed coordinates that happen to share a record.
    Request {
        /// The frozen Core event (type + decision + `mcp-re.*` reason for a rejection).
        event: AuditEvent,
        /// What the authorization authority says about this request.
        authorization: AuthorizationFacet,
    },
    /// The response half: a Core lifecycle outcome, and nothing about authorization.
    Response {
        /// The frozen Core event.
        event: AuditEvent,
    },
}

impl AuditSubject {
    /// A record for an ACCEPTED request. The facet is required, not defaulted.
    pub fn request_accepted(authorization: AuthorizationFacet) -> Self {
        AuditSubject(Subject::Request {
            event: AuditEvent::request_accepted(),
            authorization,
        })
    }

    /// A record for a REFUSED request. `Some` when Core decided the verdict, `None` when the
    /// authority that terminated the exchange was not Core.
    pub fn request_rejected(
        verdict: Option<&McpReError>,
        authorization: AuthorizationFacet,
    ) -> Self {
        AuditSubject(Subject::Request {
            event: match verdict {
                Some(e) => AuditEvent::request_rejected(e),
                None => AuditEvent::request_rejected_elsewhere(),
            },
            authorization,
        })
    }

    /// A record for a SIGNED response.
    pub fn response_signed() -> Self {
        AuditSubject(Subject::Response {
            event: AuditEvent::response_signed(),
        })
    }

    /// A record for a REFUSED response, on the same terms as
    /// [`request_rejected`](Self::request_rejected).
    pub fn response_rejected(verdict: Option<&McpReError>) -> Self {
        AuditSubject(Subject::Response {
            event: match verdict {
                Some(e) => AuditEvent::response_rejected(e),
                None => AuditEvent::response_rejected_elsewhere(),
            },
        })
    }

    /// The frozen Core event, which every kind carries.
    pub fn event(&self) -> &AuditEvent {
        match &self.0 {
            Subject::Request { event, .. } | Subject::Response { event } => event,
        }
    }

    /// What the authorization authority said, when this record is entitled to carry it.
    ///
    /// `None` on a response record, and that is the shape of the claim rather than missing
    /// data: authorization is request-side, so a response has nothing to say about it. The
    /// projection replaces a destructure — a consumer that matched
    /// `Request { authorization, .. }` was reading exactly this, and reading it through the
    /// representation is what let the representation be rebuilt.
    pub fn authorization(&self) -> Option<&AuthorizationFacet> {
        match &self.0 {
            Subject::Request { authorization, .. } => Some(authorization),
            Subject::Response { .. } => None,
        }
    }

    /// The authority-specific fields, composed from what each authority named in its own
    /// vocabulary. A response record contributes nothing: there is nothing it may say.
    ///
    /// Fields rather than text, because text is where the property dies: a finished string
    /// cannot tell a separator its owner emitted from one that arrived inside a value. The
    /// spelling is [`super::text::render_record`]'s to decide, and it is the only thing that
    /// decides it.
    pub(crate) fn audit_fields(&self) -> Vec<AuditField<'_>> {
        match &self.0 {
            Subject::Request { authorization, .. } => authorization.audit_fields(),
            Subject::Response { .. } => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request record contributes the authorization authority's OWN fields, unchanged.
    ///
    /// R3's structural half — that a request record cannot omit an authorization outcome —
    /// is the absence of an `Option` in the enum, and no runtime control can fail to observe
    /// it. What CAN regress is this arm rebuilding, filtering or renaming what the authority
    /// produced, which is how a coordinate stops being the authority's statement and starts
    /// being this type's opinion of it. Asserted against the facet's own projection rather
    /// than against a literal, so a change to the vocabulary moves both sides together and
    /// only a change to the DELEGATION moves one.
    #[test]
    fn a_request_record_contributes_the_authorization_authoritys_own_fields() {
        let facet =
            AuthorizationFacet::Refused(crate::authorization::AuthorizationRefusalFacet::ByPolicy(
                mcp_re_policy::PolicyError::AuthorizationScopeDenied,
            ));
        let subject = AuditSubject::request_accepted(facet.clone());
        assert_eq!(
            subject.audit_fields(),
            facet.audit_fields(),
            "the arm carries what the authority said; it does not restate it"
        );
        assert!(
            !subject.audit_fields().is_empty(),
            "and the authority did say something, or the comparison above is vacuous"
        );
    }

    /// R5: a response record has nothing to say about authorization, and says nothing.
    ///
    /// Authorization is request-side. That a `Response` arm cannot CARRY a facet is the
    /// enum's shape; what this measures is the projection — an arm that grew a contribution
    /// would put a second authorization decision on the record for an exchange that took
    /// one.
    #[test]
    fn a_response_record_contributes_nothing_to_say() {
        let subject = AuditSubject::response_signed();
        assert!(subject.audit_fields().is_empty());
    }

    /// **R11-161.** Every constructor lands on the arm whose half CORE reports, so the two
    /// representations of *which half is this about* cannot disagree.
    ///
    /// This is the control that makes the seal checkable rather than merely tidy. Each
    /// constructor calls exactly one `mcp-re-core` constructor; one rewired to the wrong
    /// Core call still compiles, and this is what fails. Asserted against
    /// [`AuditEvent::half`] rather than against a literal, so the mapping stays Core's — a
    /// second list here would be the duplication the seal exists to remove.
    #[test]
    fn every_constructor_lands_on_the_arm_core_says_it_is_about() {
        use mcp_re_core::audit::AuditHalf;
        let err = mcp_re_core::McpReError::ReplayDetected;
        let request_side = [
            AuditSubject::request_accepted(AuthorizationFacet::NotConfigured),
            AuditSubject::request_rejected(Some(&err), AuthorizationFacet::NotConfigured),
            AuditSubject::request_rejected(None, AuthorizationFacet::NotConfigured),
        ];
        for s in &request_side {
            assert_eq!(s.event().half(), AuditHalf::Request);
            assert!(
                s.authorization().is_some(),
                "a request record carries the facet"
            );
        }
        let response_side = [
            AuditSubject::response_signed(),
            AuditSubject::response_rejected(Some(&err)),
            AuditSubject::response_rejected(None),
        ];
        for s in &response_side {
            assert_eq!(s.event().half(), AuditHalf::Response);
            assert!(
                s.authorization().is_none(),
                "a response record has none to carry"
            );
        }
    }

    /// A rejection whose verdict CORE reached keeps its token; one it did not reach carries
    /// none, and the two are different records.
    ///
    /// The `Option` is the only thing either rejection constructor decides, and it decides
    /// it from a fact the emitter already holds (`core_verdict()`). Folding the two together
    /// would put a policy's refusal into Core's `reason`, which ADR-MCPRE-066 §1.1 refuses.
    #[test]
    fn a_verdict_core_did_not_reach_carries_no_core_reason() {
        let err = mcp_re_core::McpReError::ReplayDetected;
        let decided = AuditSubject::request_rejected(Some(&err), AuthorizationFacet::NotConfigured);
        let elsewhere = AuditSubject::request_rejected(None, AuthorizationFacet::NotConfigured);
        assert_eq!(decided.event().reason, Some(err.wire_code()));
        assert_eq!(elsewhere.event().reason, None);
        assert_ne!(decided.event(), elsewhere.event());
    }
}
