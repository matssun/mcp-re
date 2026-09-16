// SPDX-License-Identifier: Apache-2.0
//! WHICH HALF of an exchange a record is about, and therefore which authorities may speak.
//!
//! The structural half of ADR-MCPRE-066: a request record always states an authorization
//! outcome and a response record has none to carry. Separate from [`super::AuditRecord`]
//! because they own different things — the record carries the exchange-wide facts, and
//! this decides what a record of that kind is ENTITLED to say. Two things a reviewer must
//! be able to check independently, and only one of them is a closed algebra.

use mcp_re_core::audit::AuditEvent;

use crate::audit_record::text::AuditField;
use crate::authorization::AuthorizationFacet;

/// Which half of the exchange a record is about — and therefore which authorities may speak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditSubject {
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
    /// A record about the request half. The facet is required, not defaulted.
    pub fn request(event: AuditEvent, authorization: AuthorizationFacet) -> Self {
        AuditSubject::Request {
            event,
            authorization,
        }
    }

    /// A record about the response half.
    pub fn response(event: AuditEvent) -> Self {
        AuditSubject::Response { event }
    }

    /// The frozen Core event, which every kind carries.
    pub fn event(&self) -> &AuditEvent {
        match self {
            AuditSubject::Request { event, .. } | AuditSubject::Response { event } => event,
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
        match self {
            AuditSubject::Request { authorization, .. } => authorization.audit_fields(),
            AuditSubject::Response { .. } => Vec::new(),
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
        let subject = AuditSubject::request(AuditEvent::request_accepted(), facet.clone());
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
        let subject = AuditSubject::response(AuditEvent::response_signed());
        assert!(subject.audit_fields().is_empty());
    }
}
