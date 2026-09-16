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

    #[test]
    fn a_request_record_always_states_an_authorization_outcome() {
        // R3 as a type property: there is no way to build one without saying which of the
        // three happened, so an absent facet can only mean a record from before this slice.
        let r = AuditSubject::request(
            AuditEvent::request_accepted(),
            AuthorizationFacet::NotConfigured,
        );
        let AuditSubject::Request { authorization, .. } = &r else {
            panic!("a request record");
        };
        assert_eq!(authorization, &AuthorizationFacet::NotConfigured);
    }

    #[test]
    fn a_response_record_has_no_authorization_coordinate_to_carry() {
        // R5, structurally. Authorization is request-side; a response record does not
        // represent a second decision, and cannot be made to claim one.
        let r = AuditSubject::response(AuditEvent::response_signed());
        assert!(matches!(r, AuditSubject::Response { .. }));
        assert!(r.audit_fields().is_empty());
    }
}
