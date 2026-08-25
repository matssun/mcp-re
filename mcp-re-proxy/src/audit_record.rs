// SPDX-License-Identifier: Apache-2.0
//! What an audit record IS — ADR-MCPRE-066 Slice 1.
//!
//! Separate from [`crate::audit_sink`] because they answer different questions. The sink
//! owns delivery: the bounded hand-off, the attribution ceiling, the thread that owns
//! stderr. This owns composition — which authorities contribute to a record, and what each
//! is entitled to say.
//!
//! # A record composes products; it does not translate them
//!
//! ```text
//! Core verification evidence  ---+
//!                                +--> AuditRecord
//! Authorization evidence      ---+
//! ```
//!
//! Core owns `event_type` and `reason` and always did. Authorization owns
//! [`AuthorizationFacet`]. Neither is expressed in the other's vocabulary, and the record
//! does not interpret either — it carries both, side by side (ADR-MCPRE-066 §4.1, §4.3).
//!
//! # The record has a KIND, and the kind decides what may be said
//!
//! ```text
//! AuditRecord
//!     +-- Request   lifecycle + authorization
//!     +-- Response  lifecycle
//! ```
//!
//! Two things are structural here rather than remembered:
//!
//! * **A request record always carries an authorization facet.** There is no `Option` and no
//!   `NotApplicable`, so absence has exactly one meaning — a record from before this slice.
//!   That is ADR-MCPRE-066 R3, and it is why the facet's own `NotConfigured` is a state
//!   rather than an absence: *nobody asked* has to be sayable.
//! * **A response record cannot carry one.** Authorization is request-side (R5). A response
//!   record does not represent a second authorization decision, and the type will not let a
//!   caller pretend it does.
//!
//! The kind lives in [`AuditSubject`] with the exchange-wide fields beside it rather than
//! inside each arm. That is an encoding of the algebra ADR-MCPRE-066 §4.3 names, not a
//! departure from it: `actor_id`, `status` and `at_unix` are facts about the exchange in
//! every kind, and duplicating them per arm would make them look kind-specific.
//!
//! # Key lifecycle is not an `AuditRecord`
//!
//! ADR-MCPRE-066 §4.3 draws three arms. Only two are here, because the third never used
//! this type: the delegated-key lifecycle events (ADR-MCPRE-052 §7) are emitted by the
//! custody layer as bare [`AuditEvent`]s on its own path. Adding an arm nothing constructs
//! would model a producer that does not exist.

use mcp_re_core::audit::AuditEvent;

use crate::authorization::AuthorizationFacet;

/// One audit record: what happened, to whom, and when.
///
/// `actor_id` is the VERIFIER-RESOLVED actor for an accepted request (the same value the
/// continuation key is domain-separated by), and `None` when the request was rejected
/// before an actor could be resolved — which is itself the useful signal, so it is
/// represented rather than defaulted to a placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Which half of the exchange this record is about, and what each authority said.
    pub subject: AuditSubject,
    /// The verifier-resolved actor id, when one was established before this exit.
    pub actor_id: Option<String>,
    /// The HTTP status the PEP returned alongside this decision.
    pub status: u16,
    /// Unix seconds at the decision, taken from the serving path's clock (never a second,
    /// independently-read clock — two clocks would let the record disagree with the
    /// freshness decision it describes).
    pub at_unix: i64,
}

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

    /// The record's authority-specific fields as stable `key=value` text.
    ///
    /// Each authority renders its own vocabulary; this composes what they returned. A
    /// response record contributes nothing here, because there is nothing it may say.
    pub fn audit_fields(&self) -> String {
        match self {
            AuditSubject::Request { authorization, .. } => authorization.audit_fields(),
            AuditSubject::Response { .. } => String::new(),
        }
    }
}

impl AuditRecord {
    /// The frozen Core event this record carries.
    pub fn event(&self) -> &AuditEvent {
        self.subject.event()
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::AuthorizationRefusalFacet;
    use mcp_re_policy::PolicyError;

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
        assert_eq!(r.audit_fields(), "");
    }

    #[test]
    fn the_two_coordinates_stay_separate_on_one_record() {
        // Co-location is not conflation. Core's token is in `reason`; the policy's is in the
        // authorization field; neither appears in the other.
        let r = AuditRecord {
            subject: AuditSubject::request(
                AuditEvent::request_rejected_code("mcp-re.digest_mismatch"),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(
                    PolicyError::AuthorizationScopeDenied,
                )),
            ),
            actor_id: Some("did:example:agent-1".to_owned()),
            status: 403,
            at_unix: 1,
        };
        assert_eq!(r.event().reason, Some("mcp-re.digest_mismatch"));
        assert!(r
            .subject
            .audit_fields()
            .contains("authz_policy_reason=mcp-re.authorization_scope_denied"));
        assert!(!r.subject.audit_fields().contains("digest_mismatch"));
    }
}
