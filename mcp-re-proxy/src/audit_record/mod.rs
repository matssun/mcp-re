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

pub(crate) mod scalar;
pub(crate) mod subject;
pub(crate) mod text;

use mcp_re_core::audit::AuditEvent;
use mcp_re_core::audit::Decision;

use crate::audit_record::text::AuditField;

pub use subject::AuditSubject;

/// One audit record: what happened, to whom, and when.
///
/// # What holding one proves, and what it does not
///
/// A record is a CARRIER. Possession of one is not evidence that this proxy emitted it,
/// and the type does not attempt to make it so: the fields are open, and any code that can
/// name the type can compose a record saying whatever it likes.
///
/// Provenance is owned where records are produced — [`record_to`] and the serving path
/// that calls it — because that is where a record's values are projections of decisions an
/// authority already took. The structural algebra is owned by [`AuditSubject`], and that
/// part IS the record's: no caller can build a request record without stating an
/// authorization outcome, or a response record that claims one.
///
/// Sealing construction would buy nothing here. Every consumer is an
/// [`AuditSink`](crate::audit_sink::AuditSink) installed by this process's own composition
/// root, the type has no deserialization and no wire form, and nothing outside the crate
/// produces a record — the public surface exists so an embedder can INSTALL a sink and
/// read what reached it. A sealed constructor would therefore not exclude one record a
/// reader currently has to trust.
///
/// `actor_id` carries the verifier-resolved actor when the serving path had one — the same
/// value the continuation key is domain-separated by — and `None` when the request was
/// rejected before an actor could be resolved, which is itself the useful signal and so is
/// represented rather than defaulted to a placeholder. Its meaning is that producer's
/// claim, not this type's guarantee, and the delivery ceiling that reads it
/// ([`crate::audit_sink`]) is accounting for its own queue rather than adjudicating
/// provenance.
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

impl AuditRecord {
    /// The frozen Core event this record carries.
    pub fn event(&self) -> &AuditEvent {
        self.subject.event()
    }

    /// Every field this record contributes, each value classified by its owner.
    ///
    /// Every value is a number or a closed-vocabulary member except `actor`, which is a
    /// resolved identity built from four components: a `keyid` held to the
    /// signature-parameter charset, and three values out of the operator's trust store.
    /// That charset admits SPACE and `=`, so an enrolled `keyid` of `k status=200` would
    /// otherwise contribute a second `key=value` token and shadow a real field for any
    /// last-wins reader. It is [`AuditValue::Text`], and the constraint that bounds it
    /// lives in another crate on an ancestor — which is the reason not to lean on it.
    ///
    /// `decision` is matched exhaustively rather than taken from `{:?}`, so the spelling is
    /// this crate's decision rather than a derive it inherits. Core's `Decision` gains no
    /// `wire_name()` for it: that vocabulary is frozen behind a drift guard.
    pub(crate) fn audit_fields(&self) -> Vec<AuditField<'_>> {
        let event = self.event();
        let mut fields = vec![
            AuditField::token("event", event.event_type),
            AuditField::token(
                "decision",
                match event.decision {
                    Decision::Accepted => "Accepted",
                    Decision::Signed => "Signed",
                    Decision::Rejected => "Rejected",
                },
            ),
            AuditField::token_or_absent("reason", event.reason),
            AuditField::text_or_absent("actor", self.actor_id.as_deref()),
            AuditField::number("status", i64::from(self.status)),
            AuditField::number("at", self.at_unix),
        ];
        fields.extend(self.subject.audit_fields());
        fields
    }
}

/// Deliver one record, if a sink is installed.
///
/// The one place that turns "a sink may or may not be installed" into an emission, so no
/// emitter carries its own copy of that conditional. `subject` decides which authorities
/// the record carries; the caller that knows which half of the exchange it is reporting
/// makes that choice, and the type refuses the other combination.
pub(crate) fn record_to(
    audit: &crate::audit_sink::MaybeAuditSink,
    subject: AuditSubject,
    actor_id: Option<String>,
    status: u16,
    now: i64,
) {
    if let Some(sink) = audit {
        sink.record(&AuditRecord {
            subject,
            actor_id,
            status,
            at_unix: now,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_record::text::render_record;
    use crate::authorization::AuthorizationFacet;
    use crate::authorization::AuthorizationRefusalFacet;
    use mcp_re_core::audit::AuditEvent;
    use mcp_re_policy::PolicyError;

    #[test]
    fn the_two_coordinates_stay_separate_on_one_record() {
        // Co-location is not conflation. Core's token is in `reason`; the policy's is in the
        // authorization field; neither appears in the other.
        let r = AuditRecord {
            subject: AuditSubject::request(
                AuditEvent::request_rejected(&mcp_re_core::McpReError::DigestMismatch),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(
                    PolicyError::AuthorizationScopeDenied,
                )),
            ),
            actor_id: Some("did:example:agent-1".to_owned()),
            status: 403,
            at_unix: 1,
        };
        assert_eq!(r.event().reason, Some("mcp-re.digest_mismatch"));
        let rendered = render_record(&r.subject.audit_fields());
        assert!(
            rendered.contains("authz_policy_reason=mcp-re.authorization_scope_denied"),
            "{rendered}"
        );
        assert!(!rendered.contains("digest_mismatch"), "{rendered}");
    }
}
