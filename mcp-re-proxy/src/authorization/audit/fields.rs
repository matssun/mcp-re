// SPDX-License-Identifier: Apache-2.0
//! How an authorization outcome is SPELLED on a diagnostic audit line.
//!
//! Separate from the outcome itself: [`AuthorizationFacet`](super::AuthorizationFacet) is
//! what the authority decided, and this is the one place that turns it into text. Two
//! authorities, and only one of them is a security fact — a record line's field names are a
//! reader-facing vocabulary that can change without any decision changing, and the reverse
//! must never be true.
//!
//! Named here rather than by the sink, so no sink has to learn authorization vocabulary in
//! order to write a record down. A structured sink matches on the type instead.
//!
//! This module names fields and CLASSIFIES its own values; it does not spell them. The one
//! new decision it makes is the one it is uniquely qualified to make — for each of its own
//! values, is this a member of a closed vocabulary or is it open text? — and
//! [`crate::audit_record::text`] owns everything that follows from the answer. The
//! `&'static str` in [`AuditValue::Token`] is what makes the classification checkable: a
//! string read out of a request body cannot be `'static`.

use super::AuthorizationFacet;
use super::AuthorizationRefusalFacet;
use crate::audit_record::text::AuditField;
use crate::audit_record::text::AuditValue;
use crate::authorization::verified_action::AuthorizationTarget;

/// The target as one stable field, keeping the three states the coordinate distinguishes.
///
/// `named()` answers `None` for two of them, which is right for a policy that treats them
/// alike and wrong for a record: *this operation names no target* and *this operation names
/// one and the signed body carried none* are different facts about the request, and a reader
/// holding only the record could not recover the difference.
/// Two states are tokens of this module's own vocabulary and one is client-chosen text.
/// This is the one place the three-state distinction and the classification meet, which is
/// the right place for both.
fn target_field(target: &AuthorizationTarget) -> AuditValue<'_> {
    match target {
        AuthorizationTarget::NotApplicable => AuditValue::Token("none"),
        AuthorizationTarget::Named(t) => AuditValue::Text(t.as_str().into()),
        AuthorizationTarget::Absent => AuditValue::Token("absent"),
    }
}

impl AuthorizationFacet {
    /// This facet as named `key=value` fields, each value classified by this authority.
    ///
    /// Named HERE rather than by the sink, so no sink has to learn authorization vocabulary
    /// in order to write a record down. A structured sink matches on the type.
    ///
    /// The values borrow from `&self` rather than being cloned, and the arity varies by arm
    /// — which is why this is a `Vec` and not a fixed array.
    pub(crate) fn audit_fields(&self) -> Vec<AuditField<'_>> {
        match self {
            AuthorizationFacet::NotConfigured => {
                vec![AuditField::token("authz", "not-configured")]
            }
            AuthorizationFacet::Authorized(a) => vec![
                AuditField::token("authz", "authorized"),
                // Everything below is chosen off-box: the first four by the PDP that signed
                // the decision, the next two by whichever enrolled client signed the body.
                // A trusted issuer is still not this proxy's operator, so none of them is a
                // token of a vocabulary this crate closes.
                AuditField::text("authz_authority", a.authority.as_str()),
                AuditField::text("authz_version", a.version.as_str()),
                AuditField::text("authz_decision_id", a.authority_decision_id.as_str()),
                AuditField::text("authz_decision_evidence", a.decision_evidence.rendered()),
                AuditField::text("authz_operation", a.action.operation()),
                AuditField {
                    name: "authz_target",
                    value: target_field(a.action.target()),
                },
                AuditField::text("authz_evidence", a.attributable_to.digest_value.as_str()),
            ],
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy) => {
                vec![AuditField::token("authz", "refused-before-policy")]
            }
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(e)) => vec![
                AuditField::token("authz", "refused-by-policy"),
                AuditField::token("authz_policy_reason", e.wire_code()),
            ],
        }
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_record::scalar::unescape_scalar;
    use crate::audit_record::text::render_record;
    use crate::authorization::audit::AuthorizationFacet;

    /// The unconfigured posture has its own spelling, and it is not the authorized one.
    #[test]
    fn the_unconfigured_line_cannot_be_read_as_an_authorization() {
        let fields = AuthorizationFacet::NotConfigured.audit_fields();
        assert_eq!(fields, vec![AuditField::token("authz", "not-configured")]);
        let line = render_record(&fields);
        assert_eq!(line, "authz=not-configured");
        assert!(!line.contains("authz=authorized"));
    }

    /// A client-chosen target is classified as TEXT, and this module's own two states as
    /// tokens.
    ///
    /// `target_field` is the one place in this module where a `Token` arm and a `Text` arm
    /// sit in one match over the same coordinate, so it is the one place a
    /// misclassification is expressible at all. The other client-controlled value,
    /// `authz_operation`, cannot be misclassified: `AuditValue::Token` takes
    /// `&'static str`, and a `String` read out of a request body is not `'static`, so the
    /// mistake is a compile error rather than something a test has to catch.
    #[test]
    fn a_client_named_target_is_classified_as_text() {
        let forged = "read\nmcp-re-proxy: audit seq=9 event=mcp-re.request.accepted";
        let named = AuthorizationTarget::Named(forged.to_owned());

        assert_eq!(target_field(&named), AuditValue::Text(forged.into()));
        assert_eq!(
            target_field(&AuthorizationTarget::NotApplicable),
            AuditValue::Token("none")
        );
        assert_eq!(
            target_field(&AuthorizationTarget::Absent),
            AuditValue::Token("absent")
        );

        let line = render_record(&[AuditField {
            name: "authz_target",
            value: target_field(&named),
        }]);
        assert!(!line.contains('\n'), "{line}");
        assert_eq!(line.split(' ').count(), 1, "{line}");
        let (name, value) = line.split_once('=').expect("one field");
        assert_eq!(name, "authz_target");
        assert_eq!(unescape_scalar(value).as_deref(), Some(forged));
    }
}
