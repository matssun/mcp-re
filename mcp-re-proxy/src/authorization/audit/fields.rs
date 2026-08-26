// SPDX-License-Identifier: Apache-2.0
//! How an authorization outcome is SPELLED on a diagnostic audit line.
//!
//! Separate from the outcome itself: [`AuthorizationFacet`](super::AuthorizationFacet) is
//! what the authority decided, and this is the one place that turns it into text. Two
//! authorities, and only one of them is a security fact — a record line's field names are a
//! reader-facing vocabulary that can change without any decision changing, and the reverse
//! must never be true.
//!
//! Rendered here rather than by the sink, so no sink has to learn authorization vocabulary
//! in order to write a record down. A structured sink matches on the type instead.

use super::AuthorizationFacet;
use super::AuthorizationRefusalFacet;
use crate::authorization::verified_action::AuthorizationTarget;

/// The target as one stable field, keeping the three states the coordinate distinguishes.
///
/// `named()` answers `None` for two of them, which is right for a policy that treats them
/// alike and wrong for a record: *this operation names no target* and *this operation names
/// one and the signed body carried none* are different facts about the request, and a reader
/// holding only the record could not recover the difference.
fn target_field(target: &AuthorizationTarget) -> &str {
    match target {
        AuthorizationTarget::NotApplicable => "none",
        AuthorizationTarget::Named(t) => t,
        AuthorizationTarget::Absent => "absent",
    }
}

impl AuthorizationFacet {
    /// This facet as stable `key=value` fields for the diagnostic audit line.
    ///
    /// Rendered HERE rather than by the sink, so no sink has to learn authorization
    /// vocabulary in order to write a record down. A structured sink matches on the type.
    pub fn audit_fields(&self) -> String {
        match self {
            AuthorizationFacet::NotConfigured => "authz=not-configured".to_owned(),
            AuthorizationFacet::Authorized(a) => format!(
                "authz=authorized authz_authority={} authz_version={} \
                 authz_decision_id={} authz_decision_evidence={} authz_operation={} \
                 authz_target={} authz_evidence={}",
                a.authority,
                a.version,
                a.authority_decision_id,
                a.decision_evidence.rendered(),
                a.action.operation(),
                target_field(a.action.target()),
                a.attributable_to.digest_value,
            ),
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy) => {
                "authz=refused-before-policy".to_owned()
            }
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(e)) => {
                format!(
                    "authz=refused-by-policy authz_policy_reason={}",
                    e.wire_code()
                )
            }
        }
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use crate::authorization::audit::AuthorizationFacet;

    /// The unconfigured posture has its own spelling, and it is not the authorized one.
    #[test]
    fn the_unconfigured_line_cannot_be_read_as_an_authorization() {
        let line = AuthorizationFacet::NotConfigured.audit_fields();
        assert_eq!(line, "authz=not-configured");
        assert!(!line.contains("authz=authorized"));
    }
}
