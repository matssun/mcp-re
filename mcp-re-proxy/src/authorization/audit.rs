// SPDX-License-Identifier: Apache-2.0
//! What the authorization authority contributes to an audit record — ADR-MCPRE-066 Slice 1.
//!
//! # The proposition
//!
//! Possession of an [`AuthorizationFacet`] means:
//!
//! > This deployment's authorization authority reached exactly this outcome for the request
//! > the record describes, stated in the authorization authority's own vocabulary.
//!
//! # Why this type exists at all
//!
//! `AuditEvent.reason` is Core's field. It carries an `McpReError::wire_code()` token and
//! nothing else, because ADR-MCPS-035 froze that vocabulary and the drift guard pins it.
//! Issue #637 measured what happens when a second authority needs to say something: its
//! token is rendered into that same field, and from the record alone nobody can tell which
//! authority spoke. ADR-MCPRE-066 ruled the two authorities independently describable, so
//! the fix is not a wider Core vocabulary — it is a *second coordinate* on the record.
//!
//! This is that coordinate. Core keeps `event_type`/`reason`; authorization keeps this; the
//! record co-locates them without either interpreting the other. **Co-location is not
//! conflation** (ADR-MCPRE-066 §4.3).
//!
//! # Three outcomes, because there are three facts
//!
//! ```text
//! NotConfigured   no policy is deployed; this boundary claims nothing
//! Authorized      a policy evaluated verified facts and permitted this action
//! Refused         no permission was established, by one of two authorities
//! ```
//!
//! The first two mirror [`AuthorizationPosture`](super::posture::AuthorizationPosture)
//! exactly, and for the reason that type gives: **`Off` is not `Allow`**. A record that
//! reported an unconfigured proxy the same way as a policy-protected one would destroy at
//! the record the distinction ADR-MCPRE-065 built three postures to keep in the type
//! (ADR-MCPRE-066 §1.1).
//!
//! There is no fourth *absent* state, and none is reachable: every request record carries
//! one of the three. Absence can therefore only ever mean *a record from before this slice*
//! — which is the whole content of ADR-MCPRE-066 R3.
//!
//! # `BeforePolicy` imports no vocabulary
//!
//! A request can fail long before any policy is consulted — its signature does not verify,
//! its nonce replays, its action coordinate cannot be read from the signed body. In every
//! such case the authorization authority has exactly one fact to contribute: *no policy
//! verdict was reached*. WHY is already stated by the Core-owned lifecycle reason on the
//! same record, so restating it here would put a copy of `McpReError` inside the
//! authorization authority — the merge this ADR exists to prevent, running the other way.
//!
//! # What this slice does not carry, and why not
//!
//! **No decision-evidence identity.** ADR-MCPRE-066 §4.4 names the digest bound by
//! `BoundDecisionEvidence` as the natural answer to *on what evidence*, and it is — but no
//! mechanism states it. [`GrantAttribution`](super::grant::GrantAttribution) returns
//! authority and version; obtaining a decision digest here would mean re-reading the
//! verified request at the audit site, which invariant 5 forbids, and representing it as an
//! `Option` whose `None` means both *no decision was presented* and *this deployment runs no
//! decision profile*. That is the shape `grant.rs` already refused for expiry, for the same
//! reason: it arrives with the first production mechanism, typed by what that mechanism can
//! establish. Until then the record answers *which exchange* with the request evidence
//! handle every other authority on this path attributes by.
//!
//! **No PDP-internal refusal detail.** ADR-MCPRE-066 R4: `PdpRelationRefusal` is a
//! mechanism-specific algebra and does not enter a normative audit facet.
//!
//! **No policy artifact, and no request material.** The action coordinate arrives as the
//! already-evaluated [`VerifiedAuthorizationAction`] — operation and target as the policy
//! saw them, never raw params and never a second representation of the request
//! (R-COMPOSE, ADR-MCPRE-066 R2 and invariant 7).

use mcp_re_http_profile::RequestEvidence;
use mcp_re_policy::PolicyError;

use super::verified_action::AuthorizationTarget;
use super::verified_action::VerifiedAuthorizationAction;

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

/// What this deployment's authorization authority says about one request.
///
/// Produced only by the owners of the facts it reports —
/// [`AuthorizationPosture::audit_facet`](super::posture::AuthorizationPosture::audit_facet)
/// and
/// [`AuthorizationRefusal::audit_facet`](super::decide::AuthorizationRefusal::audit_facet).
/// Nothing composes one out of parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationFacet {
    /// No authorization policy is deployed. NOT an allow, and not an examination.
    NotConfigured,
    /// A policy evaluated the verified facts and permitted this action.
    Authorized(AuthorizationAttribution),
    /// No permission was established.
    Refused(AuthorizationRefusalFacet),
}

/// Who authorized what, under which authority, on which exchange.
///
/// Every member is a projection of a fact an owner already established: two from the
/// grant the evaluator returned, two from the sealed request it decided over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationAttribution {
    /// The policy authority that permitted this.
    pub authority: String,
    /// The version of that authority's policy the decision was taken under.
    pub version: String,
    /// The operation and target as evaluated — never reconstructed from the request.
    pub action: VerifiedAuthorizationAction,
    /// The request evidence handle this decision is attributable to. A role-labelled
    /// digest, so naming the exchange costs no byte of its content.
    pub attributable_to: RequestEvidence,
}

/// Why no permission was established — and, load-bearingly, by which authority.
///
/// Two arms because ADR-MCPRE-065 has two refusal paths and only one of them reached a
/// policy at all. An operator sent to inspect a grant that was never consulted is an
/// operator the record has misled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationRefusalFacet {
    /// No policy verdict was reached. The defect is stated by the record's Core-owned
    /// lifecycle reason; this arm adds exactly one fact and imports no vocabulary.
    BeforePolicy,
    /// A policy decided, and the decision was not to permit. The token is the policy
    /// authority's own, in the authorization coordinate — never in Core's `reason`.
    ByPolicy(PolicyError),
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
                "authz=authorized authz_authority={} authz_version={} authz_operation={} \
                 authz_target={} authz_evidence={}",
                a.authority,
                a.version,
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
    use super::*;

    #[test]
    fn an_unconfigured_deployment_is_not_rendered_as_an_authorized_one() {
        // The record-level half of "`Off` is not `Allow`". These two lines must not be
        // confusable by a reader who has only the record.
        let off = AuthorizationFacet::NotConfigured.audit_fields();
        assert_eq!(off, "authz=not-configured");
        assert!(!off.contains("authorized"));
    }

    #[test]
    fn a_policy_denial_puts_its_token_in_the_authorization_coordinate() {
        // The whole point of the facet: the policy authority's token appears under its own
        // key, so a reader can tell WHICH authority refused. Issue #637 is the case where
        // this same token reached Core's `reason` and nothing could tell.
        let f = AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(
            PolicyError::AuthorizationScopeDenied,
        ));
        assert_eq!(
            f.audit_fields(),
            "authz=refused-by-policy authz_policy_reason=mcp-re.authorization_scope_denied"
        );
    }

    #[test]
    fn the_two_refusal_arms_are_distinguishable_in_the_record() {
        let before = AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy);
        let by = AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(
            PolicyError::AuthorizationBlockMissing,
        ));
        assert_ne!(before, by);
        assert_ne!(before.audit_fields(), by.audit_fields());
    }

    #[test]
    fn before_policy_imports_no_vocabulary() {
        // It names no error, from either authority. The lifecycle reason on the same record
        // already says what was wrong with the request.
        let line =
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy).audit_fields();
        assert!(!line.contains("mcp-re."), "got: {line}");
    }
}
