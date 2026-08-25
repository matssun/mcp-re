// SPDX-License-Identifier: Apache-2.0
//! Why a decision does not authorize a request, and how that renders on the wire.
//!
//! Two separable things, kept in one file because the second is a projection of the first:
//! the ALGEBRA is what this authority decided, and the RENDERING is what the frozen
//! ADR-MCPS-013 vocabulary can express about it. Splitting them further would hide that the
//! rendering loses information — which is exactly what the comments here exist to record.

use mcp_re_http_profile::pdp_decision::DecisionScope;
use mcp_re_http_profile::pdp_decision::PdpDecisionRefusal;
use mcp_re_policy::PolicyError;

use super::evidence::DecisionEvidenceRefusal;

/// Why a decision does not authorize this request.
///
/// Its own algebra because each arm is a different thing to do about it: a stale decision is
/// a clock or a lifetime, a scope mismatch is a configuration, an actor mismatch is a
/// presenter, an explicit deny is the policy working. They are rendered onto the frozen
/// `mcp-re.authorization_*` tokens at the boundary — which is where the wire vocabulary is
/// owned, and where the conflations the frozen set forces are named rather than hidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdpRelationRefusal {
    /// The deployment requires a decision and the request presented none.
    NoDecisionPresented,
    /// The presented bytes are not the ones the request's binding committed to.
    EvidenceNotBound(DecisionEvidenceRefusal),
    /// The decision could not be authenticated as an authority's statement.
    NotAuthenticated(PdpDecisionRefusal),
    /// The decision is scoped differently from what this deployment accepts.
    ScopeNotAccepted {
        /// What the signed decision says it is.
        decided: DecisionScope,
        /// What this deployment acts on.
        accepted: DecisionScope,
    },
    /// The decision is about a different principal, credential, or trust domain.
    DifferentActor,
    /// The decision permits a different operation or target than the signed body asks for.
    DifferentAction,
    /// The authority evaluated this and refused it.
    ExplicitDeny,
}

impl PdpRelationRefusal {
    /// The frozen ADR-MCPS-013 wire token this refusal is served as.
    ///
    /// Two conflations the frozen set forces, both named rather than papered over:
    ///
    /// * **An untrusted issuer and a bad signature are one token.** They are different facts
    ///   — an authority this deployment has not been told about is not a forgery — and only
    ///   the diagnostic channel can tell them apart. `authorization_signature_invalid` is
    ///   nevertheless the truthful one for both: neither could be authenticated under the
    ///   configured authorization-authority trust.
    /// * **An explicit deny and an action mismatch are one token.** The taxonomy has no
    ///   generic `authorization_denied`, so `authorization_scope_denied` is this profile's
    ///   coarse policy-denial surface.
    ///
    /// `authorization_binding_profile_required` keeps its documented meaning exactly: no
    /// authorization-authority profile is configured at all, so there is nobody to validate
    /// against. That is a deployment fact, not a caller fact, and it is not conflated with
    /// an issuer a configured resolver refuses.
    pub fn wire_code(&self) -> PolicyError {
        match self {
            PdpRelationRefusal::NoDecisionPresented => PolicyError::AuthorizationBlockMissing,
            PdpRelationRefusal::EvidenceNotBound(DecisionEvidenceRefusal::DigestMismatch) => {
                PolicyError::AuthorizationHashMismatch
            }
            PdpRelationRefusal::EvidenceNotBound(_) => PolicyError::AuthorizationMalformed,
            PdpRelationRefusal::NotAuthenticated(PdpDecisionRefusal::Malformed(_)) => {
                PolicyError::AuthorizationMalformed
            }
            PdpRelationRefusal::NotAuthenticated(PdpDecisionRefusal::AudienceMismatch) => {
                PolicyError::AuthorizationAudienceMismatch
            }
            PdpRelationRefusal::NotAuthenticated(
                PdpDecisionRefusal::Expired
                | PdpDecisionRefusal::Stale
                | PdpDecisionRefusal::IssuedInTheFuture,
            ) => PolicyError::AuthorizationExpired,
            PdpRelationRefusal::NotAuthenticated(
                PdpDecisionRefusal::IssuerUntrusted
                | PdpDecisionRefusal::SignatureInvalid
                | PdpDecisionRefusal::ProfileMismatch,
            ) => PolicyError::AuthorizationSignatureInvalid,
            PdpRelationRefusal::ScopeNotAccepted { .. } => {
                PolicyError::AuthorizationProfileUnsupported
            }
            PdpRelationRefusal::DifferentActor => PolicyError::AuthorizationSignerMismatch,
            PdpRelationRefusal::DifferentAction | PdpRelationRefusal::ExplicitDeny => {
                PolicyError::AuthorizationScopeDenied
            }
        }
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::PdpRelationRefusal;
    use crate::authorization::pdp::evidence::DecisionEvidenceRefusal;
    use mcp_re_http_profile::pdp_decision::DecisionScope;
    use mcp_re_http_profile::pdp_decision::PdpDecisionRefusal;
    use mcp_re_policy::PolicyError;

    #[test]
    fn no_configured_authority_and_an_untrusted_issuer_are_different_tokens() {
        // The correction this profile exists to get right. `binding_profile_required` means
        // the DEPLOYMENT configured nobody to validate against; an issuer a configured
        // resolver refuses is a different fact and must not borrow that token.
        assert_eq!(
            PdpRelationRefusal::NotAuthenticated(PdpDecisionRefusal::IssuerUntrusted).wire_code(),
            PolicyError::AuthorizationSignatureInvalid
        );
        assert_ne!(
            PdpRelationRefusal::NotAuthenticated(PdpDecisionRefusal::IssuerUntrusted).wire_code(),
            PolicyError::AuthorizationBindingProfileRequired
        );
    }

    #[test]
    fn a_digest_mismatch_is_not_reported_as_a_malformed_artifact() {
        assert_eq!(
            PdpRelationRefusal::EvidenceNotBound(DecisionEvidenceRefusal::DigestMismatch)
                .wire_code(),
            PolicyError::AuthorizationHashMismatch
        );
        assert_eq!(
            PdpRelationRefusal::EvidenceNotBound(DecisionEvidenceRefusal::NotTheEvidenceForm)
                .wire_code(),
            PolicyError::AuthorizationMalformed
        );
    }

    #[test]
    fn an_actor_mismatch_and_an_action_mismatch_are_different_tokens() {
        assert_eq!(
            PdpRelationRefusal::DifferentActor.wire_code(),
            PolicyError::AuthorizationSignerMismatch
        );
        assert_eq!(
            PdpRelationRefusal::DifferentAction.wire_code(),
            PolicyError::AuthorizationScopeDenied
        );
    }

    #[test]
    fn an_explicit_deny_and_an_action_mismatch_collapse_onto_one_token() {
        // The conflation the frozen taxonomy forces, asserted so it stays a KNOWN cost
        // rather than a surprise: there is no generic `authorization_denied`.
        assert_eq!(
            PdpRelationRefusal::ExplicitDeny.wire_code(),
            PdpRelationRefusal::DifferentAction.wire_code()
        );
    }

    #[test]
    fn a_scope_the_deployment_does_not_accept_is_not_an_actor_mismatch() {
        // The actor may match on every dimension; the decision is simply not the KIND of
        // decision this deployment acts on, which is a profile fact.
        assert_eq!(
            PdpRelationRefusal::ScopeNotAccepted {
                decided: DecisionScope::Credential,
                accepted: DecisionScope::Principal,
            }
            .wire_code(),
            PolicyError::AuthorizationProfileUnsupported
        );
    }

    #[test]
    fn a_request_presenting_nothing_says_so_rather_than_borrowing_a_denial() {
        assert_eq!(
            PdpRelationRefusal::NoDecisionPresented.wire_code(),
            PolicyError::AuthorizationBlockMissing
        );
    }
}
