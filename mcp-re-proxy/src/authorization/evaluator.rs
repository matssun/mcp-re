// SPDX-License-Identifier: Apache-2.0
//! The mechanism seam — ADR-MCPRE-065 §5.
//!
//! ```text
//! verified semantic prerequisites
//!         v
//! mechanism adapter          <- token parsing, caveats, policy language live HERE
//!         v
//! authorization semantic fact
//!         v
//! serving decision
//! ```
//!
//! The same shape ADR-MCPRE-063 established for communication mechanisms. What crosses this
//! seam is verified facts in and a decision out; nothing above it learns how the decision
//! was reached, and nothing below it learns how the facts were verified.
//!
//! # The mechanism that ships, and the one that does not
//!
//! ADR-MCPS-013 selected Biscuit in the context of the native/JCS authorization carrier that
//! ADR-MCPRE-050 replaced, and ADR-MCPRE-065 R-1 rules that the selection does not carry
//! forward as a normative requirement for the RFC 9421 path. There is no Biscuit code in
//! this tree and no dependency to preserve.
//!
//! The mechanism chosen UNDER this architecture is the carried PDP decision
//! ([`super::pdp`], ADR-MCPRE-065 §8). It implements this trait, and `--authz pdp-decision`
//! installs it at the composition root — so a deployment can select it, and one that does
//! refuses any request no decision permits.
//!
//! A deployment that attaches no evaluator is not authorizing anything, and
//! [`AuthorizationPosture`](super::posture::AuthorizationPosture) says exactly that rather
//! than reporting an allow.
//!
//! # The denial taxonomy is the frozen one
//!
//! Failures cross the seam as [`PolicyError`], the ADR-MCPS-013 taxonomy, so a mechanism
//! adapter cannot mint a wire token. That taxonomy already separates a DENIAL from an
//! evaluation that could not complete — `authorization_revocation_unavailable` is the
//! worked case — and an adapter that cannot decide must choose the token that says so.
//! Both fail closed; they are not the same operational fact and are not reported as one.

use mcp_re_policy::PolicyError;

use super::decision_evidence::DecisionEvidenceIdentity;
use super::grant::GrantAttribution;
use super::request::AuthorizationRequest;

/// What a mechanism produces when it permits a request.
///
/// Two coordinates, kept apart because they answer different questions: the grant says which
/// authority decided and which of its decisions this was; the evidence identity says which
/// exact bytes this deployment authenticated and acted on. A single `evidence_id` folding
/// both would look like a cross-audit chain while being unable to distinguish two documents
/// an issuer gave one `jti`.
///
/// They travel as ONE value because the mechanism established them together. A seam handing
/// back two values would let a caller pair one decision's attribution with another's
/// evidence — two honest facts stating a false relation.
///
/// The evidence identity is REQUIRED, not optional. Every mechanism this architecture has
/// authenticates a carried decision document, so every one of them can name it, and an
/// `Option` here would have no production `None` — only test evaluators. If a mechanism
/// that decides without a carried artifact is ever selected, this becomes a sum type with
/// its own arm, and the compile error that forces the question is the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedDecision {
    grant: GrantAttribution,
    evidence: DecisionEvidenceIdentity,
}

impl AuthorizedDecision {
    /// Pair the attribution with the evidence it was read from. Called by the mechanism
    /// that established both.
    pub fn new(grant: GrantAttribution, evidence: DecisionEvidenceIdentity) -> Self {
        AuthorizedDecision { grant, evidence }
    }

    /// Which authority decided, under which policy version, and which decision it was.
    pub fn grant(&self) -> &GrantAttribution {
        &self.grant
    }

    /// Which exact decision evidence was authenticated and acted upon.
    pub fn evidence(&self) -> &DecisionEvidenceIdentity {
        &self.evidence
    }
}

/// A policy mechanism that decides over verified request facts.
///
/// `Send + Sync` because the serving path is thread-per-core and one evaluator is shared by
/// every core. Evaluation borrows: an implementation that needs interior state owns its own
/// synchronization, exactly as the admission and trust seams do.
pub trait AuthorizationEvaluator: Send + Sync {
    /// Decide whether this request's actor may perform this request's action.
    ///
    /// `Ok` names the policy authority that granted it and the evidence it decided from — a
    /// decision nobody can attribute is a decision nobody can revisit. `Err` is a refusal,
    /// carrying the frozen token that says why.
    fn evaluate(&self, request: &AuthorizationRequest) -> Result<AuthorizedDecision, PolicyError>;
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::AuthorizationEvaluator;
    use super::AuthorizedDecision;
    use crate::authorization::action_harness::verified_over;
    use crate::authorization::decision_evidence::DecisionEvidenceIdentity;
    use crate::authorization::grant::GrantAttribution;
    use crate::authorization::request::authorization_request;
    use crate::authorization::request::AuthorizationRequest;
    use mcp_re_policy::PolicyError;

    /// A conformance evaluator: grants exactly one tool to exactly one subject.
    ///
    /// It exists to exercise the SEAM, and it is `#[cfg(test)]` so it can never be reached
    /// from a serving path. A test needing an allow path is not a reason to promote an
    /// evaluator to production authority.
    struct OneToolForOneSubject;

    impl AuthorizationEvaluator for OneToolForOneSubject {
        fn evaluate(
            &self,
            request: &AuthorizationRequest,
        ) -> Result<AuthorizedDecision, PolicyError> {
            let subject_ok = request.actor().subject() == "did:example:agent-1";
            let target_ok = request.action().target().named() == Some("read");
            if subject_ok && target_ok {
                return Ok(AuthorizedDecision::new(
                    GrantAttribution::new("conformance", "1", "decision-1"),
                    DecisionEvidenceIdentity::from_verified_binding("sha-256", "fixture"),
                ));
            }
            Err(PolicyError::AuthorizationScopeDenied)
        }
    }

    const READ: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;
    const DELETE: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete"}}"#;

    #[test]
    fn the_seam_carries_verified_facts_in_and_an_attributed_grant_out() {
        let verified = verified_over(READ);
        let granted = OneToolForOneSubject
            .evaluate(&authorization_request(&verified, READ, None).expect("composes"))
            .expect("granted");
        assert_eq!(granted.grant().authority(), "conformance");
        assert_eq!(granted.grant().version(), "1");
        assert_eq!(granted.grant().authority_decision_id(), "decision-1");
    }

    /// The two coordinates are separate members of the product, not one field.
    ///
    /// A mechanism that answered both questions with one value would produce a record that
    /// looks like a cross-audit chain while being unable to distinguish two documents an
    /// issuer gave one `jti`.
    #[test]
    fn the_authority_decision_id_and_the_evidence_identity_are_different_coordinates() {
        let verified = verified_over(READ);
        let decision = OneToolForOneSubject
            .evaluate(&authorization_request(&verified, READ, None).expect("composes"))
            .expect("granted");
        assert_ne!(
            decision.grant().authority_decision_id(),
            decision.evidence().rendered(),
            "the authority's decision id must not be the evidence digest"
        );
    }

    #[test]
    fn a_denial_crosses_the_seam_as_the_frozen_token() {
        let verified = verified_over(DELETE);
        assert_eq!(
            OneToolForOneSubject
                .evaluate(&authorization_request(&verified, DELETE, None).expect("composes")),
            Err(PolicyError::AuthorizationScopeDenied)
        );
    }
}
