// SPDX-License-Identifier: Apache-2.0
//! The relation between a verified request and an authenticated decision.
//!
//! Where the chain in [`super`] ends: authenticated claims on one side, ADR-MCPRE-065's
//! verified facts on the other, and the question *is this decision about THIS request, and
//! does it permit it*.

use mcp_re_http_profile::pdp_decision::verify_authorization_decision;
use mcp_re_http_profile::pdp_decision::PdpDecisionClaims;
use mcp_re_http_profile::pdp_decision::PdpDecisionOutcome;
use mcp_re_policy::PolicyError;

use super::policy::PdpDecisionPolicy;
use super::refusal::PdpRelationRefusal;
use crate::authorization::evaluator::AuthorizationEvaluator;
use crate::authorization::grant::GrantAttribution;
use crate::authorization::request::AuthorizationRequest;
use crate::authorization::verified_action::AuthorizationTarget;

/// The production PDP-decision evaluator.
pub struct PdpDecisionEvaluator {
    policy: PdpDecisionPolicy,
    /// The audiences this enforcement point answers to — a decision naming none of them was
    /// issued for somewhere else.
    audiences: Vec<String>,
    /// The evidence profile this deployment serves.
    profile: String,
    /// The clock. Injected so a control can place a decision in time without sleeping.
    now: std::sync::Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl PdpDecisionEvaluator {
    /// Wire the mechanism for one deployment.
    pub fn new(
        policy: PdpDecisionPolicy,
        profile: impl Into<String>,
        audiences: Vec<String>,
        now: std::sync::Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        PdpDecisionEvaluator {
            policy,
            audiences,
            profile: profile.into(),
            now,
        }
    }

    /// The actor relation, at the scope the decision itself declares.
    ///
    /// Every dimension compared separately against a verified fact. Nothing parses a
    /// composite `actor_id()` back into components — the defect ADR-MCPRE-064 Slice 4
    /// removed from the transport binding, and the reason each dimension is its own claim.
    fn actor_matches(&self, claims: &PdpDecisionClaims, request: &AuthorizationRequest) -> bool {
        let decided = &claims.mcp_re_decided_actor;
        let actor = request.actor();
        if decided.trust_domain() != actor.trust_domain() || decided.subject() != actor.subject() {
            return false;
        }
        // A principal-scoped decision has no keyid to compare, which is the scope speaking.
        // A credential-scoped one always has one, so there is no absent-field branch here at
        // all: the type made it unrepresentable.
        match decided.keyid() {
            None => true,
            Some(keyid) => keyid == actor.keyid(),
        }
    }

    /// The action relation, over the signed body's coordinate (Law A-1).
    ///
    /// The target is compared as the typed value, not as two `Option`s: a decision naming no
    /// target must not authorize an operation that names one, and *the body omitted its
    /// target* is a third state that matches neither.
    fn action_matches(&self, claims: &PdpDecisionClaims, request: &AuthorizationRequest) -> bool {
        if claims.mcp_re_decided_operation != request.action().operation() {
            return false;
        }
        match (
            claims.mcp_re_decided_target.as_deref(),
            request.action().target(),
        ) {
            (None, AuthorizationTarget::NotApplicable) => true,
            (Some(decided), AuthorizationTarget::Named(asked)) => decided == asked,
            // `Absent` matches nothing. A request that named no tool was not decided.
            _ => false,
        }
    }

    /// Run the chain.
    fn decide(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<GrantAttribution, PdpRelationRefusal> {
        let evidence = request
            .decision_evidence()
            .map_err(PdpRelationRefusal::EvidenceNotBound)?
            .ok_or(PdpRelationRefusal::NoDecisionPresented)?;

        let audiences: Vec<&str> = self.audiences.iter().map(String::as_str).collect();
        let claims = verify_authorization_decision(
            evidence.document(),
            &self.profile,
            &audiences,
            &self.policy.freshness,
            (self.now)(),
            |kid| (self.policy.resolve_authority)(kid),
        )
        .map_err(PdpRelationRefusal::NotAuthenticated)?;

        let decided_scope = claims.mcp_re_decided_actor.scope();
        if decided_scope != self.policy.accepted_scope {
            return Err(PdpRelationRefusal::ScopeNotAccepted {
                decided: decided_scope,
                accepted: self.policy.accepted_scope,
            });
        }
        if !self.actor_matches(&claims, request) {
            return Err(PdpRelationRefusal::DifferentActor);
        }
        if !self.action_matches(&claims, request) {
            return Err(PdpRelationRefusal::DifferentAction);
        }
        // LAST. Everything above establishes that this decision is ABOUT this request; only
        // the decision itself says whether the request may proceed.
        match claims.mcp_re_decision {
            PdpDecisionOutcome::Permit => Ok(GrantAttribution::new(
                claims.iss,
                claims.mcp_re_policy_version,
            )),
            PdpDecisionOutcome::Deny => Err(PdpRelationRefusal::ExplicitDeny),
        }
    }
}

impl AuthorizationEvaluator for PdpDecisionEvaluator {
    fn evaluate(&self, request: &AuthorizationRequest) -> Result<GrantAttribution, PolicyError> {
        self.decide(request).map_err(|r| r.wire_code())
    }
}
