// SPDX-License-Identifier: Apache-2.0
//! The relation between a verified request and an authenticated decision.
//!
//! Where the chain in [`super`] ends: authenticated claims on one side, ADR-MCPRE-065's
//! verified facts on the other, and the question *is this decision about THIS request, and
//! does it permit it*.

use mcp_re_http_profile::pdp_decision::verify_authorization_decision;
use mcp_re_http_profile::pdp_decision::PdpDecisionClaims;
use mcp_re_http_profile::pdp_decision::PdpDecisionOutcome;
use mcp_re_http_profile::pdp_decision::PdpDecisionRefusal;
use mcp_re_policy::PolicyError;

use super::policy::PdpDecisionPolicy;
use super::refusal::PdpRelationRefusal;
use crate::authorization::evaluator::AuthorizationEvaluator;
use crate::authorization::evaluator::AuthorizedDecision;
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
    ) -> Result<AuthorizedDecision, PdpRelationRefusal> {
        let evidence = request
            .decision_evidence()
            .map_err(PdpRelationRefusal::EvidenceNotBound)?
            .ok_or(PdpRelationRefusal::NoDecisionPresented)?;

        let audiences: Vec<&str> = self.audiences.iter().map(String::as_str).collect();
        let answered = std::cell::OnceCell::new();
        let claims = verify_authorization_decision(
            evidence.document(),
            &self.profile,
            &audiences,
            &self.policy.freshness,
            (self.now)(),
            |kid| {
                let authority = (self.policy.resolve_authority)(kid)?;
                let key = authority.key().clone();
                answered.set(authority).ok()?;
                Some(key)
            },
        )
        .map_err(PdpRelationRefusal::NotAuthenticated)?;

        // The name attributed is the one from the same resolver answer whose key verified
        // the signature; a resolver consulted a second time could answer differently.
        let Some(authority) = answered.into_inner() else {
            return Err(PdpRelationRefusal::NotAuthenticated(
                PdpDecisionRefusal::IssuerUntrusted,
            ));
        };

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
            // The evidence identity comes from `evidence`, which established it while
            // proving the correspondence — not from the document, and not from the claims.
            // The deciding AUTHORITY comes from the enrolment for the same reason: `iss` is
            // a string the signer chose, so a record built from it says which authority the
            // document names itself, not which one this deployment trusted to decide.
            PdpDecisionOutcome::Permit => Ok(AuthorizedDecision::new(
                GrantAttribution::new(authority.name(), claims.mcp_re_policy_version, claims.jti),
                evidence.identity().clone(),
            )),
            PdpDecisionOutcome::Deny => Err(PdpRelationRefusal::ExplicitDeny),
        }
    }
}

impl AuthorizationEvaluator for PdpDecisionEvaluator {
    fn evaluate(&self, request: &AuthorizationRequest) -> Result<AuthorizedDecision, PolicyError> {
        self.decide(request).map_err(|r| r.wire_code())
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mcp_re_http_profile::pdp_decision::DecidedActor;
    use mcp_re_http_profile::pdp_decision::DecisionScope;
    use mcp_re_http_profile::pdp_decision::PdpDecisionClaims;
    use mcp_re_http_profile::pdp_decision::PdpDecisionFreshness;
    use mcp_re_http_profile::pdp_decision::PdpDecisionOutcome;
    use mcp_re_http_profile::Audience;
    use mcp_re_http_profile::PROFILE_TAG;

    use super::PdpDecisionEvaluator;
    use crate::authorization::action_harness::covering_unverifiable;
    use crate::authorization::pdp::policy::PdpDecisionPolicy;
    use crate::authorization::request::authorization_request;
    use crate::authorization::request::AuthorizationRequest;

    fn evaluator() -> PdpDecisionEvaluator {
        PdpDecisionEvaluator::new(
            PdpDecisionPolicy {
                resolve_authority: Arc::new(|_| None),
                accepted_scope: DecisionScope::Principal,
                freshness: PdpDecisionFreshness {
                    max_clock_skew: 30,
                    max_decision_age: 600,
                },
            },
            PROFILE_TAG,
            vec!["verifier-1".to_owned()],
            Arc::new(|| 0),
        )
    }

    fn decision(operation: &str, target: Option<&str>) -> PdpDecisionClaims {
        PdpDecisionClaims {
            iss: "pdp".into(),
            iat: 0,
            nbf: 0,
            exp: 1,
            jti: "decision-1".into(),
            aud: Audience::One("verifier-1".into()),
            mcp_re_profile: PROFILE_TAG.into(),
            mcp_re_decided_actor: DecidedActor::Principal {
                trust_domain: "example.com".into(),
                subject: "did:example:agent-1".into(),
            },
            mcp_re_decided_operation: operation.into(),
            mcp_re_decided_target: target.map(str::to_owned),
            mcp_re_decision: PdpDecisionOutcome::Permit,
            mcp_re_policy_version: "v1".into(),
            issuer_kid: "pdp-kid".into(),
        }
    }

    fn request_over(body: &[u8]) -> AuthorizationRequest {
        authorization_request(&covering_unverifiable(body), body, None).expect("a readable body")
    }

    /// A request naming no tool matches no decision, whether the decision names a target or
    /// names none.
    ///
    /// The transport contract refuses a `tools/call` naming no tool before any verified
    /// request exists, so the serving path never presents the `Absent` state to this
    /// relation and no served exchange can exercise the arm. The relation is total over the
    /// states the type admits, and this drives it over the one the serving path cannot
    /// reach. Collapsing `Absent` into the not-applicable arm would let a decision about an
    /// operation that takes no target authorize a call that omitted its target.
    #[test]
    fn a_call_naming_no_tool_is_matched_by_no_decision_target() {
        let absent = request_over(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#);
        assert!(!evaluator().action_matches(&decision("tools/call", None), &absent));
        assert!(!evaluator().action_matches(&decision("tools/call", Some("read")), &absent));
    }

    /// The control for the one above: the same relation matches when the call names the tool
    /// the decision is about, and a targetless operation matches a targetless decision, so
    /// the refusals above are about `Absent` and not about the relation matching nothing.
    #[test]
    fn a_named_target_and_a_targetless_operation_each_match_their_own_decision() {
        let named = request_over(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#,
        );
        assert!(evaluator().action_matches(&decision("tools/call", Some("read")), &named));
        assert!(!evaluator().action_matches(&decision("tools/call", Some("write")), &named));
        assert!(!evaluator().action_matches(&decision("tools/call", None), &named));
        let listing = request_over(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        assert!(evaluator().action_matches(&decision("tools/list", None), &listing));
        assert!(!evaluator().action_matches(&decision("tools/list", Some("read")), &listing));
    }
}
