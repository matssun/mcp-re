// SPDX-License-Identifier: Apache-2.0
//! What a policy decides over — ADR-MCPRE-065.
//!
//! # The proposition
//!
//! Possession of [`AuthorizationRequest`] means:
//!
//! > These actor facts, this action coordinate and these prerequisites are all about ONE
//! > verified request.
//!
//! That "one" is the whole reason this type exists. An evaluator handed an actor and an
//! action as separate arguments would be deciding over a pair its caller assembled, and the
//! caller assembling the pair is the L-5 defect ADR-MCPRE-063 names. Both operands are
//! derived here from the same [`VerifiedMcpRequest`], so no second request can enter.
//!
//! # What is carried, and what is not
//!
//! The ADR-MCPRE-064 products arrive WHOLE (R-COMPOSE). Authorization consumes them; it
//! does not recreate them, does not read peer identity out of certificate fields or raw TLS
//! state, and does not re-derive the request actor from strings. The binding's own
//! projections stay reachable through it, so a policy that legitimately wants to know
//! whether the channel was bound asks the binding rather than re-deciding it.
//!
//! The request evidence digest is carried as the attribution key: a decision has to be
//! attributable to the exchange it was taken for, and the evidence handle is the identifier
//! every other authority on this path already attributes by.

use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::VerifiedMcpRequest;

use super::verified_action::interpret_authorization_action;
use super::verified_action::AuthorizationActionRefusal;
use super::verified_action::VerifiedAuthorizationAction;
use super::verified_actor::interpret_authorization_actor;
use super::verified_actor::VerifiedAuthorizationActor;
use crate::communication_assurance::RequestPeerBindingFacts;

/// One verified request, as an authorization policy sees it.
///
/// Sealed: the representation and the constructor are private to this module, so the only
/// inhabitants are the ones [`authorization_request`] composed from a single verified
/// request. An evaluator cannot be handed a mismatched actor and action.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    actor: VerifiedAuthorizationActor,
    action: VerifiedAuthorizationAction,
    /// The ADR-MCPRE-064 Slice 4 product, carried whole. `None` means this deployment
    /// installs no transport binding, so the channel is NOT CLAIMED to be bound — never
    /// that a binding was attempted and skipped.
    binding: Option<RequestPeerBindingFacts>,
    evidence: RequestEvidence,
}

impl AuthorizationRequest {
    /// Who the request verifier resolved. The policy selects which dimensions matter
    /// (Law A-2).
    pub fn actor(&self) -> &VerifiedAuthorizationActor {
        &self.actor
    }

    /// What the signed body asks for (Law A-1).
    pub fn action(&self) -> &VerifiedAuthorizationAction {
        &self.action
    }

    /// The request↔peer binding this decision is taken under, where the deployment
    /// establishes one.
    ///
    /// A prerequisite, not a permission: that a request and a channel are the same
    /// principal says nothing about what that principal may do. It is offered because a
    /// policy may legitimately require a bound channel for a given grant — and refusing
    /// there is the POLICY's decision, not this boundary's.
    pub fn channel_binding(&self) -> Option<&RequestPeerBindingFacts> {
        self.binding.as_ref()
    }

    /// The request evidence handle this decision is attributable to.
    pub fn evidence(&self) -> &RequestEvidence {
        &self.evidence
    }
}

/// Compose the policy input from ONE verified request.
///
/// THE construction operation. The actor and the action are both derived from `verified`,
/// which is what makes them provably about the same request; `body` is checked against the
/// digest that request's signature covered before anything is read from it.
pub fn authorization_request(
    verified: &VerifiedMcpRequest,
    body: &[u8],
    binding: Option<&RequestPeerBindingFacts>,
) -> Result<AuthorizationRequest, AuthorizationActionRefusal> {
    Ok(AuthorizationRequest {
        actor: interpret_authorization_actor(verified.resolved_actor()),
        action: interpret_authorization_action(verified, body)?,
        binding: binding.cloned(),
        evidence: verified.evidence().clone(),
    })
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::authorization_request;
    use crate::authorization::action_harness::verified_over_as;
    use crate::authorization::verified_action::AuthorizationActionRefusal;

    const CALL: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

    #[test]
    fn the_actor_and_the_action_come_from_one_request() {
        let verified = verified_over_as(CALL, "did:example:agent-1", "key-a");
        let req = authorization_request(&verified, CALL, None).expect("composes");
        assert_eq!(req.actor().subject(), "did:example:agent-1");
        assert_eq!(req.actor().keyid(), "key-a");
        assert_eq!(req.action().operation(), "tools/call");
        assert_eq!(req.action().target().named(), Some("read"));
        assert_eq!(req.evidence(), verified.evidence());
    }

    #[test]
    fn a_body_from_another_request_cannot_be_paired_with_this_actor() {
        // The composition inherits the action authority's L-5 guard rather than restating
        // it: an input built from actor A and a body signed by B is unconstructible.
        let verified = verified_over_as(CALL, "did:example:agent-1", "key-a");
        let other = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete"}}"#;
        assert_eq!(
            authorization_request(&verified, other, None).map(|_| ()),
            Err(AuthorizationActionRefusal::BodyIsNotTheSignedBody)
        );
    }

    #[test]
    fn the_binding_reaches_the_policy_whole_and_is_not_reopened() {
        // R-COMPOSE. The ADR-MCPRE-064 product arrives as itself, so a policy that wants to
        // require a bound channel reads the binding's own projections — the principal, the
        // establishment path, whether currency was examined — instead of this authority
        // re-deriving any of them from certificate fields or TLS state.
        use crate::communication_assurance::authenticate_relationship_peer;
        use crate::communication_assurance::certificate_identity_policy::CertificateIdentityPolicy;
        use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
        use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;
        use crate::communication_assurance::AuthenticatedChannelPeer;
        use crate::transport::TransportBinding;

        const PRINCIPAL: &str = "did:example:agent-1";
        let root = make_ca("authz-root");
        let server_ca = make_ca("authz-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_uri_leaf(&root, PRINCIPAL);
        let server = server_config(&[root.der()], vec![server_leaf], server_key);
        let client = client_config(&server_ca.der(), Some((vec![client_leaf], client_key)));
        let accepted = verified_credential(&handshake(&client, &server)).expect("accepts");
        let peer = AuthenticatedChannelPeer::CurrencyNotEvaluated(
            authenticate_relationship_peer(accepted, CertificateIdentityPolicy::UriSan)
                .expect("the leaf carries the configured field"),
        );
        let verified = verified_over_as(CALL, PRINCIPAL, "key-a");
        let bound = TransportBinding::exact_match()
            .bind(
                Some(&peer),
                crate::communication_assurance::request_peer_binding::http_profile_adapter::verified_request_subject(
                    verified.resolved_actor(),
                ),
            )
            .expect("one principal");

        let req = authorization_request(&verified, CALL, Some(&bound)).expect("composes");
        let carried = req
            .channel_binding()
            .expect("the binding is offered to the policy");
        assert_eq!(carried.principal().as_str(), PRINCIPAL);
        assert!(!carried.currency_was_evaluated());
    }

    #[test]
    fn an_unbound_deployment_says_not_claimed_rather_than_asserting_a_binding() {
        let verified = verified_over_as(CALL, "did:example:agent-1", "key-a");
        let req = authorization_request(&verified, CALL, None).expect("composes");
        assert!(req.channel_binding().is_none());
    }
}
