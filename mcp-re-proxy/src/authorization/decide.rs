// SPDX-License-Identifier: Apache-2.0
//! The authorization decision — ADR-MCPRE-065.
//!
//! One operation, and the only producer of an
//! [`AuthorizedRequestFacts`](super::posture::AuthorizedRequestFacts). It composes the
//! policy input from a single verified request, asks the configured mechanism, and turns
//! the answer into what this deployment may honestly say.

use mcp_re_core::McpReError;
use mcp_re_policy::PolicyError;

use super::evaluator::AuthorizationEvaluator;
use super::posture::AuthorizationPosture;
use super::posture::AuthorizedRequestFacts;
use super::request::authorization_request;
use super::verified_action::AuthorizationActionRefusal;
use crate::communication_assurance::RequestPeerBindingFacts;
use mcp_re_http_profile::VerifiedMcpRequest;

/// Why a request is not authorized.
///
/// Two arms, because there are two authorities that can refuse: this boundary, when the
/// verified request yields no action coordinate at all, and the policy mechanism, when it
/// has one and denies. Collapsing them would report a malformed request as a policy denial
/// and send an operator to inspect a grant that was never consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationRefusal {
    /// No action coordinate could be read from the verified request, so there is nothing
    /// for a policy to decide over.
    ActionNotVerifiable(AuthorizationActionRefusal),
    /// A policy decided, and the decision was not to permit. Carries the frozen
    /// ADR-MCPS-013 token, which already distinguishes a denial from an evaluation that
    /// could not complete.
    PolicyRefused(PolicyError),
}

impl AuthorizationRefusal {
    /// The frozen wire token this refusal is served as.
    ///
    /// The action arm renders EXISTING core tokens rather than minting authorization ones:
    /// a body that is not the signed body is a digest mismatch, and a body that names no
    /// operation is a malformed envelope. Both are true statements about the request that
    /// this slice is not entitled to restate in a vocabulary ADR-MCPS-035 freezes.
    pub fn wire_code(&self) -> &'static str {
        match self {
            AuthorizationRefusal::ActionNotVerifiable(
                AuthorizationActionRefusal::BodyIsNotTheSignedBody,
            ) => McpReError::DigestMismatch.wire_code(),
            AuthorizationRefusal::ActionNotVerifiable(_) => {
                McpReError::MalformedEnvelope.wire_code()
            }
            AuthorizationRefusal::PolicyRefused(e) => e.wire_code(),
        }
    }
}

/// Decide what this deployment may say about a request's permission.
///
/// THE operation. `evaluator` is the deployment's mechanism, absent when none is configured
/// — and its absence is answered with [`AuthorizationPosture::NoPolicyConfigured`], never
/// with a grant.
///
/// The action coordinate is read even when no evaluator is attached. That is deliberate:
/// were it read only under a configured policy, an unauthorized deployment and an authorized
/// one would disagree about which requests are well-formed enough to serve, and enabling a
/// policy would start refusing requests for reasons that have nothing to do with the policy.
pub fn authorize(
    evaluator: Option<&dyn AuthorizationEvaluator>,
    verified: &VerifiedMcpRequest,
    body: &[u8],
    binding: Option<&RequestPeerBindingFacts>,
) -> Result<AuthorizationPosture, AuthorizationRefusal> {
    let request = authorization_request(verified, body, binding)
        .map_err(AuthorizationRefusal::ActionNotVerifiable)?;
    let Some(evaluator) = evaluator else {
        return Ok(AuthorizationPosture::NoPolicyConfigured);
    };
    match evaluator.evaluate(&request) {
        Ok(granted) => Ok(AuthorizationPosture::Authorized(Box::new(
            AuthorizedRequestFacts::new(request, granted),
        ))),
        Err(e) => Err(AuthorizationRefusal::PolicyRefused(e)),
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::authorize;
    use super::AuthorizationRefusal;
    use crate::authorization::action_harness::verified_over;
    use crate::authorization::evaluator::AuthorizationEvaluator;
    use crate::authorization::grant::GrantAttribution;
    use crate::authorization::request::AuthorizationRequest;
    use crate::authorization::verified_action::AuthorizationActionRefusal;
    use mcp_re_policy::PolicyError;

    struct Always(Result<&'static str, PolicyError>);

    impl AuthorizationEvaluator for Always {
        fn evaluate(&self, _: &AuthorizationRequest) -> Result<GrantAttribution, PolicyError> {
            match &self.0 {
                Ok(authority) => Ok(GrantAttribution::new(*authority, "1")),
                Err(e) => Err(e.clone()),
            }
        }
    }

    const READ: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

    #[test]
    fn no_evaluator_yields_no_policy_configured_and_never_a_grant() {
        let verified = verified_over(READ);
        let posture = authorize(None, &verified, READ, None).expect("not a refusal");
        assert!(
            posture.authorized().is_none(),
            "an unconfigured deployment must not report an authorization it never made"
        );
    }

    #[test]
    fn a_granting_evaluator_yields_an_attributed_authorization() {
        let verified = verified_over(READ);
        let posture =
            authorize(Some(&Always(Ok("conformance"))), &verified, READ, None).expect("granted");
        let facts = posture.authorized().expect("a policy permitted this");
        assert_eq!(facts.granted().authority(), "conformance");
        assert_eq!(facts.request().action().target().named(), Some("read"));
        assert_eq!(facts.request().actor().subject(), "did:example:agent-1");
    }

    #[test]
    fn a_denying_evaluator_refuses_with_its_own_token() {
        let verified = verified_over(READ);
        let refusal = authorize(
            Some(&Always(Err(PolicyError::AuthorizationScopeDenied))),
            &verified,
            READ,
            None,
        )
        .expect_err("denied");
        assert_eq!(refusal.wire_code(), "mcp-re.authorization_scope_denied");
    }

    #[test]
    fn an_evaluator_that_could_not_decide_fails_closed_and_says_which_fact_that_is() {
        // Fail-closed is not in doubt; being able to TELL an outage from a denial is. The
        // frozen taxonomy already carries the split, so the boundary neither invents a
        // token nor flattens the two into one.
        let verified = verified_over(READ);
        let refusal = authorize(
            Some(&Always(Err(
                PolicyError::AuthorizationRevocationUnavailable,
            ))),
            &verified,
            READ,
            None,
        )
        .expect_err("could not decide");
        assert_eq!(
            refusal.wire_code(),
            "mcp-re.authorization_revocation_unavailable"
        );
    }

    #[test]
    fn a_request_with_no_readable_action_is_refused_before_any_policy_is_consulted() {
        // The evaluator here would grant anything. The refusal must still happen, and must
        // not be reported as a policy denial — nothing was asked of the policy.
        let junk = b"not json";
        let verified = verified_over(junk);
        let refusal = authorize(Some(&Always(Ok("conformance"))), &verified, junk, None)
            .expect_err("no coordinate");
        assert_eq!(
            refusal,
            AuthorizationRefusal::ActionNotVerifiable(AuthorizationActionRefusal::BodyIsNotJson)
        );
        assert_eq!(refusal.wire_code(), "mcp-re.malformed_envelope");
    }

    #[test]
    fn the_coordinate_is_read_whether_or_not_a_policy_is_configured() {
        // Otherwise enabling a policy would start refusing requests for reasons that have
        // nothing to do with the policy — the same class of hidden coupling Law A-1 rules
        // out for the transport contract.
        let junk = b"not json";
        let verified = verified_over(junk);
        assert!(authorize(None, &verified, junk, None).is_err());
    }
}
