// SPDX-License-Identifier: Apache-2.0
//! The deployment's authorization mechanism, as the serving path holds it.
//!
//! The serving file owns the PIPELINE — which stage follows which, and what a refusal costs
//! the client. It does not own the mechanism, the posture, or what a decision means, and
//! this is where those live: the serving stage is three lines of ordering over
//! [`AuthorizationStage::decide`].

use std::sync::Arc;

use mcp_re_http_profile::VerifiedMcpRequest;

use super::decide::authorize;
use super::decide::AuthorizationRefusal;
use super::evaluator::AuthorizationEvaluator;
use super::posture::AuthorizationPosture;
use crate::communication_assurance::RequestPeerBindingFacts;

/// What this deployment decides authorization with, including deciding it with nothing.
///
/// `None` is the explicit no-policy-deployed posture, not a disabled stage: the boundary
/// still runs, still reads the action coordinate, and reports
/// [`AuthorizationPosture::NoPolicyConfigured`] — never an allow.
///
/// A production mechanism exists — [`PdpDecisionEvaluator`](super::pdp::PdpDecisionEvaluator),
/// ADR-MCPRE-065 §8 — but **no configuration installs it**. The composition root
/// (`app::run_validated`) never calls
/// [`with_authorization`](crate::HttpProfileProxy::with_authorization), so this seam is
/// reachable only by a caller that constructs an evaluator itself. `--authz reference`
/// remains refused by Layer-A validation, and it names the retired reference profile rather
/// than this one. A test needing an allow path does not promote one to production authority.
#[derive(Default, Clone)]
pub(crate) struct AuthorizationStage {
    evaluator: Option<Arc<dyn AuthorizationEvaluator>>,
}

impl AuthorizationStage {
    /// Decide under `evaluator`.
    pub(crate) fn under(evaluator: Arc<dyn AuthorizationEvaluator>) -> Self {
        AuthorizationStage {
            evaluator: Some(evaluator),
        }
    }

    /// Decide for one verified request.
    ///
    /// The action coordinate comes from `body`, which the decision proves is the body the
    /// signature covered (Law A-1) — never from a transport routing header, and never
    /// conditioned on whether the MCP transport contract is enforced.
    ///
    /// `binding` is the ADR-MCPRE-064 Slice 4 prerequisite, offered to the policy WHOLE.
    /// This authority does not reopen it, does not read peer identity out of certificate
    /// fields, and does not re-derive the actor from strings.
    pub(crate) fn decide(
        &self,
        verified: &VerifiedMcpRequest,
        body: &[u8],
        binding: Option<&RequestPeerBindingFacts>,
    ) -> Result<AuthorizationPosture, AuthorizationRefusal> {
        authorize(self.evaluator.as_deref(), verified, body, binding)
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::AuthorizationStage;
    use crate::authorization::action_harness::verified_over;

    const CALL: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

    #[test]
    fn a_deployment_that_installs_nothing_still_decides_and_claims_nothing() {
        let posture = AuthorizationStage::default()
            .decide(&verified_over(CALL), CALL, None)
            .expect("a deployment with no policy is entitled to serve");
        assert!(
            posture.authorized().is_none(),
            "`Off` is not `Allow`: no policy permitted this, and the posture says so"
        );
    }
}
