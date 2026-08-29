// SPDX-License-Identifier: Apache-2.0
//! May this ACTION be performed?
//!
//! The one question in the pre-admission region that is about what the caller asked for
//! rather than about the caller. The action is read from the SIGNED body (ADR-MCPRE-065),
//! so what is decided over is what the client actually authenticated, never a coordinate
//! reconstructed from somewhere more convenient.
//!
//! Separate from [`super::standing`] because a deployment can hold one of these and not the
//! other, and the two refusals mean different things to whoever reads the audit record.

use crate::authorization::AuthorizationPosture;
use crate::communication_assurance::RequestPeerBindingFacts;
use crate::refusal::Refusal;

use super::super::Exchange;
use super::super::HttpProfileProxy;

impl HttpProfileProxy {
    /// AUTHORIZED — what this deployment's policy says about the action in the signed body.
    ///
    /// ```text
    /// ensures   Ok  => a policy permitted this action, or no policy is deployed and the
    ///                  posture says exactly that rather than reading as an allow
    ///           Err => 403, bound
    /// forbids   burning a nonce, running the backend
    /// refusal   free
    /// ```
    ///
    /// Ordered after admission and before everything irreversible. Admission's facts are an
    /// input to the decision, and running a tool for an action no policy permits is exactly
    /// what a free refusal here prevents.
    ///
    /// The posture it returns is not advisory: [`crate::request_stages::ReadyForDispatch`]
    /// carries a body that only `AuthorizationPosture::release` can produce, so a pipeline
    /// that dropped this stage would not compile at the dispatch. What the DECISION means is
    /// [`crate::authorization::AuthorizationStage`]'s; what a refusal costs the client is
    /// the machine's.
    pub(super) fn authorization_stage(
        &self,
        ex: &Exchange<'_>,
        bound: Option<&RequestPeerBindingFacts>,
    ) -> Result<AuthorizationPosture, Refusal> {
        self.authorization
            .decide(ex.verified, &ex.http_req.body, bound)
            .map_err(|refusal| Refusal::before_admission(refusal, 403))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::audit::AuthorizationFacet;

    /// *No policy is deployed* is not *a policy permitted this*. The stage returns the
    /// posture rather than a boolean precisely so the record path cannot collapse them
    /// (ADR-MCPRE-066 §1.1, invariant 5).
    #[test]
    fn an_unconfigured_deployment_claims_nothing_about_permission() {
        assert!(matches!(
            AuthorizationPosture::NoPolicyConfigured.audit_facet(),
            AuthorizationFacet::NotConfigured
        ));
    }
}
