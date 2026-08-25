// SPDX-License-Identifier: Apache-2.0
//! What a deployment declares about the decisions it will act on.

use std::sync::Arc;

use mcp_re_core::VerificationKey;
use mcp_re_http_profile::pdp_decision::DecisionScope;
use mcp_re_http_profile::pdp_decision::PdpDecisionFreshness;

/// Resolves a decision's `issuer_kid` to an authorization authority's root key.
///
/// Its own seam, deliberately not the request-signer trust resolver. *This key signs
/// requests* and *this key decides permission* are different authorities; a deployment may
/// back both with one key infrastructure, but it says so twice rather than having the second
/// inferred from the first. Returning `None` means **this deployment does not trust that
/// issuer to authorize**, whatever else it may trust that key for.
pub type AuthorizationAuthorityResolver =
    Arc<dyn Fn(&str) -> Option<VerificationKey> + Send + Sync>;

/// The deployment's PDP-decision profile.
pub struct PdpDecisionPolicy {
    /// The authorization-authority trust seam.
    pub resolve_authority: AuthorizationAuthorityResolver,
    /// Which decision scope this deployment accepts (ADR-MCPRE-065 Law A-2).
    ///
    /// The deployment declares what it ACCEPTS; the decision declares what it IS, in its own
    /// signed claims. Neither infers the other, so one document cannot mean a principal
    /// grant here and a credential grant next door.
    pub accepted_scope: DecisionScope,
    /// How stale, and how far outside its window, a decision may be.
    pub freshness: PdpDecisionFreshness,
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::PdpDecisionPolicy;
    use mcp_re_http_profile::pdp_decision::DecisionScope;
    use mcp_re_http_profile::pdp_decision::PdpDecisionFreshness;
    use std::sync::Arc;

    #[test]
    fn a_resolver_that_trusts_nobody_is_a_deployment_that_authorizes_nothing() {
        // The honest default shape: an authorization-authority seam is not populated by
        // whatever the request-signer seam happens to trust.
        let policy = PdpDecisionPolicy {
            resolve_authority: Arc::new(|_| None),
            accepted_scope: DecisionScope::Principal,
            freshness: PdpDecisionFreshness {
                max_clock_skew: 30,
                max_decision_age: 600,
            },
        };
        assert!((policy.resolve_authority)("any-kid").is_none());
        assert_eq!(policy.accepted_scope, DecisionScope::Principal);
    }
}
