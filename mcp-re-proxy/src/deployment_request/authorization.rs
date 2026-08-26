// SPDX-License-Identifier: Apache-2.0
//! What a deployment asks for on the authorization axis — ADR-MCPRE-065.
//!
//! One family rather than four loose fields on [`DeploymentRequest`](super::DeploymentRequest):
//! the selection, the two parameters only one selection has, and the policy-layer deny-list
//! are all inputs to the same authority, and a field group that travels together is one a
//! reader can check for coherence in one place.
//!
//! Nothing here is classified. `Off` beside a decision scope is representable, because
//! refusing that combination is the [`AuthorizationState`](crate::config_state::AuthorizationState)
//! machine's job and a request type that could not express the mistake would move the
//! refusal into whichever parser happened to build the value.

use mcp_re_http_profile::pdp_decision::DecisionScope;

use super::kinds::AuthzKind;

/// The authorization inputs of one deployment request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// Which authorization authority, if any, this deployment installs.
    pub kind: AuthzKind,
    /// The actor scope this deployment accepts decisions at (ADR-MCPRE-065 Law A-2).
    ///
    /// Declared explicitly and never defaulted: `principal` and `credential` differ in
    /// whether a signing-key rotation voids a decision, and inferring one would let the
    /// same document mean a lasting grant here and a key-bound grant next door.
    pub decision_scope: Option<DecisionScope>,
    /// How old a decision this deployment will still act on, in seconds.
    ///
    /// Separate from the issuer's own `exp`: the authority bounds its document's lifetime,
    /// and the enforcement point bounds how stale a decision it is willing to enforce. A
    /// deployment that could not state the second would have delegated that choice to
    /// whoever issued the decision.
    pub max_decision_age_secs: Option<i64>,
    /// Offline policy-layer revocation deny-list paths (ADR-MCPS-013). Each
    /// `--revocation-list` value (comma-separated and/or repeated) adds a file of
    /// newline-delimited revoked `revocation_id`s. Loaded once at startup (OFFLINE
    /// only — restart to update). Empty means no grant deny-list is configured.
    pub revocation_list_paths: Vec<String>,
}

impl AuthorizationRequest {
    /// The no-authorization request: nothing selected, no parameters supplied.
    pub fn off() -> Self {
        AuthorizationRequest {
            kind: AuthzKind::Off,
            decision_scope: None,
            max_decision_age_secs: None,
            revocation_list_paths: Vec::new(),
        }
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::AuthorizationRequest;
    use super::AuthzKind;

    #[test]
    fn the_off_request_supplies_no_parameter_any_machine_could_dangle() {
        let request = AuthorizationRequest::off();
        assert_eq!(request.kind, AuthzKind::Off);
        assert!(request.decision_scope.is_none());
        assert!(request.max_decision_age_secs.is_none());
        assert!(request.revocation_list_paths.is_empty());
    }

    #[test]
    fn a_scope_beside_off_is_representable_because_refusing_it_is_not_this_types_job() {
        let mut request = AuthorizationRequest::off();
        request.decision_scope = Some(mcp_re_http_profile::pdp_decision::DecisionScope::Principal);
        assert_eq!(request.kind, AuthzKind::Off);
    }
}
