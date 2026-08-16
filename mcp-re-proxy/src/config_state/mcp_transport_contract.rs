// SPDX-License-Identifier: Apache-2.0
//! The `McpTransportContract` machine — `work/CONFIG-STATE-ATLAS.md` §C.12.
//!
//! Whether this deployment enforces the MCP transport/version contract (#415 rev 2 §4.1).
//! Two states:
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `Unconstrained` | — | — | — |
//! | `Enforced` | at least one accepted protocol version | — | — |
//!
//! **The twelfth machine, and it was found by looking outward rather than inward.** The
//! atlas named eleven because eleven were reachable from the fields the validation boundary
//! already read. This one was reachable only from a capability seam:
//! `serving_capabilities::mcp_transport_contract` tested `mcp_protocol_versions.is_empty()`
//! and branched on it, which is a classification — made below layer A, by the code that
//! consumes it.
//!
//! **The two states differ in what is required of every request, not in a parameter.**
//! Under `Enforced`, `Mcp-Method` and `MCP-Protocol-Version` are mandatory on every POST,
//! `Mcp-Name` is mandatory for `tools/call` and `resources/read` and must agree with the
//! protected body, legacy header omission is off, and a version header naming a value
//! outside the accepted set is refused. Under `Unconstrained` none of that is asserted.
//! That is a posture, which is what makes this a machine rather than a flag.
//!
//! **The accepted set is the DEPLOYMENT's, and this machine does not narrow it.** No value
//! is refused here, and none is parsed. The set is compared by exact string equality at
//! request time, there is no canonical protocol-version type anywhere in the workspace, and
//! `McpTransportPolicy::mcp_2026_07_28` takes the set as a parameter precisely so the
//! deployment chooses it — "its consent, not the client's claim". A set that no ordinary
//! client can satisfy is therefore an operator's decision, however unusual, and inventing a
//! refusal for it here would narrow a vocabulary the product deliberately delegates.
//! Whether it SHOULD be narrowed is a product question, and a different commit.

use crate::deployment_request::DeploymentRequest;

/// Which MCP transport-contract state a configuration requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpTransportContractState {
    /// No contract is asserted. The transport headers are not required and `Mcp-Name` is
    /// not checked against the body, so a signed request may name one tool in its header
    /// and invoke another in its body.
    Unconstrained,
    /// The contract is enforced for an accepted set of protocol versions.
    Enforced {
        /// The versions this deployment serves. Non-empty by construction: emptiness is
        /// what selects `Unconstrained`, so the state that is enforced carries the set
        /// that made it so, and nothing downstream re-asks whether there is one.
        versions: Vec<String>,
    },
}

impl McpTransportContractState {
    /// Whether the transport contract is asserted at all.
    ///
    /// Named here so a consumer reads the posture rather than re-testing the collection it
    /// happens to be carrying.
    pub fn is_enforced(&self) -> bool {
        matches!(self, Self::Enforced { .. })
    }
}

/// Recognise the requested state. Total: every `DeploymentRequest` names one, and neither state has
/// a column to check.
pub fn classify(config: &DeploymentRequest) -> McpTransportContractState {
    if config.mcp_protocol_versions.is_empty() {
        return McpTransportContractState::Unconstrained;
    }
    McpTransportContractState::Enforced {
        versions: config.mcp_protocol_versions.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn state_of(mutate: impl FnOnce(&mut DeploymentRequest)) -> McpTransportContractState {
        let mut config = legal_config();
        mutate(&mut config);
        classify(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified() {
        assert_eq!(
            state_of(|c| c.mcp_protocol_versions.clear()),
            McpTransportContractState::Unconstrained
        );
        assert_eq!(
            state_of(|c| c.mcp_protocol_versions = vec!["2026-07-28".to_string()]),
            McpTransportContractState::Enforced {
                versions: vec!["2026-07-28".to_string()]
            }
        );
    }

    /// `Unconstrained` is a posture the operator chose, not configuration that is missing.
    /// Nothing is refused for its absence.
    #[test]
    fn the_absent_contract_is_a_state_and_not_a_defect() {
        assert!(!state_of(|c| c.mcp_protocol_versions.clear()).is_enforced());
    }

    /// The enforced state carries the set that selected it, so the seam has no emptiness
    /// left to re-test. Asserted with versions the fixture does not name.
    #[test]
    fn the_enforced_state_carries_the_set_that_selected_it() {
        let McpTransportContractState::Enforced { versions } = state_of(|c| {
            c.mcp_protocol_versions = vec!["2026-07-28".to_string(), "2025-11-05".to_string()];
        }) else {
            panic!("a declared version selects the enforced state");
        };
        assert_eq!(versions, vec!["2026-07-28", "2025-11-05"]);
        assert!(!versions.is_empty(), "non-empty by construction");
    }

    /// The set is the deployment's own. This machine parses nothing and refuses nothing:
    /// comparison is exact string equality at request time, and the accepted set is the
    /// deployment's consent rather than a protocol constant. A set no ordinary client can
    /// satisfy is an operator's decision, and whether the product should narrow that
    /// vocabulary is not this machine's question.
    #[test]
    fn an_unusual_accepted_set_is_classified_rather_than_refused() {
        assert_eq!(
            state_of(|c| c.mcp_protocol_versions = vec!["not-a-version".to_string()]),
            McpTransportContractState::Enforced {
                versions: vec!["not-a-version".to_string()]
            }
        );
    }
}
