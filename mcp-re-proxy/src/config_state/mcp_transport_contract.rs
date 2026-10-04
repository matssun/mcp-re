// SPDX-License-Identifier: Apache-2.0
//! The MCP transport/version contract this deployment enforces (#415 rev 2 §4.1).
//!
//! The contract is mandatory. Every request carries `Mcp-Method` and `MCP-Protocol-Version`,
//! `Mcp-Name` for `tools/call` and `resources/read` agrees with the protected body, and a
//! version header naming a value outside the accepted set is refused. A deployment chooses
//! the accepted set; it cannot choose to have no contract, because without one a signed
//! request may name one tool in its header and invoke another in its body.
//!
//! **The accepted set is the DEPLOYMENT's, and this owner does not narrow it.** No value is
//! refused here beyond emptiness, and none is parsed. The set is compared by exact string
//! equality at request time, there is no canonical protocol-version type anywhere in the
//! workspace, and `McpTransportPolicy::mcp_2026_07_28` takes the set as a parameter
//! precisely so the deployment chooses it — "its consent, not the client's claim". A set no
//! ordinary client can satisfy is an operator's decision, however unusual. Whether it SHOULD
//! be narrowed is a product question, and a different commit.

use crate::deployment_request::DeploymentRequest;

/// The protocol versions a configuration declares. The representation is private and
/// [`classify`] is the only producer; [`violations`] refuses the empty set before a
/// configuration state exists, so a state that is held names at least one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTransportContractState {
    versions: Vec<String>,
}

impl McpTransportContractState {
    /// The versions the contract is enforced for.
    pub fn versions(&self) -> &[String] {
        &self.versions
    }
}

/// Recognise the declared set. Total: emptiness is [`violations`]' to refuse, not a state.
pub fn classify(config: &DeploymentRequest) -> McpTransportContractState {
    McpTransportContractState {
        versions: config.mcp_protocol_versions.clone(),
    }
}

/// The contract is mandatory: at least one accepted protocol version, none of them blank.
pub fn violations(config: &DeploymentRequest) -> Vec<String> {
    let blank = config
        .mcp_protocol_versions
        .iter()
        .any(|v| v.trim().is_empty());
    if config.mcp_protocol_versions.is_empty() || blank {
        return vec![
            "the MCP transport contract is mandatory: pass --mcp-protocol-version <version> \
             (repeatable) naming each protocol version this deployment serves, for example \
             2026-07-28"
                .to_string(),
        ];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn request_with(versions: &[&str]) -> DeploymentRequest {
        let mut config = legal_config();
        config.mcp_protocol_versions = versions.iter().map(|v| (*v).to_string()).collect();
        config
    }

    /// The declared set is carried verbatim, in the order given.
    #[test]
    fn the_state_carries_the_set_the_operator_declared() {
        let state = classify(&request_with(&["2026-07-28", "2025-11-05"]));
        assert_eq!(state.versions(), ["2026-07-28", "2025-11-05"]);
    }

    /// The contract is not optional: no version, or a blank one, is a refusal.
    #[test]
    fn declaring_no_version_is_refused_not_a_posture() {
        assert_eq!(violations(&request_with(&[])).len(), 1);
        assert_eq!(violations(&request_with(&["2026-07-28", " "])).len(), 1);
        assert!(violations(&request_with(&["2026-07-28"])).is_empty());
    }

    /// The set is the deployment's own: this owner parses nothing and refuses nothing but
    /// emptiness. A set no ordinary client can satisfy is an operator's decision.
    #[test]
    fn an_unusual_accepted_set_is_classified_rather_than_refused() {
        let config = request_with(&["not-a-version"]);
        assert!(violations(&config).is_empty());
        assert_eq!(classify(&config).versions(), ["not-a-version"]);
    }
}
