// SPDX-License-Identifier: Apache-2.0
//! The machines that CANNOT refuse.
//!
//! Every combination each of these can be handed is a legal deployment, so each answers
//! with a value and says nothing. That is a claim about the machine, not a convenience: an
//! owner listed here asserts its illegal states are not representable, and moving one here
//! silently is how a refusal gets lost.

use crate::deployment_request::DeploymentRequest;

/// What the total machines classified. No `Option`: every combination they can be handed is
/// a legal deployment.
pub(super) struct TotalStates {
    pub(super) audit: crate::config_state::AuditState,
    pub(super) in_flight_limit: crate::config_state::InFlightLimitBasis,
    pub(super) key_file_access: crate::config_state::KeyFileAccessPolicy,
    pub(super) mcp_transport_contract: crate::config_state::McpTransportContractState,
    pub(super) retention: crate::config_state::RetentionState,
    pub(super) shard_topology: crate::config_state::ShardTopologyRequest,
    pub(super) topology: crate::config_state::DeploymentTopology,
    pub(super) verified_context: crate::config_state::VerifiedContextState,
}

/// The machines that cannot refuse: every combination they can be handed is a legal
/// deployment, so each answers with a value and says nothing.
pub(super) fn classify_total(config: &DeploymentRequest) -> TotalStates {
    use crate::config_state as m;
    let (audit, retention, verified_context) = m::evidence::classify(config);
    // Two facts at two altitudes, deliberately not one owner: the topology is knowable from
    // the request, the shard COUNT is not — `0` means ask the host.
    let (topology, shard_topology) = m::topology::classify(config);
    TotalStates {
        audit,
        retention,
        verified_context,
        topology,
        shard_topology,
        mcp_transport_contract: m::mcp_transport_contract::classify(config),
        // The request states one of three things and the default makes the third a basis
        // too; the illegal combination is not representable.
        in_flight_limit: m::in_flight_limit::classify(config),
        // Both key-file postures are legal deployments. What the owner holds is the RULE,
        // and the rule is applied to a file rather than to the request.
        key_file_access: m::key_file_access::classify(config),
    }
}
