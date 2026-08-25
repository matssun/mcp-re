// SPDX-License-Identifier: Apache-2.0
//! Where an MCP method names its target in the request body.
//!
//! A fact about the MCP PROTOCOL, separate from any deployment's transport contract, and it
//! has two readers that must never disagree: the contract in
//! [`mcp_transport`](crate::mcp_transport), which compares the `Mcp-Name` header against
//! the body, and the ADR-MCPRE-065 authorization action coordinate, which reads the body and
//! never the header.
//!
//! Stated once for that reason. Law A-1 requires authorization to find the target whether or
//! not a transport contract is enforced, so it cannot read the mapping out of a policy
//! object that may not exist — and a second copy is how the two end up disagreeing about
//! which key a method names its target under.

use serde_json::Value;

/// The body field an `Mcp-Name` header must agree with, per method.
///
/// `tools/call` names the tool in `params.name`; `resources/read` names the
/// resource in `params.uri`. The mapping is explicit because the two methods put
/// the same routing value under different keys, and a verifier comparing against
/// the wrong key would either miss a mismatch or invent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpNameSource {
    /// `params.name` — the `tools/call` shape.
    ParamsName,
    /// `params.uri` — the `resources/read` shape.
    ParamsUri,
}

impl McpNameSource {
    /// Read the routing value this source names out of a request's `params`.
    ///
    /// Public because the mapping is a fact about the MCP protocol, not about any
    /// deployment's contract: ADR-MCPRE-065 Law A-1 requires authorization to find the
    /// method's target in the SIGNED BODY whether or not a transport contract is enforced,
    /// and it must not carry a second copy of where that value lives.
    pub fn extract(self, params: &Value) -> Option<&str> {
        match self {
            McpNameSource::ParamsName => params.get("name").and_then(Value::as_str),
            McpNameSource::ParamsUri => params.get("uri").and_then(Value::as_str),
        }
    }
}

/// Where an MCP method names its target in the request body.
///
/// The protocol fact, stated once and read by both consumers: the transport contract
/// (which compares the `Mcp-Name` header against it) and the authorization action
/// coordinate (which reads the body and never the header). `None` for a method that names
/// no target — `tools/list`, `initialize`, and everything else whose authority is the
/// method alone.
pub fn mcp_name_source(method: &str) -> Option<McpNameSource> {
    match method {
        "tools/call" => Some(McpNameSource::ParamsName),
        "resources/read" => Some(McpNameSource::ParamsUri),
        _ => None,
    }
}
