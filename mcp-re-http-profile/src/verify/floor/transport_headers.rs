// SPDX-License-Identifier: Apache-2.0
//! The MCP transport headers (§4.1): which are coverable, and that a covered one may not
//! lie about the signed body.
//!
//! One authority: **the routing claims a message makes in the clear agree with the message
//! itself.** The set is closed here because the point of these headers is that
//! intermediaries may read them — an intermediary reading `tools/list` while the server
//! executes `tools/call` is exactly the divergence §4.1 closes.

use crate::error::HttpProfileError;
use crate::ids::MCP_METHOD_HEADER;
use crate::ids::MCP_NAME_HEADER;
use crate::ids::MCP_PROTOCOL_VERSION_HEADER;
use crate::message::single_header;
use crate::message::HttpRequest;

/// The MCP transport headers this profile can cover (§4.1).
///
/// `mcp-session-id` is deliberately ABSENT. Protocol sessions are a 2025-11-25
/// concept that MCP 2026-07-28 removes, and MCP-RE never adopted them: its
/// serving path is stateless per-request by design (ADR-MCPRE-051), so there is
/// no session for a session id to identify. Covering a header whose referent does
/// not exist would manufacture the appearance of a binding over nothing. If a
/// deployment sends one anyway it is simply not coverable, and the closed
/// allowlist rejects it as an unknown covered component — which is the correct
/// answer, not an oversight.
pub(super) const MCP_COVERABLE_TRANSPORT_HEADERS: [&str; 3] = [
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
];
/// Reject a request whose covered `Mcp-Method` header disagrees with the JSON-RPC
/// `method` in its covered body (§4.1).
///
/// Both values are protected by the signature by the time this runs, so a
/// disagreement is not tampering — it is the signer making two contradictory
/// statements about what it is asking for. The verifier refuses rather than
/// choosing a winner: the whole point of the transport header is that
/// intermediaries may read it, and an intermediary reading `tools/list` while the
/// server executes `tools/call` is precisely the divergence §4.1 closes.
///
/// The body is authoritative wherever this profile acts (ADR-MCPS-025); this does
/// not change that. It ensures the header cannot CLAIM otherwise.
pub(super) fn reject_mcp_method_divergence(request: &HttpRequest) -> Result<(), HttpProfileError> {
    let Some(header_method) = single_header(&request.headers, MCP_METHOD_HEADER)? else {
        return Ok(());
    };
    let body: serde_json::Value = serde_json::from_slice(&request.body)
        .map_err(|_| HttpProfileError::MalformedEvidence("body json"))?;
    // A body with no `method` gives the header nothing to agree with, so the signed
    // value would be constrained by nothing at all — and an intermediary that routes,
    // rate-limits or audits on `Mcp-Method` (the stated reason §4.1 covers it) would
    // act on an arbitrary signer-chosen string carrying full authenticity. Skipping
    // the check here would make "the header always mirrors the body" true only for
    // the shapes that happen to have a body method. A message that sends this header
    // must therefore carry the `method` it mirrors.
    let Some(body_method) = body.get("method").and_then(|m| m.as_str()) else {
        return Err(HttpProfileError::McpMethodDivergence);
    };
    if header_method.trim() != body_method {
        return Err(HttpProfileError::McpMethodDivergence);
    }
    Ok(())
}
