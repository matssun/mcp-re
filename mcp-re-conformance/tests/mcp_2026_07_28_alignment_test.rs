// SPDX-License-Identifier: Apache-2.0
//! Alignment with MCP 2026-07-28 / SEP-2322 (issue #426).
//!
//! STATUS: the 2026-07-28 spec is not final until 2026-07-28; these are RC-shape
//! drift guards, not a conformance claim. Each pins a value that the final spec
//! could move, so that if it moves, a test fails instead of a deployment.
//!
//! The issue's headline task — "bump the backend handshake / protocol-version
//! handling to 2026-07-28" — has no code to act on: MCP-RE performs no protocol
//! version negotiation anywhere. Its serving path is stateless per-request by
//! design (ADR-MCPRE-051), the proxy forwards single request/response exchanges,
//! and the only `2025-06-18` in the tree is a COMMENT citing which spec revision
//! mandates the dual `Accept` header. There is no handshake state to target at a
//! version. See docs/spec/http-profile-conformance-notes.md.

use mcp_re_http_profile::JSON_RPC_ERROR_CODE;

/// MCP reserves the JSON-RPC error range -32020..=-32099 for its own error
/// allocation policy. MCP-RE's rejection code must stay outside it: a collision
/// would make an MCP-RE rejection indistinguishable from an MCP protocol error
/// to a client dispatching on the integer.
///
/// The load-bearing signal is the `mcp-re.*` wire code in `error.data`, not this
/// integer — but a client that switches on the code must not be misled, and
/// "the real signal is elsewhere" is not a reason to collide.
#[test]
fn rejection_code_is_outside_the_mcp_reserved_range() {
    const MCP_RESERVED_LOW: i64 = -32099;
    const MCP_RESERVED_HIGH: i64 = -32020;
    assert!(
        !(MCP_RESERVED_LOW..=MCP_RESERVED_HIGH).contains(&JSON_RPC_ERROR_CODE),
        "-32003 must not fall in MCP's reserved {MCP_RESERVED_LOW}..={MCP_RESERVED_HIGH} range"
    );
    assert_eq!(JSON_RPC_ERROR_CODE, -32003);
}

/// -32003 also sits in the JSON-RPC 2.0 implementation-defined server-error range
/// (-32000..=-32099), which is where an application-defined code belongs.
#[test]
fn rejection_code_is_a_jsonrpc_server_error() {
    assert!((-32099..=-32000).contains(&JSON_RPC_ERROR_CODE));
}

/// SEP-2322 (MRTR) discriminates a non-terminal turn with `resultType` carrying
/// the snake_case value `input_required`. MCP-RE's classifier already matches the
/// RC. Pinning it here means a rename in the final spec text surfaces as a test
/// failure rather than as continuations silently classifying as terminal — which
/// would end a call record at the first hop and look like success.
#[test]
fn mrtr_input_required_discriminator_matches_sep_2322() {
    use mcp_re_client_core::classify_result;
    use mcp_re_client_core::ResultClass;

    let non_terminal = serde_json::json!({ "resultType": "input_required" });
    assert_eq!(
        classify_result(Some(&non_terminal)),
        ResultClass::InputRequired,
        "the SEP-2322 discriminator is snake_case `input_required` on `resultType`"
    );

    // camelCase is NOT the discriminator: if the final spec were to switch, this
    // must fail rather than quietly accept both spellings.
    let camel = serde_json::json!({ "resultType": "inputRequired" });
    assert_eq!(classify_result(Some(&camel)), ResultClass::Terminal);

    // An absent or unrelated resultType is terminal.
    assert_eq!(
        classify_result(Some(&serde_json::json!({ "ok": true }))),
        ResultClass::Terminal
    );
    assert_eq!(classify_result(None), ResultClass::Terminal);
}
