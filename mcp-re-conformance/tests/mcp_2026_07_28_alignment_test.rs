// SPDX-License-Identifier: Apache-2.0
//! Alignment with MCP 2026-07-28 / SEP-2322 (issue #426).
//!
//! Checked against the FINAL published text of MCP 2026-07-28, which is the
//! current protocol revision. Each test pins a value the specification fixes, so
//! that a future revision moving it fails a test rather than a deployment.
//!
//! The issue's headline task — "bump the backend handshake / protocol-version
//! handling to 2026-07-28" — has no code to act on: MCP-RE performs no protocol
//! version negotiation anywhere. Its serving path is stateless per-request by
//! design (ADR-MCPRE-051), the proxy forwards single request/response exchanges,
//! and 2026-07-28 is itself a stateless per-request protocol. Which protocol
//! versions a deployment accepts is enforced by `McpTransportPolicy` (#425), not
//! by a handshake. See docs/spec/http-profile-conformance-notes.md.

use mcp_re_http_profile::JSON_RPC_ERROR_CODE;

/// MCP 2026-07-28 §Error Codes partitions JSON-RPC's implementation-defined band
/// `-32000..=-32099` completely: `-32000..=-32019` is legacy, which new
/// implementations "SHOULD NOT use ... at all" and where new codes MUST NOT be
/// allocated, and `-32020..=-32099` is reserved for the MCP specification, where
/// an implementation MUST NOT emit any code the specification does not define.
/// Codes for purposes MCP does not define belong outside the whole JSON-RPC
/// reserved range `-32768..=-32000`.
///
/// A rejection is exactly such a purpose, so MCP-RE's code sits outside that
/// range. The load-bearing signal remains the `mcp-re.*` wire code in
/// `error.data` — but a client that dispatches on the integer must not be misled,
/// and "the real signal is elsewhere" is not a licence to squat in a reserved
/// band.
#[test]
fn rejection_code_is_outside_the_json_rpc_reserved_range() {
    const JSON_RPC_RESERVED_LOW: i64 = -32768;
    const JSON_RPC_RESERVED_HIGH: i64 = -32000;
    assert!(
        !(JSON_RPC_RESERVED_LOW..=JSON_RPC_RESERVED_HIGH).contains(&JSON_RPC_ERROR_CODE),
        "{JSON_RPC_ERROR_CODE} must not fall in JSON-RPC's reserved \
         {JSON_RPC_RESERVED_LOW}..={JSON_RPC_RESERVED_HIGH} range"
    );
    assert_eq!(JSON_RPC_ERROR_CODE, -31000);
}

/// The two sub-ranges MCP 2026-07-28 partitions the implementation-defined band
/// into, named separately so a regression tells you which rule it broke.
#[test]
fn rejection_code_is_in_neither_mcp_sub_range() {
    assert!(
        !(-32019..=-32000).contains(&JSON_RPC_ERROR_CODE),
        "the legacy sub-range is closed to new implementations"
    );
    assert!(
        !(-32099..=-32020).contains(&JSON_RPC_ERROR_CODE),
        "the MCP-reserved sub-range admits only codes the MCP specification defines"
    );
}

/// The one MCP-RE-emitted code is the same integer everywhere. The core envelope
/// and the HTTP-profile rejection are written by different crates; a client
/// dispatching on the integer must not need to know which one answered.
#[test]
fn the_core_and_http_profile_codes_are_the_same_integer() {
    assert_eq!(
        JSON_RPC_ERROR_CODE,
        mcp_re_core::wire::MCP_RE_JSON_RPC_ERROR_CODE
    );
}

/// SEP-2322 (MRTR) discriminates a non-terminal turn with `resultType` carrying
/// the snake_case value `input_required` — confirmed against the final text.
/// Pinning it means a rename in a later revision surfaces as a test failure
/// rather than as continuations silently classifying as terminal, which would end
/// a call record at the first hop and look like success.
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

    // camelCase is NOT the discriminator: if a later revision were to switch,
    // this must fail rather than quietly accept both spellings.
    let camel = serde_json::json!({ "resultType": "inputRequired" });
    assert_eq!(classify_result(Some(&camel)), ResultClass::Terminal);

    // An absent resultType is terminal, which the final text requires of clients
    // for backward compatibility with revisions that predate the field: "clients
    // MUST treat an absent resultType as `complete`".
    assert_eq!(
        classify_result(Some(&serde_json::json!({ "ok": true }))),
        ResultClass::Terminal
    );
    assert_eq!(classify_result(None), ResultClass::Terminal);
}

/// `complete` is the final text's terminal discriminator, and MCP-RE reads it as
/// terminal. Unrecognized values are a separate question the final text answers
/// differently from this implementation — see #495.
#[test]
fn the_complete_discriminator_is_terminal() {
    use mcp_re_client_core::classify_result;
    use mcp_re_client_core::ResultClass;

    let terminal = serde_json::json!({ "resultType": "complete" });
    assert_eq!(classify_result(Some(&terminal)), ResultClass::Terminal);
}
