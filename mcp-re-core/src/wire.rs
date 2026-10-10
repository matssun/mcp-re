//! JSON-RPC wire representation of MCP-RE errors (MCP_RE_SPEC §12/§13).
//!
//! A failed verification is returned to the caller as a JSON-RPC error object
//! whose `message` and `data.mcp_re_error` are the frozen `mcp-re.*` wire token.
//! Pre-/at-verification errors are UNSIGNED (ADR-MCPS-004 §6.7). This is the one
//! place that shape is defined, so every MCP-RE server (the native echo server,
//! the sidecar proxy) emits an identical error envelope.

use serde_json::json;
use serde_json::Value;

use crate::error::McpReError;

/// JSON-RPC application error code MCP-RE uses for verification failures.
///
/// Allocated outside JSON-RPC's reserved band (`-32768..=-32000`), as MCP
/// 2026-07-28 §Error Codes requires of codes for purposes the MCP specification
/// does not define. The code identifies the emitter, not the reason: the frozen
/// `mcp-re.*` token in `message`/`data.mcp_re_error` carries every meaning.
pub const MCP_RE_JSON_RPC_ERROR_CODE: i64 = -31000;

/// Serialize `error` as the canonical MCP-RE JSON-RPC error object bound to the
/// request `id` (use [`Value::Null`] when the id is unavailable). The bytes are
/// always the canonical object: a [`Value`] renders without a failure path.
pub fn json_rpc_error_object(error: &McpReError, id: &Value) -> Vec<u8> {
    let code = error.wire_code();
    let object = json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "error": {
            "code": MCP_RE_JSON_RPC_ERROR_CODE,
            "message": code,
            "data": {
                "mcp_re_error": code,
                "policy": "core",
                "retryable": false,
                "details": code
            }
        }
    });
    object.to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ALL_ERRORS;

    fn render(error: &McpReError, id: &Value) -> Value {
        serde_json::from_slice::<Value>(&json_rpc_error_object(error, id))
            .expect("the envelope is JSON")
    }

    #[test]
    fn every_variant_renders_its_frozen_token_in_message_mcp_re_error_and_details() {
        assert_eq!(MCP_RE_JSON_RPC_ERROR_CODE, -31000);
        assert!(!(-32768..=-32000).contains(&MCP_RE_JSON_RPC_ERROR_CODE));
        for e in ALL_ERRORS {
            let v = render(e, &json!("req-1"));
            assert_eq!(v["jsonrpc"], "2.0");
            assert_eq!(v["id"], "req-1");
            assert_eq!(v["error"]["code"], -31000);
            assert_eq!(v["error"]["message"], e.wire_code());
            assert_eq!(v["error"]["data"]["mcp_re_error"], e.wire_code());
            assert_eq!(v["error"]["data"]["details"], e.wire_code());
            assert_eq!(v["error"]["data"]["policy"], "core");
        }
    }

    #[test]
    fn a_transport_binding_refusal_is_bound_to_the_request_id_and_is_not_retryable() {
        for id in [Value::Null, json!(7)] {
            let v = render(&McpReError::TransportBindingFailed, &id);
            assert_eq!(v["id"], id);
            assert_eq!(v["error"]["data"]["retryable"], false);
        }
    }
}
