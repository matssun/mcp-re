//! JSON-RPC wire representation of authorization denials (MCPS-023).
//!
//! Mirrors `mcp_re_core::json_rpc_error_object` so a sidecar enforcing policy emits
//! the SAME error envelope shape as a Core verification failure, differing only in
//! `data.policy` (`"authorization"` vs `"core"`) and carrying the
//! `mcp-re.authorization_*` token. Authorization denials, like pre-dispatch
//! verification failures, are UNSIGNED and fail closed.

use mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE;
use serde_json::json;
use serde_json::Value;

use crate::error::PolicyError;

/// Serialize a [`PolicyError`] as the MCP-RE JSON-RPC error object bound to the
/// request `id` (use [`Value::Null`] when unavailable). Never fails.
pub fn json_rpc_authorization_error(error: &PolicyError, id: &Value) -> Vec<u8> {
    let code = error.wire_code();
    let object = json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "error": {
            "code": MCP_RE_JSON_RPC_ERROR_CODE,
            "message": code,
            "data": {
                "mcp_re_error": code,
                "policy": "authorization",
                "retryable": false,
                "details": code
            }
        }
    });
    serde_json::to_vec(&object).unwrap_or_else(|_| {
        b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603}}".to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::json_rpc_authorization_error;
    use crate::error::PolicyError;
    use serde_json::Value;

    #[test]
    fn renders_the_authorization_error_envelope() {
        let bytes = json_rpc_authorization_error(
            &PolicyError::AuthorizationScopeDenied,
            &Value::String("req-1".to_string()),
        );
        let value: Value = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(value["id"].as_str(), Some("req-1"));
        assert_eq!(
            value["error"]["message"].as_str(),
            Some("mcp-re.authorization_scope_denied")
        );
        assert_eq!(value["error"]["data"]["policy"].as_str(), Some("authorization"));
        assert_eq!(value["error"]["data"]["retryable"].as_bool(), Some(false));
        assert_eq!(value["error"]["code"].as_i64(), Some(-32003));
    }
}
