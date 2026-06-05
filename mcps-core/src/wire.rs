//! JSON-RPC wire representation of MCP-S errors (MCPS_SPEC §12/§13).
//!
//! A failed verification is returned to the caller as a JSON-RPC error object
//! whose `message` and `data.mcps_error` are the frozen `mcps.*` wire token.
//! Pre-/at-verification errors are UNSIGNED (ADR-MCPS-004 §6.7). This is the one
//! place that shape is defined, so every MCP-S server (the native echo server,
//! the sidecar proxy) emits an identical error envelope.

use serde_json::json;
use serde_json::Value;

use crate::error::McpsError;

/// JSON-RPC application error code MCP-S uses for verification failures.
pub const MCPS_JSON_RPC_ERROR_CODE: i64 = -32003;

/// Serialize `error` as the canonical MCP-S JSON-RPC error object bound to the
/// request `id` (use [`Value::Null`] when the id is unavailable). Never fails:
/// a plain JSON object always serializes, with a minimal literal fallback.
pub fn json_rpc_error_object(error: &McpsError, id: &Value) -> Vec<u8> {
    let code = error.wire_code();
    let object = json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "error": {
            "code": MCPS_JSON_RPC_ERROR_CODE,
            "message": code,
            "data": {
                "mcps_error": code,
                "policy": "core",
                "retryable": false,
                "details": code
            }
        }
    });
    serde_json::to_vec(&object).unwrap_or_else(|_| {
        b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603}}".to_vec()
    })
}
