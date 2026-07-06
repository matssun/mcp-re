//! A plain (MCP-RE-UNAWARE) inner MCP server fixture for the full-stack CLI smoke
//! test. It reads one JSON-RPC request from stdin to EOF and writes one JSON-RPC
//! response to stdout, echoing back the request's `params._meta` so the test can
//! prove the proxy injected a fresh verified-context block before forwarding.
//!
//! This is exactly how `cli::SubprocessInner` drives an inner server: one spawn
//! per request, request bytes on stdin, response bytes on stdout.

use std::io::Read;
use std::io::Write;

fn main() {
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        return;
    }
    let value: serde_json::Value = serde_json::from_slice(&buf).unwrap_or(serde_json::Value::Null);
    let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let meta = value
        .get("params")
        .and_then(|params| params.get("_meta"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let method = value.get("method").cloned().unwrap_or(serde_json::Value::Null);

    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "echoed_meta": meta, "echoed_method": method },
    });
    let bytes = serde_json::to_vec(&response).unwrap_or_default();
    let _ = std::io::stdout().write_all(&bytes);
    let _ = std::io::stdout().flush();
}
