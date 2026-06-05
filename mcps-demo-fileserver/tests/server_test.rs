//! Black-box tests for the demo fileserver (MCPS-045).
//!
//! Drive the public `FileServer::handle(raw_request_bytes) -> response_bytes`
//! seam with plain MCP JSON-RPC and assert on the parsed responses. The server
//! is MCP-S-UNAWARE: no signing, no envelopes, no verified context here.
//!
//! The committed `demo_root/` fixture makes every result deterministic. Tests
//! point the server at the in-tree fixture via CARGO_MANIFEST_DIR so they work
//! under both Cargo and Bazel (Cargo.toml is in compile_data).

use std::path::PathBuf;

use mcps_demo_fileserver::FileServer;
use serde_json::json;
use serde_json::Value;

/// Absolute path to the committed `demo_root/` fixture.
///
/// Under Bazel the fixture is delivered via runfiles: the BUILD target sets
/// `DEMO_ROOT_README` to `$(rlocationpath .../demo_root/readme.txt)`, which we
/// resolve against the runfiles root and take the parent of. Under plain Cargo
/// (no such env) we fall back to `CARGO_MANIFEST_DIR/demo_root`.
fn demo_root() -> PathBuf {
    if let Ok(rel) = std::env::var("DEMO_ROOT_README") {
        let mut candidates: Vec<PathBuf> = Vec::new();
        for key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
            if let Ok(root) = std::env::var(key) {
                candidates.push(PathBuf::from(&root).join(&rel));
            }
        }
        candidates.push(PathBuf::from(&rel));
        for candidate in candidates {
            if candidate.exists() {
                return candidate
                    .parent()
                    .expect("readme.txt has a parent")
                    .to_path_buf();
            }
        }
        panic!("cannot locate demo_root via DEMO_ROOT_README='{rel}'");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("demo_root")
}

/// Build a server rooted at the committed fixture.
fn server() -> FileServer {
    FileServer::new(demo_root())
}

/// Parse the server's response bytes into JSON.
fn handle(server: &FileServer, request: Value) -> Value {
    let request_bytes = serde_json::to_vec(&request).expect("serialize request");
    let response_bytes = server.handle(&request_bytes);
    serde_json::from_slice(&response_bytes).expect("parse response")
}

#[test]
fn initialize_returns_well_formed_result() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-06-18" }
        }),
    );

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(response.get("error").is_none(), "initialize must not error");
    let result = &response["result"];
    assert!(result["protocolVersion"].is_string());
    assert!(result["capabilities"]["tools"].is_object());
    assert!(result["serverInfo"]["name"].is_string());
}

#[test]
fn tools_list_includes_list_files_with_path_schema() {
    let server = server();
    let response = handle(
        &server,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    );

    assert!(response.get("error").is_none());
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert_eq!(tools.len(), 1, "exactly one tool");
    let tool = &tools[0];
    assert_eq!(tool["name"], "list_files");
    assert!(tool["description"].is_string());
    let schema = &tool["inputSchema"];
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["properties"]["path"]["type"], "string");
    let required = schema["required"].as_array().expect("required array");
    assert!(required.iter().any(|r| r == "path"));
}

#[test]
fn list_files_on_root_returns_fixture_entries_deterministically() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "." } }
        }),
    );

    assert!(response.get("error").is_none());
    let result = &response["result"];
    assert_eq!(result["isError"], false);
    let entries = result["structuredContent"]["entries"]
        .as_array()
        .expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().expect("entry name"))
        .collect();
    // Deterministic, sorted listing of the committed fixture root.
    assert_eq!(
        names,
        vec!["config.yaml", "data.csv", "readme.txt", "reports"]
    );
    // The subdirectory must be flagged as a directory.
    let reports = entries
        .iter()
        .find(|e| e["name"] == "reports")
        .expect("reports entry");
    assert_eq!(reports["type"], "directory");
}

#[test]
fn list_files_on_subdirectory_returns_its_entries() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "reports" } }
        }),
    );

    assert!(response.get("error").is_none());
    let entries = response["result"]["structuredContent"]["entries"]
        .as_array()
        .expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().expect("entry name"))
        .collect();
    assert_eq!(names, vec!["q1.txt", "q2.txt"]);
}

#[test]
fn list_files_refuses_dotdot_escape() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "../.." } }
        }),
    );

    // A refusal is reported as a tool error result (isError: true), never a panic
    // and never a directory listing.
    assert!(response.get("result").is_some(), "tool error is a result");
    let result = &response["result"];
    assert_eq!(result["isError"], true);
    assert!(result.get("structuredContent").is_none());
    let text = result["content"][0]["text"]
        .as_str()
        .expect("error text");
    assert!(text.to_lowercase().contains("escape") || text.to_lowercase().contains("outside"));
}

#[test]
fn list_files_refuses_absolute_path_outside_root() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "/etc" } }
        }),
    );

    let result = &response["result"];
    assert_eq!(result["isError"], true);
    assert!(result.get("structuredContent").is_none());
}

#[test]
fn list_files_on_missing_directory_is_a_tool_error_not_a_panic() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": "list_files", "arguments": { "path": "does_not_exist" } }
        }),
    );

    assert_eq!(response["result"]["isError"], true);
}

#[test]
fn unknown_tool_is_a_jsonrpc_error() {
    let server = server();
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": { "name": "no_such_tool", "arguments": {} }
        }),
    );

    assert!(response.get("error").is_some(), "unknown tool -> JSON-RPC error");
    assert_eq!(response["id"], 8);
}

#[test]
fn unknown_method_is_a_jsonrpc_method_not_found_error() {
    let server = server();
    let response = handle(
        &server,
        json!({ "jsonrpc": "2.0", "id": 9, "method": "no/such/method" }),
    );

    let error = &response["error"];
    assert_eq!(error["code"], -32601);
    assert_eq!(response["id"], 9);
}

#[test]
fn malformed_json_is_a_parse_error_with_null_id() {
    let server = server();
    let response_bytes = server.handle(b"{ this is not json ");
    let response: Value = serde_json::from_slice(&response_bytes).expect("parse response");
    assert_eq!(response["error"]["code"], -32700);
    assert_eq!(response["id"], Value::Null);
}
