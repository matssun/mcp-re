//! Black-box tests for the long-lived demo server (MCPS-062).
//!
//! Drive the public `DemoServer::handle(raw_request_bytes) -> response_bytes`
//! seam with plain MCP JSON-RPC and assert on the parsed responses. The server
//! is MCP-RE-UNAWARE: no signing, no envelopes, no verified context here. The
//! in-memory item set is seeded deterministically so every result is stable.

use mcp_re_demo_server::DemoServer;
use serde_json::json;
use serde_json::Value;

/// Build a server seeded with a fixed item set.
fn server() -> DemoServer {
    DemoServer::new(vec!["alpha".into(), "beta".into(), "gamma".into()])
}

/// Parse the server's response bytes into JSON.
fn handle(server: &DemoServer, request: Value) -> Value {
    let request_bytes = serde_json::to_vec(&request).expect("serialize request");
    let response_bytes = server.handle(&request_bytes);
    serde_json::from_slice(&response_bytes).expect("parse response")
}

/// Send an `initialize` and assert success; used to satisfy the lifecycle gate.
fn initialize(server: &DemoServer) -> Value {
    handle(
        server,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-06-18" }
        }),
    )
}

#[test]
fn initialize_returns_well_formed_result() {
    let server = server();
    let response = initialize(&server);

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(response.get("error").is_none(), "initialize must not error");
    let result = &response["result"];
    assert!(result["protocolVersion"].is_string());
    assert!(result["capabilities"]["tools"].is_object());
    assert_eq!(result["serverInfo"]["name"], "mcp-re-demo-server");
}

#[test]
fn requests_before_initialize_are_not_initialized_errors() {
    let server = server();
    // No initialize first: tools/list must be refused with the -32002 code.
    let response = handle(
        &server,
        json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" }),
    );
    assert!(response.get("result").is_none());
    assert_eq!(response["error"]["code"], -32002);
    assert_eq!(response["id"], 7);
}

#[test]
fn tools_list_includes_three_scoped_tools_after_initialize() {
    let server = server();
    initialize(&server);
    let response = handle(
        &server,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    );

    assert!(response.get("error").is_none());
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert_eq!(tools.len(), 3, "public + protected + admin");

    // Map tool name -> intended-scope annotation so #3959 can bind grants.
    let scope_of = |name: &str| -> String {
        tools
            .iter()
            .find(|t| t["name"] == name)
            .and_then(|t| t["annotations"]["net.mcp-re.intendedScope"].as_str())
            .unwrap_or_else(|| panic!("tool {name} with scope annotation"))
            .to_string()
    };
    assert_eq!(scope_of("echo"), "public");
    assert_eq!(scope_of("list_items"), "protected");
    assert_eq!(scope_of("reset_items"), "admin");

    // The public tool keeps a real input schema.
    let echo = tools.iter().find(|t| t["name"] == "echo").unwrap();
    assert_eq!(echo["inputSchema"]["properties"]["message"]["type"], "string");
}

#[test]
fn echo_public_tool_returns_the_message() {
    let server = server();
    initialize(&server);
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "echo", "arguments": { "message": "hello mcp-re" } }
        }),
    );

    assert!(response.get("error").is_none());
    let result = &response["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["content"][0]["text"], "hello mcp-re");
    assert_eq!(result["structuredContent"]["message"], "hello mcp-re");
}

#[test]
fn echo_without_message_is_a_tool_error_not_a_panic() {
    let server = server();
    initialize(&server);
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "echo", "arguments": {} }
        }),
    );
    assert_eq!(response["result"]["isError"], true);
}

#[test]
fn list_items_protected_tool_returns_seeded_items() {
    let server = server();
    initialize(&server);
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": { "name": "list_items", "arguments": {} }
        }),
    );

    let items = response["result"]["structuredContent"]["items"]
        .as_array()
        .expect("items array");
    let names: Vec<&str> = items.iter().map(|i| i.as_str().unwrap()).collect();
    assert_eq!(names, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn reset_items_admin_tool_restores_the_seed_set() {
    let server = server();
    initialize(&server);
    // reset is idempotent against the seed and never errors.
    let response = handle(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": { "name": "reset_items", "arguments": {} }
        }),
    );
    assert_eq!(response["result"]["isError"], false);
    let items = response["result"]["structuredContent"]["items"]
        .as_array()
        .expect("items array");
    assert_eq!(items.len(), 3);
}

#[test]
fn unknown_tool_is_a_jsonrpc_error() {
    let server = server();
    initialize(&server);
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
    initialize(&server);
    let response = handle(
        &server,
        json!({ "jsonrpc": "2.0", "id": 9, "method": "no/such/method" }),
    );
    assert_eq!(response["error"]["code"], -32601);
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

#[test]
fn shutdown_is_acknowledged_and_flagged_to_stop() {
    let server = server();
    let bytes = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 10, "method": "shutdown"
    }))
    .unwrap();
    assert!(server.handle_should_stop(&bytes), "shutdown stops the loop");
    let response: Value = serde_json::from_slice(&server.handle(&bytes)).unwrap();
    assert_eq!(response["result"]["ok"], true);
}
