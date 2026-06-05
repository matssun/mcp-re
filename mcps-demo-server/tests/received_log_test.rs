//! Inner-server received-request instrumentation test (MCPS-068, #3965).
//!
//! Anti-gaming: "deny-before-dispatch / inner not reached" must be verifiable
//! AT THE INNER SERVER, independent of any proxy claim. This test spawns the
//! REAL `mcps-demo-server` binary with the received-log ENABLED (via the
//! `--received-log <path>` flag), drives a full MCP session over the single
//! long-lived process, then reads back the inner's OWN append-only record and
//! asserts it lists EXACTLY the JSON-RPC ids + tool names of the `tools/call`
//! requests it actually executed — and omits ids it never received.
//!
//! No proxy is involved; the only signal consulted is the inner's own file.

use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use serde_json::json;
use serde_json::Value;

/// Resolve a runfiles-relative path delivered via an `$(rlocationpath ...)` env
/// var against the runfiles roots, returning the first candidate that exists.
fn resolve_runfile(env_key: &str) -> PathBuf {
    mcps_test_paths::resolve_runfile(env_key)
}

fn server_binary() -> PathBuf {
    resolve_runfile("DEMO_SERVER_BIN")
}

/// A unique-enough temp path under Bazel's per-test tmp dir (TEST_TMPDIR), so the
/// received-log write is hermetic and never collides between test cases.
fn received_log_path(tag: &str) -> PathBuf {
    let dir = std::env::var("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    dir.join(format!("mcps_demo_received_{tag}.log"))
}

/// Drive the binary with `requests` over one process, optionally enabling the
/// received-log at `log_path`. Returns the parsed response lines.
fn drive(bin: &PathBuf, log_path: Option<&PathBuf>, requests: &[Value]) -> Vec<Value> {
    let mut cmd = Command::new(bin);
    if let Some(path) = log_path {
        cmd.arg("--received-log").arg(path);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn mcps-demo-server");

    {
        let mut stdin = child.stdin.take().expect("child stdin");
        for req in requests {
            let line = serde_json::to_string(req).expect("serialize request");
            stdin.write_all(line.as_bytes()).expect("write request");
            stdin.write_all(b"\n").expect("write newline");
        }
    }

    let stdout = child.stdout.take().expect("child stdout");
    let responses: Vec<Value> = BufReader::new(stdout)
        .lines()
        .map(|l| l.expect("read response line"))
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(&l).expect("parse response line"))
        .collect();

    let status = child.wait().expect("wait for child");
    assert!(status.success(), "server must exit cleanly on EOF");
    responses
}

/// Read the inner's received-log into the list of (id, tool) pairs it recorded.
fn read_received(log_path: &PathBuf) -> Vec<(Value, String)> {
    let text = std::fs::read_to_string(log_path).expect("read received-log");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l).expect("parse received-log line");
            let id = v["id"].clone();
            let tool = v["tool"].as_str().expect("tool name").to_string();
            (id, tool)
        })
        .collect()
}

#[test]
fn received_log_lists_only_calls_the_inner_actually_served() {
    let bin = server_binary();
    let log_path = received_log_path("served");

    // initialize + tools/list (NOT a tools/call) + three tools/call requests.
    // The received-log must record ONLY the three tools/call ids (3, 5, 6),
    // never the initialize (1) or tools/list (2) — they are not tool dispatches.
    let requests = vec![
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2025-06-18" } }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "echo", "arguments": { "message": "one" } } }),
        json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": { "name": "list_items", "arguments": {} } }),
        json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": { "name": "reset_items", "arguments": {} } }),
    ];

    let responses = drive(&bin, Some(&log_path), &requests);
    assert_eq!(responses.len(), requests.len());

    let received = read_received(&log_path);
    assert_eq!(
        received,
        vec![
            (json!(3), "echo".to_string()),
            (json!(5), "list_items".to_string()),
            (json!(6), "reset_items".to_string()),
        ],
        "received-log records exactly the tools/call ids+names actually served, in order"
    );

    // A request-id never sent (e.g. a denied call the proxy would drop) must not
    // appear — the inner only records what it executed.
    let ids: Vec<&Value> = received.iter().map(|(id, _)| id).collect();
    assert!(!ids.contains(&&json!(99)), "an unsent/denied id is absent from the inner record");
}

#[test]
fn received_log_omits_unknown_tool_calls_that_were_not_executed() {
    let bin = server_binary();
    let log_path = received_log_path("unknown");

    // One served call (id 3) and one unknown-tool call (id 4). The unknown tool
    // is a JSON-RPC error and was NOT executed, so its id must NOT be recorded.
    let requests = vec![
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2025-06-18" } }),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "echo", "arguments": { "message": "hi" } } }),
        json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "no_such_tool", "arguments": {} } }),
    ];

    drive(&bin, Some(&log_path), &requests);

    let received = read_received(&log_path);
    assert_eq!(
        received,
        vec![(json!(3), "echo".to_string())],
        "only the served echo call is recorded; the unknown-tool call is omitted"
    );
}

#[test]
fn received_log_is_off_by_default_no_file_written() {
    let bin = server_binary();
    let log_path = received_log_path("default_off");
    // Ensure no stale file.
    let _ = std::fs::remove_file(&log_path);

    let requests = vec![
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2025-06-18" } }),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "echo", "arguments": { "message": "x" } } }),
    ];

    // No --received-log flag: a normal run must not write any file.
    drive(&bin, None, &requests);
    assert!(
        !log_path.exists(),
        "with the flag absent the server writes no received-log (default OFF)"
    );
}
