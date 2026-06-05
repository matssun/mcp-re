//! Persistence end-to-end test for the long-lived demo server (MCPS-062).
//!
//! Spawns the REAL `mcps-demo-server` binary as its own OS process and drives a
//! full MCP session over ONE process: an `initialize` handshake followed by
//! SEVERAL `tools/call` / `tools/list` requests, all written as newline-
//! delimited JSON-RPC to the child's stdin. This is the strongest proof of the
//! persistence property — a one-shot server would answer the first request and
//! die, leaving the later responses missing. We assert that every one of the
//! many requests gets its own response line over the single process, and that
//! the process exits cleanly on stdin EOF.
//!
//! The binary is delivered via Bazel runfiles (`data` dep) and resolved via the
//! `$(rlocationpath ...)` env var — no hardcoded path, no cargo.

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

#[test]
fn many_requests_over_one_long_lived_process() {
    let bin = server_binary();

    // A scripted MCP session: initialize, then MANY interleaved tool calls and a
    // tools/list — all over the SAME process. A one-shot server cannot answer
    // every line.
    let requests = vec![
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2025-06-18" } }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "echo", "arguments": { "message": "one" } } }),
        json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "list_items", "arguments": {} } }),
        json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": { "name": "echo", "arguments": { "message": "two" } } }),
        json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": { "name": "reset_items", "arguments": {} } }),
        json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": { "name": "echo", "arguments": { "message": "three" } } }),
    ];

    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn mcps-demo-server");

    // Write all requests, one JSON object per line, then close stdin (EOF) so the
    // long-lived loop ends cleanly.
    {
        let mut stdin = child.stdin.take().expect("child stdin");
        for req in &requests {
            let line = serde_json::to_string(req).expect("serialize request");
            stdin.write_all(line.as_bytes()).expect("write request");
            stdin.write_all(b"\n").expect("write newline");
        }
        // Dropping stdin here closes it -> EOF -> the server exits its loop.
    }

    // Read exactly one response line per request from the single process.
    let stdout = child.stdout.take().expect("child stdout");
    let reader = BufReader::new(stdout);
    let responses: Vec<Value> = reader
        .lines()
        .map(|l| l.expect("read response line"))
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(&l).expect("parse response line"))
        .collect();

    let status = child.wait().expect("wait for child");
    assert!(status.success(), "long-lived server must exit cleanly on EOF");

    // Every request over the one process got its own response line, in order.
    assert_eq!(
        responses.len(),
        requests.len(),
        "one response per request over a single persistent process"
    );
    for (req, resp) in requests.iter().zip(responses.iter()) {
        assert_eq!(resp["id"], req["id"], "responses correlate by id, in order");
        assert!(resp.get("error").is_none(), "no errors in the happy session");
    }

    // Spot-check that the LATER requests (proof the process stayed alive) carry
    // real payloads, not a stale first answer.
    assert_eq!(responses[2]["result"]["content"][0]["text"], "one");
    assert_eq!(responses[6]["result"]["content"][0]["text"], "three");
    let items = responses[3]["result"]["structuredContent"]["items"]
        .as_array()
        .expect("items array");
    assert_eq!(items.len(), 3);
}
