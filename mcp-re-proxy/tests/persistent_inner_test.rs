//! MCPS-063 (MCP-RE-EPIC-P6.6B) — the proxy fronts a LONG-LIVED inner MCP server.
//!
//! These tests drive the REAL `mcp-re-demo-server` binary (#3956) as the
//! persistent inner subprocess behind a real [`Proxy`], with the host signing
//! every request. They prove the persistence property end to end: ONE inner
//! process serves an `initialize` handshake (done once at construction) followed
//! by N verified `tools/call` requests, with `inner_spawned` emitted exactly once
//! and `inner_request_forwarded` emitted once per forwarded request.
//!
//! The binary is delivered via Bazel runfiles (`data` dep) and resolved via the
//! `$(rlocationpath ...)` env var — no hardcoded path, no cargo.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_host::HostSigner;
use mcp_re_proxy::InnerLaunchConfig;
use mcp_re_proxy::InnerLogEvent;
use mcp_re_proxy::InnerLogSink;
use mcp_re_proxy::PersistentSubprocessInner;
use mcp_re_proxy::Proxy;
use serde_json::json;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const SKEW: i64 = 300;

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn now() -> i64 {
    mcp_re_core::parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60
}
fn inbound_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r
}
fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

/// A signed `echo` tool call carrying the (unique) `nonce` and `message`.
fn signed_echo(nonce: &str, message: &str) -> Vec<u8> {
    host()
        .sign_tool_call(
            &Value::String(format!("req-{nonce}")),
            "echo",
            json!({ "message": message }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs")
}

/// Resolve a runfiles-relative path delivered via `$(rlocationpath ...)`.
fn resolve_runfile(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

fn demo_server_command() -> Vec<String> {
    vec![resolve_runfile("DEMO_SERVER_BIN").to_string_lossy().into_owned()]
}

/// A capturing log sink shared by BOTH the inner (spawn/exit/stderr) and the
/// proxy (request_forwarded/response_signed), so a single counter sees the whole
/// lifecycle.
#[derive(Default)]
struct RecordingSink {
    tags: Mutex<Vec<String>>,
}
impl InnerLogSink for RecordingSink {
    fn log(&self, _inner_identity: &str, event: &InnerLogEvent) {
        self.tags.lock().expect("lock").push(event.tag().to_string());
    }
    fn log_stderr(&self, _inner_identity: &str, _captured: &[u8]) {}
}
impl RecordingSink {
    fn count(&self, tag: &str) -> usize {
        self.tags.lock().expect("lock").iter().filter(|t| *t == tag).count()
    }
}

/// The temp dir is a valid controlled working dir for the inner.
fn launch() -> InnerLaunchConfig {
    InnerLaunchConfig::new()
}

#[test]
fn persistent_inner_initializes_and_forwards_one_request() {
    let sink = Arc::new(RecordingSink::default());
    let inner = PersistentSubprocessInner::with_log_sink(
        &demo_server_command(),
        launch(),
        Arc::clone(&sink) as _,
    )
    .expect("spawn + initialize the persistent inner");

    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_log_sink(Arc::clone(&sink) as _);

    let response = proxy.handle(&signed_echo("nonce-0001", "hello-persistent"), now());
    let value: Value = serde_json::from_slice(&response).expect("response is JSON");
    assert!(value.get("error").is_none(), "happy path must not error: {value}");
    // The signed response wraps the demo server's echo tool result.
    assert_eq!(
        value["result"]["content"][0]["text"].as_str(),
        Some("hello-persistent"),
    );

    // The inner was spawned ONCE (at construction), and the one request was
    // forwarded once.
    assert_eq!(sink.count("inner_spawned"), 1, "inner spawned exactly once");
    assert_eq!(sink.count("inner_request_forwarded"), 1);
}

#[test]
fn n_requests_over_one_persistent_inner_process() {
    let sink = Arc::new(RecordingSink::default());
    let inner = PersistentSubprocessInner::with_log_sink(
        &demo_server_command(),
        launch(),
        Arc::clone(&sink) as _,
    )
    .expect("spawn + initialize");

    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_log_sink(Arc::clone(&sink) as _);

    // Five distinct verified requests over the SAME inner process. A one-shot
    // inner would answer the first and die; the persistent inner answers all.
    let messages = ["one", "two", "three", "four", "five"];
    for (i, message) in messages.iter().enumerate() {
        let nonce = format!("nonce-n-{i:04}");
        let response = proxy.handle(&signed_echo(&nonce, message), now());
        let value: Value = serde_json::from_slice(&response).expect("JSON response");
        assert!(value.get("error").is_none(), "request {i} errored: {value}");
        assert_eq!(
            value["result"]["content"][0]["text"].as_str(),
            Some(*message),
            "request {i} got the wrong (or stale) answer",
        );
    }

    // The persistence property, observable: ONE spawn, N forwards.
    assert_eq!(sink.count("inner_spawned"), 1, "one persistent process");
    assert_eq!(
        sink.count("inner_request_forwarded"),
        messages.len(),
        "inner_request_forwarded is the durable per-request 'inner reached' signal",
    );
    assert_eq!(sink.count("inner_response_signed"), messages.len());
}

#[test]
fn pre_dispatch_denial_yields_zero_forwards_while_inner_stays_alive() {
    let sink = Arc::new(RecordingSink::default());
    let inner = PersistentSubprocessInner::with_log_sink(
        &demo_server_command(),
        launch(),
        Arc::clone(&sink) as _,
    )
    .expect("spawn + initialize");

    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(inbound_resolver()),
        AUDIENCE,
        SKEW,
        Box::new(inner),
    )
    .with_log_sink(Arc::clone(&sink) as _);

    // An UNSIGNED request is rejected before dispatch (verify fails closed); the
    // inner is never reached.
    let plain = serde_json::to_vec(&json!({
        "id": "req-denied",
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": { "name": "echo", "arguments": { "message": "should not arrive" } }
    }))
    .unwrap();
    let response = proxy.handle(&plain, now());
    let value: Value = serde_json::from_slice(&response).expect("JSON");
    assert_eq!(value["error"]["message"].as_str(), Some("mcp-re.missing_envelope"));

    // The denial produced ZERO forwards (the inner-reached count is the signal).
    assert_eq!(
        sink.count("inner_request_forwarded"),
        0,
        "a pre-dispatch denial must not forward to the inner",
    );

    // ...and the inner is still alive: a subsequent VERIFIED request succeeds over
    // the same process (it was never torn down by the denial).
    let ok = proxy.handle(&signed_echo("nonce-after-denial", "alive"), now());
    let ok_value: Value = serde_json::from_slice(&ok).expect("JSON");
    assert_eq!(ok_value["result"]["content"][0]["text"].as_str(), Some("alive"));
    assert_eq!(sink.count("inner_spawned"), 1, "still the same one process");
    assert_eq!(sink.count("inner_request_forwarded"), 1);
}

#[test]
fn inner_crash_mid_session_fails_closed_not_hang_or_panic() {
    // A persistent inner whose process is a shell that reads ONE line then EXITS
    // (mid-session crash after the first response). The first request succeeds at
    // the inner level; the second observes EOF and must fail closed, never hang
    // or panic. We do not go through verification here — we drive the inner
    // directly via the InnerServer trait to isolate the crash-handling behavior.
    use mcp_re_proxy::InnerServer;

    let sink = Arc::new(RecordingSink::default());
    // sh that answers initialize + the first request, then exits (closes stdout).
    // Reads exactly two lines (initialize, then one dispatch), echoing a valid
    // JSON-RPC result for each, then falls off the end -> EOF on the next read.
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "read a; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'; \
         read b; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'"
            .to_string(),
    ];
    let inner = PersistentSubprocessInner::with_log_sink(&cmd, launch(), Arc::clone(&sink) as _)
        .expect("spawn + initialize (the sh answers the handshake)");

    // First dispatch: the sh answers, then the process ends after this line.
    let first = inner.dispatch(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"noop\"}");
    let first_value: Value = serde_json::from_slice(&first).expect("JSON");
    // The sh echoes id:1; the response is whatever line it wrote (valid JSON).
    assert!(first_value.get("result").is_some() || first_value.get("error").is_some());

    // Second dispatch: stdout is now closed (the sh exited). The inner must fail
    // closed with a JSON-RPC internal error, not hang or panic.
    let second = inner.dispatch(b"{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"noop\"}");
    let second_value: Value = serde_json::from_slice(&second).expect("JSON error frame");
    assert_eq!(
        second_value["error"]["code"], -32603,
        "a crashed inner must fail closed: {second_value}",
    );
}

#[test]
fn malformed_response_line_fails_closed() {
    use mcp_re_proxy::InnerServer;

    let sink = Arc::new(RecordingSink::default());
    // Answers the initialize handshake with a valid frame, then emits GARBAGE for
    // the next request.
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "read a; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'; \
         read b; printf 'NOT JSON AT ALL\\n'; cat >/dev/null"
            .to_string(),
    ];
    let inner = PersistentSubprocessInner::with_log_sink(&cmd, launch(), Arc::clone(&sink) as _)
        .expect("spawn + initialize");

    let out = inner.dispatch(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"noop\"}");
    let value: Value = serde_json::from_slice(&out).expect("JSON error frame");
    assert_eq!(
        value["error"]["code"], -32603,
        "a malformed inner response line must fail closed: {value}",
    );
}

#[test]
fn inner_read_timeout_fires_on_hung_inner() {
    // MCPS-074 (audit §3 H-3): an inner that answers the initialize handshake,
    // reads the dispatch line, then goes silent forever (sleep 3600) must NOT
    // wedge the serve loop. With a short per-read timeout the dispatch must fail
    // closed (-32603) within ~timeout + slack. The dispatch runs on a spawned
    // thread joined via recv_timeout so this test FAILS (not hangs) if no
    // timeout exists.
    use mcp_re_proxy::InnerServer;
    use std::sync::mpsc;
    use std::time::Duration;

    let sink = Arc::new(RecordingSink::default());
    // sh: answer initialize, read the dispatch line, then hang forever.
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "read a; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'; \
         read b; sleep 3600"
            .to_string(),
    ];
    let launch = InnerLaunchConfig {
        inner_read_timeout: Duration::from_secs(1),
        ..InnerLaunchConfig::new()
    };
    let inner = PersistentSubprocessInner::with_log_sink(&cmd, launch, Arc::clone(&sink) as _)
        .expect("spawn + initialize (the sh answers the handshake)");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let out = inner.dispatch(b"{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"noop\"}");
        let _ = tx.send(out);
    });
    let out = rx
        .recv_timeout(Duration::from_secs(8))
        .expect("dispatch must return within timeout + slack, not hang on a silent inner");
    let value: Value = serde_json::from_slice(&out).expect("JSON error frame");
    assert_eq!(
        value["error"]["code"], -32603,
        "a hung/silent inner must fail closed via the per-read timeout: {value}",
    );
}

#[test]
fn inner_read_timeout_fires_on_unterminated_line() {
    // MCPS-074: an inner that answers initialize, then emits partial bytes with
    // NO trailing newline and goes silent. A naive poll-then-read_line would
    // block inside read_line forever waiting for '\n'; the deadline-bounded line
    // reader must fire mid-line. MAX_SKIPPED_LINES does not save this (no line is
    // ever completed). Must fail closed (-32603) within ~timeout + slack.
    use mcp_re_proxy::InnerServer;
    use std::sync::mpsc;
    use std::time::Duration;

    let sink = Arc::new(RecordingSink::default());
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "read a; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'; \
         read b; printf 'partial-no-newline'; sleep 3600"
            .to_string(),
    ];
    let launch = InnerLaunchConfig {
        inner_read_timeout: Duration::from_secs(1),
        ..InnerLaunchConfig::new()
    };
    let inner = PersistentSubprocessInner::with_log_sink(&cmd, launch, Arc::clone(&sink) as _)
        .expect("spawn + initialize");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let out = inner.dispatch(b"{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"noop\"}");
        let _ = tx.send(out);
    });
    let out = rx
        .recv_timeout(Duration::from_secs(8))
        .expect("dispatch must return within timeout + slack, not block inside read_line on a partial line");
    let value: Value = serde_json::from_slice(&out).expect("JSON error frame");
    assert_eq!(
        value["error"]["code"], -32603,
        "an unterminated line then silence must fail closed via the deadline reader: {value}",
    );
}

#[test]
fn inner_read_oversized_line_fails_closed() {
    // MCPS-074 (review follow-up): an inner that answers initialize, then floods
    // a very large UNTERMINATED line *quickly* (well within the read timeout) then
    // sleeps. The time bound alone would let the line buffer grow to gigabytes
    // before the deadline fires — an OOM / availability DoS. The incremental
    // line-length cap (MAX_INNER_LINE_BYTES = 1 MiB) must trip FIRST, failing
    // closed (-32603) PROMPTLY — well within the (generous) read timeout — proving
    // memory is bounded. The dispatch runs on a spawned thread joined via
    // recv_timeout so this test FAILS (not hangs) if the cap is absent.
    use mcp_re_proxy::InnerServer;
    use std::sync::mpsc;
    use std::time::Duration;
    use std::time::Instant;

    let sink = Arc::new(RecordingSink::default());
    // sh: answer initialize, read the dispatch line, then emit ~5_000_000 bytes
    // with NO trailing newline (a single unterminated line), then hang.
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "read a; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'; \
         read b; yes | head -c 5000000 | tr -d '\\n'; sleep 3600"
            .to_string(),
    ];
    // A GENEROUS read timeout: if the test passes promptly it is the SIZE cap that
    // tripped, not the time bound (which would only fire after 30s).
    let launch = InnerLaunchConfig {
        inner_read_timeout: Duration::from_secs(30),
        ..InnerLaunchConfig::new()
    };
    let inner = PersistentSubprocessInner::with_log_sink(&cmd, launch, Arc::clone(&sink) as _)
        .expect("spawn + initialize (the sh answers the handshake)");

    let (tx, rx) = mpsc::channel();
    let started = Instant::now();
    std::thread::spawn(move || {
        let out = inner.dispatch(b"{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"noop\"}");
        let _ = tx.send(out);
    });
    // Far below the 30s read timeout: a prompt return proves the SIZE cap tripped.
    let out = rx
        .recv_timeout(Duration::from_secs(8))
        .expect("dispatch must fail closed PROMPTLY on the size cap, not grow unbounded or hang");
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "the size cap must trip well within the read timeout (memory bounded)",
    );
    let value: Value = serde_json::from_slice(&out).expect("JSON error frame");
    assert_eq!(
        value["error"]["code"], -32603,
        "an oversized unterminated line must fail closed via the line-length cap: {value}",
    );
}

#[test]
fn inner_write_timeout_fires_when_inner_stops_draining_stdin() {
    // MCPS-093 (audit §3 H-3, WRITE half): an inner that completes the initialize
    // handshake then STOPS draining its stdin must NOT wedge the serve loop when a
    // forwarded request is larger than the OS pipe buffer (~64 KiB). Without a
    // bounded write, `write_all` blocks forever holding the session Mutex once the
    // pipe fills. With the poll(POLLOUT) deadline (sharing inner_read_timeout) the
    // dispatch fails closed (-32603) within ~timeout + slack.
    //
    // Self-disarming: the dispatch runs on a spawned thread joined via
    // recv_timeout(8s). The configured write deadline is 1s, so WITH the fix the
    // channel delivers fast; WITHOUT the fix `write_all` blocks indefinitely, the
    // 8s recv_timeout elapses, `.expect(..)` fails, and the test FAILS (not hangs
    // the runner — the spawned writer thread is abandoned, the test process exits).
    use mcp_re_proxy::InnerServer;
    use std::sync::mpsc;
    use std::time::Duration;

    let sink = Arc::new(RecordingSink::default());
    // sh: answer the initialize handshake, then read NOTHING more — it sleeps,
    // never draining its stdin. The proxy's forwarded request (256 KiB, far above
    // the ~64 KiB pipe buffer) cannot be fully written: write_all would block.
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "read a; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'; sleep 3600"
            .to_string(),
    ];
    let launch = InnerLaunchConfig {
        inner_read_timeout: Duration::from_secs(1),
        ..InnerLaunchConfig::new()
    };
    let inner = PersistentSubprocessInner::with_log_sink(&cmd, launch, Arc::clone(&sink) as _)
        .expect("spawn + initialize (the sh answers the handshake)");

    // A single-line JSON-RPC request whose total size (>256 KiB) far exceeds the
    // pipe buffer. The padding lives in a string field so the frame stays one line.
    let padding = "x".repeat(256 * 1024);
    let big_request = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "noop",
        "params": { "pad": padding }
    }))
    .expect("serialize big request");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let out = inner.dispatch(&big_request);
        let _ = tx.send(out);
    });
    let out = rx
        .recv_timeout(Duration::from_secs(8))
        .expect("dispatch must return within the write timeout + slack, not block in write_all on a non-draining inner");
    let value: Value = serde_json::from_slice(&out).expect("JSON error frame");
    assert_eq!(
        value["error"]["code"], -32603,
        "an inner that stops draining stdin must fail closed via the per-write timeout: {value}",
    );
}

#[test]
fn handshake_failure_aborts_construction() {
    // An inner that immediately exits cannot complete the initialize handshake;
    // construction must fail closed (no Proxy ever serves an un-initialized inner)
    // and reap the child.
    let sink = Arc::new(RecordingSink::default());
    let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), "exit 0".to_string()];
    let result =
        PersistentSubprocessInner::with_log_sink(&cmd, launch(), Arc::clone(&sink) as _);
    assert!(
        result.is_err(),
        "an inner that cannot complete the initialize handshake must fail construction",
    );
}
