//! Subprocess-hardening coverage for [`PersistentSubprocessInner`] — relocated here
//! (ADR-MCPRE-051 Phase B) when the subprocess/sandbox surface moved OUT of the
//! `mcp-re-proxy` PEP's TCB into this out-of-TCB bridge crate.
//!
//! These tests drive the persistent stdio inner DIRECTLY through the
//! [`InnerServer`] seam — no `Proxy`, no signing, no verification — to isolate the
//! child-containment behavior that is this crate's entire reason to exist: a
//! crashed, malformed, silent, flooding, or non-draining inner must FAIL CLOSED
//! (a `-32603` JSON-RPC error frame) rather than hang, panic, or grow memory
//! unbounded. Every inner here is a self-contained `/bin/sh` script, so the tests
//! need no external server binary and run on any POSIX host.
//!
//! (The pre-dispatch *verification* denial that used to live alongside these is a
//! PEP concern and stays with the proxy's policy tests; it has no meaning in this
//! crate, which never verifies.)

use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_stdio_bridge::inner_launch::InnerLaunchConfig;
use mcp_re_stdio_bridge::log_sink::InnerLogEvent;
use mcp_re_stdio_bridge::log_sink::InnerLogSink;
use mcp_re_stdio_bridge::persistent_inner::PersistentSubprocessInner;
use mcp_re_stdio_bridge::subprocess_inner::InnerServer;
use serde_json::Value;

/// A capturing log sink that counts lifecycle-event tags (spawn/exit/stderr), so a
/// test can assert the persistence property (ONE spawn across N dispatches).
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

/// The hardened default launch policy (empty env, controlled working dir, bounded
/// stderr, resource ceilings).
fn launch() -> InnerLaunchConfig {
    InnerLaunchConfig::new()
}

#[test]
fn n_dispatches_over_one_persistent_inner_process() {
    // The persistence property, observable at the inner seam WITHOUT a proxy: a
    // `/bin/sh` that answers the initialize handshake ONCE, then answers three
    // more request lines from the SAME process, proves ONE process serves N
    // dispatches. A one-shot inner would answer the first and die.
    //
    // The reader/printf sequence is deliberate (a `while read` loop deadlocks on
    // block-buffered pipe stdout): `sh` flushes its pending `printf` when it next
    // blocks on `read` — or on process exit for the final line — so each response
    // reaches the parent exactly when the parent is waiting for it.
    let sink = Arc::new(RecordingSink::default());
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "read a; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'; \
         read b; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\\n'; \
         read c; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\\n'; \
         read d; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\\n'"
            .to_string(),
    ];
    let inner = PersistentSubprocessInner::with_log_sink(&cmd, launch(), Arc::clone(&sink) as _)
        .expect("spawn + initialize the persistent inner");

    // The request `id` must match the inner's response `id` (the session
    // correlates them and skips stray frames); the sh answers every line with
    // `"id":1`, so each request carries `id:1`.
    for i in 0..3 {
        let out = inner.dispatch(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"noop\"}");
        let value: Value = serde_json::from_slice(&out).expect("JSON response");
        assert_eq!(
            value["result"]["ok"], true,
            "dispatch {i} must be answered by the same live process: {value}",
        );
    }

    // ONE spawn across all three dispatches: the process persisted.
    assert_eq!(sink.count("inner_spawned"), 1, "one persistent process");
}

#[test]
fn inner_crash_mid_session_fails_closed_not_hang_or_panic() {
    // A persistent inner whose process is a shell that reads ONE line then EXITS
    // (mid-session crash after the first response). The first request succeeds at
    // the inner level; the second observes EOF and must fail closed, never hang
    // or panic.
    let sink = Arc::new(RecordingSink::default());
    // sh that answers initialize + the first request, then exits (closes stdout).
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
    // memory is bounded.
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
    use std::sync::mpsc;
    use std::time::Duration;

    let sink = Arc::new(RecordingSink::default());
    // sh: answer the initialize handshake, then read NOTHING more — it sleeps,
    // never draining its stdin. The forwarded request (256 KiB, far above the
    // ~64 KiB pipe buffer) cannot be fully written: write_all would block.
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
    let big_request = serde_json::to_vec(&serde_json::json!({
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
    // construction must fail closed (nothing ever serves an un-initialized inner)
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
