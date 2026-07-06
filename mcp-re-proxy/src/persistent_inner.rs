//! MCPS-063 (MCP-RE-EPIC-P6.6B) — a LONG-LIVED inner MCP server.
//!
//! [`PersistentSubprocessInner`] is the persistent counterpart of the one-shot
//! [`crate::cli::SubprocessInner`]. Where the one-shot impl spawns the inner
//! command per request (write one request, close stdin, read stdout to EOF, and
//! expect the process to exit), this impl spawns the inner command **once** at
//! construction, performs the MCP `initialize` handshake, and then keeps the
//! child — and its stdin/stdout pipes — alive across ANY number of requests. A
//! real MCP server (the `mcp-re-demo-server`, #3956) is long-lived and cannot be
//! fronted by the one-shot path.
//!
//! ## Framing (matches mcp-re-demo-server, #3956 / #3957)
//! Messages are **newline-delimited JSON-RPC**: each request is written as one
//! UTF-8 line (a single JSON object, no embedded newline) terminated by `\n`,
//! and each response is read as one line from the child's stdout. This is the
//! real MCP stdio convention (the reference `mcp/server/stdio.py` reads
//! `async for line in stdin` and writes `json + "\n"`); it is NOT the LSP-style
//! `Content-Length` header framing.
//!
//! ## Handshake
//! At construction the proxy sends a single `initialize` request and reads its
//! result line. The demo server gates every non-`initialize` method on having
//! seen `initialize`, and requires NO separate `initialized` notification, so the
//! handshake is exactly one request/response. (A server that DID require the
//! `initialized` notification would receive it here; the demo server does not.)
//!
//! ## Concurrency model
//! A persistent inner over a single stdin/stdout pipe pair is a **serial
//! channel**: a request must be fully written and its response fully read before
//! the next request, or two interleaved callers would read each other's
//! responses. The whole live session (child handle + framed reader/writer) lives
//! behind ONE [`Mutex`]; [`PersistentSubprocessInner::dispatch`] takes that lock
//! for the entire write-then-read, so even if multiple proxy connections shared
//! one inner they are serialized. Correlation is positional under the lock (the
//! response on the line we read is the response to the request we just wrote);
//! as a defensive cross-check the dispatch also drops any response line whose
//! JSON-RPC `id` does not match the request's `id` (a stray notification line),
//! reading on until the matching id or EOF.
//!
//! ## Failure posture (fail closed, never panic / never hang)
//! Inner failure — a crash mid-session (EOF on stdout), a malformed
//! (non-JSON) response line, or an I/O error — yields a JSON-RPC internal error
//! object, never a panic and never an unbounded read. Once the session is poisoned
//! it stays poisoned: every subsequent dispatch returns the same fail-closed
//! error rather than touching a half-dead child.
//!
//! ## Hardening parity
//! The same launch hardening as the one-shot path is applied (working dir, env
//! minimization, bounded stderr capture, Unix `setrlimit` ceilings) via the
//! shared [`InnerLaunchConfig`].

use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::process::Child;
use std::process::ChildStdin;
use std::process::ChildStdout;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use serde_json::json;
use serde_json::Value;

use crate::inner_launch::InnerLaunchConfig;
use crate::inner_launch::InnerLogEvent;
use crate::inner_launch::InnerLogSink;
use crate::inner_launch::StderrLogSink;
use crate::proxy::InnerServer;

/// The MCP protocol version the proxy advertises in its `initialize` handshake.
/// Matches the version `mcp-re-demo-server` advertises (#3956).
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Maximum length (bytes) of a single newline-delimited line read from the inner
/// stdout (MCPS-074). The deadline reader is time-bounded, but a hostile inner
/// can write a very large UNTERMINATED line *quickly* (well within the timeout),
/// growing the line buffer without bound — an OOM / availability DoS even though
/// the read is time-bounded. The cap is enforced INCREMENTALLY as bytes
/// accumulate, so a flood is rejected (fail closed) BEFORE the buffer grows
/// large, not after. 1 MiB is far above any legitimate JSON-RPC frame the proxy
/// forwards yet bounds memory tightly.
const MAX_INNER_LINE_BYTES: usize = 1_048_576;

/// A long-lived inner MCP server backed by a single persistent subprocess.
///
/// Spawn-once, initialize-once, then forward many newline-delimited JSON-RPC
/// requests over the SAME process. See the module docs for the framing,
/// handshake, concurrency model, and fail-closed posture.
pub struct PersistentSubprocessInner {
    /// A stable identity tagged onto every lifecycle event.
    inner_identity: String,
    log_sink: Arc<dyn InnerLogSink + Send + Sync>,
    /// The live session (child + framed pipes), behind a lock so `&self`
    /// dispatch has interior mutability AND concurrent callers are serialized.
    session: Mutex<Session>,
}

/// The live inner session: the child handle plus its framed stdin/stdout. Once
/// `poisoned` is set (an inner failure), the session refuses further dispatch.
struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Monotonic JSON-RPC id allocator for proxy-originated frames (handshake,
    /// id correlation cross-check). Forwarded requests carry the caller's id.
    next_id: i64,
    /// Set once an inner failure is observed; every later dispatch fails closed.
    poisoned: bool,
    /// Per-read timeout on the inner stdout pipe (MCPS-074): every response-line
    /// read is bounded by this deadline so a hung/silent/unterminated-line inner
    /// can never block the serve loop forever. Always bounded; never disabled.
    read_timeout: Duration,
}

impl PersistentSubprocessInner {
    /// Spawn the inner command ONCE, apply the shared launch hardening, drain its
    /// stderr into a bounded capture on a dedicated thread, and perform the MCP
    /// `initialize` handshake. Construction fails (fail closed) if the launch
    /// policy is unappliable, the spawn fails, or the handshake does not complete.
    pub fn new(inner_command: &[String], launch: InnerLaunchConfig) -> Result<Self, String> {
        PersistentSubprocessInner::with_log_sink(inner_command, launch, Arc::new(StderrLogSink))
    }

    /// As [`PersistentSubprocessInner::new`], with an injected lifecycle-event
    /// sink (used by tests to capture emissions deterministically).
    pub fn with_log_sink(
        inner_command: &[String],
        launch: InnerLaunchConfig,
        log_sink: Arc<dyn InnerLogSink + Send + Sync>,
    ) -> Result<Self, String> {
        if inner_command.is_empty() {
            return Err("persistent inner: empty inner command".to_string());
        }
        let inner_identity = inner_command[0].clone();

        let mut command = Command::new(&inner_command[0]);
        command
            .args(&inner_command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // stderr is captured separately into the bounded log; never merged
            // into stdout (the protocol stream).
            .stderr(Stdio::piped());
        // The same hardening as the one-shot path. A failure here aborts startup
        // (fail closed) — never a silently-misconfigured inner.
        launch.apply_env(&mut command, |name| std::env::var(name).ok())?;
        launch.apply_working_dir(&mut command)?;
        launch.apply_rlimits(&mut command)?;
        // OS sandbox profile (#3865): fail-closed platform/capability gate +
        // (future) kernel-enforcement install, applied before the spawn below. A
        // requested `enforce` that cannot be enforced aborts startup here, never a
        // silently-unsandboxed inner.
        launch.apply_sandbox(&mut command)?;
        // M15 (audit 0.2, #4080): close every inherited fd above stdio in the child
        // before exec, so the inner never inherits the proxy's own (already-open,
        // already-connected) client/listener sockets — which a seccomp egress
        // filter could not revoke. Registered LAST so it never closes an fd the
        // setrlimit/sandbox hooks needed.
        launch.apply_close_extra_fds(&mut command)?;

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                log_sink.log(&inner_identity, &InnerLogEvent::SpawnFailed { reason: e.to_string() });
                return Err(format!("persistent inner: spawn failed: {e}"));
            }
        };
        log_sink.log(&inner_identity, &InnerLogEvent::Spawned { pid: child.id() });

        // Drain stderr on a dedicated thread into the bounded capture so a noisy
        // or hostile inner can neither deadlock the pipe nor exhaust proxy memory.
        // The thread runs for the life of the child and reports to the sink on EOF.
        let stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| "persistent inner: no child stderr".to_string())?;
        spawn_stderr_drain(stderr_pipe, launch.clone(), Arc::clone(&log_sink), inner_identity.clone());

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "persistent inner: no child stdin".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "persistent inner: no child stdout".to_string())?;

        let mut session = Session {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
            poisoned: false,
            read_timeout: launch.inner_read_timeout,
        };

        // The MCP `initialize` handshake: send one initialize request, read its
        // result line. A handshake failure aborts construction (fail closed) and
        // reaps the half-started child rather than serving an un-initialized inner.
        if let Err(err) = session.initialize() {
            session.poisoned = true;
            log_sink.log(
                &inner_identity,
                &InnerLogEvent::ProtocolError { detail: format!("initialize handshake: {err}") },
            );
            session.kill_and_reap(&log_sink, &inner_identity, "initialize handshake failed");
            return Err(format!("persistent inner: initialize handshake failed: {err}"));
        }

        Ok(PersistentSubprocessInner {
            inner_identity,
            log_sink,
            session: Mutex::new(session),
        })
    }

    fn fail_closed(detail: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": { "code": -32603, "message": "inner server unavailable", "data": detail }
        }))
        .unwrap_or_default()
    }
}

impl InnerServer for PersistentSubprocessInner {
    /// Forward one (already verified + stripped) request to the persistent inner
    /// over the serial channel and return its response bytes. Fail-closed on any
    /// inner failure; never panics, never hangs.
    fn dispatch(&self, request: &[u8]) -> Vec<u8> {
        // A poisoned lock (a panic while another caller held it) is itself an
        // inner failure: fail closed rather than propagating the panic.
        let mut session = match self.session.lock() {
            Ok(guard) => guard,
            Err(_) => return PersistentSubprocessInner::fail_closed("inner session lock poisoned"),
        };
        if session.poisoned {
            return PersistentSubprocessInner::fail_closed("inner session previously failed");
        }
        match session.exchange(request) {
            Ok(response) => {
                if serde_json::from_slice::<Value>(&response).is_err() {
                    self.log_sink.log(
                        &self.inner_identity,
                        &InnerLogEvent::ProtocolError {
                            detail: "inner stdout line is not a JSON-RPC frame".to_string(),
                        },
                    );
                }
                response
            }
            Err(err) => {
                // Poison the session so a half-dead child is never touched again.
                session.poisoned = true;
                self.log_sink.log(
                    &self.inner_identity,
                    &InnerLogEvent::ProtocolError { detail: err.clone() },
                );
                session.kill_and_reap(&self.log_sink, &self.inner_identity, "dispatch failure");
                PersistentSubprocessInner::fail_closed(&err)
            }
        }
    }
}

impl Session {
    /// Perform the one-request `initialize` handshake, discarding the result body
    /// (the proxy does not surface inner capabilities; it only needs the inner to
    /// be initialized). An error here is a handshake failure.
    fn initialize(&mut self) -> Result<(), String> {
        let id = self.alloc_id();
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "mcp-re-proxy", "version": env!("CARGO_PKG_VERSION") }
            }
        });
        let bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let response = self.write_line_read_matching(&bytes, &json!(id))?;
        let value: Value = serde_json::from_slice(&response)
            .map_err(|_| "initialize response was not JSON".to_string())?;
        if value.get("error").is_some() {
            return Err(format!("inner rejected initialize: {}", value["error"]));
        }
        if value.get("result").is_none() {
            return Err("initialize response carried no result".to_string());
        }
        Ok(())
    }

    /// Forward a caller request and return the matching response line. The
    /// caller's own JSON-RPC `id` is used for correlation.
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, String> {
        let id = serde_json::from_slice::<Value>(request)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(Value::Null);
        self.write_line_read_matching(request, &id)
    }

    /// Write one newline-delimited request line, then read response lines until
    /// one whose JSON-RPC `id` matches `want_id` (skipping any stray notification
    /// line that carries no/other id). EOF before a match is an inner crash.
    fn write_line_read_matching(&mut self, request: &[u8], want_id: &Value) -> Result<Vec<u8>, String> {
        if request.contains(&b'\n') {
            return Err("request frame contained an embedded newline".to_string());
        }
        // MCPS-093 (audit §3 H-3, WRITE half): the stdin WRITE is bounded by the
        // SAME `read_timeout` deadline knob the read side uses. A hostile inner that
        // completes the handshake then refuses to drain its stdin would, on a
        // forwarded request larger than the OS pipe buffer (~64 KiB; max_body_bytes
        // is 16 MiB), block `write_all` indefinitely while holding the session
        // Mutex — wedging the single-threaded serve loop. The bounded writer
        // poll(POLLOUT)s until the pipe is writable or the deadline passes; a
        // timeout fails closed exactly like the read-side deadline.
        let write_deadline = Instant::now()
            .checked_add(self.read_timeout)
            .ok_or_else(|| "inner write deadline overflow (timeout too large)".to_string())?;
        write_all_until_deadline(&mut self.stdin, request, write_deadline, self.read_timeout)
            .map_err(|e| format!("write to inner stdin: {e}"))?;
        write_all_until_deadline(&mut self.stdin, b"\n", write_deadline, self.read_timeout)
            .map_err(|e| format!("write newline to inner stdin: {e}"))?;
        self.stdin
            .flush()
            .map_err(|e| format!("flush inner stdin: {e}"))?;

        // The per-read timeout (MCPS-074) is an ABSOLUTE deadline spanning the
        // whole response-reading phase of this exchange: a hung/silent inner — or
        // one that emits an unterminated line then goes quiet — can never block
        // the single-threaded serve loop past `read_timeout`. MAX_SKIPPED_LINES is
        // the orthogonal line-count bound on a chatty (but responsive) inner.
        // `checked_add` is defense-in-depth: an absurdly large configured timeout
        // would overflow `Instant`, which would PANIC on `+`. This is the
        // fail-closed read path — it must never panic — so an overflow returns a
        // fail-closed error routed through the dispatch error path. The CLI also
        // caps the timeout at parse time (see `cli.rs`), so this is unreachable in
        // practice.
        let deadline = Instant::now()
            .checked_add(self.read_timeout)
            .ok_or_else(|| "inner read deadline overflow (timeout too large)".to_string())?;

        // Read at most a bounded number of lines looking for the matching id, so a
        // chatty inner emitting endless non-matching lines cannot hang the proxy.
        const MAX_SKIPPED_LINES: usize = 64;
        for _ in 0..=MAX_SKIPPED_LINES {
            let line = self.read_line_until_deadline(deadline)?;
            match line {
                ReadLineOutcome::Eof => {
                    return Err(
                        "inner closed stdout (crash mid-session?) before responding".to_string()
                    )
                }
                ReadLineOutcome::Line(bytes) => {
                    let line = String::from_utf8_lossy(&bytes);
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let value: Value = serde_json::from_str(line)
                        .map_err(|_| "inner stdout line is not valid JSON".to_string())?;
                    // A matching id (or a null want_id where we cannot correlate) is
                    // the response. A non-matching id is a stray frame; skip and
                    // read on.
                    let line_id = value.get("id").cloned().unwrap_or(Value::Null);
                    if want_id.is_null() || &line_id == want_id {
                        return Ok(line.as_bytes().to_vec());
                    }
                }
            }
        }
        Err("inner produced no response with the matching id within the line bound".to_string())
    }

    /// Read ONE newline-terminated line from the inner stdout, but never block
    /// past `deadline` (MCPS-074). Returns the line (without enforcing a trailing
    /// `\n` if EOF arrives mid-line) or [`ReadLineOutcome::Eof`].
    ///
    /// Correctness subtlety (the unterminated-line attack): a naive "poll the fd
    /// then call `BufRead::read_line`" does NOT fix a partial line — `read_line`
    /// would consume the buffered bytes and then block inside the single call
    /// waiting for `\n`/EOF, so the poll never fires again. This reader instead
    /// works at the `BufReader` level: it serves already-buffered bytes WITHOUT
    /// polling (poll reflects only the underlying fd, not the BufReader's internal
    /// buffer), and only `poll`s + `fill_buf`s the raw fd once the buffer is
    /// drained. A `poll` that times out (or a zero remaining budget) is a
    /// fail-closed timeout error, mid-line or not.
    fn read_line_until_deadline(&mut self, deadline: Instant) -> Result<ReadLineOutcome, String> {
        let mut line: Vec<u8> = Vec::new();
        loop {
            // 1. Drain any bytes ALREADY buffered by the BufReader without touching
            //    the fd (poll does not see these — `BufReader::buffer()` returns the
            //    unconsumed buffered bytes WITHOUT blocking / refilling). Stop at
            //    the first newline.
            let (consumed, found_newline, over_cap) = {
                let buffered = self.stdout.buffer();
                let mut taken = 0usize;
                let mut newline = false;
                let mut over = false;
                for &byte in buffered {
                    taken += 1;
                    line.push(byte);
                    if byte == b'\n' {
                        newline = true;
                        break;
                    }
                    // Enforce the line-length cap INCREMENTALLY (MCPS-074): trip
                    // the moment accumulation exceeds the bound, so a fast
                    // unterminated flood is rejected before the buffer grows
                    // large — bounded memory regardless of how quickly the inner
                    // writes within the read timeout.
                    if line.len() > MAX_INNER_LINE_BYTES {
                        over = true;
                        break;
                    }
                }
                (taken, newline, over)
            };
            if consumed > 0 {
                self.stdout.consume(consumed);
            }
            if over_cap {
                return Err(format!(
                    "inner stdout line exceeded {MAX_INNER_LINE_BYTES} bytes (unbounded-line flood)"
                ));
            }
            if found_newline {
                return Ok(ReadLineOutcome::Line(line));
            }

            // 2. Buffer is drained and no newline yet. Bound the wait on the raw fd
            //    by the remaining budget; a timeout (or zero budget) fails closed.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "inner stdout read exceeded {:?} (silent or hung inner)",
                    self.read_timeout
                ));
            }
            let fd = self.stdout.get_ref().as_raw_fd();
            match poll_readable(fd, remaining)? {
                PollOutcome::TimedOut => {
                    return Err(format!(
                        "inner stdout read exceeded {:?} (silent or hung inner)",
                        self.read_timeout
                    ))
                }
                PollOutcome::Readable => {
                    // The fd is readable: pull more bytes into the BufReader's
                    // buffer. A zero-length fill is EOF.
                    let filled = self
                        .stdout
                        .fill_buf()
                        .map_err(|e| format!("read from inner stdout: {e}"))?;
                    if filled.is_empty() {
                        if line.is_empty() {
                            return Ok(ReadLineOutcome::Eof);
                        }
                        // EOF mid-line: return what we have (no trailing newline).
                        return Ok(ReadLineOutcome::Line(line));
                    }
                    // Loop: the next iteration drains the freshly-filled buffer.
                }
            }
        }
    }

    fn alloc_id(&mut self) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Close stdin (EOF), kill the child if still running, and reap it. Best
    /// effort: teardown never panics and never blocks indefinitely (the demo
    /// server exits on stdin EOF; kill covers a wedged child).
    fn kill_and_reap(
        &mut self,
        log_sink: &Arc<dyn InnerLogSink + Send + Sync>,
        inner_identity: &str,
        reason: &str,
    ) {
        // Best-effort kill: if the child already exited, kill() errors harmlessly.
        let killed = self.child.kill().is_ok();
        let code = self.child.wait().ok().and_then(|s| s.code());
        if killed {
            log_sink.log(inner_identity, &InnerLogEvent::Killed { reason: reason.to_string() });
        }
        log_sink.log(inner_identity, &InnerLogEvent::Exited { code });
    }
}

/// The result of one deadline-bounded line read from the inner stdout.
enum ReadLineOutcome {
    /// A line (the trailing `\n` is included when present; absent only on an
    /// EOF that arrived mid-line).
    Line(Vec<u8>),
    /// The inner closed stdout (EOF) before any bytes of a new line.
    Eof,
}

/// The result of polling the inner stdout fd for readability within a budget.
enum PollOutcome {
    /// The fd is readable now (data or EOF is available).
    Readable,
    /// The poll budget elapsed with the fd not readable (hung/silent inner).
    TimedOut,
}

/// The result of polling the inner stdin fd for writability within a budget.
enum PollWriteOutcome {
    /// The fd is writable now (the pipe has buffer room, or the read end closed).
    Writable,
    /// The poll budget elapsed with the fd not writable (inner not draining stdin).
    TimedOut,
}

/// Write `buf` in full to the inner stdin, but never block past `deadline`
/// (MCPS-093). This is the WRITE-half mirror of [`Session::read_line_until_deadline`]:
/// a hostile inner that stops draining its stdin would otherwise pin `write_all`
/// (and the session Mutex) forever once the OS pipe buffer fills.
///
/// `write_all` on a blocking pipe is itself unbounded, so we drive the fd
/// nonblocking + a manual poll(POLLOUT)/write loop: poll until writable or the
/// deadline, then write one chunk; repeat until the whole buffer is sent. A
/// timeout (or zero budget) is a fail-closed timeout error matching the read-side
/// `read_timeout` message shape. The fd's nonblocking flag is restored before
/// returning so subsequent operations (flush) see the original blocking pipe.
fn write_all_until_deadline(
    stdin: &mut ChildStdin,
    buf: &[u8],
    deadline: Instant,
    timeout: Duration,
) -> Result<(), String> {
    let fd = stdin.as_raw_fd();
    // Set nonblocking so a full pipe surfaces as WouldBlock (and we poll) instead
    // of an unbounded block inside the write syscall. Restored on every exit path.
    let restore = set_nonblocking(fd, true)?;
    let result = write_all_nonblocking(stdin, fd, buf, deadline, timeout);
    // Best-effort restore of the original blocking flag regardless of outcome.
    let _ = set_nonblocking(fd, restore);
    result
}

/// The nonblocking write loop body. Separated so the caller can always restore
/// the fd's blocking flag (see [`write_all_until_deadline`]).
fn write_all_nonblocking(
    stdin: &mut ChildStdin,
    fd: std::os::unix::io::RawFd,
    buf: &[u8],
    deadline: Instant,
    timeout: Duration,
) -> Result<(), String> {
    let mut sent = 0usize;
    while sent < buf.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "inner stdin write exceeded {timeout:?} (inner not draining stdin)"
            ));
        }
        match poll_writable(fd, remaining)? {
            PollWriteOutcome::TimedOut => {
                return Err(format!(
                    "inner stdin write exceeded {timeout:?} (inner not draining stdin)"
                ))
            }
            PollWriteOutcome::Writable => match stdin.write(&buf[sent..]) {
                Ok(0) => {
                    // The read end closed: no further progress is possible. Treat
                    // like the read-side EOF (inner crash mid-session) — fail closed.
                    return Err("inner closed stdin (crash mid-session?) before draining the request".to_string());
                }
                Ok(n) => sent += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Spurious wakeup / pipe filled between poll and write: loop and
                    // re-poll within the remaining budget.
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.to_string()),
            },
        }
    }
    Ok(())
}

/// Set (or clear) `O_NONBLOCK` on `fd`, returning the PREVIOUS nonblocking state
/// so the caller can restore it. Fail-closed on a failed fcntl (never panic).
fn set_nonblocking(fd: std::os::unix::io::RawFd, nonblocking: bool) -> Result<bool, String> {
    // SAFETY: F_GETFL takes no extra args and only reads the fd's status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!("fcntl F_GETFL on inner stdin: {}", std::io::Error::last_os_error()));
    }
    let was_nonblocking = (flags & libc::O_NONBLOCK) != 0;
    let new_flags = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if new_flags != flags {
        // SAFETY: F_SETFL with the computed status flags for the live stdin fd.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) };
        if rc < 0 {
            return Err(format!(
                "fcntl F_SETFL on inner stdin: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(was_nonblocking)
}

/// Wait until `fd` is writable or `budget` elapses, using `libc::poll` (MCPS-093).
///
/// The WRITE-half mirror of [`poll_readable`]: `POLLOUT` means the pipe has room
/// to accept at least one byte (or the read end closed, which polls writable then
/// surfaces as a short/zero write). `EINTR` is retried within the remaining
/// budget; any other poll error is surfaced fail-closed.
fn poll_writable(fd: std::os::unix::io::RawFd, budget: Duration) -> Result<PollWriteOutcome, String> {
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| "inner write deadline overflow (timeout too large)".to_string())?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(PollWriteOutcome::TimedOut);
        }
        let millis = remaining.as_millis().min(i32::MAX as u128).max(1) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: `pfd` is a single valid pollfd for the live child-stdin fd; the
        // call writes only `revents`. The fd outlives this call (owned by the
        // Session's ChildStdin). No other invariants are involved.
        let rc = unsafe { libc::poll(&mut pfd, 1, millis) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue; // EINTR: retry within the remaining budget.
            }
            return Err(format!("poll inner stdin: {err}"));
        }
        if rc == 0 {
            return Ok(PollWriteOutcome::TimedOut);
        }
        return Ok(PollWriteOutcome::Writable);
    }
}

/// Wait until `fd` is readable or `budget` elapses, using `libc::poll` (MCPS-074).
///
/// Single-threaded, blocking, no async, no reader thread — the crate already
/// depends on `libc` (see `rlimits.rs`). `POLLIN` covers both "data available"
/// and "EOF" (a closed pipe polls readable, then `read` returns 0). `EINTR` is
/// retried within the remaining budget so a stray signal does not spuriously
/// time out. Any other poll error is surfaced fail-closed.
fn poll_readable(fd: std::os::unix::io::RawFd, budget: Duration) -> Result<PollOutcome, String> {
    // `checked_add` defense-in-depth (see the call site in `write_line_read_matching`):
    // an overflowing deadline must fail closed, never panic on `+`.
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| "inner read deadline overflow (timeout too large)".to_string())?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(PollOutcome::TimedOut);
        }
        // Clamp to i32 milliseconds (poll's timeout type); at least 1ms so we make
        // forward progress rather than busy-spinning on sub-millisecond budgets.
        let millis = remaining.as_millis().min(i32::MAX as u128).max(1) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a single valid pollfd for the live child-stdout fd; the
        // call writes only `revents`. The fd outlives this call (owned by the
        // Session's BufReader). No other invariants are involved.
        let rc = unsafe { libc::poll(&mut pfd, 1, millis) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue; // EINTR: retry within the remaining budget.
            }
            return Err(format!("poll inner stdout: {err}"));
        }
        if rc == 0 {
            return Ok(PollOutcome::TimedOut);
        }
        return Ok(PollOutcome::Readable);
    }
}

impl Drop for PersistentSubprocessInner {
    /// Tear down cleanly on shutdown: send a modelled `shutdown`, then close
    /// stdin (EOF) and reap the child. No zombie, no hang.
    fn drop(&mut self) {
        let Ok(mut session) = self.session.lock() else {
            return;
        };
        if session.poisoned {
            return; // already killed + reaped on the failing dispatch
        }
        // Best-effort modelled shutdown so a server that wants it tears down
        // gracefully; ignore the response (we are going away). The demo server
        // also exits on stdin EOF, which the drop of `stdin` below delivers.
        let id = session.alloc_id();
        let shutdown = json!({ "jsonrpc": "2.0", "id": id, "method": "shutdown" });
        // MCPS-093: the Drop shutdown-frame write has the SAME unbounded-write
        // exposure as the dispatch path — a hostile inner that stopped draining
        // stdin would pin the whole Drop (and thus the dropping thread). On Drop we
        // cannot return an error, but it must not block indefinitely: bound the
        // write by a SHORT budget (capped by the configured read_timeout) and give
        // up if the inner is not draining. The `child.kill()` below covers the
        // wedged inner regardless.
        let drop_budget = session.read_timeout.min(Duration::from_secs(1));
        if let Ok(bytes) = serde_json::to_vec(&shutdown) {
            if let Some(deadline) = Instant::now().checked_add(drop_budget) {
                let read_timeout = session.read_timeout;
                let _ = write_all_until_deadline(&mut session.stdin, &bytes, deadline, read_timeout);
                let _ = write_all_until_deadline(&mut session.stdin, b"\n", deadline, read_timeout);
            }
            let _ = session.stdin.flush();
        }
        // Reap. kill() is a no-op-ish error if the child already exited on EOF.
        let _ = session.child.kill();
        let code = session.child.wait().ok().and_then(|s| s.code());
        self.log_sink
            .log(&self.inner_identity, &InnerLogEvent::Exited { code });
    }
}

/// Drain the child's stderr on a dedicated thread into a bounded capture, then
/// report it (and any truncation) to the sink on EOF. Mirrors the one-shot
/// path's stderr handling so a persistent inner's stderr is bounded too.
fn spawn_stderr_drain(
    mut stderr_pipe: impl Read + Send + 'static,
    launch: InnerLaunchConfig,
    log_sink: Arc<dyn InnerLogSink + Send + Sync>,
    inner_identity: String,
) {
    std::thread::spawn(move || {
        let mut capture = launch.new_stderr_capture();
        let mut chunk = [0u8; 4096];
        loop {
            match stderr_pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => capture.push(&chunk[..n]),
                Err(_) => break,
            }
        }
        if capture.truncated() {
            log_sink.log(
                &inner_identity,
                &InnerLogEvent::StderrTruncated {
                    captured_bytes: capture.bytes().len(),
                    cap_bytes: capture.cap_bytes(),
                },
            );
        }
        if !capture.bytes().is_empty() {
            log_sink.log_stderr(&inner_identity, capture.bytes());
        }
    });
}
