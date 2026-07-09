//! The one-shot subprocess inner server (relocated OUT of the `mcp-re-proxy` PEP
//! into this out-of-TCB bridge — ADR-MCPRE-051 Phase B / task C3).
//!
//! This module owns [`SubprocessInner`] (per-request spawn of a stdio MCP server)
//! and the local [`InnerServer`] dispatch seam both subprocess inners implement.
//! The struct + its launch/sandbox/rlimit wiring moved VERBATIM from the proxy's
//! `cli.rs`; only module paths and the `InnerServer` trait home changed.

use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde_json::Value;

use crate::inner_launch::BoundedStderr;
use crate::inner_launch::InnerLaunchConfig;
use crate::log_sink::InnerLogEvent;
use crate::log_sink::InnerLogSink;
use crate::log_sink::StderrLogSink;

/// The sync inner-server dispatch seam. Both the one-shot [`SubprocessInner`] and
/// the persistent `PersistentSubprocessInner` implement it: given the (already
/// verified, stripped, verified-context-injected) JSON-RPC request bytes, produce
/// the inner server's JSON-RPC response bytes. A dispatch failure yields a
/// JSON-RPC internal error rather than reaching for a fallback.
pub trait InnerServer {
    /// Dispatch one request to the inner server and return its response bytes.
    fn dispatch(&self, request: &[u8]) -> Vec<u8>;
}

/// An inner MCP server backed by a subprocess: each request spawns the command,
/// writes the request bytes to its stdin, and reads its **stdout** as the
/// response (the MCP protocol stream). Per-request spawn keeps it trivially
/// correct under the (single-threaded) serve loop; a failure yields a JSON-RPC
/// internal error rather than reaching for a fallback.
///
/// MCPS-036 inner-server hygiene:
///   * the inner server is launched in a CONTROLLED working directory (never
///     silently the proxy's cwd) — see [`InnerLaunchConfig::apply_working_dir`];
///   * its **stdout is reserved for the protocol stream** and read as the
///     response bytes;
///   * its **stderr is captured separately** into a BOUNDED structured log
///     ([`BoundedStderr`]) and NEVER forwarded as MCP content;
///   * lifecycle events (`inner_spawned`, `inner_exited`, `inner_killed`,
///     `inner_stderr_truncated`, `inner_protocol_error`, `inner_spawn_failed`)
///     are emitted to the proxy's own [`InnerLogSink`].
pub struct SubprocessInner {
    command: String,
    args: Vec<String>,
    launch: InnerLaunchConfig,
    /// A stable identity for this inner server, tagged onto every lifecycle
    /// event so emissions stay attributable.
    inner_identity: String,
    log_sink: Arc<dyn InnerLogSink + Send + Sync>,
}

impl SubprocessInner {
    /// Build from an `[cmd, arg, ...]` vector (non-empty), with the inner-launch
    /// policy validated against the proxy's OWN environment and working dir.
    ///
    /// This validation is where a configured-but-unappliable policy fails LOUDLY
    /// rather than at spawn time — e.g. an `--inner-env-allow KEY` naming a
    /// variable absent from the proxy's environment, or an `--inner-working-dir`
    /// that is not an existing directory, is rejected here, at startup, so the
    /// proxy never serves with a silently-dropped behavior.
    pub fn new(inner_command: &[String], launch: InnerLaunchConfig) -> Result<Self, String> {
        SubprocessInner::with_log_sink(inner_command, launch, Arc::new(StderrLogSink))
    }

    /// As [`SubprocessInner::new`], with an injected lifecycle-event sink (used by
    /// tests to capture emissions deterministically).
    pub fn with_log_sink(
        inner_command: &[String],
        launch: InnerLaunchConfig,
        log_sink: Arc<dyn InnerLogSink + Send + Sync>,
    ) -> Result<Self, String> {
        // Validate the env + working-dir policy up front against the real process
        // environment; a failure aborts startup (the same fail-closed posture as
        // key loading). Both must be appliable before we agree to serve.
        let mut probe = Command::new(&inner_command[0]);
        launch.apply_env(&mut probe, |name| std::env::var(name).ok())?;
        launch.apply_working_dir(&mut probe)?;
        // Resource-hardening ceilings (MCPS-037): startup platform validation
        // (non-Unix + required = fail closed) plus the pre_exec setrlimit hook.
        launch.apply_rlimits(&mut probe)?;
        // OS sandbox profile (#3865): the fail-closed platform/capability gate is
        // checked HERE, at startup, before any inner server is spawned. Under
        // `--inner-sandbox enforce` this refuses to start unless a kernel backend
        // can actually enforce containment (none ships yet); `off` (default) is
        // inert and passes through.
        launch.apply_sandbox(&mut probe)?;
        Ok(SubprocessInner {
            command: inner_command[0].clone(),
            args: inner_command[1..].to_vec(),
            launch,
            inner_identity: inner_command[0].clone(),
            log_sink,
        })
    }

    fn emit(&self, event: InnerLogEvent) {
        self.log_sink.log(&self.inner_identity, &event);
    }

    fn run(&self, request: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut command = Command::new(&self.command);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // stderr is PIPED (not null) so it is captured separately into the
            // bounded log; it is never merged into stdout (the protocol stream).
            .stderr(Stdio::piped());
        // Apply the (already validated) env + working-dir policy. Resolution
        // against the proxy env/fs is stable for the process lifetime, so a
        // repeat failure here is not expected; surface it as an IO error rather
        // than silently spawning with an unintended launch context.
        self.launch
            .apply_env(&mut command, |name| std::env::var(name).ok())
            .map_err(std::io::Error::other)?;
        self.launch
            .apply_working_dir(&mut command)
            .map_err(std::io::Error::other)?;
        // Install the Unix setrlimit ceilings (MCPS-037) as a pre_exec hook. A
        // required limit the kernel refuses fails the spawn below (fail closed),
        // never a silently-unbounded inner server.
        self.launch
            .apply_rlimits(&mut command)
            .map_err(std::io::Error::other)?;
        // OS sandbox profile (#3865). Already gated at startup; re-applied here so
        // the (future) kernel enforcement is installed on the actual spawn
        // command, and so a still-ungated `enforce` can never spawn unsandboxed.
        self.launch
            .apply_sandbox(&mut command)
            .map_err(std::io::Error::other)?;
        // M15 (audit 0.2, #4080): close every inherited fd above stdio in the child
        // before exec (registered last), so the inner never inherits the proxy's
        // own open sockets — a leak a seccomp egress filter cannot revoke.
        self.launch
            .apply_close_extra_fds(&mut command)
            .map_err(std::io::Error::other)?;

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                self.emit(InnerLogEvent::SpawnFailed { reason: e.to_string() });
                return Err(e);
            }
        };
        let pid = child.id();
        self.emit(InnerLogEvent::Spawned { pid });

        // Bound the one-shot interaction so a wedged inner cannot hang the
        // single-threaded serve loop (MCPS-084 / audit M-7). A watchdog thread
        // waits for completion OR the inner-read deadline; on timeout the inner
        // is not draining stdin or not closing stdout, so SIGKILL it to unblock
        // the write_all + wait_with_output below. `recv_timeout` means the kill
        // fires ONLY on a real timeout, and the child is not reaped until
        // wait_with_output() — so `pid` is unambiguously this child (no reuse
        // race) at the moment we signal.
        let timeout = self.launch.inner_read_timeout;
        let timed_out = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let wd_flag = Arc::clone(&timed_out);
        let watchdog = std::thread::spawn(move || {
            if done_rx.recv_timeout(timeout).is_err() {
                wd_flag.store(true, Ordering::SeqCst);
                // SAFETY: kill(2) on a child pid we own and have not yet reaped.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
            }
        });

        // Drain stderr on a dedicated thread into the BOUNDED capture so a noisy
        // or hostile inner server can neither deadlock the pipe nor exhaust proxy
        // memory. The capture is moved back when the thread joins.
        let mut stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("no child stderr"))?;
        let mut capture = self.launch.new_stderr_capture();
        let stderr_thread = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match stderr_pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => capture.push(&chunk[..n]),
                    Err(_) => break,
                }
            }
            capture
        });

        // Capture (do NOT early-return on) a stdin write error: a wedged inner
        // that the watchdog kills makes write_all fail with a broken pipe, and we
        // must still reap the child and join the watchdog before surfacing it.
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no child stdin"))
            .and_then(|mut stdin| stdin.write_all(request));

        let output = child.wait_with_output()?;
        // Reaped: tell the watchdog to stand down (it never kills a reaped pid).
        let _ = done_tx.send(());
        let _ = watchdog.join();
        let capture: BoundedStderr = stderr_thread
            .join()
            .unwrap_or_else(|_| self.launch.new_stderr_capture());

        self.emit(InnerLogEvent::Exited {
            code: output.status.code(),
        });
        if capture.truncated() {
            self.emit(InnerLogEvent::StderrTruncated {
                captured_bytes: capture.bytes().len(),
                cap_bytes: capture.cap_bytes(),
            });
        }
        if !capture.bytes().is_empty() {
            // The captured stderr goes ONLY to the proxy's structured log (via the
            // dedicated stderr channel), never onto stdout (the protocol stream)
            // and never into MCP content.
            self.log_sink.log_stderr(&self.inner_identity, capture.bytes());
        }
        // The inner exceeded its read deadline and was terminated: fail closed
        // with a timeout rather than treating the (partial / empty) stdout as a
        // response. This is the one-shot analogue of the persistent path's
        // per-read deadline (MCPS-074); together they honour the never-hang
        // posture for BOTH inner modes.
        if timed_out.load(Ordering::SeqCst) {
            self.emit(InnerLogEvent::ProtocolError {
                detail: format!("inner exceeded inner_read_timeout ({timeout:?}); terminated"),
            });
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("inner exceeded inner_read_timeout ({timeout:?}) and was terminated"),
            ));
        }
        // Surface a genuine (non-timeout) stdin write failure now that the child
        // is reaped and the watchdog has stood down.
        write_result?;

        // The inner server's stdout is the MCP protocol stream: if it is not a
        // JSON object the proxy can frame, flag a protocol error (the dirty bytes
        // are still returned for the proxy's normal error handling, but the
        // observability event makes the dirty-stream case attributable).
        if serde_json::from_slice::<Value>(&output.stdout).is_err() {
            self.emit(InnerLogEvent::ProtocolError {
                detail: "inner stdout is not a JSON-RPC frame".to_string(),
            });
        }
        Ok(output.stdout)
    }
}

impl InnerServer for SubprocessInner {
    fn dispatch(&self, request: &[u8]) -> Vec<u8> {
        match self.run(request) {
            Ok(response) => response,
            Err(e) => serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": serde_json::Value::Null,
                "error": { "code": -32603, "message": "inner server unavailable", "data": e.to_string() }
            }))
            .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InnerServer;
    use super::SubprocessInner;
    use crate::inner_launch::InnerLaunchConfig;
    use crate::log_sink::InnerLogEvent;
    use crate::log_sink::InnerLogSink;
    use crate::rlimits::RLimits;
    use crate::sandbox::SandboxMode;
    use crate::sandbox::SandboxProfile;
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::Mutex;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Build a `/bin/sh -c` inner whose script first DRAINS the dispatched request
    /// from stdin (`cat >/dev/null`), then runs `script`. This mirrors a real inner
    /// MCP server, which reads its request before responding. Without the drain a
    /// `printf`-only fixture exits immediately, closing its stdin read-end; the
    /// proxy's `write_all(request)` then races that close and, on Linux,
    /// deterministically loses — surfacing as a broken-pipe write error instead of
    /// the fixture's intended output. (The race is benign on macOS, which is why it
    /// hid until the Linux CI gate ran these to completion.) Every shell fixture
    /// that the proxy dispatches a request to goes through this helper so the whole
    /// class is fixed at the source rather than per-test.
    fn sh_inner(script: &str) -> Vec<String> {
        args(&["/bin/sh", "-c", &format!("cat >/dev/null; {script}")])
    }

    /// MCPS-084 / audit M-7: a one-shot inner that never drains stdin and never
    /// exits must NOT hang the single-threaded serve loop — the per-read deadline
    /// terminates it and the call fails closed within the budget. Load-bearing:
    /// without the watchdog, `wait_with_output` would block forever and this test
    /// would hang (time out) instead of returning an error response.
    #[test]
    fn oneshot_inner_that_never_exits_is_bounded_by_timeout() {
        let launch = InnerLaunchConfig {
            inner_read_timeout: std::time::Duration::from_millis(300),
            ..InnerLaunchConfig::new()
        };
        // `sleep` ignores stdin and never writes stdout nor exits.
        let inner = SubprocessInner::new(&args(&["sleep", "3600"]), launch).expect("construct");
        let start = std::time::Instant::now();
        let response = inner.dispatch(b"{\"jsonrpc\":\"2.0\",\"id\":1}");
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "a wedged one-shot inner must be bounded by inner_read_timeout, not hang (took {elapsed:?})"
        );
        let value: Value = serde_json::from_slice(&response).expect("error response is JSON");
        assert_eq!(
            value["error"]["message"].as_str(),
            Some("inner server unavailable"),
            "a timed-out inner must surface as unavailable, got {value}"
        );
    }

    // --- MCPS-036 lifecycle / stderr capture proofs ---------------------------

    /// A capturing log sink: records every lifecycle event and every captured
    /// stderr chunk so tests can assert what the proxy emitted (deterministic,
    /// no scraping of the real proxy stderr).
    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<(String, InnerLogEvent)>>,
        stderr: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl InnerLogSink for RecordingSink {
        fn log(&self, inner_identity: &str, event: &InnerLogEvent) {
            self.events
                .lock()
                .expect("lock")
                .push((inner_identity.to_string(), event.clone()));
        }
        fn log_stderr(&self, inner_identity: &str, captured: &[u8]) {
            self.stderr
                .lock()
                .expect("lock")
                .push((inner_identity.to_string(), captured.to_vec()));
        }
    }

    impl RecordingSink {
        fn tags(&self) -> Vec<String> {
            self.events
                .lock()
                .expect("lock")
                .iter()
                .map(|(_, e)| e.tag().to_string())
                .collect()
        }
        fn captured_stderr(&self) -> Vec<u8> {
            self.stderr
                .lock()
                .expect("lock")
                .iter()
                .flat_map(|(_, bytes)| bytes.clone())
                .collect()
        }
    }

    #[test]
    fn inner_launches_in_explicit_working_dir_not_proxy_cwd() {
        // The fixture prints its OWN cwd to stdout (after draining the request).
        // With an explicit --inner-working-dir, the child must run there, NOT in
        // the proxy's cwd.
        let tmp = std::env::temp_dir();
        let dir = tmp.join(format!("mcp-re036_wd_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        // macOS resolves /var -> /private/var; canonicalize both sides.
        let canonical = std::fs::canonicalize(&dir).expect("canonicalize");
        let launch = InnerLaunchConfig {
            working_dir: Some(dir.to_string_lossy().into_owned()),
            ..InnerLaunchConfig::new()
        };
        let cmd = sh_inner("pwd -P");
        let inner = SubprocessInner::new(&cmd, launch).expect("construct");
        let seen = String::from_utf8(inner.dispatch(b"{}")).expect("utf8");
        let proxy_cwd = std::env::current_dir().expect("cwd");
        assert_ne!(
            seen.trim(),
            proxy_cwd.to_string_lossy(),
            "inner ran in the proxy's cwd instead of the explicit working dir"
        );
        assert_eq!(seen.trim(), canonical.to_string_lossy());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_explicit_working_dir_fails_construction() {
        let launch = InnerLaunchConfig {
            working_dir: Some("/no/such/dir/MCPS036_MISSING".to_string()),
            ..InnerLaunchConfig::new()
        };
        match SubprocessInner::new(&args(&["/bin/true"]), launch) {
            Ok(_) => panic!("a working dir that cannot be honored must fail closed"),
            Err(err) => assert!(err.contains("MCPS036_MISSING"), "got: {err}"),
        }
    }

    // --- MCPS-037 setrlimit resource-hardening proofs ------------------------

    #[cfg(unix)]
    #[test]
    fn rlimit_nofile_actually_constrains_the_child() {
        // EFFECT test: with RLIMIT_NOFILE applied, the child's OWN view of its
        // soft fd limit (`ulimit -n`, which reads RLIMIT_NOFILE) must equal what
        // we set — proving the pre_exec setrlimit took effect on the child, not
        // just the parent's Command config.
        let launch = InnerLaunchConfig {
            rlimits: RLimits {
                nofile: Some(48),
                core_bytes: None,
                ..RLimits::new()
            },
            ..InnerLaunchConfig::new()
        };
        // The inner prints its soft fd limit; `sh_inner` drains the request stdin
        // first so it behaves like a real one-shot inner and the EFFECT assertion
        // is deterministic on every platform (see `sh_inner` for the race).
        let cmd = sh_inner("ulimit -n");
        let inner = SubprocessInner::new(&cmd, launch).expect("construct");
        let seen = String::from_utf8(inner.dispatch(b"{}")).expect("utf8");
        assert_eq!(
            seen.trim(),
            "48",
            "RLIMIT_NOFILE was not applied to the child (saw ulimit -n = {seen:?})"
        );
    }

    #[cfg(unix)]
    #[test]
    fn required_unappliable_rlimit_fails_the_spawn_not_silently() {
        // FAIL-CLOSED test: ask for an RLIMIT_NOFILE ceiling far above the
        // current HARD limit. As a non-root process the kernel REFUSES to raise
        // the hard limit (EPERM/EINVAL), so the pre_exec setrlimit returns an
        // error, which (strict mode) aborts the spawn. The dispatch must surface
        // an inner-server error — NEVER a silently-unbounded successful run.
        let launch = InnerLaunchConfig {
            rlimits: RLimits {
                // 2^60 fds is unattainable; raising the hard limit there fails.
                nofile: Some(1u64 << 63),
                core_bytes: None,
                best_effort: false,
                ..RLimits::new()
            },
            ..InnerLaunchConfig::new()
        };
        // The child WOULD print a clean frame if it ever ran; it must not.
        let cmd = sh_inner("printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'");
        let inner = SubprocessInner::new(&cmd, launch).expect("construct (validation is unix-ok)");
        let out = inner.dispatch(b"{}");
        let parsed: Value = serde_json::from_slice(&out).expect("dispatch returns a JSON frame");
        assert!(
            parsed.get("error").is_some(),
            "a required-but-unappliable rlimit must fail the spawn closed, not run unbounded: {parsed}"
        );
        assert_eq!(parsed["error"]["code"], -32603);
    }

    #[cfg(unix)]
    #[test]
    fn best_effort_unappliable_rlimit_does_not_block_the_spawn() {
        // In explicit best-effort mode the SAME unattainable ceiling is
        // downgraded: the setrlimit failure is ignored in the child and the
        // inner server still runs (the relaxation is opt-in + warned, never the
        // default). Contrast with the strict test above.
        let launch = InnerLaunchConfig {
            rlimits: RLimits {
                nofile: Some(1u64 << 63),
                core_bytes: None,
                best_effort: true,
                ..RLimits::new()
            },
            ..InnerLaunchConfig::new()
        };
        let cmd = sh_inner("printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'");
        let inner = SubprocessInner::new(&cmd, launch).expect("construct");
        let out = inner.dispatch(b"{}");
        let parsed: Value = serde_json::from_slice(&out).expect("JSON frame");
        assert_eq!(
            parsed["jsonrpc"], "2.0",
            "best-effort mode must let the inner server run despite an unappliable limit: {parsed}"
        );
        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn inner_stderr_is_captured_separately_and_stdout_stays_protocol_only() {
        // The fixture writes a JSON-RPC frame to STDOUT and noise to STDERR.
        // stdout (the protocol stream) must contain ONLY the JSON frame; the
        // stderr noise must land in the bounded capture, never on stdout.
        let sink = Arc::new(RecordingSink::default());
        let cmd = sh_inner(
            "printf 'STDERR-NOISE-LEAK' 1>&2; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'",
        );
        let inner =
            SubprocessInner::with_log_sink(&cmd, InnerLaunchConfig::new(), Arc::clone(&sink) as _)
                .expect("construct");
        let stdout = inner.dispatch(b"{}");
        let stdout_str = String::from_utf8(stdout).expect("utf8");
        assert!(
            !stdout_str.contains("STDERR-NOISE-LEAK"),
            "stderr leaked onto the stdout protocol stream: {stdout_str:?}"
        );
        let parsed: Value = serde_json::from_str(&stdout_str).expect("stdout is a clean JSON frame");
        assert_eq!(parsed["jsonrpc"], "2.0");
        let captured = String::from_utf8(sink.captured_stderr()).expect("utf8");
        assert!(
            captured.contains("STDERR-NOISE-LEAK"),
            "inner stderr was not captured into the bounded log: {captured:?}"
        );
    }

    #[test]
    fn oversized_inner_stderr_is_bounded_and_emits_truncation_event() {
        // The fixture floods stderr well past the byte cap. The capture must be
        // bounded to the cap and an `inner_stderr_truncated` event emitted.
        let sink = Arc::new(RecordingSink::default());
        let launch = InnerLaunchConfig {
            stderr_cap_bytes: 16,
            stderr_cap_lines: 1000,
            ..InnerLaunchConfig::new()
        };
        // 1000 'A' bytes to stderr; valid frame to stdout.
        let cmd = sh_inner(
            "for i in $(seq 1 1000); do printf 'A' 1>&2; done; \
             printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'",
        );
        let inner = SubprocessInner::with_log_sink(&cmd, launch, Arc::clone(&sink) as _)
            .expect("construct");
        let _ = inner.dispatch(b"{}");
        let captured = sink.captured_stderr();
        assert!(captured.len() <= 16, "stderr capture exceeded the cap: {}", captured.len());
        assert!(
            sink.tags().iter().any(|t| t == "inner_stderr_truncated"),
            "expected inner_stderr_truncated; got: {:?}",
            sink.tags()
        );
    }

    #[test]
    fn lifecycle_events_spawn_and_exit_are_emitted() {
        let sink = Arc::new(RecordingSink::default());
        let cmd = sh_inner("printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'");
        let inner = SubprocessInner::with_log_sink(&cmd, InnerLaunchConfig::new(), Arc::clone(&sink) as _)
            .expect("construct");
        let _ = inner.dispatch(b"{}");
        let tags = sink.tags();
        assert!(tags.iter().any(|t| t == "inner_spawned"), "got: {tags:?}");
        assert!(tags.iter().any(|t| t == "inner_exited"), "got: {tags:?}");
    }

    #[test]
    fn dirty_stdout_emits_protocol_error_event() {
        // The fixture writes non-JSON to stdout: the protocol stream is dirty.
        let sink = Arc::new(RecordingSink::default());
        let cmd = sh_inner("printf 'NOT JSON AT ALL'");
        let inner = SubprocessInner::with_log_sink(&cmd, InnerLaunchConfig::new(), Arc::clone(&sink) as _)
            .expect("construct");
        let _ = inner.dispatch(b"{}");
        assert!(
            sink.tags().iter().any(|t| t == "inner_protocol_error"),
            "expected inner_protocol_error; got: {:?}",
            sink.tags()
        );
    }

    // --- MCPS-035 environment-minimization leak proofs ------------------------
    //
    // The inner command is a tiny shell that IGNORES stdin and prints the value
    // of a chosen variable to stdout. Driving it through the real
    // `SubprocessInner` proves what the spawned child actually receives.

    /// An inner command (`[cmd, arg...]`) that prints `${name}` (or empty if
    /// unset) to stdout. Uses `sh_inner` so it drains the request stdin first
    /// (portable on the unix CI hosts; see `sh_inner` for the EPIPE race).
    fn dump_var_command(name: &str) -> Vec<String> {
        sh_inner(&format!("printf '%s' \"${{{name}}}\""))
    }

    fn run_inner(inner: &SubprocessInner) -> String {
        String::from_utf8(inner.dispatch(b"{}")).expect("utf8 child stdout")
    }

    #[test]
    fn secret_in_proxy_env_is_not_visible_to_inner_by_default() {
        // A secret-looking var is present in THIS (the proxy's) process env, as
        // an env-backed KeySource would put it. With the secure default
        // (inherit_env = false, no allowlist) the inner server must NOT see it.
        let var = "MCPS035_SECRET_DEFAULT";
        std::env::set_var(var, "TOP-SECRET-KEY-MATERIAL");
        let inner = SubprocessInner::new(&dump_var_command(var), InnerLaunchConfig::new())
            .expect("construct");
        let seen = run_inner(&inner);
        assert_eq!(
            seen, "",
            "inner server leaked an env-loaded secret under default minimization; saw: {seen:?}"
        );
        std::env::remove_var(var);
    }

    #[test]
    fn explicit_inner_env_pair_is_visible_to_inner() {
        let launch = InnerLaunchConfig {
            explicit_env: vec![("MCPS035_EXPLICIT".to_string(), "hello".to_string())],
            ..InnerLaunchConfig::new()
        };
        let inner =
            SubprocessInner::new(&dump_var_command("MCPS035_EXPLICIT"), launch).expect("construct");
        assert_eq!(run_inner(&inner), "hello");
    }

    #[test]
    fn allowlisted_var_passes_through_but_others_do_not() {
        // Two vars in the proxy env; only one is allowlisted.
        let allowed = "MCPS035_ALLOWED";
        let blocked = "MCPS035_BLOCKED";
        std::env::set_var(allowed, "pass");
        std::env::set_var(blocked, "leak");
        let launch = InnerLaunchConfig {
            allow_env_names: vec![allowed.to_string()],
            ..InnerLaunchConfig::new()
        };
        let inner_allowed =
            SubprocessInner::new(&dump_var_command(allowed), launch.clone()).expect("construct");
        assert_eq!(run_inner(&inner_allowed), "pass");

        let inner_blocked =
            SubprocessInner::new(&dump_var_command(blocked), launch).expect("construct");
        assert_eq!(
            run_inner(&inner_blocked),
            "",
            "a non-allowlisted proxy var must not reach the inner server"
        );
        std::env::remove_var(allowed);
        std::env::remove_var(blocked);
    }

    #[test]
    fn inherit_env_true_exposes_the_proxy_env() {
        // The escape hatch: with inheritance ON, the proxy env IS visible. This
        // is the loudly-warned, opt-in behavior — the contrast that proves the
        // default actually clears the environment.
        let var = "MCPS035_INHERITED";
        std::env::set_var(var, "inherited-value");
        let launch = InnerLaunchConfig {
            inherit_env: true,
            ..InnerLaunchConfig::new()
        };
        let inner = SubprocessInner::new(&dump_var_command(var), launch).expect("construct");
        assert_eq!(run_inner(&inner), "inherited-value");
        std::env::remove_var(var);
    }

    // --- M15 (audit 0.2, #4080): inherited-fd leak across exec --------------------
    //
    // The inner must NOT inherit a non-stdio descriptor the proxy holds open. The
    // threat: an already-connected socket survives `exec`, so a seccomp egress
    // filter (which denies CREATING sockets) cannot revoke it. The proxy closes
    // every fd >= 3 in the child before exec (`apply_close_extra_fds`). This is a
    // black-box test of that hook over the REAL `SubprocessInner` launch pipeline:
    // it opens a pipe whose read end has O_CLOEXEC CLEARED (so std/Command would
    // otherwise leak it across exec), then spawns an inner that reports whether
    // that exact fd is open in the child. Without the close hook the fd LEAKS
    // (RED); with it, the fd is CLOSED in the child (GREEN). Cross-platform Unix:
    // it tests the fd-close itself, not any Linux-only sandbox.

    /// An inner command that prints `LEAKED` if `/dev/fd/<fd>` exists in the child
    /// (the descriptor was inherited across exec) or `CLOSED` otherwise. `/dev/fd`
    /// reflects the calling process's own descriptors on both Linux and macOS.
    /// Uses `sh_inner` so it drains the request stdin first (see that helper).
    fn probe_fd_command(fd: libc::c_int) -> Vec<String> {
        sh_inner(&format!(
            "if [ -e /dev/fd/{fd} ]; then printf LEAKED; else printf CLOSED; fi"
        ))
    }

    #[test]
    fn inner_does_not_inherit_a_non_cloexec_fd_across_exec() {
        // Create a pipe; the read end is the descriptor we will try to leak.
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe` writes two fds into the provided length-2 array.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe() failed: {}", std::io::Error::last_os_error());
        let (read_fd, write_fd) = (fds[0], fds[1]);

        // Clear O_CLOEXEC on the read end so that, absent the proxy's close hook,
        // it WOULD survive exec into the child (this is the leak we are guarding).
        // SAFETY: F_GETFD/F_SETFD read/clear the close-on-exec flag on our own fd.
        let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed: {}", std::io::Error::last_os_error());
        let set = unsafe { libc::fcntl(read_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        assert_eq!(set, 0, "F_SETFD clear CLOEXEC failed: {}", std::io::Error::last_os_error());
        // Confirm the flag is actually cleared — otherwise the test would pass
        // vacuously (std's own CLOEXEC, not our hook, would close it).
        let after = unsafe { libc::fcntl(read_fd, libc::F_GETFD) };
        assert_eq!(after & libc::FD_CLOEXEC, 0, "CLOEXEC must be cleared for a meaningful test");

        let inner = SubprocessInner::new(&probe_fd_command(read_fd), InnerLaunchConfig::new())
            .expect("construct inner for fd-leak probe");
        let seen = run_inner(&inner);

        // SAFETY: closing our own pipe fds after the child has been spawned + run.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }

        assert_eq!(
            seen, "CLOSED",
            "a non-CLOEXEC fd ({read_fd}) the proxy held open LEAKED into the inner across exec \
             — the proxy must close every fd >= 3 before exec so an inherited (already-connected) \
             socket cannot survive a seccomp egress filter"
        );
    }

    #[test]
    fn close_extra_fds_hook_is_registered_on_the_launch_pipeline() {
        // A cross-platform unit check that the hook exists and is appliable on the
        // launch config used by every spawn (complements the exec-level probe).
        let mut command = std::process::Command::new("/bin/true");
        InnerLaunchConfig::new()
            .apply_close_extra_fds(&mut command)
            .expect("close-extra-fds hook must apply cleanly");
    }

    #[test]
    fn unsatisfiable_allowlist_fails_construction_loudly() {
        let launch = InnerLaunchConfig {
            allow_env_names: vec!["MCPS035_DEFINITELY_UNSET".to_string()],
            ..InnerLaunchConfig::new()
        };
        match SubprocessInner::new(&dump_var_command("x"), launch) {
            Ok(_) => panic!("a configured pass-through that cannot be satisfied must fail"),
            Err(err) => assert!(err.contains("MCPS035_DEFINITELY_UNSET"), "got: {err}"),
        }
    }

    #[test]
    fn sandbox_enforce_gate_matches_backend_capability() {
        // The load-bearing honesty gate, asserted against the SAME runtime probe
        // the production path uses (`SandboxProfile::backend_can_enforce`): where
        // no kernel backend can enforce (darwin, or a Linux kernel without
        // Landlock), `enforce` MUST refuse to start at construction time; where the
        // kernel CAN enforce (Linux + Landlock at the required ABI), construction
        // succeeds and the backend is installed lazily at spawn. The gate is
        // exercised through SubprocessInner::new (startup validation), the same
        // path the launcher takes before any inner server is spawned.
        let launch = InnerLaunchConfig {
            sandbox: SandboxProfile {
                mode: SandboxMode::Enforce,
                ..SandboxProfile::new()
            },
            ..InnerLaunchConfig::new()
        };
        let result = SubprocessInner::new(&args(&["my-server", "--flag"]), launch);
        if SandboxProfile::backend_can_enforce() {
            // A platform/kernel that CAN enforce: construction must succeed (the
            // Landlock ruleset + seccomp filter install as a pre_exec hook later).
            assert!(
                result.is_ok(),
                "enforce must construct where the kernel backend can enforce"
            );
        } else {
            // No kernel backend: the gate MUST fail closed BEFORE any spawn. Match
            // rather than `.expect_err` so the assertion does not require
            // `SubprocessInner: Debug` (the Ok value is never printed here).
            let err = match result {
                Ok(_) => panic!("enforce without a kernel backend must fail closed before spawn"),
                Err(e) => e,
            };
            assert!(err.contains("enforce"), "got: {err}");
            assert!(err.contains("refusing to start"), "got: {err}");
            assert!(
                err.contains("#3865"),
                "error must point at the follow-up: {err}"
            );
        }
    }
}
