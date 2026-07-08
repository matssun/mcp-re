//! Spawn + manage the out-of-TCB `mcp-re-stdio-bridge` (ADR-MCPRE-051).
//!
//! The proxy (the signing PEP) no longer launches a stdio subprocess inner: its
//! sole inner plane is a stateless HTTP client. An unmodified local stdio MCP
//! server (the demo fileserver / demo server) is therefore fronted by the
//! `mcp-re-stdio-bridge` binary — a stdio↔HTTP adapter that lives OUTSIDE the
//! cryptographic TCB — and reached over HTTP:
//!
//! ```text
//!   proxy (PEP, signs)  ──HTTP──▶  BridgeProcess  ──stdio──▶  unmodified MCP server
//! ```
//!
//! This helper spawns that bridge fronting a given inner command, parses the
//! `listening on http://<addr>` line the bridge prints to its stderr, and exposes
//! the resulting base URL for the proxy's `--inner-http-url` (multi-process) or a
//! [`mcp_re_proxy::http_inner::HttpInnerPool`] (in-process). The child is killed +
//! reaped on drop.
//!
//! Both the in-process demo tests/bins and the multi-process walkthrough drive the
//! REAL bridge binary fronting the REAL inner server — the faithful production
//! topology, not an emulation — so every assertion about the inner's behaviour
//! (tool set, listings, writes, received-log) stays valid.

use std::io::Read;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

/// Which subprocess model the bridge runs the inner under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeInnerMode {
    /// Spawn the inner fresh per request (stateless inner, e.g. the fileserver).
    OneShot,
    /// Spawn the inner ONCE and keep the MCP session alive (stateful inner, e.g.
    /// the long-lived demo server). The bridge emits exactly one `inner_spawned`.
    Persistent,
}

/// A spawned `mcp-re-stdio-bridge` process fronting one stdio inner server over
/// HTTP. Killed + reaped on drop. Its stderr is drained into a shared buffer so a
/// caller can read the `inner_spawned` lifecycle markers the bridge's own
/// `StderrLogSink` prints (the spawn-count oracle now lives on the BRIDGE's
/// stderr, since the PEP no longer launches the subprocess).
pub struct BridgeProcess {
    child: Child,
    url: String,
    stderr: Arc<Mutex<String>>,
}

impl Drop for BridgeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl BridgeProcess {
    /// Spawn the bridge (`bridge_bin`) listening on an ephemeral loopback port,
    /// fronting `inner_command` (the inner binary path followed by its own argv)
    /// under `mode`, with an optional controlled `working_dir` for the inner.
    ///
    /// Blocks until the bridge prints its `listening on http://<addr>` marker (so
    /// the returned [`Self::url`] is immediately usable), or errors if the bridge
    /// exits early / never reports within a bounded budget.
    pub fn spawn(
        bridge_bin: impl AsRef<std::path::Path>,
        mode: BridgeInnerMode,
        working_dir: Option<&str>,
        inner_command: &[String],
    ) -> Result<Self, String> {
        let bridge_bin = bridge_bin.as_ref();
        if inner_command.is_empty() {
            return Err("BridgeProcess requires a non-empty inner command".to_string());
        }
        let mut args: Vec<String> = vec!["--listen".into(), "127.0.0.1:0".into()];
        if mode == BridgeInnerMode::Persistent {
            args.push("--inner-mode".into());
            args.push("persistent".into());
        }
        if let Some(dir) = working_dir {
            args.push("--inner-working-dir".into());
            args.push(dir.to_string());
        }
        // Everything after `--` is the inner command + argv, verbatim.
        args.push("--".into());
        args.extend(inner_command.iter().cloned());

        let mut child = Command::new(bridge_bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn mcp-re-stdio-bridge ({}): {e}", bridge_bin.display()))?;

        // Drain the bridge's stderr into a shared buffer: it prints its listening
        // marker there, and (via its own StderrLogSink) the inner lifecycle events.
        let stderr = Arc::new(Mutex::new(String::new()));
        let mut pipe = child.stderr.take().ok_or("bridge stderr not piped")?;
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Ok(mut buf) = sink.lock() {
                            buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Wait for the `listening on http://<addr>` marker, reading the OS-resolved
        // address back from it. Fail fast if the bridge exits before it binds.
        let deadline = Instant::now() + Duration::from_secs(30);
        let url = loop {
            if let Some(u) = stderr.lock().ok().and_then(|buf| parse_listening_url(&buf)) {
                break u;
            }
            if let Ok(Some(status)) = child.try_wait() {
                let captured = stderr.lock().map(|b| b.clone()).unwrap_or_default();
                let _ = child.wait();
                return Err(format!(
                    "mcp-re-stdio-bridge exited before listening (status {status}):\n{captured}"
                ));
            }
            if Instant::now() > deadline {
                let captured = stderr.lock().map(|b| b.clone()).unwrap_or_default();
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "mcp-re-stdio-bridge did not report a listening URL within budget:\n{captured}"
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        Ok(BridgeProcess { child, url, stderr })
    }

    /// The bridge's base HTTP URL (e.g. `http://127.0.0.1:54321/`) for the proxy's
    /// `--inner-http-url` or an [`mcp_re_proxy::http_inner::HttpInnerPool`].
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The bridge's captured stderr so far — carries the `inner_spawned`
    /// lifecycle markers (the independent spawn-count oracle) and any inner
    /// diagnostics the bridge surfaces.
    pub fn stderr_snapshot(&self) -> String {
        self.stderr.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

/// Parse the bridge's `mcp-re-stdio-bridge: listening on http://<addr> (…)` line
/// and return the base URL `http://<addr>/`. Requires the trailing space after the
/// address so a partially-captured line never yields a truncated URL.
fn parse_listening_url(stderr: &str) -> Option<String> {
    let marker = "listening on ";
    let start = stderr.find(marker)? + marker.len();
    let rest = &stderr[start..];
    let end = rest.find(char::is_whitespace)?;
    let base = &rest[..end];
    if !base.starts_with("http://") {
        return None;
    }
    // Normalise to a trailing-slash base path the HTTP inner plane POSTs to.
    if base.ends_with('/') {
        Some(base.to_string())
    } else {
        Some(format!("{base}/"))
    }
}
