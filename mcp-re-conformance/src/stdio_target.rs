//! stdio process harness (MCPS-012).
//!
//! [`StdioHarness`] launches the `mcp-re-stdio-server` binary as a child process,
//! drives newline-delimited signed JSON-RPC over its stdin/stdout, and collects
//! the response lines. [`outcome_token`] reduces a server response to the same
//! wire token the object target produces, so a test can assert the stdio
//! transport yields identical Core outcomes (ADR-MCPS-011).
//!
//! The harness takes the server path explicitly: locating it in bazel runfiles
//! is the test's concern (it owns the `runfiles` dependency), keeping this
//! library free of any runfiles/env coupling.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use mcp_re_core::verify_response;
use mcp_re_core::TrustResolver;
use serde_json::Value;

use crate::server::ServerKind;

/// Launches `mcp-re-stdio-server` and exchanges newline-delimited messages.
#[derive(Debug, Clone)]
pub struct StdioHarness {
    server_path: PathBuf,
}

impl StdioHarness {
    /// Construct a harness for the server binary at `server_path`.
    pub fn new(server_path: impl Into<PathBuf>) -> Self {
        StdioHarness {
            server_path: server_path.into(),
        }
    }

    /// Send each request in order to a single NATIVE server process and return
    /// one response per request. See [`StdioHarness::serve_kind`].
    pub fn serve(&self, requests: &[Vec<u8>], now_unix: i64) -> Result<Vec<Vec<u8>>, String> {
        self.serve_kind(requests, now_unix, ServerKind::Native)
    }

    /// Send each request in order to a single server process of `kind` (clock
    /// pinned to `now_unix`) and return one response per request, in order.
    ///
    /// Sending two identical requests exercises replay detection: the server's
    /// replay cache persists across both lines because they hit the same
    /// process. stdin is fully written and closed before stdout is read; the
    /// conformance payloads are well under the OS pipe buffer, so this cannot
    /// deadlock.
    pub fn serve_kind(
        &self,
        requests: &[Vec<u8>],
        now_unix: i64,
        kind: ServerKind,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut child = Command::new(&self.server_path)
            .arg("--now-unix")
            .arg(now_unix.to_string())
            .arg("--mode")
            .arg(kind.mode_arg())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", self.server_path.display()))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| "child stdin unavailable".to_string())?;
            for request in requests {
                stdin
                    .write_all(request)
                    .map_err(|e| format!("write request: {e}"))?;
                stdin
                    .write_all(b"\n")
                    .map_err(|e| format!("write nl: {e}"))?;
            }
            // Dropping stdin closes it, signaling EOF to the serve loop.
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("wait child: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "server exited {:?}; stderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let responses: Vec<Vec<u8>> = output
            .stdout
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| line.to_vec())
            .collect();
        Ok(responses)
    }

    /// Convenience: a single request/response round trip.
    pub fn roundtrip(&self, request: &[u8], now_unix: i64) -> Result<Vec<u8>, String> {
        let mut responses = self.serve(&[request.to_vec()], now_unix)?;
        match responses.len() {
            1 => Ok(responses.remove(0)),
            n => Err(format!("expected 1 response, got {n}")),
        }
    }
}

/// Reduce a server response to the wire token the object target compares
/// against:
///   - a JSON-RPC error object ⇒ its `error.message` (the frozen `mcp-re.*` code),
///   - otherwise verify the signed response binds to `expected_request_hash`:
///     `Ok ⇒ "verify_ok"`, `Err(e) ⇒ e.wire_code()`.
pub fn outcome_token(
    response: &[u8],
    expected_request_hash: &str,
    resolver: &dyn TrustResolver,
) -> String {
    let value: Value = match serde_json::from_slice(response) {
        Ok(value) => value,
        Err(e) => return format!("harness_error: parse response: {e}"),
    };

    if let Some(message) = value.get("error").and_then(|e| e.get("message")) {
        return message
            .as_str()
            .unwrap_or("harness_error: non-string error.message")
            .to_string();
    }

    match verify_response(response, resolver, expected_request_hash) {
        Ok(_) => "verify_ok".to_string(),
        Err(err) => err.wire_code().to_string(),
    }
}
