//! Streamable HTTP process harness (MCPS-013).
//!
//! [`HttpHarness`] runs the documented MCP-RE echo server on a loopback TCP
//! socket (ephemeral port) in a background thread and drives signed JSON-RPC to
//! it over real HTTP `POST`s. It reuses [`outcome_token`] from the stdio harness
//! to reduce a response to a wire token, so the SAME assertions prove the HTTP
//! transport yields identical Core outcomes to stdio and the object target
//! (ADR-MCPS-011).
//!
//! The server is built INSIDE the worker thread, so no `EchoServer` (which holds
//! non-`Send`-bounded trait objects) crosses the thread boundary — only the
//! bound `TcpListener` and the pinned `now_unix` do.

use std::net::TcpListener;
use std::thread;

use crate::http::http_post;
use crate::http::serve_http_requests;
use crate::server::build_server;
use crate::server::ServerKind;

/// Drives a documented server (native or sidecar) over loopback HTTP.
#[derive(Debug, Clone, Default)]
pub struct HttpHarness;

impl HttpHarness {
    /// Construct an HTTP harness.
    pub fn new() -> Self {
        HttpHarness
    }

    /// Send each request to one NATIVE server instance over HTTP. See
    /// [`HttpHarness::serve_kind`].
    pub fn serve(&self, requests: &[Vec<u8>], now_unix: i64) -> Result<Vec<Vec<u8>>, String> {
        self.serve_kind(requests, now_unix, ServerKind::Native)
    }

    /// Send each request in order to one server instance of `kind` (clock pinned
    /// to `now_unix`) over its own HTTP connection, returning one response body
    /// per request. Two identical requests exercise replay detection: the
    /// server's replay cache persists because all connections hit the same
    /// instance. The server is built INSIDE the worker thread (so the non-`Send`
    /// server never crosses the boundary — only the `Send` listener/kind/clock
    /// do).
    pub fn serve_kind(
        &self,
        requests: &[Vec<u8>],
        now_unix: i64,
        kind: ServerKind,
    ) -> Result<Vec<Vec<u8>>, String> {
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind loopback: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("local_addr: {e}"))?;
        let count = requests.len();

        let server = thread::spawn(move || {
            let server = build_server(kind);
            serve_http_requests(&listener, count, |body| server.handle(body, now_unix))
        });

        let mut responses = Vec::with_capacity(count);
        for request in requests {
            let body = http_post(addr, request).map_err(|e| format!("http_post: {e}"))?;
            responses.push(body);
        }

        server
            .join()
            .map_err(|_| "server thread panicked".to_string())?
            .map_err(|e| format!("server loop: {e}"))?;
        Ok(responses)
    }

    /// Convenience: a single request/response round trip against the native
    /// server.
    pub fn roundtrip(&self, request: &[u8], now_unix: i64) -> Result<Vec<u8>, String> {
        let mut responses = self.serve(&[request.to_vec()], now_unix)?;
        match responses.len() {
            1 => Ok(responses.remove(0)),
            n => Err(format!("expected 1 response, got {n}")),
        }
    }
}
