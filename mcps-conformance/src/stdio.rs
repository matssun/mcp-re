//! stdio transport for the MCP-S conformance server (MCPS-012).
//!
//! Newline-delimited JSON-RPC: each inbound request is one line on the input
//! stream; each response is one line on the output stream. This is the MCP stdio
//! framing (one JSON object per line, no embedded newlines). The transport is
//! pure plumbing — every verification verdict still comes from
//! [`EchoServer::handle`], so the Core outcome is identical to the in-process
//! object target (ADR-MCPS-011 transport parity).
//!
//! `now_unix` pins the server clock so the frozen conformance vectors verify
//! deterministically regardless of wall-clock time.

use std::io::BufRead;
use std::io::Write;

use crate::server::McpsServer;

/// Serve newline-delimited MCP-S requests from `input`, writing one
/// newline-terminated response line per request to `output`.
///
/// Blank lines are skipped. The loop ends at EOF on `input`. Returns the number
/// of requests served. Propagates only I/O errors on the streams themselves —
/// verification failures are returned in-band as JSON-RPC error objects by the
/// server's `handle`, not as `Err` here. Works for any [`McpsServer`] (native
/// echo or sidecar proxy), so stdio parity holds for both target kinds.
pub fn serve_stdio<R: BufRead, W: Write>(
    server: &dyn McpsServer,
    now_unix: i64,
    input: R,
    output: &mut W,
) -> std::io::Result<usize> {
    let mut served = 0usize;
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = server.handle(line.as_bytes(), now_unix);
        output.write_all(&response)?;
        output.write_all(b"\n")?;
        output.flush()?;
        served += 1;
    }
    Ok(served)
}
