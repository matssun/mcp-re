//! Newline-delimited stdio transport for the LONG-LIVED demo server (MCPS-062).
//!
//! ## Framing (confirmed against the MCP spec + the `mcp` python package)
//! The MCP stdio transport is **newline-delimited JSON-RPC**: each inbound
//! JSON-RPC message is one line on stdin, and each response is one line on
//! stdout (one JSON object per line, no embedded newlines, UTF-8). This is NOT
//! the LSP-style `Content-Length` header framing. The reference Python server
//! (`mcp/server/stdio.py`) reads `async for line in stdin` and writes
//! `json + "\n"`; #3957's persistent-inner proxy support frames identically.
//!
//! ## Persistence
//! Unlike a one-shot server, the loop here is genuinely long-lived: it serves
//! an `initialize` handshake followed by ANY number of `tools/list` /
//! `tools/call` requests over the SAME process, ending only at stdin EOF or a
//! modelled `shutdown`. The transport is pure plumbing — every result comes
//! from [`DemoServer::handle`]. Blocking `std::io`; no async runtime.

use std::io::BufRead;
use std::io::Write;

use crate::server::DemoServer;

/// Serve newline-delimited requests from `input`, writing one
/// newline-terminated response line per request to `output`, staying alive
/// across many requests.
///
/// Blank lines are skipped. The loop ends at stdin EOF, or as soon as a
/// `shutdown` request has been answered (clean lifecycle teardown). Returns the
/// number of requests served. Only I/O errors on the streams themselves
/// propagate as `Err`; bad request content is handled in-band by
/// [`DemoServer::handle`].
pub fn serve_stdio<R: BufRead, W: Write>(
    server: &DemoServer,
    input: R,
    output: &mut W,
) -> std::io::Result<usize> {
    let mut served = 0usize;
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let bytes = line.as_bytes();
        let stop = server.handle_should_stop(bytes);
        let response = server.handle(bytes);
        output.write_all(&response)?;
        output.write_all(b"\n")?;
        output.flush()?;
        served += 1;
        if stop {
            break;
        }
    }
    Ok(served)
}
