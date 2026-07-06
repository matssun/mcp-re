//! Newline-delimited stdio transport for the demo fileserver (MCPS-045).
//!
//! Each inbound JSON-RPC request is one line on the input stream; each response
//! is one line on the output stream (MCP stdio framing: one JSON object per
//! line, no embedded newlines). The transport is pure plumbing — every verdict
//! comes from [`FileServer::handle`]. Blocking `std::io`; no async runtime.

use std::io::BufRead;
use std::io::Write;

use crate::server::FileServer;

/// Serve newline-delimited requests from `input`, writing one
/// newline-terminated response line per request to `output`.
///
/// Blank lines are skipped. The loop ends at EOF. Returns the number of requests
/// served. Only I/O errors on the streams themselves propagate as `Err`; bad
/// request content is handled in-band by [`FileServer::handle`].
pub fn serve_stdio<R: BufRead, W: Write>(
    server: &FileServer,
    input: R,
    output: &mut W,
) -> std::io::Result<usize> {
    let mut served = 0usize;
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = server.handle(line.as_bytes());
        output.write_all(&response)?;
        output.write_all(b"\n")?;
        output.flush()?;
        served += 1;
    }
    Ok(served)
}
