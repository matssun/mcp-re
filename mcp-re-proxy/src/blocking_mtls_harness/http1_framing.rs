// SPDX-License-Identifier: Apache-2.0
//! HTTP/1.1 header-framing legality, for the harness reader next door.
//!
//! Its own authority because it is the only part of that reader that decides anything about
//! the BYTES rather than about the connection: what a well-formed header block may contain,
//! and how much of a read may be believed. `read_http_request` composes the two; it does
//! not restate either.

use std::io;

/// Reject malformed HTTP/1.1 header framing (issue #38) before the header block is
/// handed to the line-based parser. Enforces strict CRLF and bans obs-fold:
///   * a bare CR (not immediately followed by LF) — `str::lines()` would embed it
///     verbatim in a header value;
///   * a bare LF (not immediately preceded by CR) — `str::lines()` splits on it, so
///     it would smuggle an extra header line;
///   * an obs-fold continuation line (a line beginning with SP/HTAB after a CRLF) —
///     RFC 7230 §3.2.4 requires rejection, and the downstream parser would silently
///     drop it (a colon-less line) rather than fold it.
///
/// Fails closed with `InvalidData` so the connection is dropped, consistent with the
/// other framing guards here (oversized header / body).
// Class C: `i` is an index into `header_bytes` produced by `enumerate`. Every READ is a
// `get`, the predecessor included.
#[allow(clippy::arithmetic_side_effects)]
pub(super) fn reject_malformed_header_framing(header_bytes: &[u8]) -> io::Result<()> {
    for (i, &byte) in header_bytes.iter().enumerate() {
        match byte {
            b'\r' if header_bytes.get(i + 1) != Some(&b'\n') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed HTTP header framing: bare CR (not part of a CRLF)",
                ));
            }
            b'\n' if i.checked_sub(1).and_then(|p| header_bytes.get(p)) != Some(&b'\r') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed HTTP header framing: bare LF (not part of a CRLF)",
                ));
            }
            b'\n' if matches!(header_bytes.get(i + 1), Some(b' ') | Some(b'\t')) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed HTTP header framing: obs-fold continuation line",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The prefix of `chunk` a read actually filled.
///
/// Class B. `Read::read` PROMISES `n <= buf.len()` and both callers account for `n` against
/// a byte ceiling; `S` is a type parameter, so the promise is checked rather than trusted.
pub(super) fn read_bytes(chunk: &[u8], n: usize) -> io::Result<&[u8]> {
    chunk.get(..n).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "reader reported more bytes than it was given room for",
        )
    })
}
