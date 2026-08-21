// SPDX-License-Identifier: Apache-2.0
//! The harness's hand-rolled HTTP/1.1 framing — PRIVATE to the harness subtree.
//!
//! One request per connection: read headers to `\r\n\r\n`, honour `Content-Length`, write a
//! fixed `200 OK`. No chunked encoding, no SSE, no keep-alive. The framing guards here
//! (bare CR/LF, obs-fold, duplicate or unparseable `Content-Length`, oversized header or
//! body) fail closed so a malformed request is dropped rather than reinterpreted — they
//! are parser hygiene for this parser, not transport-security policy.

use std::io;
use std::io::Read;
use std::io::Write;

use crate::tls::ServerLimits;

/// One parsed HTTP/1.1 request: the request/header block (text up to and
/// including the `\r\n\r\n` terminator) and the body bytes (the JSON-RPC
/// payload). The header block is retained for the Tier-3 assertion extractor and
/// the routing-header hygiene guard; transport identity never comes from it.
pub(super) struct HttpRequest {
    /// The full header block (request line + headers + terminator), lossily
    /// decoded as UTF-8 (header bytes are ASCII in practice).
    pub(super) header_block: String,
    /// The request body (the JSON-RPC payload).
    pub(super) body: Vec<u8>,
}

/// Read one HTTP/1.1 request and return its header block + body bytes (the
/// JSON-RPC payload). Reads headers up to `\r\n\r\n`, honours `Content-Length`.
/// Minimal by design — single request per connection, no chunked encoding, no
/// SSE. Bounded by `limits`: the header block may not exceed `max_header_bytes`
/// and the body may not exceed `max_body_bytes` (either overflow fails closed
/// with an error rather than allocating without bound).
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
fn reject_malformed_header_framing(header_bytes: &[u8]) -> io::Result<()> {
    for (i, &byte) in header_bytes.iter().enumerate() {
        match byte {
            b'\r' if header_bytes.get(i + 1) != Some(&b'\n') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed HTTP header framing: bare CR (not part of a CRLF)",
                ));
            }
            b'\n' if i == 0 || header_bytes[i - 1] != b'\r' => {
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

pub(super) fn read_http_request<S: Read>(
    stream: &mut S,
    limits: &ServerLimits,
) -> io::Result<HttpRequest> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    // Read until end-of-headers, capping total header bytes.
    let header_end = loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > limits.max_header_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header block exceeds max_header_bytes",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before end of HTTP headers",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_bytes = &buf[..header_end];
    reject_malformed_header_framing(header_bytes)?;
    let header_block = String::from_utf8_lossy(header_bytes).into_owned();
    let content_length = parse_content_length(&header_block)?.unwrap_or(0);
    if content_length > limits.max_body_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Content-Length exceeds max_body_bytes",
        ));
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        // Defend against a Content-Length that under-states a flood of body bytes.
        if body.len() > limits.max_body_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request body exceeds max_body_bytes",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok(HttpRequest { header_block, body })
}

/// Write a minimal HTTP/1.1 JSON response carrying `body`.
///
/// Fixed `200 OK` and a fixed header set: this is the mTLS harness path, not an
/// MCP-RE serving path — see [`serve_once`]. Nothing here can carry RFC 9421
/// evidence, and no caller on the shipped proxy reaches it.
pub(super) fn write_http_response<S: Write>(stream: &mut S, body: &[u8]) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

/// Parse the `Content-Length` header value (case-insensitive) from a header block.
///
/// Fails closed with `InvalidData` on a duplicated `Content-Length` header (a
/// request-smuggling primitive: two lengths disagree on the body boundary) or a
/// present-but-unparseable value, consistent with the other framing guards here.
/// An absent header returns `Ok(None)` (the caller treats that as a zero-length
/// body); only present-but-malformed / conflicting lengths are rejected.
fn parse_content_length(headers: &str) -> io::Result<Option<usize>> {
    let mut seen: Option<usize> = None;
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                if seen.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed HTTP header framing: duplicate Content-Length",
                    ));
                }
                let parsed = value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed HTTP header framing: unparseable Content-Length",
                    )
                })?;
                seen = Some(parsed);
            }
        }
    }
    Ok(seen)
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod header_framing_tests {
    //! Issue #38: obs-fold / bare-CR / bare-LF header framing must fail closed.
    //!
    //! A request whose header section is not strict CRLF-framed is rejected at
    //! read time rather than handed on to a line parser that would silently drop
    //! or re-join the offending bytes.

    fn read_req(bytes: &[u8]) -> std::io::Result<super::HttpRequest> {
        super::read_http_request(
            &mut std::io::Cursor::new(bytes.to_vec()),
            &super::ServerLimits::default(),
        )
    }

    #[test]
    fn obs_fold_continuation_line_is_rejected() {
        // RFC 7230 §3.2.4: an obs-fold continuation (line starting with SP/HTAB)
        // must be rejected, not silently dropped by the downstream line parser.
        let block = b"POST /mcp HTTP/1.1\r\nMcp-Name: good\r\n\tinjected\r\n\r\n";
        assert!(
            read_req(block).is_err(),
            "an obs-fold continuation line must fail closed"
        );
    }

    #[test]
    fn bare_cr_in_header_section_is_rejected() {
        // A bare CR (not part of a CRLF) must be rejected rather than embedded
        // verbatim in a header value by `str::lines()`.
        let block = b"POST /mcp HTTP/1.1\r\nMcp-Name: good\rinjected\r\n\r\n";
        assert!(read_req(block).is_err(), "a bare CR must fail closed");
    }

    #[test]
    fn bare_lf_line_ending_is_rejected() {
        // A bare LF line ending (not CRLF) must be rejected — `str::lines()` splits
        // on it, so a bare LF would otherwise smuggle an extra header line.
        let block = b"POST /mcp HTTP/1.1\nMcp-Name: good\r\n\r\n";
        assert!(
            read_req(block).is_err(),
            "a bare LF line ending must fail closed"
        );
    }

    #[test]
    fn well_formed_strict_crlf_request_is_accepted() {
        // Regression: a clean CRLF-framed request still parses, and its headers are
        // intact (the framing guard must not reject well-formed input).
        let block = b"POST /mcp HTTP/1.1\r\nMcp-Name: good\r\n\r\n";
        let req = read_req(block).expect("a well-formed CRLF request must be accepted");
        let headers = crate::transport::RequestHeaders::parse(&req.header_block);
        assert_eq!(headers.first("mcp-name"), Some("good"));
    }
}

#[cfg(test)]
mod content_length_framing_tests {
    //! Audit LOW (ledger `84224733b1228db8`): a duplicated or unparseable
    //! `Content-Length` must fail closed with `InvalidData` rather than silently
    //! collapsing to a zero-length body. Two disagreeing lengths are a classic
    //! request-smuggling primitive; every sibling duplicate-header guard here
    //! already rejects, so this one must too.

    use std::io;

    use super::read_http_request;
    use super::ServerLimits;

    fn read(raw: &[u8]) -> io::Result<super::HttpRequest> {
        let mut stream = io::Cursor::new(raw.to_vec());
        read_http_request(&mut stream, &ServerLimits::default())
    }

    // `HttpRequest` intentionally has no `Debug`, so assert the error arm by hand
    // rather than via `expect_err`.
    fn assert_invalid_data(raw: &[u8], why: &str) {
        match read(raw) {
            Ok(_) => panic!("{why}"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{why}: {e}"),
        }
    }

    #[test]
    fn duplicate_content_length_is_rejected() {
        // Two Content-Length lines that disagree on the body boundary: the smuggling
        // case. Must fail closed rather than pick one (first-wins) silently.
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhello";
        assert_invalid_data(raw, "duplicate Content-Length must fail closed");
    }

    #[test]
    fn duplicate_content_length_same_value_is_still_rejected() {
        // Even agreeing duplicates are rejected — the strict, uniform posture (no
        // "are they equal" special-case that a smuggler could probe).
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
        assert_invalid_data(raw, "any duplicate Content-Length must fail closed");
    }

    #[test]
    fn unparseable_content_length_is_rejected() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: not-a-number\r\n\r\n";
        assert_invalid_data(raw, "unparseable Content-Length must fail closed");
    }

    #[test]
    fn negative_content_length_is_rejected() {
        // `usize` parse rejects the sign; previously this collapsed to 0.
        let raw = b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n";
        assert_invalid_data(raw, "negative Content-Length must fail closed");
    }

    #[test]
    fn absent_content_length_is_a_zero_length_body() {
        // Absent (not present-but-malformed) stays permissive: zero-length body.
        let raw = b"POST / HTTP/1.1\r\n\r\n";
        let req = read(raw).expect("absent Content-Length is a well-formed empty body");
        assert!(req.body.is_empty());
    }

    #[test]
    fn single_valid_content_length_parses() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = read(raw).expect("a single valid Content-Length must parse");
        assert_eq!(req.body, b"hello");
    }
}
