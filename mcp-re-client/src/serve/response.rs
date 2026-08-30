// SPDX-License-Identifier: Apache-2.0
//! Writing the reply the local client reads.
//!
//! A deliberately small emitter: a status line, `Content-Type`, `Content-Length`,
//! `Connection: close` — one exchange per connection — and the body. The
//! `Mcp-Re-Verified-Kind` header rides along for an embedder that wants the pipeline''s
//! classification; it is outside the plain-MCP contract, which is why nothing in the status
//! or body depends on the caller reading it.

use std::io::Write;

pub(super) fn write_response(
    stream: &mut impl Write,
    status: u16,
    kind: Option<&str>,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Bad Gateway",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    // The verified classification the pipeline produced. A non-terminal
    // `input-required` reported as a finished result is how an approval nobody gave
    // reaches an application, so the distinction is surfaced rather than left to be
    // re-derived from the body.
    if let Some(kind) = kind {
        head.push_str(&format!("Mcp-Re-Verified-Kind: {kind}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Two `Content-Length` headers let a reader and a writer disagree about where the
    /// message ends, which is a request-smuggling primitive rather than a quirk.
    #[test]
    fn the_response_writer_emits_one_content_length_and_closes() {
        let mut out = Vec::new();
        write_response(&mut out, 200, Some("success"), b"{\"ok\":true}").expect("write");
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert!(text.contains("Connection: close"));
        assert!(text.contains("Mcp-Re-Verified-Kind: success"));
        assert!(text.ends_with("{\"ok\":true}"));
    }
}
