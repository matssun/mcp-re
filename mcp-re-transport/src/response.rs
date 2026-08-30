// SPDX-License-Identifier: Apache-2.0
//! Reading the reply: what came back, bounded, and framed exactly one way.
//!
//! The status line and headers are NOT decoration. Under ADR-MCPRE-050 they carry the
//! RFC 9421 `Signature`/`Signature-Input` and RFC 9530 `Content-Digest` the response
//! verifier needs, and the status distinguishes a success from a signed rejection receipt —
//! so they are preserved rather than skipped.
//!
//! Everything ambiguous is an error. A missing header terminator once returned the whole
//! buffer AS the body, so a malformed reply reached the caller looking like content; a bare
//! CR or LF in the header block, an obs-fold continuation, a duplicated or unparsable
//! `Content-Length`, a length disagreeing with the bytes received, or a `Transfer-Encoding`
//! this transport does not implement are each a second reading the peer's parser may take.
//!
//! The size bound is the other half. An unbounded `read_to_end` let a verified-but-hostile
//! or simply buggy proxy drive the client to OOM, and the aggregate deadline stops a peer
//! trickling bytes just under the per-read timeout from extending the read without bound.

use super::request::is_token_byte;
use super::TransportError;

/// A whole HTTP/1.1 response: the status, the header block, and the body.
///
/// The status and headers are NOT decoration — under ADR-MCPRE-050 they carry the
/// RFC 9421 `Signature`/`Signature-Input` and RFC 9530 `Content-Digest` that the
/// response verifier needs, and the status distinguishes a success from a signed
/// rejection receipt. Header names are lowercased; the profile matches them
/// case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseParts {
    /// The response status code from the status line.
    pub status: u16,
    /// The response header block, names lowercased, in wire order.
    pub headers: Vec<(String, String)>,
    /// The response body bytes (after the header terminator).
    pub body: Vec<u8>,
}

/// Parse an HTTP/1.1 response into its status, headers and body, failing closed on
/// any framing the transport cannot read unambiguously.
///
/// The status line and headers are the ADR-MCPRE-050 evidence carrier, so they are
/// preserved rather than skipped. Everything ambiguous is an error: a missing
/// header terminator (previously the whole buffer was returned AS the body, so a
/// malformed reply reached the caller looking like content), a bare CR or LF in
/// the header block, an obs-fold continuation, a header line with no colon, a
/// duplicated or unparsable `Content-Length`, a `Content-Length` disagreeing with
/// the bytes received (truncation), or `Transfer-Encoding` (this transport does
/// not do chunked framing, and accepting the header while ignoring it is the
/// request-smuggling shape).
pub(super) fn parse_response(raw: &[u8]) -> Result<HttpResponseParts, TransportError> {
    let terminator = b"\r\n\r\n";
    let head_end = raw
        .windows(terminator.len())
        .position(|w| w == terminator)
        .ok_or_else(|| {
            TransportError::MalformedResponse("no CRLFCRLF header terminator".to_string())
        })?;
    // Class B: head and body are ONE split at the terminator just located, rather than
    // two ranges each re-deriving the same offset from wire bytes.
    let (head_bytes, body) = raw
        .split_at_checked(head_end)
        .and_then(|(head, rest)| rest.get(terminator.len()..).map(|body| (head, body)))
        .ok_or_else(|| TransportError::MalformedResponse("truncated header block".to_string()))?;
    let head = std::str::from_utf8(head_bytes).map_err(|_| {
        TransportError::MalformedResponse("header block is not valid UTF-8".to_string())
    })?;
    let body = body.to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| TransportError::MalformedResponse("empty response".to_string()))?;
    let status = parse_status_line(status_line)?;

    let headers = parse_header_block(lines)?;
    check_framing(&headers, body.len())?;
    Ok(HttpResponseParts {
        status,
        headers,
        body,
    })
}

/// The header block, held to one reading.
///
/// `split("\r\n")` leaves any BARE CR or LF inside a line, and either one is a second
/// framing interpretation the peer's parser may take — as is an obs-fold continuation, and
/// a line with no colon. Names are lowercased; the profile matches them case-insensitively.
fn parse_header_block<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<Vec<(String, String)>, TransportError> {
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(TransportError::MalformedResponse(
                "obs-fold header continuation".to_string(),
            ));
        }
        // `split("\r\n")` leaves any BARE CR or LF inside a line; either one is a
        // second framing interpretation the peer's parser may take.
        if line.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(TransportError::MalformedResponse(
                "bare CR or LF in the header block".to_string(),
            ));
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            TransportError::MalformedResponse("header line without a colon".to_string())
        })?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(TransportError::MalformedResponse(format!(
                "header name is not an RFC 9110 token: {name:?}"
            )));
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok(headers)
}

/// The two headers that decide where this message ends.
///
/// `Transfer-Encoding` is refused rather than ignored: this transport does not do chunked
/// framing, and accepting the header while ignoring it is the request-smuggling shape. A
/// `Content-Length` that is duplicated, unparsable, or disagrees with the bytes received is
/// refused for the same reason — the last of those is a truncation the caller would
/// otherwise read as content.
fn check_framing(headers: &[(String, String)], body_len: usize) -> Result<(), TransportError> {
    if headers.iter().any(|(name, _)| name == "transfer-encoding") {
        return Err(TransportError::MalformedResponse(
            "transfer-encoding is not supported by this transport".to_string(),
        ));
    }
    let mut declared = headers.iter().filter(|(name, _)| name == "content-length");
    if let Some((_, value)) = declared.next() {
        if declared.next().is_some() {
            return Err(TransportError::MalformedResponse(
                "duplicate content-length".to_string(),
            ));
        }
        let declared_len: usize = value.parse().map_err(|_| {
            TransportError::MalformedResponse(format!("unparsable content-length: {value:?}"))
        })?;
        if declared_len != body_len {
            return Err(TransportError::MalformedResponse(format!(
                "content-length {declared_len} disagrees with the {} bytes received",
                body_len
            )));
        }
    }
    Ok(())
}

/// Parse `HTTP/1.1 200 OK` — version, exactly three status digits, and an optional
/// space-separated reason phrase.
fn parse_status_line(line: &str) -> Result<u16, TransportError> {
    let rest = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))
        .ok_or_else(|| {
            TransportError::MalformedResponse(format!("unrecognised status line: {line:?}"))
        })?;
    let code = rest
        .get(..3)
        .filter(|c| c.bytes().all(|b| b.is_ascii_digit()));
    let code = code.ok_or_else(|| {
        TransportError::MalformedResponse(format!("status code is not three digits: {line:?}"))
    })?;
    match rest.as_bytes().get(3) {
        None | Some(b' ') => {}
        Some(_) => {
            return Err(TransportError::MalformedResponse(format!(
                "status code is not delimited: {line:?}"
            )))
        }
    }
    code.parse()
        .map_err(|_| TransportError::MalformedResponse(format!("unparsable status code: {line:?}")))
}

#[cfg(test)]
mod framing_tests {
    use super::*;

    fn header(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    // -- response parsing: the evidence carrier survives ---------------------

    #[test]
    fn status_and_headers_are_preserved() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nSignature: sig1=:AAAA:\r\nSignature-Input: sig1=(\"@status\")\r\nContent-Length: 2\r\n\r\n{}";
        let parsed = parse_response(raw).expect("well-framed response");
        assert_eq!(parsed.status, 403);
        assert_eq!(
            parsed.headers,
            vec![
                header("signature", "sig1=:AAAA:"),
                header("signature-input", "sig1=(\"@status\")"),
                header("content-length", "2"),
            ]
        );
        assert_eq!(parsed.body, b"{}");
    }

    #[test]
    fn a_response_with_no_header_terminator_is_rejected() {
        // The pre-fix behaviour returned this ENTIRE buffer as the "body", so a
        // reply with no header block reached the caller looking like content.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{}";
        assert!(matches!(
            parse_response(raw),
            Err(TransportError::MalformedResponse(_))
        ));
    }

    #[test]
    fn a_bodyless_202_is_readable() {
        let raw = b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n";
        let parsed = parse_response(raw).expect("bodyless 202");
        assert_eq!(parsed.status, 202);
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn a_truncated_body_is_rejected_not_silently_shortened() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{}";
        assert!(matches!(
            parse_response(raw),
            Err(TransportError::MalformedResponse(_))
        ));
    }

    #[test]
    fn transfer_encoding_is_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert!(matches!(
            parse_response(raw),
            Err(TransportError::MalformedResponse(_))
        ));
    }

    #[test]
    fn duplicate_content_length_is_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        assert!(matches!(
            parse_response(raw),
            Err(TransportError::MalformedResponse(_))
        ));
    }

    #[test]
    fn an_obs_fold_continuation_is_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\nSignature: sig1=:AAAA:\r\n injected\r\nContent-Length: 2\r\n\r\n{}";
        assert!(matches!(
            parse_response(raw),
            Err(TransportError::MalformedResponse(_))
        ));
    }

    #[test]
    fn a_bare_lf_in_the_header_block_is_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\nSignature: sig1=:AAAA:\ninjected: yes\r\nContent-Length: 2\r\n\r\n{}";
        assert!(matches!(
            parse_response(raw),
            Err(TransportError::MalformedResponse(_))
        ));
    }

    #[test]
    fn a_header_line_without_a_colon_is_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\nnonsense\r\nContent-Length: 2\r\n\r\n{}";
        assert!(matches!(
            parse_response(raw),
            Err(TransportError::MalformedResponse(_))
        ));
    }

    #[test]
    fn a_non_http_status_line_is_rejected() {
        assert!(matches!(
            parse_response(b"NOT-HTTP 200 OK\r\n\r\n"),
            Err(TransportError::MalformedResponse(_))
        ));
        assert!(matches!(
            parse_response(b"HTTP/1.1 2xx OK\r\n\r\n"),
            Err(TransportError::MalformedResponse(_))
        ));
        assert!(matches!(
            parse_response(b"HTTP/1.1 2000 OK\r\n\r\n"),
            Err(TransportError::MalformedResponse(_))
        ));
    }

    #[test]
    fn a_reason_phrase_is_optional() {
        let parsed = parse_response(b"HTTP/1.1 204\r\n\r\n").expect("no reason phrase");
        assert_eq!(parsed.status, 204);
    }

    // -- request emission: the evidence reaches the wire ---------------------
}
