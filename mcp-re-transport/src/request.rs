// SPDX-License-Identifier: Apache-2.0
//! Building the request bytes, and refusing anything that could be read two ways.
//!
//! This transport owns the framing, so it owns the headers that define where one message
//! ends and the next begins. A caller that could set `Host`, `Content-Length`, `Connection`
//! or `Transfer-Encoding` could desynchronise the message boundary from what the peer
//! parses — the classic request-smuggling shape — so supplying one FAILS CLOSED rather than
//! being silently dropped or duplicated. Silently dropping it would be worse than refusing:
//! the caller believes it sent something the peer never saw.
//!
//! Everything else the caller supplies is held to RFC 9110 before a socket is opened. A
//! method that is not a token, an origin-form target carrying a space (which would end the
//! target and let the rest be read as the HTTP version), a header name that is not a token,
//! a value carrying a control character — each one is a second framing interpretation
//! available to the peer, and each is a local programming error rather than something to
//! discover with a connection already established.

use super::TransportError;

/// Headers this transport owns because it owns the framing. A caller that could
/// set them could desynchronise the message boundary from what the peer parses —
/// the classic request-smuggling shape — so supplying one fails closed rather
/// than being silently dropped or duplicated.
const TRANSPORT_OWNED_HEADERS: [&str; 4] =
    ["host", "content-length", "connection", "transfer-encoding"];

/// RFC 9110 `tchar`: the characters a method or header name may contain.
pub(super) fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Serialize the request line + header block, validating everything the caller
/// supplied. `Host`, `Content-Length` and `Connection` are set here (single
/// request per connection, matching the proxy's framing).
pub(super) fn build_request_head(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    body_len: usize,
) -> Result<String, TransportError> {
    if method.is_empty() || !method.bytes().all(is_token_byte) {
        return Err(TransportError::InvalidRequest(format!(
            "method is not an RFC 9110 token: {method:?}"
        )));
    }
    // Origin-form request target: visible ASCII, no space (which would end the
    // target and let the rest be read as the HTTP version), no CR/LF.
    if !path.starts_with('/') || path.bytes().any(|b| !(0x21..=0x7E).contains(&b)) {
        return Err(TransportError::InvalidRequest(format!(
            "request target is not origin-form visible ASCII: {path:?}"
        )));
    }

    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {body_len}\r\nConnection: close\r\n");
    for (name, value) in headers {
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(TransportError::InvalidRequest(format!(
                "header name is not an RFC 9110 token: {name:?}"
            )));
        }
        let lower = name.to_ascii_lowercase();
        if TRANSPORT_OWNED_HEADERS.contains(&lower.as_str()) {
            return Err(TransportError::InvalidRequest(format!(
                "{lower} is set by the transport and must not be supplied by the caller"
            )));
        }
        // A CR or LF here would terminate the header block early and let the rest
        // of the value be read as a second request (request splitting). Reject the
        // whole exchange; never sanitise and send.
        if value
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == 0 || (b < 0x20 && b != b'\t') || b == 0x7F)
        {
            return Err(TransportError::InvalidRequest(format!(
                "header {name} carries a control character (request splitting)"
            )));
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    #[test]
    fn caller_headers_are_emitted_verbatim() {
        let head = build_request_head(
            "POST",
            "/mcp?route=a",
            "proxy.internal",
            &[
                header("signature", "sig1=:AAAA:"),
                header("content-digest", "sha-256=:BBBB:"),
            ],
            17,
        )
        .expect("emittable request");
        assert!(head.starts_with("POST /mcp?route=a HTTP/1.1\r\n"));
        assert!(head.contains("\r\nHost: proxy.internal\r\n"));
        assert!(head.contains("\r\nContent-Length: 17\r\n"));
        assert!(head.contains("\r\nsignature: sig1=:AAAA:\r\n"));
        assert!(head.contains("\r\ncontent-digest: sha-256=:BBBB:\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_crlf_in_a_header_value_is_rejected_not_sanitised() {
        let split = build_request_head(
            "POST",
            "/",
            "proxy.internal",
            &[header("signature", "sig1=:AAAA:\r\nX-Injected: yes")],
            0,
        );
        assert!(matches!(split, Err(TransportError::InvalidRequest(_))));
    }

    #[test]
    fn a_bare_lf_in_a_header_value_is_rejected() {
        let split = build_request_head(
            "POST",
            "/",
            "proxy.internal",
            &[header("signature", "sig1=:AAAA:\nX-Injected: yes")],
            0,
        );
        assert!(matches!(split, Err(TransportError::InvalidRequest(_))));
    }

    #[test]
    fn transport_owned_headers_are_refused() {
        for name in ["Host", "content-length", "Connection", "Transfer-Encoding"] {
            let result = build_request_head("POST", "/", "proxy.internal", &[header(name, "x")], 0);
            assert!(
                matches!(result, Err(TransportError::InvalidRequest(_))),
                "{name} must not be caller-settable"
            );
        }
    }

    #[test]
    fn a_non_token_method_or_header_name_is_rejected() {
        assert!(matches!(
            build_request_head("PO ST", "/", "h", &[], 0),
            Err(TransportError::InvalidRequest(_))
        ));
        assert!(matches!(
            build_request_head("POST", "/", "h", &[header("bad name", "x")], 0),
            Err(TransportError::InvalidRequest(_))
        ));
    }

    #[test]
    fn a_request_target_with_a_space_is_rejected() {
        assert!(matches!(
            build_request_head("POST", "/mcp HTTP/1.1", "h", &[], 0),
            Err(TransportError::InvalidRequest(_))
        ));
        assert!(matches!(
            build_request_head("POST", "mcp", "h", &[], 0),
            Err(TransportError::InvalidRequest(_))
        ));
    }
}
