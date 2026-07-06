//! Streamable HTTP transport for the MCP-RE conformance server (MCPS-013).
//!
//! A deliberately minimal HTTP/1.1 implementation over `std::net` — NO HTTP
//! crate — so the isolated `crates_mcp_re` hub stays free of a networking
//! dependency (ADR-MCPS-001/012 firewall). It covers the single-JSON-response
//! mode of MCP Streamable HTTP: the client `POST`s one JSON-RPC message and the
//! server replies `application/json` with one JSON-RPC message. SSE streaming
//! is intentionally not exercised — the conformance matrix is request/response
//! only.
//!
//! The transport is pure plumbing: every verdict still comes from
//! [`EchoServer::handle`], so the Core outcome is identical to the stdio and
//! object targets (ADR-MCPS-011 transport parity). `now_unix` pins the clock.

use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;

/// Read one HTTP/1.1 message body from `stream`: consume the header block up to
/// the `\r\n\r\n` terminator, parse `Content-Length`, then read exactly that
/// many body bytes. Used for both the server (request) and client (response)
/// sides, since both frame their JSON payload with `Content-Length`.
pub fn read_http_body(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            let header_end = pos + 4;
            let content_length = parse_content_length(&buf[..header_end]);
            while buf.len() < header_end + content_length {
                let n = stream.read(&mut tmp)?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let end = (header_end + content_length).min(buf.len());
            return Ok(buf[header_end..end].to_vec());
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "connection closed before HTTP header terminator",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Serve `count` HTTP requests on `listener`, one request per accepted
/// connection (`Connection: close`). Each request body is passed to `handle`
/// and its return value written back as the `application/json` response body.
/// One server instance handles all `count` requests in sequence, so any
/// per-connection state (e.g. the replay cache) persists across them.
pub fn serve_http_requests(
    listener: &TcpListener,
    count: usize,
    mut handle: impl FnMut(&[u8]) -> Vec<u8>,
) -> std::io::Result<()> {
    for _ in 0..count {
        let (mut stream, _addr) = listener.accept()?;
        let body = read_http_body(&mut stream)?;
        let response = handle(&body);
        write_response(&mut stream, &response)?;
    }
    Ok(())
}

/// Client side: open a connection to `addr`, `POST` `body` as JSON, and return
/// the response body bytes.
pub fn http_post(addr: SocketAddr, body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr)?;
    let request_head = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request_head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    read_http_body(&mut stream)
}

/// Write a `200 OK application/json` response carrying `body`.
fn write_response(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Case-insensitive `Content-Length` lookup in a header block. Absent ⇒ 0.
fn parse_content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse().unwrap_or(0);
            }
        }
    }
    0
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
