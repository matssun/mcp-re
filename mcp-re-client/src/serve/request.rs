// SPDX-License-Identifier: Apache-2.0
//! Reading one local request, and refusing everything this listener does not parse.
//!
//! `POST`, `Content-Length`, one exchange per connection, and nothing else. This socket is
//! the trust boundary''s inner face: whatever reaches it gets requests signed under this
//! client''s identity, so every byte of parser here is attack surface for no benefit.
//!
//! Chunked bodies are REFUSED rather than parsed — a framing bug on this leg would let one
//! local caller''s body be read as another''s, and no local MCP client needs chunked to send
//! a JSON-RPC message. Keep-alive is not offered for the same reason: one request per
//! connection means the reader never has to find a message boundary in a stream, which is
//! where framing confusion lives.
//!
//! The ORDER of the refusals is load-bearing. Framing is settled first, so a message with
//! no boundary is refused as one whatever else it carries — a head that cannot be framed
//! says nothing reliable about its headers. Then the caller-shape guards, all three before
//! a single byte is signed.

use std::io::Read;
use std::net::TcpStream;
use std::time::Instant;

use super::accepted_authority::AcceptedHttpAuthority;
use super::deadlines::arm;
use super::head_fields::check_framing_and_caller_shape;
use super::head_fields::HeadFields;
use super::LocalRequest;
use super::HEAD_CHUNK_BYTES;
use super::MAX_HEAD_BYTES;

/// Read one request: head to CRLFCRLF, then exactly `Content-Length` body bytes.
///
/// Returns the HTTP status to answer with on failure. Every refusal is a refusal —
/// there is no lenient path that guesses at framing.
pub(super) fn read_request(
    stream: &mut TcpStream,
    deadline: Instant,
    accepted_authority: &AcceptedHttpAuthority,
) -> Result<LocalRequest, u16> {
    let (mut buffer, head_end) = read_head(stream, deadline)?;
    // Bytes past the terminator are the start of this request's body — the chunked
    // read cannot have run into another message, because this socket serves exactly
    // one exchange per connection and never parses a second request from it.
    let body = buffer.split_off(head_end);
    let head = std::str::from_utf8(&buffer).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(400u16)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(400u16)?;
    let path = parts.next().ok_or(400u16)?.to_owned();
    if !method.eq_ignore_ascii_case("POST") {
        return Err(405);
    }

    let head = HeadFields::read(lines)?;
    let length = check_framing_and_caller_shape(&head, accepted_authority)?;
    let body = fill_body(stream, deadline, body, length)?;
    Ok(LocalRequest { path, body })
}

/// Read until the head terminator, or refuse.
///
/// Returns the buffered bytes and the index just past the terminator. Chunked reads rather
/// than one byte per syscall: reading the head a byte at a time is what let a stalled peer
/// re-arm the timer thousands of times over. Nothing is over-read — this socket serves one
/// exchange per connection, so bytes past the terminator belong to this request's body.
fn read_head(stream: &mut TcpStream, deadline: Instant) -> Result<(Vec<u8>, usize), u16> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; HEAD_CHUNK_BYTES];
    let head_end = loop {
        if let Some(at) = find_head_end(&buffer) {
            break at;
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return Err(431);
        }
        arm(stream, deadline)?;
        match stream.read(&mut chunk) {
            Ok(0) => return Err(400),
            // Class B: the head accounting above is what bounds the buffer against
            // `MAX_HEAD_BYTES`, so `Read::read`'s `n <= chunk.len()` is checked here.
            Ok(n) => match chunk.get(..n) {
                Some(filled) => buffer.extend_from_slice(filled),
                None => return Err(400),
            },
            Err(_) => return Err(408),
        }
    };
    // A terminator found beyond the bound is still an over-long head; the loop test above
    // only runs while one has not been found yet.
    if head_end > MAX_HEAD_BYTES {
        return Err(431);
    }
    Ok((buffer, head_end))
}

/// Read exactly `length` body bytes, starting from whatever arrived with the head.
///
/// Anything the caller sent beyond `Content-Length` is NOT parsed as a second request — it
/// is left for the drain to consume so the close is a FIN.
fn fill_body(
    stream: &mut TcpStream,
    deadline: Instant,
    mut body: Vec<u8>,
    length: usize,
) -> Result<Vec<u8>, u16> {
    // Exactly `Content-Length` bytes are the message. Anything the caller sent beyond
    // it is not parsed as a second request — it is left for `drain` to consume so the
    // close is a FIN — which is the same set of bytes the byte-at-a-time reader used to
    // leave in the receive queue.
    body.truncate(length);
    let already = body.len();
    body.resize(length, 0);
    let mut filled = already;
    while filled < length {
        arm(stream, deadline)?;
        // Class B: the unfilled tail through `get_mut`, so the loop condition is the
        // reason the read has somewhere to go rather than a fact stated beside it.
        let Some(tail) = body.get_mut(filled..) else {
            return Err(400);
        };
        match stream.read(tail) {
            Ok(0) => return Err(400),
            // A read claiming more than the tail it was given cannot be accounted for.
            Ok(n) => match filled.checked_add(n).filter(|f| *f <= length) {
                Some(next) => filled = next,
                None => return Err(400),
            },
            Err(_) => return Err(408),
        }
    }
    Ok(body)
}

/// Index just past the CRLFCRLF that ends the head, if the buffer holds one.
// Class C: `at` is the position of a four-byte window INSIDE `buffer`, so the sum is at
// most its length; the terminator's width is named once, as the `windows` argument.
#[allow(clippy::arithmetic_side_effects)]
pub(super) fn find_head_end(buffer: &[u8]) -> Option<usize> {
    const TERMINATOR: &[u8] = b"\r\n\r\n";
    buffer
        .windows(TERMINATOR.len())
        .position(|window| window == TERMINATOR)
        .map(|at| at + TERMINATOR.len())
}

#[cfg(test)]
mod tests {
    use crate::config::BindScope;

    /// The ordinary deployment: a loopback listener, so the loopback literals are the
    /// whole authority set.
    fn loopback_only() -> AcceptedHttpAuthority {
        AcceptedHttpAuthority::for_listener(
            &BindScope::decide("127.0.0.1:8640".parse().expect("an address"), false)
                .expect("loopback is admitted"),
        )
    }

    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::time::Duration;

    fn socket_pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral listener");
        let addr = listener.local_addr().expect("bound address");
        let client = std::net::TcpStream::connect(addr).expect("client connects");
        let (server, _) = listener.accept().expect("server accepts");
        (client, server)
    }

    #[test]
    fn the_head_terminator_is_found_at_its_own_end() {
        assert_eq!(find_head_end(b"a\r\n\r\nbody"), Some(5));
        assert_eq!(find_head_end(b"a\r\n\r"), None);
        assert_eq!(find_head_end(b""), None);
    }

    /// The head is read in chunks, so bytes of the body that arrive glued to the last
    /// head chunk must be kept rather than re-read from a socket that will not resend
    /// them.
    #[test]
    fn a_head_split_across_reads_still_frames_a_body_that_arrived_with_it() {
        let (mut client, mut server) = socket_pair();
        let writer = std::thread::spawn(move || {
            client
                .write_all(b"POST /route/r1 HTTP/1.1\r\nHost: 127.0.0.1:8640\r\nContent-Type: application/json\r\nContent-Len")
                .expect("first chunk");
            std::thread::sleep(Duration::from_millis(20));
            client
                .write_all(b"gth: 11\r\n\r\n{\"ok\":true}")
                .expect("second chunk");
            std::thread::sleep(Duration::from_millis(50));
        });
        let request = read_request(
            &mut server,
            Instant::now() + Duration::from_secs(5),
            &loopback_only(),
        )
        .expect("the request frames");
        assert_eq!(request.path, "/route/r1");
        assert_eq!(request.body, b"{\"ok\":true}");
        writer.join().expect("writer");
    }

    /// The deadline is a bound on the exchange, not on one syscall.
    ///
    /// A caller making one byte of progress per interval re-arms a per-read timer for
    /// as long as it likes; `max_in_flight` such connections take the sidecar out of
    /// service without ever sending a request.
    #[test]
    fn a_dripping_caller_hits_the_exchange_deadline_instead_of_holding_the_worker() {
        let (mut client, mut server) = socket_pair();
        let writer = std::thread::spawn(move || {
            for byte in b"POST /route/r1 HTTP/1.1\r\n" {
                if client.write_all(&[*byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let status = read_request(
            &mut server,
            Instant::now() + Duration::from_millis(120),
            &loopback_only(),
        )
        .expect_err("the deadline must fire");
        assert_eq!(status, 408);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the read returned after {:?}; the deadline did not bound it",
            started.elapsed()
        );
        let _ = writer.join();
    }
}
