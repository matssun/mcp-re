// SPDX-License-Identifier: Apache-2.0
//! The local plain-MCP listener.
//!
//! The local client speaks ORDINARY MCP over HTTP/1.1 to this socket and never sees an
//! MCP-RE field: the sidecar signs the outbound request as RFC 9421 + RFC 9530,
//! verifies the server's delegated-signed reply bound to it, and hands back plain
//! JSON-RPC. That transparency is the point — the security profile is not something an
//! agent has to implement.
//!
//! ## A deliberately small HTTP surface
//!
//! `POST`, `Content-Length`, one exchange per connection, and nothing else. This socket
//! is the trust boundary's inner face: whatever reaches it gets requests signed under
//! this client's identity, so every byte of parser here is attack surface for no
//! benefit. Chunked bodies are REFUSED rather than parsed — a framing bug on this leg
//! would let one local caller's body be read as another's, and no local MCP client
//! needs chunked to send a JSON-RPC message.
//!
//! Keep-alive is not offered for the same reason: one request per connection means the
//! reader never has to find a message boundary in a stream, which is where framing
//! confusion lives. The cost is a TCP handshake per call on loopback.

use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mcp_re_client_proxy::CallParams;
use mcp_re_client_proxy::ClientProxy;
use mcp_re_client_proxy::ProxyError;
use mcp_re_client_proxy::ResponseKind;
use serde_json::json;
use serde_json::Value;

use crate::config::LocalConfig;

/// The largest request head this listener will read before giving up.
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// The largest plain-MCP body accepted from the local client.
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// How long one local exchange may take to arrive, end to end.
///
/// This is a WALL-CLOCK budget for the whole read phase, not a per-syscall timeout.
/// A per-syscall timeout bounds nothing on its own: every byte delivered re-arms it,
/// so a caller dripping one byte per timeout-minus-one holds a worker thread and an
/// in-flight slot for as long as it cares to. `max_in_flight` such connections take
/// the sidecar out of service without sending a single request.
const EXCHANGE_DEADLINE: Duration = Duration::from_secs(30);
/// The largest single read issued while filling the head.
///
/// Reading the head one byte per syscall is what let a stalled peer re-arm the timer
/// thousands of times over. Nothing is over-read: this socket serves one exchange per
/// connection, so bytes past the head terminator belong to this request's body.
const HEAD_CHUNK_BYTES: usize = 1024;
/// Wall-clock bound on writing the at-capacity refusal from the accept thread.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(2);
/// Wall-clock bound on the post-exchange drain.
const DRAIN_DEADLINE: Duration = Duration::from_millis(200);
/// How long [`serve`] waits for accepted exchanges to finish once `stop` is set.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Everything the listener needs per request, beyond the proxy itself.
pub struct ServeContext {
    /// The signing/verifying pipeline.
    pub proxy: ClientProxy,
    /// Route id for a request whose path is not `/route/<id>`.
    pub default_route: Option<String>,
    /// Signed-request lifetime, seconds.
    pub request_lifetime_secs: i64,
    /// Concurrent local requests permitted.
    pub max_in_flight: usize,
    /// Wall clock, Unix seconds.
    pub clock: Box<dyn Fn() -> i64 + Send + Sync>,
    /// Fresh nonce bytes, Base64URL-encoded by the caller of [`next_nonce`].
    pub nonce: Box<dyn Fn() -> String + Send + Sync>,
}

/// A parsed local request.
#[derive(Debug)]
struct LocalRequest {
    path: String,
    body: Vec<u8>,
}

/// One claimed in-flight slot, released on every exit path including an unwind.
///
/// The release has to be a destructor rather than a statement after the call: a worker
/// that panics skips a trailing `fetch_sub`, and that slot is then gone for the
/// process lifetime. After `max_in_flight` such panics the listener answers 503 to
/// every call while the accounting reads full with nothing running — a sticky failure
/// that outlives the transient condition that caused it, recoverable only by restart.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serve until `stop` is set.
///
/// The listener polls with a short accept timeout rather than blocking forever, so a
/// SIGTERM is observed promptly instead of on the next local call. Once it is set,
/// accepted exchanges are given a bounded grace period to finish: each one has already
/// been signed, sent and executed by the remote server, so dropping it reports a reset
/// for work that DID happen and a retry then duplicates the side effect.
pub fn serve(listener: TcpListener, context: Arc<ServeContext>, stop: Arc<AtomicBool>) {
    listener
        .set_nonblocking(true)
        .expect("the local listener accepts non-blocking mode");
    let in_flight = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                // Claim a slot BEFORE spawning. Spawning first and checking after is how
                // a burst of local calls becomes an unbounded thread count. The guard
                // owns the release from here on, so every path below returns it.
                let claimed = in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                let slot = Slot(Arc::clone(&in_flight));
                if claimed > context.max_in_flight {
                    drop(slot);
                    // An accepted socket inherits the listener's O_NONBLOCK on the BSDs
                    // (including macOS) and does not on Linux. Without this the refusal
                    // would write on a non-blocking socket there, fail `WouldBlock`, and
                    // the caller would see the connection close with no answer — a
                    // capacity limit that reads as a crash on one platform and not the
                    // other.
                    let _ = stream.set_nonblocking(false);
                    // This write happens on the ACCEPT thread, so it must not be able to
                    // block it. A peer that advertises a zero receive window and never
                    // drains would otherwise stop the listener accepting anything and
                    // stop it observing `stop` — one connection denying the sidecar and
                    // blocking graceful shutdown, rather than being refused.
                    let _ = stream.set_write_timeout(Some(REFUSAL_TIMEOUT));
                    let _ = stream.set_read_timeout(Some(REFUSAL_TIMEOUT));
                    let _ = write_response(
                        &mut &stream,
                        503,
                        None,
                        b"{\"error\":\"mcp-re client sidecar at capacity\"}",
                    );
                    continue;
                }
                let worker_context = Arc::clone(&context);
                // A spawn failure drops the closure, and with it `slot`, so the claim is
                // released by the same destructor that releases it on unwind.
                let _ = std::thread::Builder::new()
                    .name("mcp-re-client-conn".to_owned())
                    .spawn(move || {
                        let _slot = slot;
                        handle_connection(stream, &worker_context);
                    });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while in_flight.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let stranded = in_flight.load(Ordering::Acquire);
    if stranded > 0 {
        eprintln!(
            "mcp-re-client: shutdown grace expired with {stranded} exchange(s) still in \
             flight; their callers see a reset for work the server may have performed"
        );
    }
}

fn handle_connection(mut stream: TcpStream, context: &ServeContext) {
    let deadline = Instant::now() + EXCHANGE_DEADLINE;
    let _ = stream.set_write_timeout(Some(EXCHANGE_DEADLINE));
    let _ = stream.set_nonblocking(false);
    let request = match read_request(&mut stream, deadline) {
        Ok(request) => request,
        Err(status) => {
            let _ = write_response(&mut stream, status, None, b"{}");
            // A refusal happens BEFORE the body is consumed, so bytes are still in
            // flight. Closing on top of them makes the kernel send RST rather than FIN,
            // and the caller then sees a reset instead of the refusal it was told —
            // turning every "405 method not allowed" into an unexplained broken pipe.
            drain(&mut stream);
            return;
        }
    };
    let (status, kind, body) = dispatch(context, &request);
    let _ = write_response(&mut stream, status, kind, &body);
    // The same reasoning as the refusal path, and it costs more here: what a reset
    // would discard is a VERIFIED reply to a call the remote server has already
    // executed, and a client that retries a reset re-runs the side effect.
    //
    // This drain must not WAIT, though. The caller is by now reading our response, not
    // writing, so a blocking drain would add its full bound to every single exchange.
    // What turns close() into RST is bytes already sitting in the receive queue, and
    // those are exactly the ones a non-blocking drain takes.
    drain_pending(&mut stream);
}

/// Read and discard whatever the caller had already sent, so the close is a clean FIN.
///
/// Bounded in both bytes and wall clock: a caller that keeps writing after the exchange
/// gets the connection dropped rather than a worker held open on it. The byte bound
/// alone is not enough — one byte per read against a per-read timeout is still a stall.
fn drain(stream: &mut TcpStream) {
    let deadline = Instant::now() + DRAIN_DEADLINE;
    let mut scratch = [0u8; 1024];
    let mut drained = 0usize;
    while drained < MAX_HEAD_BYTES {
        if arm(stream, deadline).is_err() {
            break;
        }
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

/// Consume what the caller has already sent, without waiting for more.
///
/// Closing a socket that still holds unread bytes makes the kernel send RST instead of
/// FIN, and the peer then loses whatever it had not yet read. Only bytes already
/// queued can cause that, so this takes those and returns — it never blocks, which is
/// what makes it safe to run on the success path of every exchange.
fn drain_pending(stream: &mut TcpStream) {
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let mut scratch = [0u8; 1024];
    let mut drained = 0usize;
    while drained < MAX_HEAD_BYTES {
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
    let _ = stream.set_nonblocking(false);
}

/// Arm the socket so the next read cannot outlive `deadline`.
///
/// Shrinking the per-read timeout to the remaining budget before every read is what
/// turns a set of per-syscall timers into one bound on the exchange. A zero or elapsed
/// budget is reported as a timeout rather than passed to `set_read_timeout`, where
/// `Duration::ZERO` means "block forever" and would invert the guarantee.
fn arm(stream: &TcpStream, deadline: Instant) -> Result<(), u16> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(408);
    }
    stream
        .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
        .map_err(|_| 408u16)
}

/// Sign, forward, verify, and render the plain reply.
fn dispatch(
    context: &ServeContext,
    request: &LocalRequest,
) -> (u16, Option<&'static str>, Vec<u8>) {
    let Some(route_id) = route_for(&request.path, context.default_route.as_deref()) else {
        return (
            404,
            None,
            local_error(&Value::Null, "no route for this path").into(),
        );
    };
    let plain: Value = match serde_json::from_slice(&request.body) {
        Ok(plain) => plain,
        Err(_) => {
            return (
                400,
                None,
                local_error(&Value::Null, "malformed JSON-RPC").into(),
            )
        }
    };
    // The id belongs to the LOCAL caller's outstanding call; it is echoed on an error
    // path so a client can match a failure to the request that caused it.
    let id = plain.get("id").cloned().unwrap_or(Value::Null);

    let now = (context.clock)();
    let params = CallParams {
        nonce: (context.nonce)(),
        created: now,
        expires: now + context.request_lifetime_secs,
        now_unix: now,
    };

    match context.proxy.handle(&route_id, &plain, &params) {
        Ok(response) => {
            let kind = match &response.kind {
                ResponseKind::Success => "success",
                ResponseKind::CallFailed { .. } => "call-failed",
                ResponseKind::InputRequired { .. } => "input-required",
                ResponseKind::AcceptedNotification => "accepted-notification",
                ResponseKind::VerifiedRejection { .. } => "verified-rejection",
            };
            // A notification has no reply, and answering it with a JSON body would
            // invent a result the local client never asked for. The 202 says what the
            // verified acknowledgement says and no more: the enforcement boundary
            // accepted the message. It does NOT say the action completed.
            if matches!(response.kind, ResponseKind::AcceptedNotification) {
                return (202, Some(kind), Vec::new());
            }
            let body = serde_json::to_vec(&response.plain_response)
                .unwrap_or_else(|_| local_error(&id, "unserializable reply").into());
            (200, Some(kind), body)
        }
        // An UNVERIFIABLE response is not a server verdict — the channel is compromised
        // or misconfigured — so it is reported as a gateway failure, never as a result.
        Err(error) => {
            let detail = match &error {
                ProxyError::UnknownRoute(_) => "unknown route",
                ProxyError::MalformedRequest => "malformed request",
                ProxyError::Transport(_) => "remote leg unavailable",
                ProxyError::FailedClosed(_) => "response failed verification",
            };
            let mut body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE,
                    "message": detail,
                },
            });
            // The frozen `mcp-re.*` reason, when there is one. The local client is
            // inside the trust boundary, so naming why verification failed helps an
            // operator and tells an attacker on the far side nothing it did not choose.
            if let Some(wire_code) = error.wire_code() {
                body["error"]["data"] = json!({ "mcp_re_error": { "wire_code": wire_code } });
            }
            let status = match &error {
                ProxyError::UnknownRoute(_) => 404,
                // Raised entirely locally, before anything is signed or sent, so it is
                // a caller error and not a verdict on the remote leg. Reporting it as
                // 502 points an operator at TLS material and trust anchors for a
                // malformed local request, and makes "502 means the reply could not be
                // verified" untrue of the one status that carries that meaning.
                ProxyError::MalformedRequest => 400,
                ProxyError::Transport(_) | ProxyError::FailedClosed(_) => 502,
            };
            (
                status,
                None,
                serde_json::to_vec(&body).expect("error body serializes"),
            )
        }
    }
}

/// `/route/<id>` names a route; anything else falls to the configured default.
fn route_for(path: &str, default_route: Option<&str>) -> Option<String> {
    let path = path.split('?').next().unwrap_or(path);
    if let Some(id) = path.strip_prefix("/route/") {
        if !id.is_empty() && !id.contains('/') {
            return Some(id.to_owned());
        }
        return None;
    }
    default_route.map(str::to_owned)
}

fn local_error(id: &Value, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": mcp_re_core::MCP_RE_JSON_RPC_ERROR_CODE, "message": message },
    })
    .to_string()
}

/// Read one request: head to CRLFCRLF, then exactly `Content-Length` body bytes.
///
/// Returns the HTTP status to answer with on failure. Every refusal is a refusal —
/// there is no lenient path that guesses at framing.
fn read_request(stream: &mut TcpStream, deadline: Instant) -> Result<LocalRequest, u16> {
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
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(408),
        }
    };
    // A terminator found beyond the bound is still an over-long head; the loop test
    // above only runs while one has not been found yet.
    if head_end > MAX_HEAD_BYTES {
        return Err(431);
    }
    // Bytes past the terminator are the start of this request's body — the chunked
    // read cannot have run into another message, because this socket serves exactly
    // one exchange per connection and never parses a second request from it.
    let mut body = buffer.split_off(head_end);
    let head = std::str::from_utf8(&buffer).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(400u16)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(400u16)?;
    let path = parts.next().ok_or(400u16)?.to_owned();
    if !method.eq_ignore_ascii_case("POST") {
        return Err(405);
    }

    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            // A repeated Content-Length is a request-smuggling primitive, not a
            // formatting quirk: two lengths let a reader and a writer disagree about
            // where the message ends.
            if content_length.is_some() {
                return Err(400);
            }
            content_length = Some(value.parse::<usize>().map_err(|_| 400u16)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(411);
        }
    }
    let length = content_length.ok_or(411u16)?;
    if length > MAX_BODY_BYTES {
        return Err(413);
    }
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
        match stream.read(&mut body[filled..]) {
            Ok(0) => return Err(400),
            Ok(n) => filled += n,
            Err(_) => return Err(408),
        }
    }
    Ok(LocalRequest { path, body })
}

/// Index just past the CRLFCRLF that ends the head, if the buffer holds one.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

fn write_response(
    stream: &mut impl Write,
    status: u16,
    kind: Option<&str>,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
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

/// Bind the local listener, refusing a non-loopback address unless declared.
///
/// The refusal lives HERE, at the seam that opens the socket, and not only in
/// [`crate::config::ClientConfig::validate`]. Every field of [`LocalConfig`] is public
/// and the type derives `Deserialize`, so a config can be built, deserialized or
/// mutated without ever passing the validator — and this one boolean is the whole
/// distance between the network and a socket that signs under this client's identity
/// on every configured route. A guard that depends on call ordering is a convention;
/// a guard at the chokepoint is an invariant.
///
/// An IPv4-mapped address such as `::ffff:127.0.0.1` reports `is_loopback() == false`
/// and is therefore refused. That is the fail-closed direction: the check never admits
/// an address that is not loopback, and an operator who wants that address can spell it
/// `127.0.0.1`.
pub fn bind(local: &LocalConfig) -> std::io::Result<TcpListener> {
    if !local.allow_non_loopback && !local.bind.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "local.bind {} is not a loopback address. The local leg is \
                 unauthenticated, so binding it off-host offers this client's signing \
                 key as a service to the network. Set local.allow_non_loopback if that \
                 is genuinely intended.",
                local.bind
            ),
        ));
    }
    TcpListener::bind(local.bind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(bind: &str, allow_non_loopback: bool) -> LocalConfig {
        LocalConfig {
            bind: bind.parse().expect("addr"),
            allow_non_loopback,
            request_lifetime_secs: 60,
            default_route: None,
            max_in_flight: 8,
        }
    }

    /// A connected pair, so the framing tests drive a real socket rather than a cursor
    /// that cannot reproduce a partial read.
    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _peer) = listener.accept().expect("accept");
        (client, server)
    }

    /// The guard must be what refuses, at the seam that opens the socket — not a
    /// validator the caller may skip.
    ///
    /// TEST-NET-1 is never assigned to a local interface, so admitting it fails in the
    /// OS with a different error kind. That is how this distinguishes "the guard
    /// refused" from "the bind failed", without opening a socket on every interface.
    #[test]
    fn bind_refuses_a_non_loopback_address_unless_it_is_declared() {
        let refused = bind(&local("192.0.2.1:0", false)).expect_err("the guard must refuse");
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            refused.to_string().contains("allow_non_loopback"),
            "the refusal must name the opt-in that exists: {refused}"
        );
        let admitted = bind(&local("192.0.2.1:0", true)).expect_err("no such local address");
        assert_ne!(
            admitted.kind(),
            std::io::ErrorKind::InvalidInput,
            "with the opt-in declared the guard must not be what refuses: {admitted}"
        );
        bind(&local("127.0.0.1:0", false)).expect("loopback binds without any opt-in");
    }

    /// The slot is released by a destructor, so an unwinding worker returns it.
    ///
    /// A trailing `fetch_sub` is skipped on panic, and the capacity is then gone for the
    /// process lifetime — the listener answers 503 forever with nothing running.
    #[test]
    fn a_panicking_worker_returns_its_in_flight_slot() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        in_flight.fetch_add(1, Ordering::AcqRel);
        let slot = Slot(Arc::clone(&in_flight));
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let handle = std::thread::spawn(move || {
            let _slot = slot;
            panic!("a worker panicked mid-exchange");
        });
        assert!(handle.join().is_err(), "the worker must have panicked");
        std::panic::set_hook(previous);
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            0,
            "a leaked slot lowers max_in_flight for the process lifetime"
        );
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
                .write_all(b"POST /route/r1 HTTP/1.1\r\nContent-Len")
                .expect("first chunk");
            std::thread::sleep(Duration::from_millis(20));
            client
                .write_all(b"gth: 11\r\n\r\n{\"ok\":true}")
                .expect("second chunk");
            std::thread::sleep(Duration::from_millis(50));
        });
        let request = read_request(&mut server, Instant::now() + Duration::from_secs(5))
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
        let status = read_request(&mut server, Instant::now() + Duration::from_millis(120))
            .expect_err("the deadline must fire");
        assert_eq!(status, 408);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the read returned after {:?}; the deadline did not bound it",
            started.elapsed()
        );
        let _ = writer.join();
    }

    #[test]
    fn a_path_names_its_route() {
        assert_eq!(route_for("/route/r1", None).as_deref(), Some("r1"));
        assert_eq!(route_for("/route/r1?x=1", None).as_deref(), Some("r1"));
    }

    /// A nested path is not a route id. Accepting `/route/a/b` as `a/b` would let the
    /// path shape decide which route's bindings a request is signed under.
    #[test]
    fn a_nested_or_empty_path_names_no_route() {
        assert_eq!(route_for("/route/a/b", Some("d")), None);
        assert_eq!(route_for("/route/", Some("d")), None);
    }

    #[test]
    fn any_other_path_falls_to_the_default_route_only_when_one_is_configured() {
        assert_eq!(route_for("/mcp", Some("d")).as_deref(), Some("d"));
        assert_eq!(route_for("/mcp", None), None);
    }

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
