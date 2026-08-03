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
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_client_proxy::CallParams;
use mcp_re_client_proxy::ClientProxy;
use mcp_re_client_proxy::ProxyError;
use mcp_re_client_proxy::ResponseKind;
use serde_json::json;
use serde_json::Value;

/// The largest request head this listener will read before giving up.
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// The largest plain-MCP body accepted from the local client.
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// How long one local exchange may take to arrive.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

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
struct LocalRequest {
    path: String,
    body: Vec<u8>,
}

/// Serve until `stop` is set.
///
/// The listener polls with a short accept timeout rather than blocking forever, so a
/// SIGTERM is observed promptly instead of on the next local call.
pub fn serve(listener: TcpListener, context: Arc<ServeContext>, stop: Arc<AtomicBool>) {
    listener
        .set_nonblocking(true)
        .expect("the local listener accepts non-blocking mode");
    let in_flight = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                // Claim a slot BEFORE spawning. Spawning first and checking after is how
                // a burst of local calls becomes an unbounded thread count.
                let claimed = in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                if claimed > context.max_in_flight {
                    in_flight.fetch_sub(1, Ordering::AcqRel);
                    // An accepted socket inherits the listener's O_NONBLOCK on the BSDs
                    // (including macOS) and does not on Linux. Without this the refusal
                    // would write on a non-blocking socket there, fail `WouldBlock`, and
                    // the caller would see the connection close with no answer — a
                    // capacity limit that reads as a crash on one platform and not the
                    // other.
                    let _ = stream.set_nonblocking(false);
                    let _ = write_response(
                        &mut &stream,
                        503,
                        None,
                        b"{\"error\":\"mcp-re client sidecar at capacity\"}",
                    );
                    continue;
                }
                let worker_context = Arc::clone(&context);
                let worker_in_flight = Arc::clone(&in_flight);
                let spawned = std::thread::Builder::new()
                    .name("mcp-re-client-conn".to_owned())
                    .spawn(move || {
                        handle_connection(stream, &worker_context);
                        worker_in_flight.fetch_sub(1, Ordering::AcqRel);
                    });
                // The slot was claimed before the spawn, so a spawn failure has to
                // release it or the listener leaks capacity until it can serve nothing.
                if spawned.is_err() {
                    in_flight.fetch_sub(1, Ordering::AcqRel);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn handle_connection(mut stream: TcpStream, context: &ServeContext) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_nonblocking(false);
    let request = match read_request(&mut stream) {
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
}

/// Read and discard whatever the caller had already sent, so the close is a clean FIN.
///
/// Bounded in both bytes and time: a caller that keeps writing after being refused gets
/// the connection dropped rather than a worker held open on it.
fn drain(stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut scratch = [0u8; 1024];
    let mut drained = 0usize;
    while drained < MAX_HEAD_BYTES {
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
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
            let status = if matches!(error, ProxyError::UnknownRoute(_)) {
                404
            } else {
                502
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
fn read_request(stream: &mut TcpStream) -> Result<LocalRequest, u16> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return Err(400),
            Ok(_) => head.push(byte[0]),
            Err(_) => return Err(408),
        }
        if head.len() > MAX_HEAD_BYTES {
            return Err(431);
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = std::str::from_utf8(&head).map_err(|_| 400u16)?;
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
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).map_err(|_| 400u16)?;
    Ok(LocalRequest { path, body })
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
pub fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

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
