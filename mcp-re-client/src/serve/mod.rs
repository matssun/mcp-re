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
//!
//! ## Loopback is not the whole boundary
//!
//! "Processes on this host" does not describe a browser. A web page the user visits can
//! issue cross-origin `POST`s to `127.0.0.1`, and a page served from a name that
//! resolves to `127.0.0.1` (DNS rebinding) is treated by the browser as SAME-origin, so
//! it does not even send an `Origin`. Either way the sidecar would sign and send the
//! attacker's tool call under this client's identity, mTLS certificate and authorization
//! bindings, and the remote server would see perfectly valid RFC 9421 evidence. That the
//! page cannot read the reply is no comfort: the side effect is the payload.
//!
//! Three checks close it, and they are checks a local MCP client passes without knowing
//! they exist:
//!
//! * an `Origin` header at all is refused — no MCP client sends one, and a browser
//!   always does on a cross-origin request;
//! * `Host` must name loopback, which is what a rebound name cannot do;
//! * `Content-Type` must be JSON, which a CORS-"simple" `POST` cannot set without a
//!   preflight the browser will not get an answer to.

use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use mcp_re_client_proxy::ClientProxy;

use crate::config::LocalConfig;

/// One wall-clock bound per phase, not a set of per-syscall timers.
mod deadlines;

/// Closing so the caller sees what it was told.
mod close;

/// What a browser cannot do, stated as two predicates.
mod guards;

/// Reading one local request, and refusing everything this listener does not parse.
mod request;

/// What the head says, and the ORDER the refusals run in.
mod head_fields;

/// Writing the reply the local client reads.
mod response;

/// One local exchange, from the accepted socket to the plain reply.
mod exchange;

/// What a verified outcome looks like to an ordinary MCP client.
mod render;

use deadlines::DeadlineWriter;
use exchange::handle_connection;
use response::write_response;

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
/// How long one local exchange may take to WRITE, end to end.
///
/// A per-syscall write timeout bounds nothing for the same reason a per-syscall read
/// timeout does not: `write_all` loops over `write`, and every byte the peer accepts
/// starts a fresh window. A local peer that opens a one-byte receive window holds a
/// worker thread and an in-flight slot for as long as it cares to, and `max_in_flight`
/// of them take the sidecar out of service.
const WRITE_DEADLINE: Duration = Duration::from_secs(30);
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
    /// Whether a request may name a `Host` other than loopback.
    ///
    /// False on every ordinary deployment: the `Host` check is what a DNS-rebound name
    /// resolving to `127.0.0.1` cannot pass, and it is the half of the browser guard
    /// that `Origin` does not cover (a rebound page is SAME-origin, so it sends none).
    /// Set only where the operator has already declared `local.allow_non_loopback`,
    /// which is the point at which they have taken the local leg off loopback anyway.
    pub allow_any_host: bool,
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
                    let _ = stream.set_read_timeout(Some(REFUSAL_TIMEOUT));
                    let _ = write_response(
                        &mut DeadlineWriter::new(&stream, Instant::now() + REFUSAL_TIMEOUT),
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
}
