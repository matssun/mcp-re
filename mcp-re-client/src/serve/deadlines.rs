// SPDX-License-Identifier: Apache-2.0
//! One wall-clock bound per phase, not a set of per-syscall timers.
//!
//! A per-syscall timeout bounds NOTHING on its own, in either direction. `read` re-arms
//! `SO_RCVTIMEO` on every byte delivered, and `write_all` loops over `write`, re-arming
//! `SO_SNDTIMEO` on every byte the peer accepts. A caller dripping one byte per
//! timeout-minus-one therefore holds a worker thread and an in-flight slot for as long as
//! it cares to, and `max_in_flight` such connections take the sidecar out of service
//! without sending a single request.
//!
//! Both constructions here are the same one: shrink the socket''s timeout to the REMAINING
//! budget before every operation, so a set of per-syscall timers becomes one bound on the
//! phase. A zero or elapsed budget is reported as a timeout rather than passed to the
//! socket, where `Duration::ZERO` means *block forever* and would invert the guarantee.

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

/// Arm the socket so the next read cannot outlive `deadline`.
///
/// Shrinking the per-read timeout to the remaining budget before every read is what
/// turns a set of per-syscall timers into one bound on the exchange. A zero or elapsed
/// budget is reported as a timeout rather than passed to `set_read_timeout`, where
/// `Duration::ZERO` means "block forever" and would invert the guarantee.
pub(super) fn arm(stream: &TcpStream, deadline: Instant) -> Result<(), u16> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(408);
    }
    stream
        .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
        .map_err(|_| 408u16)
}

/// A [`Write`] over a [`TcpStream`] that cannot outlive one wall-clock deadline.
///
/// `write_all` loops over `write`, and each successful partial write re-arms a
/// per-syscall `SO_SNDTIMEO`, so a peer accepting one byte per interval extends the
/// total write time without bound. Shrinking the socket's write timeout to the
/// REMAINING budget before every write is what turns that set of per-syscall timers
/// into one bound on the response — the same construction [`arm`] applies to reads,
/// applied to the leg that was left open.
pub(super) struct DeadlineWriter<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl<'a> DeadlineWriter<'a> {
    pub(super) fn new(stream: &'a TcpStream, deadline: Instant) -> Self {
        DeadlineWriter { stream, deadline }
    }

    /// Arm the socket so the next write cannot outlive the deadline. A zero or elapsed
    /// budget is reported as a timeout rather than passed to `set_write_timeout`, where
    /// `Duration::ZERO` means "block forever" and would invert the guarantee.
    fn arm_write(&self) -> std::io::Result<()> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the local write deadline elapsed",
            ));
        }
        self.stream
            .set_write_timeout(Some(remaining.max(Duration::from_millis(1))))
    }
}

impl Write for DeadlineWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm_write()?;
        (&*self.stream).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.arm_write()?;
        (&*self.stream).flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Duration;

    use super::super::response::write_response;

    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral listener");
        let addr = listener.local_addr().expect("bound address");
        let client = TcpStream::connect(addr).expect("client connects");
        let (server, _) = listener.accept().expect("server accepts");
        (client, server)
    }

    /// The write leg is bounded by the exchange's wall clock, not by one syscall.
    ///
    /// `write_all` loops over `write`, so a peer that accepts a trickle re-arms a
    /// per-syscall `SO_SNDTIMEO` on every partial write and holds a worker thread and an
    /// in-flight slot indefinitely. Here the peer never reads at all: the socket buffers
    /// fill, the write blocks, and the deadline — not the 30s per-syscall value — is
    /// what has to end it.
    #[test]
    fn a_peer_that_never_reads_hits_the_write_deadline() {
        let (client, server) = socket_pair();
        // Nothing ever reads from `client`; keeping it alive is what makes the peer
        // "connected but not draining" rather than "gone".
        let body = vec![b'x'; 8 * 1024 * 1024];
        let started = Instant::now();
        let outcome = write_response(
            &mut DeadlineWriter::new(&server, Instant::now() + Duration::from_millis(150)),
            200,
            None,
            &body,
        );
        assert!(
            outcome.is_err(),
            "a peer that never reads must not hold the worker",
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the write returned after {:?}; the deadline did not bound it",
            started.elapsed(),
        );
        drop(client);
    }
}
