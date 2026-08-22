// SPDX-License-Identifier: Apache-2.0
//! The harness's aggregate read-deadline wrapper — PRIVATE to the harness subtree.
//!
//! A slow-loris control over the harness's own blocking reads. It decides nothing about
//! the peer's identity or trust; it bounds how long one connection may spend being read.

use std::io;
use std::io::Read;
use std::io::Write;
use std::time::Duration;

use crate::tls::ServerLimits;

/// A `Read`/`Write` wrapper that enforces an AGGREGATE wall-clock deadline across
/// every READ on the inner stream — the server-side mirror of mcp-re-transport's
/// `DeadlineStream` (MCPS-094, #4081) and bounded response read (MCPS-093).
///
/// The per-socket `read_timeout` (`apply_socket_timeouts`) bounds each INDIVIDUAL
/// read, but a malicious peer trickling one byte just under that timeout resets
/// the per-read inactivity timer on every byte and can extend a single
/// connection's total read time without bound — driving the TLS handshake
/// (reading completes `complete_io`) and the HTTP header/body read forever
/// (slow-loris below the per-read threshold), holding a serve thread. Routing all
/// server-side reads through this wrapper caps the TOTAL read wall-clock: once
/// `deadline` passes, the next read fails closed with `io::ErrorKind::TimedOut`
/// and the connection is dropped. `None` deadline (the `request_deadline` knob
/// disabled) preserves the inner stream's own (per-read) semantics.
///
/// Writes delegate straight to the inner socket (bounded by the per-socket
/// `write_timeout`): the aggregate deadline governs the inbound read phase only,
/// so a legitimate slow response write is never spuriously dropped — symmetric
/// with mcp-re-transport, where `DeadlineStream` wraps only the handshake read and
/// the bare socket is reclaimed for the request write.
pub(super) struct DeadlineStream<S> {
    inner: S,
    deadline: Option<std::time::Instant>,
    timeout: Option<Duration>,
}

impl<S> DeadlineStream<S> {
    /// Build the wrapper from the configured limits: the aggregate deadline is
    /// `now + request_deadline` (or `None`, disabling the bound). `request_deadline`
    /// is retained only for the error message.
    ///
    /// FAIL CLOSED: if a deadline was requested but `now + t` overflows `Instant`,
    /// we MUST NOT silently drop the bound — that would disable the slow-loris
    /// defense. The CLI caps `--request-deadline-secs` at parse time
    /// (`cli::parse_timeout`) so this overflow is practically unreachable, but as
    /// defense-in-depth we saturate to the current instant (deadline already
    /// elapsed → next read fails closed) rather than disable the control. The
    /// `None` deadline is reserved exclusively for "no deadline was requested".
    pub(super) fn new(inner: S, limits: &ServerLimits) -> Self {
        let now = std::time::Instant::now();
        let deadline = limits
            .request_deadline
            .map(|t| now.checked_add(t).unwrap_or(now));
        DeadlineStream {
            inner,
            deadline,
            timeout: limits.request_deadline,
        }
    }

    /// Fail closed if the aggregate read deadline has elapsed BEFORE delegating the
    /// read.
    fn check_deadline(&self) -> io::Result<()> {
        if let Some(deadline) = self.deadline {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "aggregate request read deadline exceeded {:?} (slow-loris trickle)",
                        self.timeout
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl<S: Read> Read for DeadlineStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check_deadline()?;
        self.inner.read(buf)
    }
}

impl<S: Write> Write for DeadlineStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod aggregate_deadline_tests {
    //! Issue #100: the server read path's AGGREGATE wall-clock deadline
    //! (`DeadlineStream`) must fail closed when a peer trickles bytes just under
    //! the per-read timeout but past the aggregate budget (slow-loris), the
    //! server-side mirror of mcp-re-transport's `DeadlineStream` (MCPS-094/093).
    //!
    //! Hermetic and fast: a `TricklingReader` always makes per-read progress (so
    //! the per-socket `read_timeout`/zero-byte-stall guard NEVER fires) but never
    //! completes the header block, so only the aggregate deadline can stop it.

    use std::io;
    use std::io::Read;
    use std::time::Duration;
    use std::time::Instant;

    use super::DeadlineStream;
    use crate::tls::ServerLimits;

    /// A reader that always returns exactly one byte per `read` (never 0, never an
    /// error) and never emits the `\r\n\r\n` header terminator — modelling a peer
    /// that keeps the per-read inactivity timer alive forever while never finishing
    /// the request. Optionally sleeps per read to model a real trickle rate without
    /// making the test slow.
    struct TricklingReader {
        per_read_sleep: Duration,
    }

    impl Read for TricklingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // A zero-length buffer is legal per the `Read` contract; return
            // `Ok(0)` before touching `buf[0]` so we never panic.
            if buf.is_empty() {
                return Ok(0);
            }
            if !self.per_read_sleep.is_zero() {
                std::thread::sleep(self.per_read_sleep);
            }
            // A non-terminator byte: progress is always made, so a per-read-only
            // guard can never cut this off.
            buf[0] = b'A';
            Ok(1)
        }
    }

    #[test]
    fn aggregate_deadline_fires_on_sub_per_read_trickle() {
        // Small aggregate budget; the per-read sleep is well UNDER it, so each
        // individual read "succeeds" and only the aggregate deadline can stop the
        // header read. Without the wrapper, `read_http_request` would loop forever.
        let limits = ServerLimits {
            // Per-read timeout disabled to prove the AGGREGATE bound (not the
            // per-socket timeout) is what fails closed.
            read_timeout: None,
            request_deadline: Some(Duration::from_millis(150)),
            ..ServerLimits::default()
        };
        let mut stream = DeadlineStream::new(
            TricklingReader {
                per_read_sleep: Duration::from_millis(5),
            },
            &limits,
        );

        let start = Instant::now();
        let result = crate::blocking_mtls_harness::http1::read_http_request(&mut stream, &limits);
        let elapsed = start.elapsed();

        let err = match result {
            Ok(_) => panic!("a sub-per-read trickle past the aggregate deadline must fail closed"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::TimedOut,
            "the aggregate read deadline must surface as TimedOut (fail closed), got: {err}"
        );
        // It must be cut off PROMPTLY after the deadline, not hang. Generous upper
        // bound to stay non-flaky on a loaded CI host.
        assert!(
            elapsed < Duration::from_secs(5),
            "the connection must be dropped promptly at the aggregate deadline, took {elapsed:?}"
        );
    }

    #[test]
    fn disabled_deadline_does_not_cut_off_a_completing_read() {
        // `request_deadline: None` disables the aggregate bound; a reader that DOES
        // complete the request must still parse cleanly (the wrapper is transparent
        // when the deadline is off).
        let limits = ServerLimits {
            request_deadline: None,
            ..ServerLimits::default()
        };
        let body = b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec();
        let mut stream = DeadlineStream::new(io::Cursor::new(body), &limits);
        let req = crate::blocking_mtls_harness::http1::read_http_request(&mut stream, &limits)
            .expect("a complete request must parse when the aggregate deadline is disabled");
        assert!(req.body.is_empty());
    }
}
