// SPDX-License-Identifier: Apache-2.0
//! How long a round trip may take, and how much it may read.
//!
//! The symmetric counterpart of the proxy's `ServerLimits`. Every bound fails closed: a
//! connect, handshake or read that stalls past its timeout, or a response over the size
//! cap, surfaces as a [`TransportError`] rather than blocking the thread or allocating
//! without bound.
//!
//! **A per-socket timeout is not an aggregate one**, and the difference is the whole reason
//! [`DeadlineStream`] exists. `set_read_timeout` bounds each INDIVIDUAL read, so a peer
//! trickling one byte just under it resets the inactivity timer on every byte and can
//! extend a phase — the TLS handshake, or the response read — without bound. That is
//! slow-loris below the per-read threshold, and it evades the zero-byte-stall guard
//! entirely. Both phases are therefore driven through a wall-clock deadline as well.

use std::io;
use std::io::Read;
use std::io::Write;
use std::time::Duration;

use super::io_errors::io_or_handshake;
use super::TransportError;

/// Connection resource limits for the client — the symmetric counterpart of the
/// proxy's `ServerLimits`. Every bound fails closed: a connect/handshake/read
/// that stalls past its timeout, or a response that exceeds the size cap, is
/// surfaced as a [`TransportError`] rather than blocking the thread or
/// allocating without bound.
///
/// Defaults mirror the proxy server: 30s connect/read/write timeouts and a
/// 16 MiB response ceiling. A `None` timeout disables that one bound.
#[derive(Debug, Clone)]
pub struct ClientLimits {
    /// Maximum time to establish the TCP connection. `None` uses a plain
    /// (OS-default) blocking connect.
    pub connect_timeout: Option<Duration>,
    /// Per-socket read timeout. Covers a stalled TLS handshake AND slow-loris
    /// response trickling, since reading drives the handshake. `None` disables.
    pub read_timeout: Option<Duration>,
    /// Per-socket write timeout. `None` disables.
    pub write_timeout: Option<Duration>,
    /// Maximum response bytes read before failing closed with
    /// [`TransportError::ResponseTooLarge`]. Mirrors the proxy's
    /// `max_body_bytes`.
    pub max_response_bytes: usize,
}

impl Default for ClientLimits {
    fn default() -> Self {
        ClientLimits {
            connect_timeout: Some(Duration::from_secs(30)),
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            max_response_bytes: 16 * 1024 * 1024,
        }
    }
}

/// An `io` wrapper that enforces an AGGREGATE wall-clock deadline across many
/// reads/writes on the inner stream (MCPS-094, #4081, audit M-28/M-30).
///
/// The per-socket read timeout (`set_read_timeout`) bounds each INDIVIDUAL read,
/// but a peer trickling one byte just under that timeout resets the per-read
/// inactivity timer on every byte and can extend a phase (here, the TLS
/// handshake) without bound. Driving `complete_io` through this wrapper caps the
/// TOTAL time: once `deadline` passes, the next read/write fails closed with an
/// `io::ErrorKind::TimedOut` error — which `handshake_error` classifies as
/// [`TransportError::Timeout`]. `None` deadline disables the aggregate bound,
/// preserving the inner stream's own (per-read) semantics. `timeout` is the
/// configured value, surfaced only in the error message.
pub(super) struct DeadlineStream<S> {
    inner: S,
    deadline: Option<std::time::Instant>,
    timeout: Option<Duration>,
}

impl<S> DeadlineStream<S> {
    pub(super) fn new(
        inner: S,
        deadline: Option<std::time::Instant>,
        timeout: Option<Duration>,
    ) -> Self {
        DeadlineStream {
            inner,
            deadline,
            timeout,
        }
    }

    pub(super) fn into_inner(self) -> S {
        self.inner
    }

    /// Fail closed if the aggregate deadline has elapsed BEFORE delegating the IO.
    fn check_deadline(&self) -> io::Result<()> {
        if let Some(deadline) = self.deadline {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "aggregate handshake deadline exceeded {:?} (slow-loris trickle)",
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
        self.check_deadline()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The bytes of one read that may join the response, or the refusal that stops it.
///
/// Class B and class R together. `Read::read` PROMISES `n <= chunk.len()`; `reader` is a
/// type parameter, so a reader that over-reports would widen a body past `max_bytes`
/// through the very accounting meant to bound it — the promise is checked, not trusted.
/// And a total that cannot be represented is past every ceiling, so it takes the same
/// refusal as one that merely exceeds this response's.
fn admit_chunk(
    chunk: &[u8],
    n: usize,
    so_far: usize,
    max_bytes: usize,
) -> Result<&[u8], TransportError> {
    let filled = chunk.get(..n).ok_or_else(|| {
        TransportError::MalformedResponse(
            "reader reported more bytes than it was given room for".to_string(),
        )
    })?;
    if so_far.checked_add(n).is_none_or(|total| total > max_bytes) {
        return Err(TransportError::ResponseTooLarge { limit: max_bytes });
    }
    Ok(filled)
}

/// Read the response in bounded chunks, failing closed at `max_bytes`.
///
/// Replaces an unbounded `read_to_end`: a verified-but-hostile or buggy proxy
/// that floods the response can no longer drive the client to OOM. A peer that
/// closes without `close_notify` surfaces as `UnexpectedEof` and is tolerated
/// (matches the proxy's framing); a read that times out (slow-loris) surfaces as
/// [`TransportError::Timeout`].
///
/// MCPS-093: in addition to the per-socket read timeout (which bounds each
/// individual `read`), an optional `aggregate_deadline` (`Instant`) caps the TOTAL
/// time spent reading the response — mirroring the proxy's persistent-inner reader
/// (MCPS-074). A peer trickling bytes just under the per-read timeout cannot
/// extend total read time without bound: once the aggregate deadline passes, the
/// next iteration fails closed with [`TransportError::Timeout`]. `aggregate_timeout`
/// is the configured value, used only for the error message.
pub(super) fn read_response_bounded<R: Read>(
    reader: &mut R,
    max_bytes: usize,
    aggregate_deadline: Option<std::time::Instant>,
    aggregate_timeout: Option<Duration>,
) -> Result<Vec<u8>, TransportError> {
    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // Enforce the aggregate read deadline BEFORE each read: a peer trickling a
        // byte just under the per-read timeout indefinitely is cut off here once
        // the total budget elapses, regardless of per-read progress.
        if let Some(deadline) = aggregate_deadline {
            if std::time::Instant::now() >= deadline {
                return Err(TransportError::Timeout(format!(
                    "aggregate response read exceeded {aggregate_timeout:?} (slow-loris trickle)"
                )));
            }
        }
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(admit_chunk(&chunk, n, response.len(), max_bytes)?),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(TransportError::Timeout(e.to_string()));
            }
            Err(e) => return Err(io_or_handshake(e)),
        }
    }
    Ok(response)
}
