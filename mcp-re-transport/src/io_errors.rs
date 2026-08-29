// SPDX-License-Identifier: Apache-2.0
//! What one `io::Error` MEANS, which depends on the phase it arrived in.
//!
//! The same `io::Error` reaches this transport from three phases and means three different
//! things to whoever reads the result. A stalled handshake and a rejected server certificate
//! both surface as an IO error during `complete_io`; a peer that is not draining and a
//! socket that failed both surface as one during the write. Collapsing them would tell an
//! operator only *the connection failed*.
//!
//! The rustls-wrapped case is the one that has to be looked for rather than inferred: after
//! the handshake begins, an `io::Error` may CARRY a `rustls::Error` — the server certificate
//! was rejected — and that is a handshake failure however it arrives.

use std::io;

use super::TransportError;

/// Map a handshake-phase IO error: a socket timeout (stalled handshake)
/// surfaces as [`TransportError::Timeout`]; any other IO error here is a server
/// authentication rejection and surfaces as [`TransportError::Handshake`].
pub(super) fn handshake_error(e: io::Error) -> TransportError {
    if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
        TransportError::Timeout(e.to_string())
    } else {
        TransportError::Handshake(e.to_string())
    }
}

/// Classify a request-WRITE-phase IO error (MCPS-093, audit M-6 residual). A
/// socket write timeout (the peer's receive window is full / it is not draining —
/// slow-loris on the write side) surfaces as [`TransportError::Timeout`], exactly
/// as [`handshake_error`] classifies a stalled-handshake timeout. Otherwise it
/// defers to [`io_or_handshake`] (a rustls-wrapped error is a handshake failure;
/// anything else stays `Io`).
pub(super) fn write_error(e: io::Error) -> TransportError {
    if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
        return TransportError::Timeout(e.to_string());
    }
    io_or_handshake(e)
}

/// During/after the handshake an IO error may carry a rustls `Error` (e.g. the
/// server cert was rejected). Classify a rustls-wrapped error as a handshake
/// failure; a plain transport error stays `Io`.
pub(super) fn io_or_handshake(e: io::Error) -> TransportError {
    if e.get_ref()
        .map(|inner| inner.is::<rustls::Error>())
        .unwrap_or(false)
    {
        TransportError::Handshake(e.to_string())
    } else {
        TransportError::Io(e)
    }
}
