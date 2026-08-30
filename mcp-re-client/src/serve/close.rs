// SPDX-License-Identifier: Apache-2.0
//! Closing so the caller sees what it was told.
//!
//! What turns `close()` into an RST rather than a FIN is bytes still sitting in the receive
//! queue. A refusal happens BEFORE the body is consumed, so closing on top of those bytes
//! makes every *405 method not allowed* arrive at the caller as an unexplained broken pipe
//! instead of the refusal it was given.
//!
//! It costs more on the success path: what a reset discards there is a VERIFIED reply to a
//! call the remote server has already executed, and a client that retries a reset re-runs
//! the side effect.
//!
//! The two drains are therefore not the same operation. The refusal path may WAIT, bounded
//! in both bytes and wall clock — the byte bound alone is not enough, since one byte per
//! read against a per-read timeout is still a stall. The success path may NOT: the caller
//! is by then reading our response rather than writing, so a blocking drain would add its
//! full bound to every single exchange, and the bytes that matter are exactly the ones a
//! non-blocking drain takes.

use std::io::Read;
use std::net::TcpStream;
use std::time::Instant;

use super::deadlines::arm;
use super::DRAIN_DEADLINE;
use super::MAX_HEAD_BYTES;

/// Read and discard whatever the caller had already sent, so the close is a clean FIN.
///
/// Bounded in both bytes and wall clock: a caller that keeps writing after the exchange
/// gets the connection dropped rather than a worker held open on it. The byte bound
/// alone is not enough — one byte per read against a per-read timeout is still a stall.
pub(super) fn drain(stream: &mut TcpStream) {
    // Class R: the deadline is what bounds this drain, so one that cannot be computed is
    // no bound at all and nothing is drained.
    let Some(deadline) = Instant::now().checked_add(DRAIN_DEADLINE) else {
        return;
    };
    let mut scratch = [0u8; 1024];
    let mut drained = 0usize;
    while drained < MAX_HEAD_BYTES {
        if arm(stream, deadline).is_err() {
            break;
        }
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            // Saturating: compared against `MAX_HEAD_BYTES` and nothing else, so the
            // ceiling ends the loop where wrapping would restart the budget from zero.
            Ok(n) => drained = drained.saturating_add(n),
        }
    }
}

/// Consume what the caller has already sent, without waiting for more.
///
/// Closing a socket that still holds unread bytes makes the kernel send RST instead of
/// FIN, and the peer then loses whatever it had not yet read. Only bytes already
/// queued can cause that, so this takes those and returns — it never blocks, which is
/// what makes it safe to run on the success path of every exchange.
pub(super) fn drain_pending(stream: &mut TcpStream) {
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let mut scratch = [0u8; 1024];
    let mut drained = 0usize;
    while drained < MAX_HEAD_BYTES {
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained = drained.saturating_add(n),
        }
    }
    let _ = stream.set_nonblocking(false);
}
