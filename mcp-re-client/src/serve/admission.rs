// SPDX-License-Identifier: Apache-2.0
//! HOW MANY concurrent local exchanges this sidecar admits, and how it refuses the rest.
//!
//! One authority over the bound: the claim, the guard that releases it, and the refusal a
//! caller gets when the claim fails. They are together because each is only correct in
//! terms of the other two — a claim taken after the spawn is not a bound, a release written
//! as a statement is not a release, and a refusal written on the accept thread without a
//! deadline is not a refusal.

use std::net::TcpStream;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use super::deadlines::DeadlineWriter;
use super::response::write_response;

/// How long the sidecar may spend telling a caller it is at capacity.
///
/// A refusal is written on the ACCEPT thread, so it must not be able to block it: a peer
/// advertising a zero receive window and never draining would otherwise stop the listener
/// accepting anything and stop it observing `stop` — one connection denying the sidecar and
/// blocking graceful shutdown, rather than being refused.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(2);

/// One claimed in-flight slot, released on every exit path including an unwind.
///
/// The release has to be a destructor rather than a statement after the call: a worker that
/// panics skips a trailing `fetch_sub`, and that slot is then gone for the process
/// lifetime. After `max_in_flight` such panics the listener answers 503 to every call while
/// the accounting reads full with nothing running — a sticky failure that outlives the
/// transient condition that caused it, recoverable only by restart.
pub(super) struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Claim a slot if the ceiling admits one, BEFORE any worker is spawned.
///
/// Spawning first and checking after is how a burst of local calls becomes an unbounded
/// thread count. The returned guard owns the release from here on, so every path the caller
/// takes returns it — including the `None` case, where the claim is released by dropping
/// the guard this function took.
///
/// Saturating: the observed depth is compared against `ceiling` and nothing else, so the
/// ceiling refuses where wrapping would admit unbounded workers at exactly the moment the
/// ceiling exists to stop them.
pub(super) fn claim(in_flight: &Arc<AtomicUsize>, ceiling: usize) -> Option<Slot> {
    let claimed = in_flight.fetch_add(1, Ordering::AcqRel).saturating_add(1);
    let slot = Slot(Arc::clone(in_flight));
    (claimed <= ceiling).then_some(slot)
}

/// Tell a caller the sidecar is at capacity, without blocking the accept thread.
pub(super) fn refuse(stream: &TcpStream) {
    // An accepted socket inherits the listener's O_NONBLOCK on the BSDs (including macOS)
    // and does not on Linux. Without this the refusal would write on a non-blocking socket
    // there, fail `WouldBlock`, and the caller would see the connection close with no
    // answer — a capacity limit that reads as a crash on one platform and not the other.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(REFUSAL_TIMEOUT));
    let _ = write_response(
        &mut DeadlineWriter::new(stream, refusal_budget()),
        503,
        None,
        b"{\"error\":\"mcp-re client sidecar at capacity\"}",
    );
}

/// Saturating: this bounds how long the sidecar spends TELLING a caller it is at capacity,
/// and the refusal still has to be delivered.
fn refusal_budget() -> Instant {
    Instant::now()
        .checked_add(REFUSAL_TIMEOUT)
        .unwrap_or_else(Instant::now)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ceiling refuses the claim that would exceed it, and every refused claim is
    /// released — otherwise the accounting drifts full with nothing running.
    #[test]
    fn a_refused_claim_is_released() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let first = claim(&in_flight, 1).expect("the first claim is under the ceiling");
        assert_eq!(in_flight.load(Ordering::Acquire), 1);
        assert!(
            claim(&in_flight, 1).is_none(),
            "the second claim exceeds the ceiling"
        );
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            1,
            "a refused claim must not leave its increment behind"
        );
        drop(first);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
    }

    /// A ceiling of zero admits nothing, rather than admitting one.
    #[test]
    fn a_zero_ceiling_admits_nothing() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        assert!(claim(&in_flight, 0).is_none());
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
    }

    /// The slot is released by a destructor, so an unwinding worker returns it.
    ///
    /// A trailing `fetch_sub` is skipped on panic, and the capacity is then gone for the
    /// process lifetime — the listener answers 503 forever with nothing running.
    #[test]
    fn a_panicking_worker_returns_its_in_flight_slot() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let slot = claim(&in_flight, usize::MAX).expect("the claim is under the ceiling");
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
