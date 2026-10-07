// SPDX-License-Identifier: Apache-2.0
//! Taking the next connection off the listener, and what an accept error costs the loop.

use std::io::ErrorKind;
use tokio::time::Instant;

/// Whether the loop waits before the next `accept` after `error`. `false` only for a failure
/// that belonged to one peer. Resource exhaustion (EMFILE, ENFILE, ENOBUFS) persists until
/// something else frees capacity and `accept` returns it immediately, so an immediate retry
/// spins the core; an unlisted kind backs off because misclassifying a rare per-connection
/// error costs one interval, while misclassifying a persistent one costs the core.
fn backs_off(error: &std::io::Error) -> bool {
    !matches!(
        error.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused
    )
}

/// The end of an accept poll interval starting now. An `Instant` one interval ahead cannot
/// overflow; were it to, the deadline is now and the loop re-checks its shutdown flag at
/// once, the safe direction for a shutdown.
pub(super) fn poll_deadline(interval: std::time::Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(interval).unwrap_or(now)
}

/// Wait out what `error` costs the accept loop before it calls `accept` again.
///
/// The wait ends at `poll_deadline`, the end of the accept poll interval the error arrived
/// in, never one interval after the error: one accept attempt and its backoff together fit
/// inside one interval, so the loop re-checks the shutdown flag at least once per interval
/// whether the listener is idle, accepting or failing. A persistent error still costs the
/// loop a whole interval per attempt, because `accept` returns it at the start of one.
pub(super) async fn after_error(error: &std::io::Error, poll_deadline: Instant) {
    if backs_off(error) {
        tokio::time::sleep_until(poll_deadline).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    #[test]
    fn a_connections_own_failure_is_retried_at_once() {
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionRefused,
        ] {
            assert!(!backs_off(&std::io::Error::from(kind)));
        }
    }

    #[test]
    fn a_persistent_accept_error_waits_before_the_next_accept() {
        // EMFILE is 24 and ENFILE is 23 on both Linux and macOS.
        for errno in [24, 23] {
            assert!(backs_off(&std::io::Error::from_raw_os_error(errno)));
        }
    }

    /// THM-0104: the backoff ends with the poll interval the error arrived in, so an error
    /// late in the interval does not push the next shutdown check a further interval out.
    /// An error at the START of an interval still waits the whole interval.
    #[tokio::test]
    async fn the_backoff_ends_with_the_poll_interval_the_error_arrived_in() {
        let interval = Duration::from_millis(50);
        let emfile = std::io::Error::from_raw_os_error(24);

        let started = Instant::now();
        after_error(&emfile, started + interval).await;
        let waited = started.elapsed();
        assert!(
            waited >= interval,
            "an error at the interval's start waited {waited:?}"
        );

        let late = Instant::now();
        after_error(&emfile, late).await;
        assert!(
            late.elapsed() < interval,
            "an error at the interval's end must not wait another interval: {:?}",
            late.elapsed()
        );
    }
}
