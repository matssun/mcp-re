// SPDX-License-Identifier: Apache-2.0
//! Taking the next connection off the listener, and what an accept error costs the loop.

use std::io::ErrorKind;
use std::time::Duration;

/// The bounded wait after an accept error that is not one connection's. No longer than the
/// serve loop's accept poll interval, so a shutdown is still observed within one interval.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// How long the loop waits before the next `accept` after `error`. `None` only for a failure
/// that belonged to one peer. Resource exhaustion (EMFILE, ENFILE, ENOBUFS) persists until
/// something else frees capacity and `accept` returns it immediately, so an immediate retry
/// spins the core; an unlisted kind backs off because misclassifying a rare per-connection
/// error costs one interval, while misclassifying a persistent one costs the core.
fn backoff_after(error: &std::io::Error) -> Option<Duration> {
    match error.kind() {
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused => {
            None
        }
        _ => Some(ACCEPT_ERROR_BACKOFF),
    }
}

/// Wait out what `error` costs the accept loop before it calls `accept` again.
pub(super) async fn after_error(error: &std::io::Error) {
    if let Some(wait) = backoff_after(error) {
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connections_own_failure_is_retried_at_once() {
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionRefused,
        ] {
            assert_eq!(backoff_after(&std::io::Error::from(kind)), None);
        }
    }

    #[test]
    fn a_persistent_accept_error_waits_before_the_next_accept() {
        // EMFILE is 24 and ENFILE is 23 on both Linux and macOS.
        for errno in [24, 23] {
            assert_eq!(
                backoff_after(&std::io::Error::from_raw_os_error(errno)),
                Some(ACCEPT_ERROR_BACKOFF)
            );
        }
    }
}
