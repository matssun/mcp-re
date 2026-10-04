// SPDX-License-Identifier: Apache-2.0
//! One accepted connection, as the drain sees it.
//!
//! The count the graceful drain waits on and the signal it waits with, held by the thing they
//! are about: a connection. [`OpenConnection::accepted`] is the only increment and `Drop` the
//! only decrement, so a connection cannot be served without being counted, nor counted after
//! it has finished — and it is taken at accept, before the TLS handshake, so a peer still
//! handshaking when the drain begins is waited for rather than forgotten.
//!
//! What the drain needs from the count is that it falls to zero only when every reply a
//! connection started has been written. That holds because the connection task, and with it
//! this value, lives until hyper has finished the connection, which is after the last
//! response is flushed.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::sync::watch;

use super::core_admission::CoreAdmission;

/// A connection this core has accepted and not yet finished with.
pub(super) struct OpenConnection {
    connections: Arc<AtomicUsize>,
    drain: watch::Receiver<bool>,
}

impl OpenConnection {
    /// Count one accepted connection, and subscribe it to the drain signal.
    pub(super) fn accepted(admission: &CoreAdmission) -> Self {
        admission.connections.fetch_add(1, Ordering::AcqRel);
        OpenConnection {
            connections: Arc::clone(&admission.connections),
            drain: admission.drain_signal.subscribe(),
        }
    }

    /// Resolves once the drain has begun — immediately, for a connection accepted after it.
    /// A signal whose sender is gone means `serve` has returned, which is the drain too.
    pub(super) async fn draining(&mut self) {
        let _ = self.drain.wait_for(|draining| *draining).await;
    }
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.connections.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ServerOptions;

    fn window() -> crate::config_state::ClientCredentialWindow {
        crate::config_state::ClientCredentialWindow::new(
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(300),
        )
        .expect("a legal credential window")
    }

    fn admission() -> CoreAdmission {
        let options = ServerOptions::new(window());
        let pool = crate::async_fleet::CorePool::for_core(
            crate::async_fleet::ShardDepth::stated(2),
            &options,
        )
        .expect("an exported key admits every depth");
        CoreAdmission::for_core(&options, pool.handshake_bound())
    }

    /// A connection is counted from accept to drop, and only then.
    #[test]
    fn a_connection_is_counted_from_accept_until_it_ends() {
        let admission = admission();
        assert_eq!(admission.connections.load(Ordering::Acquire), 0);
        let first = OpenConnection::accepted(&admission);
        let second = OpenConnection::accepted(&admission);
        assert_eq!(admission.connections.load(Ordering::Acquire), 2);
        drop(first);
        assert_eq!(admission.connections.load(Ordering::Acquire), 1);
        drop(second);
        assert_eq!(admission.connections.load(Ordering::Acquire), 0);
    }

    /// The drain signal reaches a connection that was already open, and one accepted after
    /// it — a peer still in its handshake when the drain began must not miss it.
    #[tokio::test]
    async fn the_drain_signal_reaches_a_connection_accepted_before_or_after_it() {
        let admission = admission();
        let mut early = OpenConnection::accepted(&admission);
        tokio::time::timeout(std::time::Duration::from_millis(50), early.draining())
            .await
            .expect_err("no drain has begun, so the connection is not asked to close");

        admission.drain(std::time::Duration::from_millis(1)).await;

        tokio::time::timeout(std::time::Duration::from_secs(1), early.draining())
            .await
            .expect("an open connection sees the drain");
        let mut late = OpenConnection::accepted(&admission);
        tokio::time::timeout(std::time::Duration::from_secs(1), late.draining())
            .await
            .expect("a connection accepted after the drain began sees it at once");
    }

    /// The drain waits for a counted connection and returns when it ends.
    #[tokio::test]
    async fn the_drain_waits_for_an_open_connection_then_returns() {
        let admission = admission();
        let open = OpenConnection::accepted(&admission);
        let waiting = admission.clone();
        let drain = tokio::spawn(async move {
            waiting.drain(std::time::Duration::from_secs(10)).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!drain.is_finished(), "an open connection holds the drain");
        drop(open);
        tokio::time::timeout(std::time::Duration::from_secs(2), drain)
            .await
            .expect("the drain returns once the connection ends")
            .expect("drain task");
    }
}
