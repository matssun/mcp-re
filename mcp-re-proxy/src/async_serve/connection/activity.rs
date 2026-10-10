// SPDX-License-Identifier: Apache-2.0
//! Whether a connection is carrying any request, and how long it has carried none.
//!
//! HTTP/1 bounds the gap between requests with `header_read_timeout`. HTTP/2 has no such
//! bound in hyper: a peer that answers keep-alive PINGs and opens no stream holds its
//! connection permit until the age bound. This is the HTTP/2 idle bound, stated once for both
//! protocols — a connection with no request in flight for the bound is closed gracefully.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

/// The requests in flight on one connection.
#[derive(Debug, Default)]
pub(super) struct ConnectionActivity {
    in_flight: AtomicUsize,
    changed: Notify,
}

/// One request counted as in flight until it is dropped.
#[derive(Debug)]
pub(super) struct InFlight(Arc<ConnectionActivity>);

impl ConnectionActivity {
    /// Count one request in flight until the returned guard is dropped.
    pub(super) fn begin(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
        InFlight(Arc::clone(self))
    }

    /// Resolve once the connection has carried no request for `bound`.
    ///
    /// Any request starting or ending restarts the wait, so the bound is measured from the
    /// last request's end, never from a request still being served.
    pub(super) async fn idle_for(&self, bound: Duration) {
        while !self.quiet_for(bound).await {}
    }

    /// One wait: `true` once the connection has carried no request for `bound`, `false` as
    /// soon as a request starts or ends first. The notification is armed before the count
    /// is read, so a change between the two is never missed.
    async fn quiet_for(&self, bound: Duration) -> bool {
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if self.in_flight.load(Ordering::SeqCst) != 0 {
            changed.await;
            return false;
        }
        tokio::time::timeout(bound, changed).await.is_err()
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUND: Duration = Duration::from_millis(50);

    #[tokio::test]
    async fn a_connection_carrying_no_request_is_idle_after_the_bound() {
        let activity = Arc::new(ConnectionActivity::default());
        let started = tokio::time::Instant::now();
        activity.idle_for(BOUND).await;
        assert!(
            started.elapsed() >= BOUND,
            "idle after {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_request_in_flight_is_never_idle_and_its_end_restarts_the_bound() {
        let activity = Arc::new(ConnectionActivity::default());
        let request = activity.begin();
        let idle = {
            let activity = Arc::clone(&activity);
            tokio::spawn(async move { activity.idle_for(BOUND).await })
        };
        tokio::time::sleep(BOUND * 4).await;
        assert!(
            !idle.is_finished(),
            "a connection serving a request was declared idle"
        );
        let ended = tokio::time::Instant::now();
        drop(request);
        idle.await.expect("the idle wait completes");
        assert!(
            ended.elapsed() >= BOUND,
            "the bound restarted only {:?} ago",
            ended.elapsed()
        );
    }
}
