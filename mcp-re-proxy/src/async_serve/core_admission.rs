// SPDX-License-Identifier: Apache-2.0
//! What one core admits work against.
//!
//! Four bounds and one live count, held as one value because they are one decision taken
//! once per core and then consulted by every connection and every request on it. Passed
//! around separately they were five parameters that always travelled together, and nothing
//! said they had to come from the same core — which is the whole point of a per-core bound
//! (ADR-MCPRE-051 §1, share-nothing).
//!
//! The four are not interchangeable. Each answers a different question about saturation:
//!
//! | bound | what it limits | what a peer is told |
//! |---|---|---|
//! | `handshakes` | TLS handshakes signing at once | the connection is dropped |
//! | `in_flight` | requests being served at once | `503` — this core, not this request |
//! | `body_budget` | attacker-supplied body bytes resident | `503` — likewise |
//! | `in_flight_requests` | nothing; it is the live COUNT | it is what graceful drain waits on |
//!
//! `in_flight` and `body_budget` are two halves of one admission and neither implies the
//! other: the count was reasoned about as if it bounded memory, and it does not.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::tls::ServerOptions;

use super::body_budget::BodyByteBudget;
use super::BUFFERED_BODY_BUDGET_MULTIPLE;
use super::DELEGATED_TLS_HANDSHAKES_PER_CORE;
use super::DRAIN_POLL_INTERVAL;

/// The bounds one `serve` loop admits against, shared by every connection it accepts.
///
/// Cloned per connection and per request; every field is an `Arc`, so a clone is a handle
/// on the SAME bound rather than a second one. A field that copied its state would give
/// each connection its own ceiling, which is not a ceiling.
#[derive(Clone)]
pub(super) struct CoreAdmission {
    /// MCPRE-114: how many requests this core serves at once. A request that cannot
    /// acquire a permit is rejected with 503 before the handler runs — fail-closed
    /// backpressure, never unbounded queuing. `None` ⇒ unbounded (historical behavior).
    pub(super) in_flight: Option<Arc<tokio::sync::Semaphore>>,
    /// MCPRE-115: live count of requests currently BEING SERVED, past admission. Graceful
    /// drain waits for this to reach zero — idle keep-alive connections carry no in-flight
    /// request and so do not extend the drain.
    pub(super) in_flight_requests: Arc<AtomicUsize>,
    /// The byte half of admission: how much attacker-supplied body those requests may hold
    /// between them.
    pub(super) body_budget: Arc<BodyByteBudget>,
    /// How many TLS handshakes may be signing at once — and ONLY where a handshake can
    /// block. On the exported-key path the signature is in-memory and bounding it would
    /// cost throughput for nothing.
    pub(super) handshakes: Option<Arc<tokio::sync::Semaphore>>,
}

impl CoreAdmission {
    /// The bounds for one core, read from the operator's limits.
    pub(super) fn for_core(options: &ServerOptions) -> Self {
        CoreAdmission {
            in_flight: options
                .limits
                .max_in_flight_requests
                .map(|n| Arc::new(tokio::sync::Semaphore::new(n))),
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
            body_budget: Arc::new(BodyByteBudget::new(
                options
                    .limits
                    .max_body_bytes
                    .saturating_mul(BUFFERED_BODY_BUDGET_MULTIPLE),
            )),
            handshakes: options.tls_signing_may_block.then(|| {
                Arc::new(tokio::sync::Semaphore::new(
                    DELEGATED_TLS_HANDSHAKES_PER_CORE,
                ))
            }),
        }
    }

    /// MCPRE-115: wait, bounded, for the requests already in flight to finish.
    ///
    /// Called once the accept loop has stopped, so no NEW request will be admitted. Because
    /// each in-flight request is itself bounded by `request_deadline`,
    /// `drain_grace >= request_deadline` guarantees a clean, zero-abandoned drain; the grace
    /// is the hard ceiling, so a wedged request cannot delay process exit past it.
    pub(super) async fn drain(&self, grace: std::time::Duration) {
        // Class R: the grace is a HARD CEILING on how long teardown may wait, so one that
        // cannot be turned into an instant is no bound at all — the drain declines to
        // start rather than parking process exit behind a deadline it cannot enforce.
        let Some(deadline) = tokio::time::Instant::now().checked_add(grace) else {
            return;
        };
        while self.in_flight_requests.load(Ordering::Acquire) > 0 {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clone is a handle on the SAME bounds. A field that copied its state would give
    /// every connection its own ceiling, which is not a ceiling at all.
    #[test]
    fn a_clone_shares_the_cores_bounds_rather_than_making_new_ones() {
        let admission = CoreAdmission {
            in_flight: Some(Arc::new(tokio::sync::Semaphore::new(1))),
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
            body_budget: Arc::new(BodyByteBudget::new(16)),
            handshakes: None,
        };
        let per_connection = admission.clone();
        let held = per_connection
            .body_budget
            .charge(16)
            .expect("the whole budget");
        assert!(
            admission.body_budget.charge(1).is_none(),
            "the clone's charge is held against the core's one budget"
        );
        drop(held);
        assert!(admission.body_budget.charge(16).is_some());
    }
}
