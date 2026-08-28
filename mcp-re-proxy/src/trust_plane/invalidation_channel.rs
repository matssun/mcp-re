// SPDX-License-Identifier: Apache-2.0
//! The Tier-3 invalidation SEAM: what an eviction event is, where one comes from, and the
//! in-process reference channel that delivers none.
//!
//! Separate from the cache that reacts to an event. `push_trust` owns *a pushed eviction
//! removes an entry before `T` elapses, and an unhealthy channel falls back to bounded
//! `T`*; this module owns the event vocabulary and the source contract — including the
//! health signal, which is the input that fallback rule reads.
//!
//! The reference channel here is INERT: it delivers no external pushes, so a deployment
//! wiring nothing runs Tier 3 at its honest bounded-`T` fallback. Its publishers exist to
//! drive it, and a networked source (the MCPS-84 Redis trust-epoch reader) replaces it
//! without either half changing.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

/// One pushed invalidation event. A real channel would carry sequence/ordering
/// metadata; the reference events are just the invalidation to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationEvent {
    /// Evict one `(signer, key_id)` binding — a precise, per-key revocation (the
    /// in-process reference channel's granularity).
    Evict {
        /// The signer whose binding is revoked.
        signer: String,
        /// The key id whose binding is revoked.
        key_id: String,
    },
    /// Invalidate ALL cached positive trust (MCPS-84). A COARSE, fleet-wide
    /// invalidation: a networked source (e.g. a monotonic trust-epoch key, see
    /// `redis_trust_epoch.rs`) signals that the trust configuration advanced but not
    /// which key, so every cached binding loses its authority to answer and
    /// re-resolves live. Each binding keeps the deadline it already carried, so a
    /// flush can only tighten trust, never widen it.
    ///
    /// Its reach is the CACHE, not the store. It bounds how stale a cached answer is
    /// relative to the resolver this tier wraps; that resolver is a snapshot of
    /// `--trust` re-read on its own cadence `R`. A key removed from the file
    /// therefore stops resolving no sooner than that re-read lands, whatever the
    /// epoch does — the delivered window is `R + T`, and advancing the epoch alone
    /// revokes nothing.
    FlushAll,
}

/// An injected source of revocation push events plus a health signal.
///
/// The cache drains pending events before each lookup and evicts the named
/// entries. CRITICAL: [`is_healthy`](InvalidationChannel::is_healthy) gates the
/// honesty contract — when it returns `false` (a missed heartbeat / disconnect),
/// the cache MUST NOT claim a near-zero window for that interval; it falls back to
/// the bounded `T`. The trait makes no delivery/ordering guarantee, which is
/// exactly why the reference Tier 3 is "near-zero + bounded fallback", not
/// zero-window.
pub trait InvalidationChannel {
    /// Drain and return all revocation events received since the last drain. An
    /// empty vector means none pending (NOT that the channel is down — see
    /// [`is_healthy`](InvalidationChannel::is_healthy)).
    fn drain_pending(&self) -> Vec<InvalidationEvent>;

    /// Whether the channel is currently healthy (connected, heartbeat fresh). When
    /// `false`, the caller treats pushes as possibly-lost and relies on the
    /// bounded `T` fallback for the affected interval.
    fn is_healthy(&self) -> bool;
}

/// In-memory reference [`InvalidationChannel`]: a queue of pending events plus a
/// settable health flag, for deterministic unit tests and single-process
/// deployments. It does NOT prove reliable ordering/delivery across nodes (it is
/// in-process), which is precisely why Tier 3 over this channel surfaces the
/// near-zero+bounded-fallback guarantee, never zero-window.
#[derive(Clone)]
pub struct InMemoryInvalidationChannel {
    pending: Arc<Mutex<VecDeque<InvalidationEvent>>>,
    healthy: Arc<Mutex<bool>>,
}

impl Default for InMemoryInvalidationChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryInvalidationChannel {
    // The three publishers below are exercised only by this module's own tests, and that is
    // question 8 of the ADR-MCPRE-061 §8 census — *what public interface exists only
    // because tests need it* — answered by narrowing rather than by widening: each stays
    // `pub(super)`, and the attribute states that a production build has no caller. They
    // are the drive side of the inert reference channel, which is exactly what a networked
    // event source would replace.
    /// A fresh, healthy channel with no pending events.
    pub fn new() -> Self {
        InMemoryInvalidationChannel {
            pending: Arc::new(Mutex::new(VecDeque::new())),
            healthy: Arc::new(Mutex::new(true)),
        }
    }

    /// Push a revocation event for `(signer, key_id)` onto the channel. The next
    /// drain (and thus the next cache lookup) evicts the affected entry.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn push_revocation(&self, signer: &str, key_id: &str) {
        if let Ok(mut q) = self.pending.lock() {
            q.push_back(InvalidationEvent::Evict {
                signer: signer.to_string(),
                key_id: key_id.to_string(),
            });
        }
    }

    /// Push a coarse flush-all invalidation (invalidate every cached binding on the
    /// next drain). The networked-source analogue of a trust-epoch advance.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn push_flush_all(&self) {
        if let Ok(mut q) = self.pending.lock() {
            q.push_back(InvalidationEvent::FlushAll);
        }
    }

    /// Simulate a channel health transition (heartbeat lost / restored). When
    /// unhealthy, pushed events may be silently lost — the cache must fall back to
    /// bounded `T`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn set_healthy(&self, healthy: bool) {
        if let Ok(mut h) = self.healthy.lock() {
            *h = healthy;
        }
    }
}

impl InvalidationChannel for InMemoryInvalidationChannel {
    fn drain_pending(&self) -> Vec<InvalidationEvent> {
        // An unhealthy channel may have lost events; deliver only what is queued
        // (the test of honesty is that the cache still falls back to T, not that
        // an unhealthy channel magically delivers).
        match self.pending.lock() {
            Ok(mut q) => q.drain(..).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn is_healthy(&self) -> bool {
        self.healthy.lock().map(|h| *h).unwrap_or(false)
    }
}
