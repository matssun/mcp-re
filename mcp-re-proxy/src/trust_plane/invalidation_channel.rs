// SPDX-License-Identifier: Apache-2.0
//! The Tier-3 invalidation SEAM: what an eviction event is, where one comes from, and the
//! in-process reference channel that delivers none.
//!
//! Separate from the cache that reacts to an event. `push_trust` owns *a pushed eviction
//! removes an entry before `T` elapses, and an unhealthy channel falls back to bounded
//! `T`*; this module owns the event vocabulary and the source contract — including the
//! health signal, which is the input that fallback rule reads.
//!
//! The reference channel here is INERT: nothing can publish to it, so a deployment wiring
//! no networked source runs Tier 3 at its honest bounded-`T` fallback, and the channel
//! reports itself not operational. A networked source (the MCPS-84 Redis trust-epoch
//! reader) takes its place without either half changing.

/// One pushed invalidation event. A real channel would carry sequence/ordering
/// metadata; the reference events are just the invalidation to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationEvent {
    /// Evict one `(signer, key_id)` binding — a precise, per-key revocation, for a
    /// channel that knows which key changed. The in-tree trust-epoch source does not,
    /// and emits only [`FlushAll`](Self::FlushAll).
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

/// An injected source of revocation push events plus a health WITNESS.
///
/// The cache drains pending events before each lookup and evicts the named entries. The
/// trait makes no delivery or ordering guarantee, which is exactly why the reference Tier 3
/// is "re-read bound + bounded fallback" rather than zero-window.
///
/// # `is_healthy` reports; it does not gate
///
/// This said `is_healthy` GATES the honesty contract. It does not, and nothing in this
/// crate reads it on a serving path: `channel_is_healthy` has no production caller. What
/// makes the fallback safe is BEHAVIOURAL and holds regardless of the witness — a cached
/// binding answers for at most `T` and never past the deadline it was first cached under,
/// so an undelivered push costs at most `T`, whether or not anything noticed the channel
/// was down.
///
/// Reading it as a gate is worse than useless: it suggests a control that would have to
/// exist for the push claim to be honest, and none does. The witness is worth keeping
/// — it is the difference between "no events arrived" and "nothing could have arrived", and
/// a reader with only `drain_pending` cannot tell those apart — but it is evidence for an
/// operator, not an input to a decision.
pub trait InvalidationChannel {
    /// Drain and return all revocation events received since the last drain. An
    /// empty vector means none pending (NOT that the channel is down — see
    /// [`is_healthy`](InvalidationChannel::is_healthy)).
    fn drain_pending(&self) -> Vec<InvalidationEvent>;

    /// Whether the channel is currently healthy (connected, heartbeat fresh).
    ///
    /// A WITNESS. `false` means pushes may have been lost, and the bounded `T` fallback
    /// already covers that interval whether or not anyone asks — see the type doc. A caller
    /// that begins gating on this is adding a control, and owes the argument for why the
    /// behavioural bound is no longer sufficient.
    fn is_healthy(&self) -> bool;
}

/// The channel a Tier-3 deployment gets when it wires no networked source: nothing can
/// publish to it, so it never delivers an event and never reports itself operational.
///
/// The deployment is legal and runs at the bounded-`T` fallback either way; what this type
/// owns is the truthfulness of the witness. `is_healthy` answers "could a push arrive", and
/// for a channel nobody can publish to the answer is no — the distinction the trait doc
/// draws between "no events arrived" and "nothing could have arrived".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InertInvalidationChannel;

impl InvalidationChannel for InertInvalidationChannel {
    fn drain_pending(&self) -> Vec<InvalidationEvent> {
        Vec::new()
    }

    fn is_healthy(&self) -> bool {
        false
    }
}

/// A drivable channel for the Tier-3 cache's own tests: a queue of pending events plus a
/// settable health flag.
#[cfg(test)]
pub(super) mod drivable {
    use super::InvalidationChannel;
    use super::InvalidationEvent;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// An in-process channel whose events and health the test publishes.
    #[derive(Clone)]
    pub(in crate::trust_plane) struct InMemoryInvalidationChannel {
        pending: Arc<Mutex<VecDeque<InvalidationEvent>>>,
        healthy: Arc<Mutex<bool>>,
    }

    impl InMemoryInvalidationChannel {
        /// A fresh, healthy channel with no pending events.
        pub(in crate::trust_plane) fn new() -> Self {
            InMemoryInvalidationChannel {
                pending: Arc::new(Mutex::new(VecDeque::new())),
                healthy: Arc::new(Mutex::new(true)),
            }
        }

        /// Push a revocation event for `(signer, key_id)`; the next drain evicts it.
        pub(in crate::trust_plane) fn push_revocation(&self, signer: &str, key_id: &str) {
            if let Ok(mut q) = self.pending.lock() {
                q.push_back(InvalidationEvent::Evict {
                    signer: signer.to_string(),
                    key_id: key_id.to_string(),
                });
            }
        }

        /// Push a coarse flush-all invalidation, the analogue of a trust-epoch advance.
        pub(in crate::trust_plane) fn push_flush_all(&self) {
            if let Ok(mut q) = self.pending.lock() {
                q.push_back(InvalidationEvent::FlushAll);
            }
        }

        /// Simulate a health transition (heartbeat lost / restored).
        pub(in crate::trust_plane) fn set_healthy(&self, healthy: bool) {
            if let Ok(mut h) = self.healthy.lock() {
                *h = healthy;
            }
        }
    }

    impl InvalidationChannel for InMemoryInvalidationChannel {
        fn drain_pending(&self) -> Vec<InvalidationEvent> {
            match self.pending.lock() {
                Ok(mut q) => q.drain(..).collect(),
                Err(_) => Vec::new(),
            }
        }

        fn is_healthy(&self) -> bool {
            self.healthy.lock().map(|h| *h).unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InertInvalidationChannel;
    use super::InvalidationChannel;

    #[test]
    fn an_inert_channel_never_reports_itself_operational() {
        assert!(!InertInvalidationChannel.is_healthy());
    }

    #[test]
    fn an_inert_channel_delivers_nothing() {
        assert!(InertInvalidationChannel.drain_pending().is_empty());
    }
}
