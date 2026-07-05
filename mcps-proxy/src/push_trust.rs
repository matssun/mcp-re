//! Tier 3 — push-invalidation trust cache (ADR-MCPS-021, Axis 2).
//!
//! Tier 3 caches trust resolutions like Tier 1 (bounded window `T`), BUT a
//! revocation **event** invalidates affected cache entries *immediately* via an
//! injected [`InvalidationChannel`]: a pushed eviction removes the entry before
//! `T` elapses, so a revoked key is rejected on the next request instead of
//! lingering for up to `T`.
//!
//! ## The honesty rule (load-bearing)
//!
//! ADR-MCPS-021 is explicit: Tier 3 is **NOT "zero window"** unless its push
//! mechanism proves reliable ordering and delivery with explicit failure
//! handling. The in-process reference channel here does NOT prove that, so:
//!
//! - while the channel is **healthy**, pushed evictions take effect before `T` →
//!   *near-zero* window;
//! - if the channel is **unhealthy** (a missed heartbeat / disconnect), a
//!   revocation push may be lost, so the cache MUST fall back to the bounded `T`:
//!   entries still expire after `t_secs`, capping the exposure window at `T`
//!   exactly as Tier 1 does. It NEVER serves an entry past `T` on the assumption a
//!   push "would have" arrived.
//!
//! The surfaced guarantee is therefore "near-zero with bounded-`T` fallback"
//! ([`RevocationTier::Push`](crate::RevocationTier)) and NEVER the zero-window
//! claim. A reliable-ordering networked channel (e.g. an ordered Redis pub/sub
//! with sequence numbers and gap detection) could justify a stronger claim; that
//! would be a separate, feature-gated backend beyond this in-process reference.
//!
//! Internally this reuses the exact Tier-1 [`BoundedTrustCache`](crate::BoundedTrustCache)
//! for the bounded-`T` caching and fail-closed-past-`T` behavior (so that
//! load-bearing property is shared, not re-implemented), and layers the
//! drain-pending-evictions step on top before each lookup.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

use mcps_core::TrustResolver;
use mcps_core::TrustResolverError;
use mcps_core::VerificationKey;

use crate::trust_cache::BoundedTrustCache;
use crate::trust_cache::UnixClock;

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
    /// Evict ALL cached positive trust (MCPS-84). A COARSE, fleet-wide
    /// invalidation: a networked source (e.g. a monotonic trust-epoch key, see
    /// `redis_trust_epoch.rs`) knows the trust store changed but not which key, so
    /// it flushes the whole positive cache and every entry re-resolves live. Can
    /// only tighten trust, never widen it.
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
    /// A fresh, healthy channel with no pending events.
    pub fn new() -> Self {
        InMemoryInvalidationChannel {
            pending: Arc::new(Mutex::new(VecDeque::new())),
            healthy: Arc::new(Mutex::new(true)),
        }
    }

    /// Push a revocation event for `(signer, key_id)` onto the channel. The next
    /// drain (and thus the next cache lookup) evicts the affected entry.
    pub fn push_revocation(&self, signer: &str, key_id: &str) {
        if let Ok(mut q) = self.pending.lock() {
            q.push_back(InvalidationEvent::Evict {
                signer: signer.to_string(),
                key_id: key_id.to_string(),
            });
        }
    }

    /// Push a coarse flush-all invalidation (evict every cached binding on the next
    /// drain). The networked-source analogue of a trust-epoch advance.
    pub fn push_flush_all(&self) {
        if let Ok(mut q) = self.pending.lock() {
            q.push_back(InvalidationEvent::FlushAll);
        }
    }

    /// Simulate a channel health transition (heartbeat lost / restored). When
    /// unhealthy, pushed events may be silently lost — the cache must fall back to
    /// bounded `T`.
    pub fn set_healthy(&self, healthy: bool) {
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

/// A [`TrustResolver`] implementing ADR-MCPS-021 **Tier 3 (push invalidation)**.
///
/// Wraps a Tier-1 [`BoundedTrustCache`] (bounded `T`, fail-closed past `T`) and an
/// injected [`InvalidationChannel`]. Before each `resolve`, it drains pending
/// revocation events and evicts the affected entries from the bounded cache, so a
/// pushed revocation rejects the key BEFORE `T` elapses. On channel failure the
/// bounded `T` still caps the exposure window (entries expire after `t_secs`) — so
/// the guarantee degrades to bounded-`T`, never to "indefinitely stale".
pub struct PushInvalidationTrustCache {
    cache: BoundedTrustCache,
    channel: Box<dyn InvalidationChannel + Send + Sync>,
}

impl PushInvalidationTrustCache {
    /// Build a Tier-3 cache over `inner` with bounded window `t_secs` /
    /// `negative_ttl_secs` (the Tier-1 fallback parameters) and the injected push
    /// `channel`. `clock` is the same injected [`UnixClock`] the bounded cache
    /// uses, so the `T` fallback arithmetic stays deterministic in tests.
    pub fn new(
        inner: Box<dyn TrustResolver + Send + Sync>,
        t_secs: i64,
        negative_ttl_secs: i64,
        clock: UnixClock,
        channel: Box<dyn InvalidationChannel + Send + Sync>,
    ) -> Self {
        PushInvalidationTrustCache {
            cache: BoundedTrustCache::new(inner, t_secs, negative_ttl_secs, clock),
            channel,
        }
    }

    /// Drain pending push events and evict the affected cache entries. Returns the
    /// number of entries evicted (for observability/tests). Whether the channel is
    /// healthy or not, draining is best-effort: an unhealthy channel simply has
    /// nothing (or partial) to deliver, and the bounded `T` fallback covers the
    /// gap.
    fn apply_pending_invalidations(&self) -> usize {
        let events = self.channel.drain_pending();
        let mut evicted = 0;
        for event in events {
            match event {
                InvalidationEvent::Evict { signer, key_id } => {
                    if self.cache.evict(&signer, &key_id) {
                        evicted += 1;
                    }
                }
                // Coarse fleet-wide invalidation: drop the whole positive cache so
                // every subsequent lookup re-resolves live (tighten-only).
                InvalidationEvent::FlushAll => {
                    evicted += self.cache.clear();
                }
            }
        }
        evicted
    }

    /// Whether the invalidation channel is currently healthy. Exposed so a caller
    /// (and the honesty tests) can confirm that an unhealthy channel does NOT
    /// upgrade the surfaced window — the proxy keeps surfacing the bounded-`T`
    /// fallback guarantee regardless.
    pub fn channel_is_healthy(&self) -> bool {
        self.channel.is_healthy()
    }
}

impl TrustResolver for PushInvalidationTrustCache {
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        // 1. Apply any pushed revocations FIRST: a pending eviction must take
        //    effect before we read the cache, so a just-revoked key is not served
        //    from a stale-but-within-T entry.
        self.apply_pending_invalidations();
        // 2. Delegate to the Tier-1 bounded cache: a still-cached entry is served
        //    within T; otherwise the inner store is consulted and the bounded-T /
        //    fail-closed-past-T contract holds unchanged.
        self.cache.resolve(signer, key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryInvalidationChannel;
    use super::InvalidationChannel;
    use super::PushInvalidationTrustCache;

    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;

    use mcps_core::SigningKey;
    use mcps_core::TrustResolver;
    use mcps_core::TrustResolverError;
    use mcps_core::VerificationKey;

    use crate::trust_cache::UnixClock;

    const SEED_A: [u8; 32] = [1u8; 32];
    const T: i64 = 60;
    const NEG_TTL: i64 = 5;

    fn key_from(seed: &[u8; 32]) -> VerificationKey {
        SigningKey::from_seed_bytes(seed).public_key()
    }

    struct ScriptedResolver {
        outcome: Mutex<Result<VerificationKey, TrustResolverError>>,
        calls: AtomicUsize,
    }
    impl ScriptedResolver {
        fn new(initial: Result<VerificationKey, TrustResolverError>) -> Self {
            ScriptedResolver {
                outcome: Mutex::new(initial),
                calls: AtomicUsize::new(0),
            }
        }
        fn set(&self, outcome: Result<VerificationKey, TrustResolverError>) {
            *self.outcome.lock().unwrap() = outcome;
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl TrustResolver for ScriptedResolver {
        fn resolve(
            &self,
            _signer: &str,
            _key_id: &str,
        ) -> Result<VerificationKey, TrustResolverError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome.lock().unwrap().clone()
        }
    }

    fn controllable_clock(start: i64) -> (UnixClock, Arc<AtomicI64>) {
        let now = Arc::new(AtomicI64::new(start));
        let handle = now.clone();
        let clock: UnixClock = Box::new(move || now.load(Ordering::SeqCst));
        (clock, handle)
    }

    fn push_cache_over(
        inner: Arc<ScriptedResolver>,
        clock: UnixClock,
        channel: InMemoryInvalidationChannel,
    ) -> PushInvalidationTrustCache {
        struct Shared(Arc<ScriptedResolver>);
        impl TrustResolver for Shared {
            fn resolve(
                &self,
                signer: &str,
                key_id: &str,
            ) -> Result<VerificationKey, TrustResolverError> {
                self.0.resolve(signer, key_id)
            }
        }
        PushInvalidationTrustCache::new(
            Box::new(Shared(inner)),
            T,
            NEG_TTL,
            clock,
            Box::new(channel),
        )
    }

    #[test]
    fn pushed_invalidation_rejects_the_key_before_t_elapses() {
        // The load-bearing Tier 3 property: a pushed revocation evicts the cached
        // entry, so the key is re-resolved (and rejected) BEFORE the bounded T.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let channel = InMemoryInvalidationChannel::new();
        let cache = push_cache_over(inner.clone(), clock, channel.clone());

        // Prime the cache with an active binding.
        cache.resolve("did:host", "key-1").expect("active cached");
        assert_eq!(inner.calls(), 1);
        // Within T, a normal second call would be a cache hit (no inner consult).
        // Instead the store revokes AND a push arrives — well BEFORE T elapses.
        inner.set(Err(TrustResolverError::Revoked));
        channel.push_revocation("did:host", "key-1");
        now.store(1000 + 1, Ordering::SeqCst); // 1s << T
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "a pushed invalidation rejects the key before T elapses"
        );
        // The eviction forced a re-consult of the inner store (proves it was not a
        // stale cache hit).
        assert_eq!(inner.calls(), 2, "the pushed eviction forced a re-resolve");
    }

    #[test]
    fn flush_all_evicts_every_cached_binding_forcing_re_resolve() {
        // MCPS-84: a coarse FlushAll (the trust-epoch analogue) drops EVERY cached
        // positive entry, so all subsequent lookups re-resolve live — a
        // just-revoked key is then re-checked and denied even though the push named
        // no specific key.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let channel = InMemoryInvalidationChannel::new();
        let cache = push_cache_over(inner.clone(), clock, channel.clone());

        // Prime two distinct bindings (2 inner consults).
        cache.resolve("did:host", "key-1").expect("active");
        cache.resolve("did:other", "key-9").expect("active");
        assert_eq!(inner.calls(), 2);

        // A single flush-all (epoch advanced), still well within T.
        inner.set(Err(TrustResolverError::Revoked));
        channel.push_flush_all();
        now.store(1000 + 1, Ordering::SeqCst);

        // BOTH keys re-resolve (were evicted) and are now denied — 2 more consults.
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked
        );
        assert_eq!(
            cache.resolve("did:other", "key-9").unwrap_err(),
            TrustResolverError::Revoked
        );
        assert_eq!(
            inner.calls(),
            4,
            "flush-all evicted BOTH cached bindings, forcing a re-resolve of each"
        );
    }

    #[test]
    fn channel_failure_falls_back_to_bounded_t_entry_still_served_until_expiry() {
        // CRITICAL honesty property: with the channel unhealthy a revocation push
        // may be LOST, so the cache falls back to bounded T — the active entry is
        // STILL served until t_secs expiry (capped at T, never indefinitely), and
        // is re-resolved (picking up the revocation) once T elapses.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let channel = InMemoryInvalidationChannel::new();
        let cache = push_cache_over(inner.clone(), clock, channel.clone());

        cache.resolve("did:host", "key-1").expect("active cached");
        // The channel goes down and the push is lost (never enqueued).
        channel.set_healthy(false);
        inner.set(Err(TrustResolverError::Revoked));
        assert!(!cache.channel_is_healthy());

        // BEFORE T: the cached active entry is still served (bounded-T fallback) —
        // it is NOT magically invalidated without a delivered push.
        now.store(1000 + T - 1, Ordering::SeqCst);
        cache
            .resolve("did:host", "key-1")
            .expect("within T the cached active entry is served (bounded-T fallback)");
        assert_eq!(inner.calls(), 1, "still a cache hit within T");

        // AT/PAST T: the bounded window caps the exposure — the entry expires and
        // the revocation is picked up (never served indefinitely).
        now.store(1000 + T, Ordering::SeqCst);
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "past T the bounded fallback re-resolves and picks up the revocation"
        );
        assert_eq!(inner.calls(), 2);
    }

    #[test]
    fn store_outage_past_t_fails_closed_even_under_push_tier() {
        // Tier 3 inherits the Tier-1 fail-closed-past-T property: a store outage
        // past T does NOT serve stale active trust.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let channel = InMemoryInvalidationChannel::new();
        let cache = push_cache_over(inner.clone(), clock, channel);

        cache.resolve("did:host", "key-1").expect("active cached");
        inner.set(Err(TrustResolverError::Unavailable {
            details: "outage".to_string(),
        }));
        now.store(1000 + T, Ordering::SeqCst);
        assert!(
            matches!(
                cache.resolve("did:host", "key-1"),
                Err(TrustResolverError::Unavailable { .. })
            ),
            "past T with the store down, Tier 3 fails closed (no stale active)"
        );
    }

    #[test]
    fn healthy_channel_with_no_pending_events_is_a_normal_cache_hit() {
        // A healthy channel that has nothing to deliver must not perturb the
        // bounded-cache behavior: within T it is a plain cache hit.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(1000);
        let channel = InMemoryInvalidationChannel::new();
        let cache = push_cache_over(inner.clone(), clock, channel.clone());

        cache.resolve("did:host", "key-1").expect("active");
        assert!(channel.drain_pending().is_empty());
        cache.resolve("did:host", "key-1").expect("cache hit");
        assert_eq!(inner.calls(), 1, "no spurious re-resolve with an empty channel");
    }

    #[test]
    fn push_for_a_different_key_does_not_evict_the_active_entry() {
        // A revocation push for key-2 must not evict key-1's cached entry.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(1000);
        let channel = InMemoryInvalidationChannel::new();
        let cache = push_cache_over(inner.clone(), clock, channel.clone());

        cache.resolve("did:host", "key-1").expect("active cached");
        channel.push_revocation("did:host", "key-2");
        cache.resolve("did:host", "key-1").expect("key-1 still a cache hit");
        assert_eq!(inner.calls(), 1, "an unrelated push does not evict key-1");
    }
}
