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

use mcp_re_core::TrustResolver;
use mcp_re_core::TrustResolverError;
use mcp_re_core::VerificationKey;

use crate::trust_plane::trust_cache::BoundedTrustCache;
use crate::trust_plane::trust_cache::UnixClock;

use super::invalidation_channel::InvalidationChannel;
use super::invalidation_channel::InvalidationEvent;
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
        let mut evicted = 0usize;
        for event in events {
            match event {
                InvalidationEvent::Evict { signer, key_id } => {
                    if self.cache.evict(&signer, &key_id) {
                        // An observability tally over a bounded cache; saturating so the
                        // report stops being exact rather than reading as zero.
                        evicted = evicted.saturating_add(1);
                    }
                }
                // Coarse fleet-wide invalidation: strip every cached binding of its
                // authority to answer so each subsequent lookup re-resolves against
                // the store as it stands, under the deadline the binding already
                // carried (tighten-only).
                InvalidationEvent::FlushAll => {
                    evicted = evicted.saturating_add(self.cache.clear());
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
    use super::super::invalidation_channel::InMemoryInvalidationChannel;
    use super::InvalidationChannel;
    use super::PushInvalidationTrustCache;

    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;

    use mcp_re_core::SigningKey;
    use mcp_re_core::TrustResolver;
    use mcp_re_core::TrustResolverError;
    use mcp_re_core::VerificationKey;

    use crate::trust_plane::trust_cache::UnixClock;

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
        assert_eq!(
            inner.calls(),
            1,
            "no spurious re-resolve with an empty channel"
        );
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
        cache
            .resolve("did:host", "key-1")
            .expect("key-1 still a cache hit");
        assert_eq!(inner.calls(), 1, "an unrelated push does not evict key-1");
    }

    #[test]
    fn a_flush_never_extends_a_cached_bindings_deadline() {
        // A flush lands while the store still answers with the binding — the state
        // the deployment is in between an epoch advance and the `--trust` re-read.
        // The re-resolved entry inherits the deadline the flushed one carried, so
        // the binding must still be re-checked at its ORIGINAL expiry rather than at
        // a fresh T counted from the flush.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let channel = InMemoryInvalidationChannel::new();
        let cache = push_cache_over(inner.clone(), clock, channel.clone());

        cache.resolve("did:host", "key-1").expect("active cached");
        assert_eq!(inner.calls(), 1);

        // Late within T, the epoch advances and the flush lands; the store is
        // unchanged, so the same active key is re-cached.
        now.store(1000 + T - 10, Ordering::SeqCst);
        channel.push_flush_all();
        cache.resolve("did:host", "key-1").expect("still active");
        assert_eq!(inner.calls(), 2, "the flush forced a live re-resolve");

        // The file edit reaches the store, and the ORIGINAL deadline is what governs.
        inner.set(Err(TrustResolverError::Revoked));
        now.store(1000 + T - 1, Ordering::SeqCst);
        cache
            .resolve("did:host", "key-1")
            .expect("inside the original window this is a cache hit");
        assert_eq!(inner.calls(), 2);
        now.store(1000 + T, Ordering::SeqCst);
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "the flush bought the binding a fresh T past its original deadline"
        );
        assert_eq!(inner.calls(), 3);
    }

    #[test]
    fn a_flush_re_resolves_against_the_store_as_it_stands_and_revokes_nothing_itself() {
        // The reach of a flush is the CACHE, not the store: with the store unchanged
        // (the `--trust` re-read has not landed yet) the flushed binding re-resolves
        // to exactly the same active key. Advancing the epoch is not itself a
        // revocation of anything in the trust file.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let channel = InMemoryInvalidationChannel::new();
        let cache = push_cache_over(inner.clone(), clock, channel.clone());

        let before = cache.resolve("did:host", "key-1").expect("active cached");
        channel.push_flush_all();
        now.store(1000 + 1, Ordering::SeqCst);

        let after = cache
            .resolve("did:host", "key-1")
            .expect("the unchanged store still answers with the same binding");
        assert_eq!(
            inner.calls(),
            2,
            "the flush forced a live re-resolve against the store"
        );
        assert_eq!(
            before.to_bytes(),
            after.to_bytes(),
            "a flush over an unchanged store cannot revoke a binding by itself"
        );
    }
}
