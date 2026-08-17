// SPDX-License-Identifier: Apache-2.0
//! Materialisation of a revocation policy as runtime resolver behaviour.
//!
//! [`crate::revocation_tier::RevocationTier`] says WHICH policy applies. This module says
//! which runtime structure implements it — a bounded cache, a live pass-through, or a
//! push-invalidated cache over an injected channel.
//!
//! Those are separate responsibilities. That the constructor matches on the tier enum
//! does not make construction part of the enum's meaning: the tier is a policy choice a
//! deployment declares, and the resolver is machinery assembled to honour it. Keeping
//! them apart lets the policy be reasoned about without the wiring, and the wiring be
//! replaced without redefining the policy.

/// Wrap the base trust resolver according to the declared revocation tier
/// (ADR-MCPS-021, Axis 2), so the configured tier actually GOVERNS runtime
/// behavior instead of only labeling a startup line.
///
/// - [`RevocationTier::BoundedCache`] → a Tier-1 [`BoundedTrustCache`] caching
///   active state for at most `T`.
/// - [`RevocationTier::Live`] → a Tier-2 [`LiveTrustResolver`] that consults the
///   inner store on every call (no positive caching), so a store revocation is
///   visible on the very next request.
/// - [`RevocationTier::Push`] → a Tier-3 [`PushInvalidationTrustCache`] over an
///   in-process [`InMemoryInvalidationChannel`]. NOTE: no networked event source
///   ships yet, so the reference channel delivers no external pushes and the cache
///   operates at its honest bounded-`T` fallback (exactly what
///   [`RevocationTier::Push`]'s `guarantee()` already states). The wrapping is
///   still correct: it is the same code path a real push backend will drive, and
///   it never claims a near-zero window the channel cannot prove.
///
/// Pure and unit-testable: the `clock` is injected (tests pass a controllable one),
/// and the negative TTL is the named [`crate::trust_cache::DEFAULT_NEGATIVE_TTL_SECS`].
pub fn build_revocation_resolver(
    tier: &crate::revocation_tier::RevocationTier,
    base: Box<dyn mcp_re_core::TrustResolver + Send + Sync>,
    clock: crate::trust_cache::UnixClock,
) -> Box<dyn mcp_re_core::TrustResolver + Send + Sync> {
    build_revocation_resolver_with_channel(tier, base, clock, None)
}

/// As [`build_revocation_resolver`], but for the [`RevocationTier::Push`]
/// (ADR-MCPS-021 Tier 3) tier a caller may inject a networked
/// [`InvalidationChannel`](crate::push_trust::InvalidationChannel) — e.g. the
/// MCPS-84 Redis trust-epoch source. When `push_channel` is `None` the Push tier
/// falls back to the inert in-process reference channel (today's default:
/// bounded-`T`, no networked pushes). Non-Push tiers ignore `push_channel`.
pub fn build_revocation_resolver_with_channel(
    tier: &crate::revocation_tier::RevocationTier,
    base: Box<dyn mcp_re_core::TrustResolver + Send + Sync>,
    clock: crate::trust_cache::UnixClock,
    push_channel: Option<Box<dyn crate::push_trust::InvalidationChannel + Send + Sync>>,
) -> Box<dyn mcp_re_core::TrustResolver + Send + Sync> {
    let negative_ttl_secs = crate::trust_cache::DEFAULT_NEGATIVE_TTL_SECS;
    match tier {
        crate::revocation_tier::RevocationTier::BoundedCache { t_secs } => Box::new(
            crate::trust_cache::BoundedTrustCache::new(base, *t_secs, negative_ttl_secs, clock),
        ),
        crate::revocation_tier::RevocationTier::Live => {
            Box::new(crate::live_trust::LiveTrustResolver::new(base))
        }
        crate::revocation_tier::RevocationTier::Push { t_secs } => {
            // Tier 3: use the injected networked channel (MCPS-84 Redis trust-epoch
            // source) when present; otherwise the in-process reference channel is
            // inert and the cache runs at its bounded-`T` fallback (the honest
            // guarantee when no push backend is wired).
            let channel = push_channel
                .unwrap_or_else(|| Box::new(crate::push_trust::InMemoryInvalidationChannel::new()));
            Box::new(crate::push_trust::PushInvalidationTrustCache::new(
                base,
                *t_secs,
                negative_ttl_secs,
                clock,
                channel,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use mcp_re_core::SigningKey;
    use mcp_re_core::TrustResolver;
    use std::sync::Arc;
    use std::sync::Mutex;
    // ---- ADR-MCPS-021 Axis 2: build_revocation_resolver wiring ----------------
    //
    // These prove the helper does not merely label the tier but CHANGES runtime
    // behavior: Tier 2 (Live) reflects a store revocation immediately (no caching),
    // while Tier 1 (BoundedCache) caches within T. Uses the same ScriptedResolver
    // test-double style as `trust_cache` / `live_trust`.

    use super::build_revocation_resolver;
    use crate::revocation_tier::RevocationTier;
    use crate::trust_cache::UnixClock;
    use mcp_re_core::TrustResolverError;
    use mcp_re_core::VerificationKey;
    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering as AtomicOrdering;

    const SEED_A_REV: [u8; 32] = [1u8; 32];

    fn rev_key() -> VerificationKey {
        SigningKey::from_seed_bytes(&SEED_A_REV).public_key()
    }

    /// A resolver whose outcome the test flips, counting inner consultations to
    /// prove caching (or its absence). Mirrors the other modules' doubles.
    struct ScriptedRevResolver {
        outcome: Mutex<Result<VerificationKey, TrustResolverError>>,
        calls: AtomicUsize,
    }
    impl ScriptedRevResolver {
        fn new(initial: Result<VerificationKey, TrustResolverError>) -> Self {
            ScriptedRevResolver {
                outcome: Mutex::new(initial),
                calls: AtomicUsize::new(0),
            }
        }
        fn set(&self, outcome: Result<VerificationKey, TrustResolverError>) {
            *self.outcome.lock().unwrap() = outcome;
        }
        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }
    impl TrustResolver for ScriptedRevResolver {
        fn resolve(
            &self,
            _signer: &str,
            _key_id: &str,
        ) -> Result<VerificationKey, TrustResolverError> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            self.outcome.lock().unwrap().clone()
        }
    }

    /// Box a shared scripted resolver as the helper's `base`, keeping a handle.
    fn base_over(inner: Arc<ScriptedRevResolver>) -> Box<dyn TrustResolver + Send + Sync> {
        struct Shared(Arc<ScriptedRevResolver>);
        impl TrustResolver for Shared {
            fn resolve(
                &self,
                signer: &str,
                key_id: &str,
            ) -> Result<VerificationKey, TrustResolverError> {
                self.0.resolve(signer, key_id)
            }
        }
        Box::new(Shared(inner))
    }

    fn fixed_clock(start: i64) -> (UnixClock, Arc<AtomicI64>) {
        let now = Arc::new(AtomicI64::new(start));
        let handle = now.clone();
        let clock: UnixClock = Box::new(move || now.load(AtomicOrdering::SeqCst));
        (clock, handle)
    }

    #[test]
    fn live_tier_wrapping_reflects_a_store_revocation_immediately() {
        // Proves Tier 2 (Live) was actually APPLIED: the wrapped resolver consults
        // the inner store on every call, so a store-side revocation is rejected on
        // the next request with no T wait and no caching.
        let inner = Arc::new(ScriptedRevResolver::new(Ok(rev_key())));
        let (clock, _now) = fixed_clock(1000);
        let resolver =
            build_revocation_resolver(&RevocationTier::Live, base_over(inner.clone()), clock);

        resolver
            .resolve("did:host", "key-1")
            .expect("active resolves");
        // Store flips to Revoked; NO clock advance (Live has no propagation window).
        inner.set(Err(TrustResolverError::Revoked));
        assert_eq!(
            resolver.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "Live wrapping reflects a store revocation immediately"
        );
        assert_eq!(
            inner.calls(),
            2,
            "Live consults the inner store every call (no positive caching)"
        );
    }

    #[test]
    fn bounded_cache_tier_wrapping_caches_within_t() {
        // Proves Tier 1 (BoundedCache) was actually APPLIED: within T a second
        // resolve is served from cache and the inner store is consulted only once
        // — the opposite of the Live behavior above, so the two tiers are
        // genuinely distinct at runtime.
        let inner = Arc::new(ScriptedRevResolver::new(Ok(rev_key())));
        let (clock, _now) = fixed_clock(1000);
        let resolver = build_revocation_resolver(
            &RevocationTier::BoundedCache { t_secs: 60 },
            base_over(inner.clone()),
            clock,
        );

        resolver
            .resolve("did:host", "key-1")
            .expect("active resolves");
        // A store revocation within T is NOT seen — the cached active entry holds.
        inner.set(Err(TrustResolverError::Revoked));
        resolver
            .resolve("did:host", "key-1")
            .expect("within T the cached active entry is served");
        assert_eq!(
            inner.calls(),
            1,
            "BoundedCache consults the inner store once within T (caching is in effect)"
        );
    }

    #[test]
    fn push_tier_wrapping_behaves_as_bounded_t_with_an_inert_channel() {
        // Tier 3 over the inert in-process channel (no networked event source ships)
        // behaves exactly as bounded-T: within T a second resolve is a cache hit; a
        // store revocation is not picked up until T elapses.
        let inner = Arc::new(ScriptedRevResolver::new(Ok(rev_key())));
        let (clock, now) = fixed_clock(1000);
        let resolver = build_revocation_resolver(
            &RevocationTier::Push { t_secs: 60 },
            base_over(inner.clone()),
            clock,
        );

        resolver
            .resolve("did:host", "key-1")
            .expect("active resolves");
        inner.set(Err(TrustResolverError::Revoked));
        // Within T: still a cache hit (the inert channel delivers no push).
        resolver
            .resolve("did:host", "key-1")
            .expect("within T the bounded-T fallback serves the cached entry");
        assert_eq!(
            inner.calls(),
            1,
            "inert-channel Tier 3 is bounded-T (cache hit within T)"
        );
        // Past T: the bounded window caps exposure and the revocation is picked up.
        now.store(1000 + 60, AtomicOrdering::SeqCst);
        assert_eq!(
            resolver.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "past T the bounded fallback re-resolves and picks up the revocation"
        );
        assert_eq!(inner.calls(), 2);
    }
}
