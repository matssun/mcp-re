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
/// - [`RevocationTier::Push`] → a Tier-3 [`PushInvalidationTrustCache`] over the
///   injected channel, or over the [`InertInvalidationChannel`] when none is wired. The
///   inert channel delivers no pushes and reports itself not operational, so the cache
///   operates at its honest bounded-`T` fallback (exactly what
///   [`RevocationTier::Push`]'s `guarantee()` already states) and never claims a pushed
///   window the channel cannot prove.
///
/// Pure and unit-testable: the `clock` is injected (tests pass a controllable one),
/// and the negative TTL is the named [`crate::trust_plane::trust_cache::DEFAULT_NEGATIVE_TTL_SECS`].
/// For the [`RevocationTier::Push`] (ADR-MCPS-021 Tier 3) tier a caller may inject a
/// networked [`InvalidationChannel`](super::push_trust::InvalidationChannel) — e.g. the
/// MCPS-84 Redis trust-epoch source. When `push_channel` is `None` the Push tier gets the
/// inert channel (bounded-`T`, no networked pushes, not operational). Non-Push tiers
/// ignore `push_channel`.
///
/// ONE entry point. There used to be a second, `build_revocation_resolver`, whose whole
/// body was `build_revocation_resolver(tier, base, clock, None)` — a strictly
/// weaker duplicate with no production caller, since the composition root always has a
/// channel to pass or an explicit `None` to pass. Two ways in where one suffices is
/// interface width, and it is what ADR-MCPRE-061 §7 asks to be removed even where no size
/// band flags it.
pub(super) fn build_revocation_resolver(
    tier: &crate::revocation_tier::RevocationTier,
    base: Box<dyn mcp_re_core::TrustResolver + Send + Sync>,
    clock: crate::trust_plane::trust_cache::UnixClock,
    push_channel: Option<
        Box<dyn crate::trust_plane::invalidation_channel::InvalidationChannel + Send + Sync>,
    >,
) -> Box<dyn mcp_re_core::TrustResolver + Send + Sync> {
    let negative_ttl_secs = crate::trust_plane::trust_cache::DEFAULT_NEGATIVE_TTL_SECS;
    match tier {
        crate::revocation_tier::RevocationTier::BoundedCache { t_secs } => {
            Box::new(crate::trust_plane::trust_cache::BoundedTrustCache::new(
                base,
                *t_secs,
                negative_ttl_secs,
                clock,
            ))
        }
        crate::revocation_tier::RevocationTier::Live => {
            Box::new(crate::trust_plane::live_trust::LiveTrustResolver::new(base))
        }
        crate::revocation_tier::RevocationTier::Push { t_secs } => {
            let channel = push_tier_channel(push_channel);
            Box::new(
                crate::trust_plane::push_trust::PushInvalidationTrustCache::new(
                    base,
                    *t_secs,
                    negative_ttl_secs,
                    clock,
                    channel,
                ),
            )
        }
    }
}

/// The channel a Push tier runs over: the injected networked source when one is wired,
/// otherwise the [`InertInvalidationChannel`], which nothing can publish to.
fn push_tier_channel(
    push_channel: Option<
        Box<dyn crate::trust_plane::invalidation_channel::InvalidationChannel + Send + Sync>,
    >,
) -> Box<dyn crate::trust_plane::invalidation_channel::InvalidationChannel + Send + Sync> {
    push_channel.unwrap_or_else(|| {
        Box::new(crate::trust_plane::invalidation_channel::InertInvalidationChannel)
    })
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
    use crate::trust_plane::trust_cache::UnixClock;
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
            build_revocation_resolver(&RevocationTier::Live, base_over(inner.clone()), clock, None);

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
            None,
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
        // Tier 3 with no networked source wired runs over the inert channel and
        // behaves exactly as bounded-T: within T a second resolve is a cache hit; a
        // store revocation is not picked up until T elapses.
        let inner = Arc::new(ScriptedRevResolver::new(Ok(rev_key())));
        let (clock, now) = fixed_clock(1000);
        let resolver = build_revocation_resolver(
            &RevocationTier::Push { t_secs: 60 },
            base_over(inner.clone()),
            clock,
            None,
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

    #[test]
    fn a_push_tier_without_a_networked_source_reports_its_channel_not_operational() {
        use crate::trust_plane::invalidation_channel::drivable::InMemoryInvalidationChannel;
        assert!(
            !super::push_tier_channel(None).is_healthy(),
            "nothing can publish to the inert channel, so it is not operational"
        );
        assert!(
            super::push_tier_channel(Some(Box::new(InMemoryInvalidationChannel::new())))
                .is_healthy(),
            "an injected source reports its own health"
        );
    }
}
