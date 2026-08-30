//! Bounded trust-propagation cache (ADR-MCPS-021, Tier 1).
//!
//! `mcp-re-core` deliberately does NOT cache trust resolutions — its `resolver`
//! module states bounded-TTL caching is a *caller* concern, and the resolver
//! answer at verify time is final. In a multi-node fleet that caller concern
//! becomes a real one: revocation and key-status state must propagate across
//! nodes, and a verifier that re-hits the shared trust source on every request
//! pays latency and couples availability to it. ADR-MCPS-021 bounds the staleness
//! with a **trust-propagation window `T`**: a verifier MAY serve cached *active*
//! trust state for at most `T`, after which it MUST revalidate or fail closed.
//!
//! This module implements the **Tier 1** posture (bounded-cache eventual): a
//! [`TrustResolver`] wrapper that caches the inner resolver's answers under
//! ADR-MCPS-021's classification rules. It is pure (clock-injected, no I/O) so the
//! whole staleness/fail-closed contract is unit-testable without any external
//! store.
//!
//! ## Classification (ADR-MCPS-021)
//!
//! - **Active** key state is cached for at most `T` (the revocation exposure
//!   window). After `T` the entry is re-resolved; if the source is unavailable
//!   then, the request fails closed — a node never serves stale *active* trust
//!   beyond `T`, and a restart with an empty cache plus an unreachable source
//!   fails closed (no stale-trust resurrection).
//! - **`Revoked`** is a safe deny and is cached for `T` (caching a deny is never
//!   a security risk; serving it longer only delays re-admitting a key that was
//!   re-enabled, which the operator controls).
//! - **`NotFound`** uses a SHORT negative TTL so a freshly published rotation key
//!   is not suppressed (an availability hazard, not a security one).
//! - **`MalformedKey`** is a safe deny but, like `NotFound`, is correctable by
//!   republishing a valid key, so it uses the short negative TTL.
//! - **`Unavailable`** is an operational failure: it is NEVER cached as a trust
//!   decision and always fails closed.

use std::collections::HashMap;
use std::sync::Mutex;

use mcp_re_core::TrustResolver;
use mcp_re_core::TrustResolverError;
use mcp_re_core::VerificationKey;

/// The deployment-wide default trust-propagation window (seconds), ADR-MCPS-021.
pub const DEFAULT_T_SECS: i64 = 60;

/// The default short negative TTL (seconds) for `NotFound` / `MalformedKey`
/// outcomes, so a freshly published rotation key is not suppressed for the full
/// window `T` (an availability hazard, not a security one). Deliberately small and
/// `<= DEFAULT_T_SECS`; used when wiring the Tier-1 bounded cache (and the Tier-3
/// bounded fallback) from the CLI.
pub const DEFAULT_NEGATIVE_TTL_SECS: i64 = 5;

/// A source of the CURRENT Unix time (seconds). The proxy's impure edge — the
/// pure `TrustResolver` trait carries no clock, so the cache owns one to bound the
/// propagation window `T`. Production injects [`system_clock`]; tests inject a
/// controllable clock so the window arithmetic is deterministic.
pub type UnixClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// The production [`UnixClock`]: reads the system clock. A pre-epoch reading has no
/// representable Unix instant, so it yields [`i64::MAX`] rather than panicking —
/// the fail-closed direction for an expiry comparison. Every cached window then
/// reads as closed, every lookup re-resolves live against the inner store, and
/// [`BoundedTrustCache`] declines to cache an expiry it cannot represent. The
/// opposite clamp would place every entry written under a real clock permanently
/// inside its window.
pub fn system_clock() -> UnixClock {
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    Box::new(|| unix_seconds(SystemTime::now().duration_since(UNIX_EPOCH).ok()))
}

/// Map an elapsed-since-epoch reading to Unix seconds. `None` (the reading predates
/// the epoch) and a count too large for `i64` both yield [`i64::MAX`]: an unusable
/// reading must close every cached window, not open one.
fn unix_seconds(since_epoch: Option<std::time::Duration>) -> i64 {
    match since_epoch {
        Some(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        None => i64::MAX,
    }
}

/// A cached resolution outcome. The full positive result (the key) is cached so a
/// key is NEVER cached independently of its active status (ADR-MCPS-021): a hit
/// reconstructs exactly the `resolve` answer that produced it.
#[derive(Clone)]
enum CachedOutcome {
    /// An active binding with its verification key.
    Active(VerificationKey),
    /// A safe-deny: the binding is revoked/disabled.
    Revoked,
    /// A definitive negative: no binding present.
    NotFound,
    /// The stored key material was malformed.
    Malformed,
}

impl CachedOutcome {
    /// Reconstruct the `resolve` result this cached outcome represents.
    fn to_result(&self) -> Result<VerificationKey, TrustResolverError> {
        match self {
            CachedOutcome::Active(key) => Ok(key.clone()),
            CachedOutcome::Revoked => Err(TrustResolverError::Revoked),
            CachedOutcome::NotFound => Err(TrustResolverError::NotFound),
            CachedOutcome::Malformed => Err(TrustResolverError::MalformedKey),
        }
    }
}

/// One cache entry: a classified outcome plus the absolute Unix instant at which
/// it expires (`resolved_at + ttl`).
///
/// An invalidated entry has lost its authority to answer but keeps `expires_at` as
/// the DEADLINE its binding already carried. The entry that replaces it inherits
/// that instant as a ceiling, which is what makes invalidation tighten-only: a
/// binding's cached life can never be extended by invalidating it.
struct CacheEntry {
    outcome: CachedOutcome,
    expires_at: i64,
    invalidated: bool,
}

/// A [`TrustResolver`] that wraps an inner resolver with ADR-MCPS-021 Tier-1
/// bounded-`T` caching.
///
/// `resolve` serves a cached entry while it is within its window; otherwise it
/// consults the inner resolver and caches the answer per the classification
/// rules. An [`TrustResolverError::Unavailable`] from the inner resolver is never
/// cached and fails closed — and because cached *active* state lives at most `T`,
/// a node cannot serve stale active trust beyond the window even while the source
/// is down (and a fresh process with an empty cache fails closed if the source is
/// unreachable).
pub struct BoundedTrustCache {
    inner: Box<dyn TrustResolver + Send + Sync>,
    /// The trust-propagation window `T` (seconds): the max age of cached *active*
    /// or *revoked* state.
    t_secs: i64,
    /// The short negative TTL (seconds) for `NotFound` / `MalformedKey`, so a
    /// freshly published key is not suppressed.
    negative_ttl_secs: i64,
    clock: UnixClock,
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// Writes since the last eviction sweep; drives [`PRUNE_EVERY_N_WRITES`].
    writes_since_prune: Mutex<u64>,
    /// Ceiling on cached entries; see [`MAX_CACHE_ENTRIES`].
    max_entries: usize,
}

/// How often (in cache writes) an expired-entry sweep runs.
///
/// An expired entry is ignored on read but was never REMOVED there, and nothing in
/// the tree called `prune`. The keyid gate precedes trust resolution, so every
/// distinct `keyid` an unauthenticated peer presents produced one permanent entry:
/// steady, remotely-driven growth for the process lifetime. Sweeping on every write
/// would be O(n); a cadence amortises it.
const PRUNE_EVERY_N_WRITES: u64 = 64;

/// Ceiling on cached entries. Past it the cache stops CACHING (it never stops
/// answering): the resolution still happens and the request still gets its answer,
/// it is simply resolved live next time. That direction is always safe — more live
/// resolution can only tighten trust, never widen it — which is why this is a skipped
/// write rather than the fail-closed refusal a replay store must give.
const MAX_CACHE_ENTRIES: usize = 100_000;

impl BoundedTrustCache {
    // Several items below are exercised only by this module's own tests, and that is
    // question 8 of the ADR-MCPRE-061 §8 census — *what public interface exists only
    // because tests need it* — answered by narrowing rather than by widening: each stays
    // `pub(super)`, and the attribute states that a production build has no caller. The
    // capacity ceiling itself IS enforced in production; what has no production caller is
    // the ability to change it and the manual sweep, since `store` sweeps opportunistically.
    /// Wrap `inner` with a propagation window of `t_secs` for active/revoked state
    /// and `negative_ttl_secs` for not-found/malformed negatives.
    ///
    /// `t_secs` is the documented revocation exposure window. `negative_ttl_secs`
    /// should be short (and `<= t_secs`) so rotation keys propagate promptly;
    /// values are clamped to non-negative.
    pub fn new(
        inner: Box<dyn TrustResolver + Send + Sync>,
        t_secs: i64,
        negative_ttl_secs: i64,
        clock: UnixClock,
    ) -> Self {
        BoundedTrustCache {
            inner,
            t_secs: t_secs.max(0),
            negative_ttl_secs: negative_ttl_secs.max(0),
            clock,
            cache: Mutex::new(HashMap::new()),
            writes_since_prune: Mutex::new(0),
            max_entries: MAX_CACHE_ENTRIES,
        }
    }

    /// Override the cache-entry ceiling (tests, and memory-constrained deployments).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Number of cached entries, expired and invalidated ones included
    /// (test/inspection aid).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// Whether the cache holds no entries.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Compose a COLLISION-SAFE cache key for a `(signer, key_id)` pair.
    ///
    /// A naive `"{signer}#{key_id}"` join is NOT injective: a `signer` or `key_id`
    /// containing the `#` delimiter aliases distinct pairs (e.g. `("a#b", "c")` and
    /// `("a", "b#c")` both compose to `"a#b#c"`). Signer strings are DIDs/URIs that
    /// legitimately contain `#`, so two different bindings could collide — and now
    /// that [`evict`](BoundedTrustCache::evict) keys off this for Tier-3
    /// invalidation, a collision could evict the WRONG entry or fail to evict the
    /// intended one, and Tier 1/3 could serve the wrong cached key. We length-prefix
    /// each field (in BYTES) so the encoding is unambiguous regardless of any
    /// delimiter the fields contain, guaranteeing injectivity. This is the SAME
    /// hardening as `mcp_re_core::InMemoryTrustResolver::compose_key` (the #79 fix).
    /// Every cache op (resolve/cached/store/evict) routes through this one function,
    /// so fixing it here fixes all sites.
    fn compose_key(signer: &str, key_id: &str) -> String {
        format!("{}:{}|{}:{}", signer.len(), signer, key_id.len(), key_id)
    }

    /// Look up a still-live cache entry. Returns the reconstructed result on a hit
    /// within the window, or `None` if the entry is absent, invalidated, or past its
    /// window — all three take the live re-resolution path. A poisoned cache mutex is an
    /// operational failure (fail closed): surfaced as `Some(Err(Unavailable))`.
    fn cached(&self, key: &str, now: i64) -> Option<Result<VerificationKey, TrustResolverError>> {
        let cache = match self.cache.lock() {
            Ok(c) => c,
            Err(e) => {
                return Some(Err(TrustResolverError::Unavailable {
                    details: format!("trust cache mutex poisoned: {e}"),
                }))
            }
        };
        let entry = cache.get(key)?;
        if entry.invalidated {
            return None;
        }
        if now < entry.expires_at {
            Some(entry.outcome.to_result())
        } else {
            None
        }
    }

    /// Store `outcome` for `key` with `ttl` seconds from `now`. A poisoned mutex
    /// drops the write (the request still gets its answer; only caching is lost).
    ///
    /// A write that replaces an INVALIDATED entry inherits that entry's expiry as a
    /// ceiling, so re-resolving a flushed or evicted binding can only shorten its
    /// cached life, never push the deadline out. An expiry that is not representable
    /// (`now + ttl` overflows) or that has already passed is not stored at all: the
    /// binding resolves live next time.
    fn store(&self, key: String, outcome: CachedOutcome, now: i64, ttl: i64) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        // Opportunistic sweep. Correctness never depended on eviction — an expired
        // entry is ignored on read — but memory did, and nothing called `prune`.
        if let Ok(mut writes) = self.writes_since_prune.lock() {
            *writes = writes.saturating_add(1);
            if *writes >= PRUNE_EVERY_N_WRITES {
                *writes = 0;
                cache.retain(|_, e| e.expires_at > now);
            }
        }
        let ceiling = cache
            .get(&key)
            .filter(|e| e.invalidated)
            .map(|e| e.expires_at);
        let Some(mut expires_at) = now.checked_add(ttl) else {
            return;
        };
        if let Some(deadline) = ceiling {
            expires_at = expires_at.min(deadline);
        }
        if expires_at <= now {
            cache.remove(&key);
            return;
        }
        // Past the ceiling, stop caching rather than grow. Skipping the write costs
        // a live resolution next time, which can only tighten trust — so unlike a
        // replay store, refusing to remember here is not a reason to refuse the
        // request.
        if cache.len() >= self.max_entries && !cache.contains_key(&key) {
            return;
        }
        cache.insert(
            key,
            CacheEntry {
                outcome,
                expires_at,
                invalidated: false,
            },
        );
    }

    /// Evict every entry whose window has closed (`expires_at <= now`). Opportunistic
    /// housekeeping; correctness does not depend on it (an expired entry is ignored
    /// on read), but it bounds memory for churny key sets.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn prune(&self, now: i64) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.retain(|_, e| e.expires_at > now);
        }
    }

    /// Immediately strip the cached entry for `(signer, key_id)` of its authority to
    /// answer, regardless of its remaining window. Returns `true` if a serving entry
    /// was present.
    ///
    /// This is the hook the ADR-MCPS-021 **Tier 3** push-invalidation cache uses to
    /// honor a pushed revocation event BEFORE `T` elapses: the next `resolve`
    /// re-consults the inner store (picking up the revocation) instead of serving a
    /// stale-but-within-`T` active entry. The entry's original expiry is kept as the
    /// ceiling for whatever replaces it, so an eviction cannot buy the binding a
    /// fresh window; an entry whose window has already closed is dropped outright.
    /// A poisoned cache mutex is treated as "nothing to evict" (the entry, if any, is
    /// unreachable anyway and the next read fails closed via
    /// [`cached`](BoundedTrustCache::cached)).
    pub fn evict(&self, signer: &str, key_id: &str) -> bool {
        let key = Self::compose_key(signer, key_id);
        let now = (self.clock)();
        let Ok(mut cache) = self.cache.lock() else {
            return false;
        };
        let state = cache.get(&key).map(|e| (e.invalidated, e.expires_at));
        let Some((invalidated, expires_at)) = state else {
            return false;
        };
        if expires_at <= now {
            cache.remove(&key);
            return false;
        }
        if invalidated {
            return false;
        }
        if let Some(entry) = cache.get_mut(&key) {
            entry.invalidated = true;
        }
        true
    }

    /// Invalidate ALL cached bindings (MCPS-84, ADR-MCPS-021 Tier-3 COARSE
    /// invalidation). A monotonic trust-epoch advance signals "something in the
    /// trust store changed" without naming the key, so the honest response is to
    /// strip every cached binding of its authority and force each subsequent lookup
    /// to re-resolve live against the inner store.
    ///
    /// Each invalidated binding keeps the expiry it already had as the ceiling for
    /// the entry that replaces it, which is what makes a flush TIGHTEN trust rather
    /// than widen it: the deadline by which a binding must be re-checked against the
    /// inner store is never pushed out by flushing. Bindings whose windows have
    /// already closed are dropped. Returns the number of serving entries
    /// invalidated. A poisoned lock invalidates nothing and returns 0 — the
    /// bounded-`T` fallback still caps the exposure window.
    pub fn clear(&self) -> usize {
        let now = (self.clock)();
        let Ok(mut cache) = self.cache.lock() else {
            return 0;
        };
        cache.retain(|_, e| e.expires_at > now);
        let mut invalidated = 0usize;
        for entry in cache.values_mut() {
            if !entry.invalidated {
                entry.invalidated = true;
                invalidated = invalidated.saturating_add(1); // bounded by the cache size
            }
        }
        invalidated
    }
}

impl TrustResolver for BoundedTrustCache {
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        let now = (self.clock)();
        let key = Self::compose_key(signer, key_id);

        // 1. Serve a cached answer while it is within its window. Active/revoked
        //    entries live `T`; not-found/malformed live the short negative TTL.
        if let Some(hit) = self.cached(&key, now) {
            return hit;
        }

        // 2. Cache miss or expired window: consult the inner resolver. Past `T`
        //    there is no live cache to serve, so an Unavailable here fails closed —
        //    a node never serves stale active trust beyond `T`, and a fresh process
        //    (empty cache) with an unreachable source fails closed.
        let result = self.inner.resolve(signer, key_id);

        // 3. Cache the answer per ADR-MCPS-021 classification.
        match &result {
            Ok(verification_key) => self.store(
                key,
                CachedOutcome::Active(verification_key.clone()),
                now,
                self.t_secs,
            ),
            Err(TrustResolverError::Revoked) => {
                self.store(key, CachedOutcome::Revoked, now, self.t_secs)
            }
            Err(TrustResolverError::NotFound) => {
                self.store(key, CachedOutcome::NotFound, now, self.negative_ttl_secs)
            }
            Err(TrustResolverError::MalformedKey) => {
                self.store(key, CachedOutcome::Malformed, now, self.negative_ttl_secs)
            }
            // Unavailable is an operational failure: NEVER cached, always fail closed.
            Err(TrustResolverError::Unavailable { .. }) => {}
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedTrustCache;
    use super::UnixClock;
    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;

    use mcp_re_core::SigningKey;
    use mcp_re_core::TrustResolver;
    use mcp_re_core::TrustResolverError;
    use mcp_re_core::VerificationKey;

    const SEED_A: [u8; 32] = [1u8; 32];
    const SEED_B: [u8; 32] = [2u8; 32];

    fn key_from(seed: &[u8; 32]) -> VerificationKey {
        SigningKey::from_seed_bytes(seed).public_key()
    }

    /// A programmable inner resolver: returns whatever outcome is currently set and
    /// counts how many times the inner `resolve` actually ran (to prove cache hits
    /// do NOT consult it). Send+Sync via interior `Mutex`/atomics.
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

    /// A clock whose "now" the test advances. Returned alongside a handle so the
    /// test can move time forward across the window boundary.
    fn controllable_clock(start: i64) -> (UnixClock, Arc<AtomicI64>) {
        let now = Arc::new(AtomicI64::new(start));
        let handle = now.clone();
        let clock: UnixClock = Box::new(move || now.load(Ordering::SeqCst));
        (clock, handle)
    }

    const T: i64 = 60;
    const NEG_TTL: i64 = 5;
    // The negative TTL must be strictly shorter than the active window, or the
    // "republished key is picked up early" tests below would prove nothing.
    const _: () = assert!(NEG_TTL < T);

    /// A shared inner resolver wrapped so the cache owns one box while the test
    /// keeps a handle to drive/inspect it.
    fn cache_over(inner: Arc<ScriptedResolver>, clock: UnixClock) -> BoundedTrustCache {
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
        BoundedTrustCache::new(Box::new(Shared(inner)), T, NEG_TTL, clock)
    }

    #[test]
    fn expired_entries_are_swept_rather_than_merely_ignored() {
        // An expired entry was ignored on read but never removed, and nothing called
        // `prune`. The keyid gate runs BEFORE trust resolution, so every distinct keyid
        // an unauthenticated peer presents left one permanent entry behind.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        for i in 0..(super::PRUNE_EVERY_N_WRITES - 1) {
            let _ = cache.resolve("did:host", &format!("key-{i}"));
        }
        assert_eq!(cache.len() as u64, super::PRUNE_EVERY_N_WRITES - 1);

        // Past T every one of those is dead. The next write triggers the sweep.
        now.store(1000 + T + 1, Ordering::SeqCst);
        let _ = cache.resolve("did:host", "key-live");
        assert_eq!(
            cache.len(),
            1,
            "only the entry written after the sweep survives"
        );
    }

    #[test]
    fn past_the_ceiling_the_cache_stops_caching_but_keeps_answering() {
        // Refusing to REMEMBER is safe here in a way refusing to remember a nonce is
        // not: the resolution still happens, the caller still gets its answer, and the
        // next lookup resolves live — which can only tighten trust, never widen it.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock).with_max_entries(3);

        for i in 0..3 {
            assert!(cache.resolve("did:host", &format!("key-{i}")).is_ok());
        }
        assert_eq!(cache.len(), 3);

        // Over the ceiling: still answered, just not remembered.
        let before = inner.calls();
        assert!(
            cache.resolve("did:host", "key-over").is_ok(),
            "the request must still get its answer"
        );
        assert_eq!(cache.len(), 3, "and the cache must not have grown");
        assert!(cache.resolve("did:host", "key-over").is_ok());
        assert_eq!(
            inner.calls(),
            before + 2,
            "an uncached key is re-resolved live each time — tighter, never looser"
        );

        // An ALREADY-cached key is still refreshed at the ceiling: the ceiling bounds
        // distinct keys, it must not freeze the entries already held.
        assert!(cache.resolve("did:host", "key-0").is_ok());
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn active_hit_within_window_does_not_consult_inner() {
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        let first = cache.resolve("did:host", "key-1").expect("active resolves");
        assert_eq!(first.to_bytes(), key_from(&SEED_A).to_bytes());
        // A second call within T is served from cache: inner consulted only once.
        let second = cache
            .resolve("did:host", "key-1")
            .expect("served from cache");
        assert_eq!(second.to_bytes(), key_from(&SEED_A).to_bytes());
        assert_eq!(
            inner.calls(),
            1,
            "within T the inner resolver is not re-consulted"
        );
    }

    #[test]
    fn active_re_resolves_after_window() {
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        cache.resolve("did:host", "key-1").expect("first resolve");
        // Past T the entry is stale: the inner resolver is consulted again, picking
        // up a rotated key.
        inner.set(Ok(key_from(&SEED_B)));
        now.store(1000 + T, Ordering::SeqCst); // exactly at expiry → no longer < expires_at
        let rotated = cache
            .resolve("did:host", "key-1")
            .expect("re-resolves past T");
        assert_eq!(rotated.to_bytes(), key_from(&SEED_B).to_bytes());
        assert_eq!(
            inner.calls(),
            2,
            "past T the inner resolver is consulted again"
        );
    }

    #[test]
    fn revoked_is_cached_and_denies() {
        let inner = Arc::new(ScriptedResolver::new(Err(TrustResolverError::Revoked)));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked
        );
        // Even if the inner flips to Active, the cached revoke denies within T.
        inner.set(Ok(key_from(&SEED_A)));
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "a cached safe-deny holds within T"
        );
        assert_eq!(inner.calls(), 1);
    }

    #[test]
    fn not_found_uses_short_ttl_so_a_new_key_propagates() {
        let inner = Arc::new(ScriptedResolver::new(Err(TrustResolverError::NotFound)));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::NotFound
        );
        // A freshly published key must be picked up after the SHORT negative TTL,
        // well before the full T would elapse.
        inner.set(Ok(key_from(&SEED_A)));
        now.store(1000 + NEG_TTL, Ordering::SeqCst);
        let resolved = cache
            .resolve("did:host", "key-1")
            .expect("a published key resolves after the short negative TTL");
        assert_eq!(resolved.to_bytes(), key_from(&SEED_A).to_bytes());
    }

    #[test]
    fn unavailable_is_not_cached_and_fails_closed() {
        let inner = Arc::new(ScriptedResolver::new(Err(
            TrustResolverError::Unavailable {
                details: "source down".to_string(),
            },
        )));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        assert!(matches!(
            cache.resolve("did:host", "key-1"),
            Err(TrustResolverError::Unavailable { .. })
        ));
        // Not cached: the next call consults the inner resolver again (no stale
        // "unavailable" decision is served).
        inner.set(Ok(key_from(&SEED_A)));
        let resolved = cache
            .resolve("did:host", "key-1")
            .expect("recovers when source returns");
        assert_eq!(resolved.to_bytes(), key_from(&SEED_A).to_bytes());
        assert_eq!(inner.calls(), 2, "Unavailable is never cached");
    }

    #[test]
    fn active_then_source_down_within_window_still_serves_cached() {
        // ADR-MCPS-021: a node MAY serve cached active state obtained before an
        // outage while still within T.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        cache.resolve("did:host", "key-1").expect("active cached");
        inner.set(Err(TrustResolverError::Unavailable {
            details: "outage".to_string(),
        }));
        now.store(1000 + T - 1, Ordering::SeqCst); // still within the window
        let served = cache
            .resolve("did:host", "key-1")
            .expect("within T the cached active state is served despite the outage");
        assert_eq!(served.to_bytes(), key_from(&SEED_A).to_bytes());
        assert_eq!(
            inner.calls(),
            1,
            "within T the down source is not consulted"
        );
    }

    #[test]
    fn no_indefinite_stale_active_past_window_fails_closed() {
        // The load-bearing safety property: past T with the source down, the cache
        // does NOT serve stale active trust — it fails closed.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        cache.resolve("did:host", "key-1").expect("active cached");
        inner.set(Err(TrustResolverError::Unavailable {
            details: "outage".to_string(),
        }));
        now.store(1000 + T, Ordering::SeqCst); // window closed
        assert!(
            matches!(
                cache.resolve("did:host", "key-1"),
                Err(TrustResolverError::Unavailable { .. })
            ),
            "past T the cache must NOT serve stale active trust; it fails closed"
        );
    }

    #[test]
    fn restart_empty_cache_with_source_down_fails_closed() {
        // A fresh process has an empty cache. With the source unreachable it cannot
        // resurrect any trust — it fails closed (no stale-trust resurrection).
        let inner = Arc::new(ScriptedResolver::new(Err(
            TrustResolverError::Unavailable {
                details: "source down at startup".to_string(),
            },
        )));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner, clock);

        assert!(matches!(
            cache.resolve("did:host", "key-1"),
            Err(TrustResolverError::Unavailable { .. })
        ));
    }

    #[test]
    fn evict_drops_an_in_window_entry_forcing_re_resolution() {
        // The Tier-3 hook: evict removes a still-in-window entry, so the next
        // resolve re-consults the inner store rather than serving the cached one.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        cache.resolve("did:host", "key-1").expect("active cached");
        assert_eq!(inner.calls(), 1);
        // Evicting an unrelated key reports false (nothing removed).
        assert!(!cache.evict("did:host", "key-other"));
        // Evicting the cached entry reports true and forces a re-resolve.
        assert!(cache.evict("did:host", "key-1"));
        inner.set(Err(TrustResolverError::Revoked));
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "after evict the next resolve re-consults the inner store"
        );
        assert_eq!(inner.calls(), 2);
    }

    #[test]
    fn compose_key_is_injective_across_delimiter_containing_pairs() {
        // Regression for the #79 collision class (mirrors mcp-re-core's
        // `composite_key_is_injective_across_delimiter_containing_pairs`).
        // `("a#b", "c")` and `("a", "b#c")` both collapse to `"a#b#c"` under a naive
        // `#` join. With the length-prefixed encoding they must NOT collide, so an
        // evict for one pair must not evict the other's cached entry.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        // Prime BOTH colliding-under-`#` pairs (the scripted inner returns the same
        // active key for either; what matters is that they occupy DISTINCT entries).
        cache
            .resolve("a#b", "c")
            .expect("(\"a#b\",\"c\") active cached");
        cache
            .resolve("a", "b#c")
            .expect("(\"a\",\"b#c\") active cached");
        assert_eq!(inner.calls(), 2, "two distinct pairs → two distinct misses");

        // Evicting one pair must report success and NOT touch the other.
        assert!(cache.evict("a#b", "c"), "the first pair's entry is present");
        // The other pair is still cached: a second resolve is a hit (no re-consult).
        cache
            .resolve("a", "b#c")
            .expect("the other pair is still cached");
        assert_eq!(
            inner.calls(),
            2,
            "evicting (\"a#b\",\"c\") must NOT evict (\"a\",\"b#c\")"
        );
        // And the evicted pair really was dropped: it re-consults the inner store.
        inner.set(Err(TrustResolverError::Revoked));
        assert_eq!(
            cache.resolve("a#b", "c").unwrap_err(),
            TrustResolverError::Revoked,
            "the evicted pair re-resolves (its entry was actually removed)"
        );
        assert_eq!(inner.calls(), 3);
    }

    #[test]
    fn a_flush_cannot_lengthen_a_cached_bindings_deadline() {
        // A coarse flush is only allowed to TIGHTEN trust. If the forced re-resolution
        // restarted the window, an operator hitting the trust-epoch kill switch would
        // push this replica's exposure to a revoked key PAST where it would have been
        // had they done nothing at all.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        // Cached at 1000, so the binding's deadline is 1000 + T.
        cache.resolve("did:host", "key-1").expect("active cached");
        // The flush lands mid-window while the binding is still active, so the forced
        // live resolution re-caches it.
        now.store(1010, Ordering::SeqCst);
        assert_eq!(cache.clear(), 1, "one serving entry was invalidated");
        cache
            .resolve("did:host", "key-1")
            .expect("re-resolved live");
        assert_eq!(inner.calls(), 2, "the flush forced a live resolution");

        // The store now revokes. At the ORIGINAL deadline the binding must be
        // re-checked and denied.
        inner.set(Err(TrustResolverError::Revoked));
        now.store(1000 + T, Ordering::SeqCst);
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "a flush may shorten a binding's cached life, never lengthen it"
        );
    }

    #[test]
    fn an_eviction_cannot_lengthen_the_evicted_bindings_deadline() {
        // Same tighten-only obligation for the targeted Tier-3 hook: evicting a
        // binding that the inner store still reports active must not buy it a fresh T.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner.clone(), clock);

        cache.resolve("did:host", "key-1").expect("active cached");
        now.store(1010, Ordering::SeqCst);
        assert!(
            cache.evict("did:host", "key-1"),
            "a serving entry was present"
        );
        cache
            .resolve("did:host", "key-1")
            .expect("re-resolved live");
        assert_eq!(inner.calls(), 2);

        inner.set(Err(TrustResolverError::Revoked));
        now.store(1000 + T, Ordering::SeqCst);
        assert_eq!(
            cache.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "an eviction may shorten a binding's cached life, never lengthen it"
        );
    }

    #[test]
    fn a_pre_epoch_clock_reading_closes_every_window_instead_of_freezing_it() {
        // A host clock before 1970 yields no representable Unix instant. Reading that
        // as instant 0 would place every entry written under a real clock inside its
        // window forever, so the cache would serve active trust indefinitely and never
        // re-consult the inner store.
        let unusable = super::unix_seconds(None);
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, _now) = controllable_clock(unusable);
        let cache = cache_over(inner.clone(), clock);

        for _ in 0..3 {
            cache
                .resolve("did:host", "key-1")
                .expect("the request still gets its answer");
        }
        assert_eq!(
            inner.calls(),
            3,
            "under an unusable clock every lookup must resolve live"
        );
        assert!(
            cache.is_empty(),
            "and an expiry that cannot be represented is not cached"
        );
    }

    #[test]
    fn prune_evicts_closed_windows() {
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let (clock, now) = controllable_clock(1000);
        let cache = cache_over(inner, clock);
        cache.resolve("did:host", "key-1").expect("cached");
        now.store(1000 + T + 1, Ordering::SeqCst);
        cache.prune(now.load(Ordering::SeqCst));
        // After prune the entry is gone; a fresh resolve re-consults the inner
        // resolver (proven indirectly: it still returns the active key).
        assert_eq!(
            cache
                .resolve("did:host", "key-1")
                .expect("re-resolves")
                .to_bytes(),
            key_from(&SEED_A).to_bytes()
        );
    }
}
