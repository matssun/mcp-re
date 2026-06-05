//! Replay detection (MCPS_SPEC §5 / ADR-006).
//!
//! Replay protection is a caller-injected [`ReplayCache`] keyed by the triple
//! `(signer, audience, nonce)`. In the `verify_request` pipeline it is invoked
//! **only after signature verification succeeds** (MCPS_SPEC §9 step 12), so
//! invalid-signature garbage can never burn a legitimate nonce.
//!
//! ## Decision vs. failure — fail closed
//!
//! The cache returns a [`ReplayDecision`] (`Fresh` | `Replay`) on success. It
//! deliberately does NOT bake the `mcps.replay_detected` verdict into itself:
//! the pipeline maps `Ok(ReplayDecision::Replay)` to
//! [`McpsError::ReplayDetected`]. An *operational* cache failure is a
//! [`ReplayCacheError`], which maps to [`McpsError::ReplayCacheUnavailable`]
//! (fail closed, distinct from a replay verdict — parallels
//! `trust_resolver_unavailable`). A cache failure NEVER falls back to "allow".
//!
//! ## Retention & distribution
//!
//! An entry must be retained until `expires_at + max_clock_skew`: once a
//! request can no longer pass the freshness window, its nonce can never be
//! validly replayed, so the entry may be pruned. The caller parses the
//! RFC 3339 `expires_at` into Unix seconds first and passes `expires_at_unix`
//! to [`ReplayCache::check_and_insert`]; the cache adds the skew to compute the
//! retain-until instant. In a distributed deployment the verifiers MUST share
//! replay state (a per-node in-memory cache does not prevent cross-node
//! replays); [`InMemoryReplayCache`] is a single-process reference only.

use std::collections::BTreeMap;

use crate::error::McpsError;

/// The outcome of a replay-cache lookup-and-insert.
///
/// The cache returns this on success; the pipeline maps
/// [`ReplayDecision::Replay`] to [`McpsError::ReplayDetected`] (MCPS_SPEC §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDecision {
    /// The `(signer, audience, nonce)` triple was not previously seen; it has
    /// now been inserted. The request may proceed.
    Fresh,
    /// The triple was already present (and not pruned): a replay. The pipeline
    /// turns this into [`McpsError::ReplayDetected`].
    Replay,
}

/// An operational failure of a [`ReplayCache`] (distinct from a replay verdict).
///
/// Maps to [`McpsError::ReplayCacheUnavailable`] via
/// [`to_mcps_error`](ReplayCacheError::to_mcps_error) / the `From` impl. A
/// failure here fails closed and NEVER falls back to "allow".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayCacheError {
    /// The backing store could not be reached or otherwise failed to answer.
    /// → [`McpsError::ReplayCacheUnavailable`].
    #[error("replay cache unavailable: {details}")]
    Unavailable {
        /// Human-readable diagnostic; never part of any wire token.
        details: String,
    },
}

impl ReplayCacheError {
    /// Map this operational failure to its frozen [`McpsError`] (MCPS_SPEC §5/§8).
    ///
    /// Always [`McpsError::ReplayCacheUnavailable`] — fail closed, never "allow".
    pub fn to_mcps_error(&self) -> McpsError {
        match self {
            ReplayCacheError::Unavailable { .. } => McpsError::ReplayCacheUnavailable,
        }
    }
}

impl From<ReplayCacheError> for McpsError {
    fn from(err: ReplayCacheError) -> McpsError {
        err.to_mcps_error()
    }
}

/// The replay-detection injection point (MCPS_SPEC §5 / ADR-006).
///
/// Implementations are keyed by `(signer, audience, nonce)` and are consulted
/// only after signature verification. `expires_at_unix` is the request's
/// `expires_at` already parsed to Unix seconds; the implementation computes its
/// retain-until as `expires_at_unix + max_clock_skew`.
///
/// Returns `Ok(ReplayDecision::Fresh)` when the triple is newly recorded,
/// `Ok(ReplayDecision::Replay)` when it was already present, or
/// `Err(ReplayCacheError)` on an operational failure (→
/// [`McpsError::ReplayCacheUnavailable`], fail closed).
pub trait ReplayCache {
    /// Atomically check whether `(signer, audience, nonce)` was already seen and
    /// record it if not.
    fn check_and_insert(
        &mut self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError>;
}

/// Deterministic, [`BTreeMap`]-backed reference [`ReplayCache`] for tests and
/// conformance vectors (MCPS_SPEC §5).
///
/// Keyed by the `(signer, audience, nonce)` triple. Each recorded entry carries
/// a `retain_until = expires_at_unix + max_clock_skew_secs` instant; an entry
/// is considered live until that instant. Pruning is explicit (see
/// [`prune`](InMemoryReplayCache::prune)) — there is NO background clock, so the
/// cache stays pure and deterministic. This reference impl never returns
/// `Err`: in a single process the lookup always succeeds.
///
/// A distributed deployment MUST share replay state across verifiers; this
/// per-process cache does not prevent cross-node replays.
#[derive(Debug, Clone)]
pub struct InMemoryReplayCache {
    /// Symmetric clock skew added to `expires_at_unix` to compute retain-until.
    max_clock_skew_secs: i64,
    /// `(signer, audience, nonce)` -> retain-until Unix seconds.
    seen: BTreeMap<(String, String, String), i64>,
}

impl InMemoryReplayCache {
    /// Construct an empty cache with the symmetric `max_clock_skew_secs` used to
    /// compute each entry's retain-until.
    pub fn new(max_clock_skew_secs: i64) -> Self {
        InMemoryReplayCache {
            max_clock_skew_secs,
            seen: BTreeMap::new(),
        }
    }

    /// Evict every entry whose `retain_until < now_unix`.
    ///
    /// After eviction a previously-seen triple becomes [`ReplayDecision::Fresh`]
    /// again — by which point it can no longer pass the freshness window, so
    /// readmitting its nonce is safe. Pruning is explicit and side-effect free
    /// beyond the eviction itself, keeping the cache deterministic.
    pub fn prune(&mut self, now_unix: i64) {
        self.seen.retain(|_, &mut retain_until| retain_until >= now_unix);
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_insert(
        &mut self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        let key = (
            signer.to_string(),
            audience.to_string(),
            nonce.to_string(),
        );
        if self.seen.contains_key(&key) {
            return Ok(ReplayDecision::Replay);
        }
        let retain_until = expires_at_unix.saturating_add(self.max_clock_skew_secs);
        self.seen.insert(key, retain_until);
        Ok(ReplayDecision::Fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryReplayCache;
    use super::ReplayCache;
    use super::ReplayCacheError;
    use super::ReplayDecision;
    use crate::error::McpsError;

    const SIGNER: &str = "did:example:host";
    const AUD: &str = "did:example:verifier";
    const NONCE: &str = "nonce-aaaaaaaaaaaaaaaaaaaaaa";
    const EXPIRES: i64 = 1_779_998_700; // an arbitrary fixed epoch
    const SKEW: i64 = 30;

    /// A test-only cache whose every call is an operational failure. Exercises
    /// the [`McpsError::ReplayCacheUnavailable`] mapping (the in-memory
    /// reference cache has no failure path).
    struct AlwaysUnavailableReplayCache;

    impl ReplayCache for AlwaysUnavailableReplayCache {
        fn check_and_insert(
            &mut self,
            _signer: &str,
            _audience: &str,
            _nonce: &str,
            _expires_at_unix: i64,
        ) -> Result<ReplayDecision, ReplayCacheError> {
            Err(ReplayCacheError::Unavailable {
                details: "backing store unreachable".to_string(),
            })
        }
    }

    #[test]
    fn first_insert_is_fresh() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn same_triple_again_is_replay() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
    }

    #[test]
    fn different_audience_same_nonce_is_fresh() {
        // Multi-tenant keying: the same nonce under a different audience is a
        // distinct key and must NOT be flagged as a replay.
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert(SIGNER, "did:example:other-verifier", NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn different_signer_same_nonce_is_fresh() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        assert_eq!(
            cache.check_and_insert("did:example:other-host", AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn prune_after_retain_until_readmits_triple() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        // retain_until == EXPIRES + SKEW. Pruning strictly past it evicts.
        let retain_until = EXPIRES + SKEW;
        // Pruning AT retain_until keeps the entry (retain_until >= now).
        cache.prune(retain_until);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Replay)
        );
        // Pruning strictly past retain_until evicts -> triple is Fresh again.
        cache.prune(retain_until + 1);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn in_memory_cache_never_errors() {
        let mut cache = InMemoryReplayCache::new(SKEW);
        // Any number of distinct inserts succeed without an operational failure.
        for i in 0..5 {
            let nonce = format!("nonce-{i:022}");
            assert!(cache.check_and_insert(SIGNER, AUD, &nonce, EXPIRES).is_ok());
        }
    }

    #[test]
    fn operational_failure_maps_to_replay_cache_unavailable() {
        let mut cache = AlwaysUnavailableReplayCache;
        let err = cache
            .check_and_insert(SIGNER, AUD, NONCE, EXPIRES)
            .expect_err("always-unavailable cache must fail");
        assert_eq!(err.to_mcps_error(), McpsError::ReplayCacheUnavailable);
        // The `From` impl agrees.
        assert_eq!(McpsError::from(err), McpsError::ReplayCacheUnavailable);
    }
}
