//! Replay detection (MCP_RE_SPEC §5 / ADR-006).
//!
//! Replay protection is a caller-injected [`ReplayCache`] keyed by the triple
//! `(signer, audience, nonce)`. In the `verify_request` pipeline it is invoked
//! **only after signature verification succeeds** (MCP_RE_SPEC §9 step 12), so
//! invalid-signature garbage can never burn a legitimate nonce.
//!
//! ## Decision vs. failure — fail closed
//!
//! The cache returns a [`ReplayDecision`] (`Fresh` | `Replay`) on success. It
//! deliberately does NOT bake the `mcp-re.replay_detected` verdict into itself:
//! the pipeline maps `Ok(ReplayDecision::Replay)` to
//! [`McpReError::ReplayDetected`]. An *operational* cache failure is a
//! [`ReplayCacheError`], which maps to [`McpReError::ReplayCacheUnavailable`]
//! (fail closed, distinct from a replay verdict — parallels
//! `trust_resolver_unavailable`). A cache failure NEVER falls back to "allow".
//!
//! Every failure the reference cache owns is such an error VALUE, not a panic: a
//! poisoned lock and the entry ceiling both produce
//! [`ReplayCacheError::Unavailable`], so a single panic elsewhere cannot convert a
//! per-request refusal into a worker-terminating panic on every later request.
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
//!
//! ## Self-declared durability — machine-checkable, not just documented
//!
//! "Single-process reference only" is no longer prose alone: every
//! [`ReplayCache`] self-declares a [`ReplayDurabilityClass`] via
//! [`ReplayCache::durability_class`], defaulting (fail closed) to
//! [`ReplayDurabilityClass::SingleProcessReference`]. [`InMemoryReplayCache`]
//! honestly reports the single-process class, so the wiring layer can MACHINE-
//! CHECK the cache object it actually holds and refuse to run the volatile
//! reference cache on a production verify path — rather than relying on the
//! operator picking the right backend. This is a PURE, type-level capability;
//! `mcp-re-core` adds no clock, I/O, or networking (ADR-MCPS-011/012). Cross-node
//! strength beyond mere durability is still asserted by the proxy's
//! `ReplayDurabilityTier` (ADR-MCPS-020).

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::error::McpReError;

/// A [`ReplayCache`]'s self-declared durability posture (ADR-MCPS-020).
///
/// This is a PURE, type-level capability: `mcp-re-core` carries no clock, no I/O,
/// and no networking (ADR-MCPS-011/012), so this enum says nothing about *how* a
/// cache is durable — only whether the implementation asserts it survives the
/// volatility that makes the single-process reference cache unsafe in production.
///
/// It exists so the wiring layer can MACHINE-CHECK the cache it actually holds,
/// rather than inferring durability from which constructor the operator happened
/// to pick. The default ([`ReplayCache::durability_class`] returns
/// [`ReplayDurabilityClass::SingleProcessReference`]) is the conservative one: a
/// cache that does not explicitly declare itself durable is treated as the
/// non-durable reference, so an unknown or forgetful implementation can never
/// silently masquerade as a production replay store (fail closed).
///
/// `Durable` is a NECESSARY, not sufficient, condition for a production
/// horizontal deployment: cross-node strength is asserted separately by the
/// proxy's `ReplayDurabilityTier` (ADR-MCPS-020). A cache may be `Durable`
/// (survives restart) yet single-node; the tier check governs the horizontal
/// claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDurabilityClass {
    /// The cache keeps admitted `(signer, audience, nonce)` triples only in
    /// process memory. A process restart forgets every admitted nonce and a
    /// per-node instance is invisible to its peers — so it neither survives
    /// restart nor prevents cross-node replays. This is the
    /// [`InMemoryReplayCache`] reference posture: correct for tests, conformance
    /// vectors, and single-node dev, but NOT a production replay store.
    SingleProcessReference,
    /// The implementation asserts its admitted nonces outlive the process (a
    /// durable single-node store) and/or are shared across verifier instances.
    /// This is the minimum class a strict/production wiring layer accepts before
    /// it then applies the horizontal `ReplayDurabilityTier` check.
    Durable,
}

/// The outcome of a replay-cache lookup-and-insert.
///
/// The cache returns this on success; the pipeline maps
/// [`ReplayDecision::Replay`] to [`McpReError::ReplayDetected`] (MCP_RE_SPEC §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDecision {
    /// The `(signer, audience, nonce)` triple was not previously seen; it has
    /// now been inserted. The request may proceed.
    Fresh,
    /// The triple was already present (and not pruned): a replay. The pipeline
    /// turns this into [`McpReError::ReplayDetected`].
    Replay,
}

/// The replay key handed to the authoritative replay tier for the atomic
/// insert-if-absent: the `(signer, audience, nonce)` logical identity fixed by the
/// active profile, plus the parsed `expires_at`. Profile-agnostic — the RFC 9421
/// HTTP profile projects its ratified five-tuple onto these three slots
/// (`HttpReplayKey::to_core_replay_key`) and the async tier consumes THIS type, so
/// the stored composite key is identical across the sync and async admission
/// paths. `expires_at_unix` is the RAW parsed `expires_at`; the tier folds in the
/// clock skew when it derives the store TTL (`retain_until = expires_at + skew`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayKey {
    /// The verified request signer identity.
    pub signer: String,
    /// The verified PRINCIPAL the entry is accounted to, which is not the same string
    /// as [`ReplayKey::signer`].
    ///
    /// `signer` must discriminate every distinct key, so it carries the keyid — two
    /// keys of one subject must never collapse onto one replay key. An occupancy
    /// budget wants the opposite: charging per key hands a subject one budget per key
    /// it holds, which is routine during rotation and in a fleet issuing a client key
    /// per replica, so a single subject would both multiply its own allowance and
    /// inflate the divisor every other principal is measured against.
    pub principal: String,
    /// The verified request audience.
    pub audience: String,
    /// The request nonce.
    pub nonce: String,
    /// The parsed `expires_at` (Unix seconds), pre-skew-fold.
    pub expires_at_unix: i64,
}

/// An operational failure of a [`ReplayCache`] (distinct from a replay verdict).
///
/// Maps to [`McpReError::ReplayCacheUnavailable`] via
/// [`to_mcp_re_error`](ReplayCacheError::to_mcp_re_error) / the `From` impl. A
/// failure here fails closed and NEVER falls back to "allow".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayCacheError {
    /// The backing store could not be reached or otherwise failed to answer.
    /// → [`McpReError::ReplayCacheUnavailable`].
    #[error("replay cache unavailable: {details}")]
    Unavailable {
        /// Human-readable diagnostic; never part of any wire token.
        details: String,
    },
}

impl ReplayCacheError {
    /// Map this operational failure to its frozen [`McpReError`] (MCP_RE_SPEC §5/§8).
    ///
    /// Always [`McpReError::ReplayCacheUnavailable`] — fail closed, never "allow".
    pub fn to_mcp_re_error(&self) -> McpReError {
        match self {
            ReplayCacheError::Unavailable { .. } => McpReError::ReplayCacheUnavailable,
        }
    }
}

impl From<ReplayCacheError> for McpReError {
    fn from(err: ReplayCacheError) -> McpReError {
        err.to_mcp_re_error()
    }
}

/// The replay-detection injection point (MCP_RE_SPEC §5 / ADR-006).
///
/// Implementations are keyed by `(signer, audience, nonce)` and are consulted
/// only after signature verification. `expires_at_unix` is the request's
/// `expires_at` already parsed to Unix seconds; the implementation computes its
/// retain-until as `expires_at_unix + max_clock_skew`.
///
/// Returns `Ok(ReplayDecision::Fresh)` when the triple is newly recorded,
/// `Ok(ReplayDecision::Replay)` when it was already present, or
/// `Err(ReplayCacheError)` on an operational failure (→
/// [`McpReError::ReplayCacheUnavailable`], fail closed).
pub trait ReplayCache {
    /// Atomically check whether `(signer, audience, nonce)` was already seen and
    /// record it if not.
    ///
    /// Takes `&self` (not `&mut self`): a replay cache is a shared coherent tier
    /// consulted concurrently by many per-core serving tasks (ADR-MCPRE-051 §2),
    /// so implementations carry interior synchronization — the shared/atomic
    /// stores already do, and the in-memory reference cache locks its map. This
    /// is what lets a single `Proxy` be `Send + Sync` and shared across cores.
    fn check_and_insert(
        &self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError>;

    /// This cache's self-declared durability posture (ADR-MCPS-020).
    ///
    /// The wiring layer machine-checks THIS — the durability of the cache object
    /// it actually holds — instead of inferring production-readiness from which
    /// constructor was selected. The default is the conservative
    /// [`ReplayDurabilityClass::SingleProcessReference`]: a cache that does not
    /// explicitly override this is treated as non-durable, so a new or forgetful
    /// implementation can never silently pass a strict/production durability gate
    /// (fail closed). A durable implementation MUST override this to honestly
    /// return [`ReplayDurabilityClass::Durable`].
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::SingleProcessReference
    }

    /// Whether this cache is the single-process, volatile reference posture
    /// ([`ReplayDurabilityClass::SingleProcessReference`]) — `true` for
    /// [`InMemoryReplayCache`] and for any implementation that has not declared
    /// itself durable. A strict/production wiring layer rejects a cache for which
    /// this is `true`.
    fn is_single_process_reference(&self) -> bool {
        self.durability_class() == ReplayDurabilityClass::SingleProcessReference
    }
}

/// Deterministic, [`BTreeMap`]-backed reference [`ReplayCache`] for tests and
/// conformance vectors (MCP_RE_SPEC §5).
///
/// Keyed by the `(signer, audience, nonce)` triple. Each recorded entry carries
/// a `retain_until = expires_at_unix + max_clock_skew_secs` instant; an entry
/// is considered live until that instant. Pruning is explicit (see
/// [`prune`](InMemoryReplayCache::prune)) — there is NO background clock, so the
/// cache stays pure and deterministic.
///
/// **Pruning is the embedder's obligation, and forgetting it fails closed.** The
/// retained set grows by one entry per admitted request, and a signature-valid peer
/// streaming distinct fresh nonces drives that growth at will — so an embedder that
/// takes the docs at their word and never schedules [`prune`] would otherwise have a
/// remotely-driven memory leak. Past [`MAX_ENTRIES`] the cache therefore refuses
/// further inserts with [`ReplayCacheError::Unavailable`] (→
/// `mcp-re.replay_cache_unavailable`) rather than growing without bound. Refusing is
/// never "allow": a request that cannot be recorded is not admitted.
///
/// This is the same fail-closed ceiling the proxy's file-backed cache carries. It is
/// only a ceiling here, not an inline prune: the proxy anchors its inline eviction on
/// a real clock, and this crate has none by design (`expires_at_unix` cannot stand in
/// — freshness only bounds `now <= expires_at + skew`, so it may sit arbitrarily far
/// ahead of real time and would over-evict live entries, reopening a replay window).
///
/// A distributed deployment MUST share replay state across verifiers; this
/// per-process cache does not prevent cross-node replays.
#[derive(Debug)]
pub struct InMemoryReplayCache {
    /// Symmetric clock skew added to `expires_at_unix` to compute retain-until.
    max_clock_skew_secs: i64,
    /// Fail-closed ceiling on retained entries; see [`MAX_ENTRIES`].
    max_entries: usize,
    /// `(signer, audience, nonce)` -> retain-until Unix seconds.
    ///
    /// Behind a [`Mutex`] so `check_and_insert` and `prune` take `&self`
    /// (ADR-MCPRE-051 §2): the reference cache carries the same interior
    /// synchronization as [`InMemoryAtomicReplayStore`], letting a shared
    /// `Proxy` be `Send + Sync` across per-core serving tasks. The lock is held
    /// only for the O(log n) map op; the check-and-insert stays atomic.
    seen: Mutex<BTreeMap<(String, String, String), i64>>,
}

impl Clone for InMemoryReplayCache {
    /// Deep, independent copy of the seen-set (the reference cache is not a
    /// shared handle — cloning yields a private map, unlike the `Arc`-shared
    /// [`InMemoryAtomicReplayStore`]).
    ///
    /// `Clone` has no error channel, and a poisoned lock makes the seen-set
    /// unreadable. Copying an empty map would be the one unsafe answer — it
    /// readmits every nonce the source had recorded — so a clone of a poisoned
    /// cache is built with a zero entry ceiling instead: it admits nothing and
    /// answers every `check_and_insert` with [`ReplayCacheError::Unavailable`].
    fn clone(&self) -> Self {
        let Ok(seen) = self.seen.lock() else {
            return InMemoryReplayCache {
                max_clock_skew_secs: self.max_clock_skew_secs,
                max_entries: 0,
                seen: Mutex::new(BTreeMap::new()),
            };
        };
        InMemoryReplayCache {
            max_clock_skew_secs: self.max_clock_skew_secs,
            max_entries: self.max_entries,
            seen: Mutex::new(seen.clone()),
        }
    }
}

/// Fail-closed ceiling on entries retained by [`InMemoryReplayCache`].
///
/// A signature-valid peer streaming distinct fresh nonces adds one entry per request,
/// so without a ceiling the only thing bounding the set is the embedder remembering
/// to call [`InMemoryReplayCache::prune`]. Past this many entries the cache refuses
/// to admit more — `mcp-re.replay_cache_unavailable`, fail closed — and the freshness
/// window drains the backlog as the embedder prunes.
pub const MAX_ENTRIES: usize = 1_000_000;

impl InMemoryReplayCache {
    /// Construct an empty cache with the symmetric `max_clock_skew_secs` used to
    /// compute each entry's retain-until.
    pub fn new(max_clock_skew_secs: i64) -> Self {
        InMemoryReplayCache {
            max_clock_skew_secs,
            max_entries: MAX_ENTRIES,
            seen: Mutex::new(BTreeMap::new()),
        }
    }

    /// Override the fail-closed entry ceiling. Lets a bounded embedder pick a limit
    /// that fits its memory budget, and lets a test exercise the ceiling without
    /// inserting [`MAX_ENTRIES`] real entries.
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Number of retained entries (test/inspection aid). A poisoned lock counts
    /// as 0 — this is an inspection aid, never an admission decision.
    pub fn len(&self) -> usize {
        self.seen.lock().map(|seen| seen.len()).unwrap_or(0)
    }

    /// Whether the cache retains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Evict every entry whose `retain_until < now_unix`.
    ///
    /// After eviction a previously-seen triple becomes [`ReplayDecision::Fresh`]
    /// again — by which point it can no longer pass the freshness window, so
    /// readmitting its nonce is safe. Pruning is explicit and side-effect free
    /// beyond the eviction itself, keeping the cache deterministic. Takes
    /// `&self` via the interior [`Mutex`].
    ///
    /// A poisoned lock evicts nothing: eviction is the only operation here that
    /// can readmit a nonce, so an unreadable seen-set retains its entries rather
    /// than being cleared on a lock this call cannot trust.
    pub fn prune(&self, now_unix: i64) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.retain(|_, &mut retain_until| retain_until >= now_unix);
        }
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_insert(
        &self,
        signer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        let key = (signer.to_string(), audience.to_string(), nonce.to_string());
        // The check-and-insert is atomic: the lock spans both the presence
        // check and the insert, so two concurrent callers racing the same
        // triple cannot both observe it absent (exactly one `Fresh`).
        // A poisoned lock is an operational failure like any other: an error
        // value, never a panic and never an admit. Panicking would terminate the
        // serving task and leave every later caller panicking on the same lock
        // instead of receiving the frozen unavailable verdict.
        let mut seen = self
            .seen
            .lock()
            .map_err(|e| ReplayCacheError::Unavailable {
                details: format!("in-memory replay cache mutex poisoned: {e}"),
            })?;
        if seen.contains_key(&key) {
            return Ok(ReplayDecision::Replay);
        }
        // Fail-closed ceiling: refuse rather than grow without bound. Admitting a
        // request we cannot record would be the one unsafe option — a nonce that is
        // not retained can be replayed — so this is `Unavailable`, never `Fresh`.
        if seen.len() >= self.max_entries {
            return Err(ReplayCacheError::Unavailable {
                details: format!(
                    "in-memory replay cache is at its {} entry ceiling; \
                     call prune(now) to evict entries past their retain-until",
                    self.max_entries
                ),
            });
        }
        let retain_until = expires_at_unix.saturating_add(self.max_clock_skew_secs);
        seen.insert(key, retain_until);
        Ok(ReplayDecision::Fresh)
    }

    /// Honestly declares the single-process reference posture. Admitted nonces
    /// live only in this process's `BTreeMap`: a restart forgets them and a
    /// per-node instance is invisible to peers, so this cache neither survives
    /// restart nor prevents cross-node replays (ADR-MCPS-020). Declared
    /// explicitly (not left to the trait default) so the honesty is local to the
    /// reference impl and cannot drift if the default ever changes.
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::SingleProcessReference
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryReplayCache;
    use super::ReplayCache;
    use super::ReplayCacheError;
    use super::ReplayDecision;
    use super::ReplayDurabilityClass;
    use crate::error::McpReError;

    const SIGNER: &str = "did:example:host";
    const AUD: &str = "did:example:verifier";
    const NONCE: &str = "nonce-aaaaaaaaaaaaaaaaaaaaaa";
    const EXPIRES: i64 = 1_779_998_700; // an arbitrary fixed epoch
    const SKEW: i64 = 30;

    /// A test-only cache whose every call is an operational failure, and which
    /// implements only `check_and_insert` — so it exercises both the
    /// [`McpReError::ReplayCacheUnavailable`] mapping and the trait's
    /// default-only durability path.
    struct AlwaysUnavailableReplayCache;

    impl ReplayCache for AlwaysUnavailableReplayCache {
        fn check_and_insert(
            &self,
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
    fn the_entry_ceiling_refuses_rather_than_growing_without_bound() {
        // A signature-valid peer streaming distinct fresh nonces adds one entry per
        // request. Without a ceiling the only bound is the embedder remembering to
        // prune — so the failure mode was a remotely-driven memory leak in the crate
        // that DEFINES the contract.
        let cache = InMemoryReplayCache::new(SKEW).with_max_entries(3);
        for i in 0..3 {
            assert_eq!(
                cache.check_and_insert(SIGNER, AUD, &format!("nonce-{i}"), EXPIRES),
                Ok(ReplayDecision::Fresh)
            );
        }
        let refused = cache.check_and_insert(SIGNER, AUD, "nonce-over", EXPIRES);
        assert!(
            matches!(refused, Err(ReplayCacheError::Unavailable { .. })),
            "past the ceiling the cache must refuse, got {refused:?}"
        );
        // Fail CLOSED: the refusal maps to the frozen unavailable token, never an allow.
        assert_eq!(
            refused.unwrap_err().to_mcp_re_error(),
            McpReError::ReplayCacheUnavailable
        );
        assert_eq!(cache.len(), 3, "the refused entry was not recorded");

        // An already-seen nonce is still reported as a replay at the ceiling: refusing
        // to GROW must not turn a known replay into an unknown one.
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, "nonce-0", EXPIRES),
            Ok(ReplayDecision::Replay)
        );

        // Pruning drains the backlog and the cache admits again.
        cache.prune(EXPIRES + SKEW + 1);
        assert!(cache.is_empty());
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, "nonce-over", EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn first_insert_is_fresh() {
        let cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
    }

    #[test]
    fn same_triple_again_is_replay() {
        let cache = InMemoryReplayCache::new(SKEW);
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
        let cache = InMemoryReplayCache::new(SKEW);
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
        let cache = InMemoryReplayCache::new(SKEW);
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
        let cache = InMemoryReplayCache::new(SKEW);
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
    fn distinct_inserts_below_the_ceiling_do_not_error() {
        let cache = InMemoryReplayCache::new(SKEW);
        for i in 0..5 {
            let nonce = format!("nonce-{i:022}");
            assert!(cache.check_and_insert(SIGNER, AUD, &nonce, EXPIRES).is_ok());
        }
    }

    /// Poison `cache.seen` by panicking while its guard is held.
    fn poison(cache: &InMemoryReplayCache) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = cache.seen.lock().expect("not yet poisoned");
            panic!("poisoning the replay cache on purpose");
        }));
        assert!(cache.seen.lock().is_err(), "the lock must now be poisoned");
    }

    #[test]
    fn a_poisoned_lock_refuses_as_unavailable_rather_than_panicking() {
        // Poison is sticky: a cache that panics on a poisoned lock panics for every
        // later caller too, terminating serving tasks instead of returning the frozen
        // `mcp-re.replay_cache_unavailable` verdict this tier owes its pipeline.
        let cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        poison(&cache);

        for attempt in 0..2 {
            let nonce = format!("nonce-{attempt}");
            let refused = cache.check_and_insert(SIGNER, AUD, &nonce, EXPIRES);
            assert!(
                matches!(refused, Err(ReplayCacheError::Unavailable { .. })),
                "attempt {attempt} must refuse as Unavailable, got {refused:?}"
            );
            assert_eq!(
                refused.unwrap_err().to_mcp_re_error(),
                McpReError::ReplayCacheUnavailable
            );
        }
        // An already-recorded triple is refused too — never admitted off an
        // unreadable seen-set.
        assert!(cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES).is_err());
        // The inspection aids stay total.
        cache.prune(EXPIRES + SKEW + 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_clone_of_a_poisoned_cache_admits_nothing() {
        let cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.check_and_insert(SIGNER, AUD, NONCE, EXPIRES),
            Ok(ReplayDecision::Fresh)
        );
        poison(&cache);

        // `Clone` cannot report the failure, and cannot read the seen-set either — so
        // the copy must refuse admissions rather than start out empty and readmit
        // every nonce the source had recorded.
        let copy = cache.clone();
        let refused = copy.check_and_insert(SIGNER, AUD, NONCE, EXPIRES);
        assert!(
            matches!(refused, Err(ReplayCacheError::Unavailable { .. })),
            "the copy must refuse, got {refused:?}"
        );
        assert_eq!(
            refused.unwrap_err().to_mcp_re_error(),
            McpReError::ReplayCacheUnavailable
        );
        let second = copy.check_and_insert(SIGNER, AUD, "another-nonce", EXPIRES);
        assert!(
            second.is_err(),
            "the copy must refuse every nonce, got {second:?}"
        );
    }

    #[test]
    fn in_memory_reference_declares_single_process_non_durable() {
        // ADR-MCPS-020 (#78): the reference cache must honestly self-declare the
        // single-process, volatile posture so a strict/production wiring layer can
        // machine-check the cache OBJECT it holds, rather than trusting the
        // operator to pick the right backend. A regression here (declaring itself
        // Durable) would silently re-open the cross-node / restart replay window
        // this marker exists to gate.
        let cache = InMemoryReplayCache::new(SKEW);
        assert_eq!(
            cache.durability_class(),
            ReplayDurabilityClass::SingleProcessReference
        );
        assert!(cache.is_single_process_reference());
    }

    #[test]
    fn durability_class_defaults_to_single_process_reference() {
        // A cache that implements ONLY check_and_insert (forgetting to declare a
        // durability posture) must be treated as the non-durable reference, NOT as
        // durable — fail closed. AlwaysUnavailableReplayCache exercises exactly the
        // default-only path.
        let cache = AlwaysUnavailableReplayCache;
        assert_eq!(
            cache.durability_class(),
            ReplayDurabilityClass::SingleProcessReference
        );
        assert!(cache.is_single_process_reference());
    }

    #[test]
    fn operational_failure_maps_to_replay_cache_unavailable() {
        let cache = AlwaysUnavailableReplayCache;
        let err = cache
            .check_and_insert(SIGNER, AUD, NONCE, EXPIRES)
            .expect_err("always-unavailable cache must fail");
        assert_eq!(err.to_mcp_re_error(), McpReError::ReplayCacheUnavailable);
        // The `From` impl agrees.
        assert_eq!(McpReError::from(err), McpReError::ReplayCacheUnavailable);
    }
}
