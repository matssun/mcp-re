//! MCPRE-117 (ADR-MCPRE-051 §4, Phase 2) — the ASYNC authoritative replay tier seam.
//!
//! The async data plane (MCPRE-113) serves on per-core `tokio` runtimes, so the
//! replay check on the request path must NOT block a runtime worker on store I/O.
//! This module defines the async analogue of `shared_replay::AtomicReplayStore`:
//!
//!   * [`AsyncAtomicReplayStore`] — the authoritative L2 contract, one async op
//!     *insert-if-absent-with-TTL* (`atomic_insert_if_absent`). Concrete backends
//!     (async Redis `SET NX PX`, async etcd CAS) implement it without blocking the
//!     request path; the in-memory [`InMemoryAsyncAtomicReplayStore`] is the
//!     default-build reference.
//!   * [`L1FastRejectStore`] — a per-core L1 optimization in front of the shared L2,
//!     **defined and DORMANT**. `app.rs` installs the L2 directly on every backend, so
//!     the two-tier architecture is not what runs today and every request pays a full L2
//!     round trip. That is a dormancy rather than a wiring defect: no configuration
//!     surface, theorem or specification claims an L1 is in force, and the L1 can only
//!     ever fast-REJECT. Its own module documents the census.
//!
//! Fail-closed posture (ADR-MCPS-020, unchanged): any L2 operational failure surfaces
//! as [`ReplayStoreError::Unavailable`] ⇒ `mcp-re.replay_cache_unavailable`, never a
//! silent "allow".
//!
//! # What lives where
//!
//! | module | authority |
//! |---|---|
//! | this one | the seam, and the [`AsyncReplayTier`] the serving path awaits |
//! | [`bounds`] | how much retention there is, and whose share of it one actor may hold |
//! | [`retained_set`] | what the reference L2 is holding, and how it stops holding it |
//! | [`local_refusals`] | when the reference L2 says no instead of recording |
//! | [`in_memory`] | the reference L2 itself: the atomic op under its lock |
//! | [`retention_ledger`] | the per-replica account, above the backend seam |
//! | [`charge`] | one reservation against that account, and the three ways it ends |
//! | [`l1_fast_reject`] | the dormant per-core L1 |

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use mcp_re_core::ReplayCacheError;
use mcp_re_core::ReplayDecision;
use mcp_re_core::ReplayDurabilityClass;
use mcp_re_core::ReplayKey;

use crate::shared_replay::composite_replay_key;
use crate::shared_replay::ReplayStoreError;

/// How much retention there is, and whose share of it one actor may hold — one definition,
/// applied both inside the reference L2 and per replica above the backend seam.
mod bounds;

/// What the reference L2 is holding, and how it stops holding it.
mod retained_set;

/// When the reference L2 says no instead of recording.
mod local_refusals;

/// The DEFAULT-BUILD authoritative L2: retained nonces, their expiry, and whose share of
/// the store they occupy.
mod in_memory;

/// The per-replica retention ACCOUNT, kept above the backend seam so the bound holds for
/// every deployable adapter.
mod retention_ledger;

/// One reservation against that account, and the three ways an insert can end.
mod charge;

/// A per-core L1 fast-reject cache — defined, and DORMANT. Nothing wires one, and its own
/// module documentation says so rather than leaving a reader to find out.
mod l1_fast_reject;

use bounds::ASYNC_MAX_ENTRIES;
use charge::Charge;
pub use in_memory::InMemoryAsyncAtomicReplayStore;
pub use l1_fast_reject::L1FastRejectStore;
pub use l1_fast_reject::DEFAULT_L1_CAPACITY;
use retention_ledger::RetentionLedger;

/// A boxed, `Send` future returning a replay decision — the object-safe return type
/// of [`AsyncAtomicReplayStore::atomic_insert_if_absent`] (native async-fn-in-trait is
/// not `dyn`-compatible, and the tier is dispatched dynamically over feature-gated
/// backends, so the future is boxed explicitly rather than via `async fn`).
pub type ReplayDecisionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ReplayDecision, ReplayStoreError>> + Send + 'a>>;

/// One insert-if-absent request: the composite key, the actor the entry is BUDGETED
/// against, and the two clock anchors.
///
/// A struct rather than four positional arguments because `key` and `actor` are both
/// `&str`: transposed at a call site they would still compile, and the result is a
/// store that budgets every entry against a nonce — which is to say, against nothing.
#[derive(Clone, Copy, Debug)]
pub struct ReplayInsert<'a> {
    /// The collision-safe composite key the tier composed (signer|audience|nonce).
    pub key: &'a str,
    /// The RESOLVED signer this entry is charged to. Retention is a shared resource,
    /// so every entry has to name who is holding it; see [`AsyncReplayTier`] for what
    /// the charge buys.
    pub actor: &'a str,
    /// The skew-folded retain-until the tier computed.
    pub expires_at_unix: i64,
    /// The same vestigial `0` anchor as the sync contract — a backend that derives a
    /// server-side TTL reads its OWN clock and ignores this.
    pub now_unix: i64,
}

impl<'a> ReplayInsert<'a> {
    /// Build an insert charged to `actor`.
    pub fn new(key: &'a str, actor: &'a str, expires_at_unix: i64, now_unix: i64) -> Self {
        ReplayInsert {
            key,
            actor,
            expires_at_unix,
            now_unix,
        }
    }
}

/// The ASYNC authoritative (L2) replay store contract — the async analogue of
/// [`crate::shared_replay::AtomicReplayStore`]. One server-side-atomic
/// insert-if-absent-with-TTL, awaited on the request path without blocking a runtime
/// worker.
pub trait AsyncAtomicReplayStore: Send + Sync {
    /// Atomically insert `insert.key` iff absent, with a TTL derived from the
    /// skew-folded `insert.expires_at_unix` relative to the store's OWN clock.
    ///
    /// `Fresh` iff the key was absent and is now recorded (this caller won the
    /// insert), `Replay` if already present, or [`ReplayStoreError`] on operational
    /// failure (⇒ fail closed). This is the ONLY source of an authoritative `Fresh`.
    ///
    /// `insert.actor` is the principal the entry is charged to. The per-actor
    /// retention bound is enforced ABOVE this seam, by [`AsyncReplayTier`], so it
    /// applies to every backend; a backend that also bounds a local set of its own may
    /// budget that set per `insert.actor` as well, and one whose retention is a
    /// server-side TTL has no local set to budget.
    fn atomic_insert_if_absent<'a>(&'a self, insert: ReplayInsert<'a>) -> ReplayDecisionFuture<'a>;

    /// This store's declared durability class (ADR-MCPS-020). Defaults to the
    /// conservative single-process reference; only a genuinely cross-process backend
    /// overrides it to `Durable`.
    fn durability_class(&self) -> ReplayDurabilityClass {
        ReplayDurabilityClass::SingleProcessReference
    }
}

/// The async replay TIER the proxy's async serving path awaits (ADR-MCPRE-051
/// §4): the async analogue of [`crate::shared_replay::SharedReplayCache`]. Given a
/// `mcp_re_core::ReplayKey` (projected from the RFC 9421 five-tuple via
/// `HttpReplayKey::to_core_replay_key`), it composes the collision-safe composite
/// key and folds the clock skew IDENTICALLY to the sync path (via the shared
/// [`composite_replay_key`] / [`skew_folded_retain_until`] helpers), then AWAITS the
/// authoritative [`AsyncAtomicReplayStore`] insert. The store round-trip is the ONLY
/// awaited I/O on the request path.
///
/// Fail-closed: any store failure surfaces as [`ReplayCacheError::Unavailable`]
/// ⇒ `mcp-re.replay_cache_unavailable`, never a silent allow (ADR-MCPS-020).
#[derive(Clone)]
pub struct AsyncReplayTier {
    store: Arc<dyn AsyncAtomicReplayStore>,
    freshness: crate::config_state::FreshnessWindow,
    /// Shared by every clone, so the per-core tiers of one replica budget against one
    /// account rather than one each.
    ledger: Arc<RetentionLedger>,
}

impl AsyncReplayTier {
    /// Build the tier over `store`, applying the symmetric `max_clock_skew_secs`
    /// to each entry's retain-until (folded into the store TTL) exactly as the
    /// sync `SharedReplayCache` does.
    pub fn new(
        store: Arc<dyn AsyncAtomicReplayStore>,
        freshness: crate::config_state::FreshnessWindow,
    ) -> Self {
        AsyncReplayTier {
            store,
            freshness,
            ledger: Arc::new(RetentionLedger::new(ASYNC_MAX_ENTRIES)),
        }
    }

    /// Override the retained-entry ceiling the per-actor budget is computed from
    /// (tests, and bounded embedders). A fresh ledger, so this is only meaningful
    /// before the tier serves anything.
    pub fn with_max_retained_entries(mut self, max_entries: usize) -> Self {
        self.ledger = Arc::new(RetentionLedger::new(max_entries));
        self
    }

    /// This tier's declared durability class — delegated to the backing store, so
    /// a strict/production startup can machine-check the object it actually holds
    /// (never a hardcoded `Durable`).
    pub fn durability_class(&self) -> ReplayDurabilityClass {
        self.store.durability_class()
    }

    /// AWAIT the authoritative atomic insert-if-absent for `key`. Composes the
    /// composite key and folds skew identically to the sync path; maps a store
    /// failure to the fail-closed [`ReplayCacheError::Unavailable`].
    ///
    /// `now_unix` is the instant the VERIFIER used for this request — the same reading
    /// the freshness gate was evaluated against. A store that bounds its own retention
    /// judges an already-past `retain_until` against it (MCPS-08); one that derives a
    /// server-side TTL reads its own clock and ignores it (see
    /// [`AsyncAtomicReplayStore`]). Passing a constant here would silently disable that
    /// guard in the in-memory store, which is the DEFAULT one.
    pub async fn check_and_insert(
        &self,
        key: &ReplayKey,
        now_unix: i64,
    ) -> Result<ReplayDecision, ReplayCacheError> {
        let composite = composite_replay_key(&key.signer, &key.audience, &key.nonce);
        let retain_until = self.freshness.replay_retain_until(key.expires_at_unix);
        // Charged to the resolved PRINCIPAL, not to the signer slot: the slot carries
        // the keyid so distinct keys can never share a replay key, which would hand a
        // subject one budget per key it holds. Passed explicitly so a store never has
        // to recover it by parsing a key it did not compose.
        //
        // The charge is taken HERE, above the backend seam, so the bound holds for
        // every deployable adapter — see [`RetentionLedger`].
        let charge = Charge::reserve(&self.ledger, &key.principal, now_unix, retain_until)
            .map_err(ReplayCacheError::from)?;
        // Scoped to the STORE round trip alone, so the span does not also cover the
        // charge accounting around it. This is the only awaited I/O a request performs,
        // which is why every scheduling delay in the process lands here — see
        // `stage_timers`.
        let outcome = {
            let _t_replay =
                crate::stage_timers::Timed::start(crate::stage_timers::Stage::ReplayInsert);
            let _inflight = crate::stage_timers::InFlight::enter();
            self.store
                .atomic_insert_if_absent(ReplayInsert::new(
                    &composite,
                    &key.principal,
                    retain_until,
                    now_unix,
                ))
                .await
        };
        // Settled from what the store ANSWERED, and only the two answers that are answers
        // settle it. An error, and a cancellation that consumes no answer at all, leave the
        // charge indeterminate — see [`Charge`] for why that is kept rather than released.
        match outcome {
            // The nonce is retained until `retain_until`, and so is its charge.
            Ok(ReplayDecision::Fresh) => {
                charge.commit();
                Ok(ReplayDecision::Fresh)
            }
            // The entry was already there, so this insert retained nothing.
            Ok(ReplayDecision::Replay) => {
                charge.release_proven_absent();
                Ok(ReplayDecision::Replay)
            }
            Err(e) => Err(ReplayCacheError::from(e)),
        }
    }
}

#[cfg(test)]
// Everything below is test code.
#[cfg(test)]
mod tests {
    use super::*;
    use bounds::ASYNC_PRUNE_EVERY_N_INSERTS;
    use std::collections::HashSet;
    use std::sync::Mutex;

    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Runtime::new().expect("rt").block_on(f)
    }

    /// A store that declares `Durable` and bounds nothing — the shape of BOTH
    /// deployable backends, whose retention is a server-side TTL (Redis `SET NX PX`)
    /// or a per-key lease (etcd) and which therefore hold no local set to budget.
    #[derive(Default)]
    struct UnboundedDurableStore {
        seen: Mutex<HashSet<String>>,
        /// Round-trips this store was asked for. The bound is only worth having if it
        /// refuses BEFORE the shared store is touched, so the count is the assertion.
        dispatches: std::sync::atomic::AtomicUsize,
    }

    impl UnboundedDurableStore {
        fn dispatches(&self) -> usize {
            self.dispatches.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl AsyncAtomicReplayStore for UnboundedDurableStore {
        fn atomic_insert_if_absent<'a>(
            &'a self,
            insert: ReplayInsert<'a>,
        ) -> ReplayDecisionFuture<'a> {
            Box::pin(async move {
                self.dispatches
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut seen = self.seen.lock().expect("seen");
                Ok(if seen.insert(insert.key.to_string()) {
                    ReplayDecision::Fresh
                } else {
                    ReplayDecision::Replay
                })
            })
        }

        fn durability_class(&self) -> ReplayDurabilityClass {
            ReplayDurabilityClass::Durable
        }
    }

    fn replay_key(actor: &str, nonce: &str, expires_at_unix: i64) -> ReplayKey {
        ReplayKey {
            // The signer slot carries the keyid; the budget is charged to `principal`.
            signer: format!("{actor}#key-1"),
            principal: actor.to_string(),
            audience: "did:example:verifier".to_string(),
            nonce: nonce.to_string(),
            expires_at_unix,
        }
    }

    /// The bound has to hold for the backends a shipped proxy can actually select.
    /// `app.rs` refuses any tier whose store declares `SingleProcessReference`, so a
    /// budget implemented only inside the in-memory store governs no deployment: the
    /// two survivors delegate retention to a server-side TTL and budget nothing.
    #[test]
    fn the_tier_budgets_a_durable_backend_that_budgets_nothing_itself() {
        // max_entries 10 ⇒ reserve 2, pressure at 8, solo budget 8.
        let store = Arc::new(UnboundedDurableStore::default());
        let tier = AsyncReplayTier::new(
            Arc::clone(&store) as Arc<dyn AsyncAtomicReplayStore>,
            crate::config_state::test_support::freshness(0),
        )
        .with_max_retained_entries(10);
        assert_eq!(
            tier.durability_class(),
            ReplayDurabilityClass::Durable,
            "the store under test must be one a production startup accepts"
        );
        const GREEDY: &str = "did:example:greedy";
        const QUIET: &str = "did:example:quiet";

        block(async {
            let mut admitted = 0usize;
            for i in 0..20 {
                match tier
                    .check_and_insert(&replay_key(GREEDY, &format!("greedy-{i}"), 9_000), 1_000)
                    .await
                {
                    Ok(ReplayDecision::Fresh) => admitted += 1,
                    Err(ReplayCacheError::Unavailable { .. }) => break,
                    other => panic!("unexpected decision {other:?}"),
                }
            }
            assert_eq!(
                admitted, 8,
                "one actor must stop at its budget, not at the global ceiling"
            );
            assert_eq!(tier.ledger.held_by(GREEDY), 8);

            // THE PROPERTY: a signer that has sent nothing is still served while the
            // greedy one is refused.
            assert_eq!(
                tier.check_and_insert(&replay_key(QUIET, "quiet-0", 9_000), 1_000)
                    .await
                    .expect("the quiet actor must still be admitted"),
                ReplayDecision::Fresh
            );

            // And the greedy one stays refused — fail closed on the frozen token, never
            // an allow, because an unrecorded nonce can be replayed.
            let before = store.dispatches();
            let refused = tier
                .check_and_insert(&replay_key(GREEDY, "greedy-99", 9_000), 1_000)
                .await
                .expect_err("over budget");
            assert_eq!(
                refused.to_mcp_re_error(),
                mcp_re_core::McpReError::ReplayCacheUnavailable
            );

            // THE MECHANISM: the refusal happens above the backend seam, so the actor
            // over its share cannot spend the shared store's capacity — not even the
            // round-trip. A nonce it re-presents is refused on the same token rather
            // than reported as a replay, which is the direction that is safe: an
            // over-budget actor is denied either way, and asking the store would mean
            // performing the very insert the budget refuses to fund.
            assert!(tier
                .check_and_insert(&replay_key(GREEDY, "greedy-0", 9_000), 1_000)
                .await
                .is_err());
            assert_eq!(
                store.dispatches(),
                before,
                "an over-budget actor must not reach the shared store at all"
            );
        });
    }

    /// A replay retains nothing new, so it must not leave the actor charged for one —
    /// otherwise re-sending one nonce would spend an actor's whole budget.
    #[test]
    fn a_replay_hands_the_charge_back() {
        let tier = AsyncReplayTier::new(
            Arc::new(UnboundedDurableStore::default()),
            crate::config_state::test_support::freshness(0),
        )
        .with_max_retained_entries(10);
        const ACTOR: &str = "did:example:repeater";
        block(async {
            for _ in 0..5 {
                let _ = tier
                    .check_and_insert(&replay_key(ACTOR, "one-nonce", 9_000), 1_000)
                    .await;
            }
            assert_eq!(
                tier.ledger.held_by(ACTOR),
                1,
                "one retained nonce is one charge, however often it is presented"
            );
        });
    }

    /// A store whose insert never completes — the shape of a wedged backend, and the
    /// case where the caller stops waiting.
    struct NeverAnsweringStore;

    impl AsyncAtomicReplayStore for NeverAnsweringStore {
        fn atomic_insert_if_absent<'a>(
            &'a self,
            _insert: ReplayInsert<'a>,
        ) -> ReplayDecisionFuture<'a> {
            Box::pin(std::future::pending())
        }

        fn durability_class(&self) -> ReplayDurabilityClass {
            ReplayDurabilityClass::Durable
        }
    }

    /// A request abandoned mid-insert KEEPS its charge, because the tier does not know
    /// whether the write landed.
    ///
    /// The serving path awaits the handler inside a hyper service, so a peer that closes
    /// its connection drops the future while the store round-trip is outstanding. For the
    /// Redis and etcd backends retention IS the round trip — a `SET NX PX`, a lease — so
    /// the command may already have reached the server. Handing the charge back there
    /// records did-not-retain for unknown-whether-retained, and the bypass is total: those
    /// backends have no local ceiling, so this ledger is their only bound, and a peer that
    /// aborts after every request fills the shared store while its occupancy reads zero.
    ///
    /// The broken implementation this catches is releasing on every non-`Fresh` exit.
    #[test]
    fn an_abandoned_insert_keeps_its_charge_because_the_write_may_have_landed() {
        let tier = AsyncReplayTier::new(
            Arc::new(NeverAnsweringStore),
            crate::config_state::test_support::freshness(0),
        )
        .with_max_retained_entries(10);
        const ACTOR: &str = "did:example:quitter";
        block(async {
            for i in 0..50 {
                let key = replay_key(ACTOR, &format!("nonce-{i}"), 9_000);
                // Give it a chance to reserve and reach the store, then walk away.
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(1),
                    tier.check_and_insert(&key, 1_000),
                )
                .await;
            }
            assert!(
                tier.ledger.held_by(ACTOR) > 0,
                "entries the shared store may be retaining must be charged to somebody"
            );

            // Cancelling is not a way to buy more than a fair share: the per-actor budget
            // refuses the greedy actor before the tier's reserve is spent...
            assert!(
                tier.ledger.held_by(ACTOR) < 10,
                "the cancelling actor is bounded by its own budget, not by the ceiling"
            );
            // ...so a quiet second actor is still admitted. A charge that closed the tier
            // for everyone would be its own outage.
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(1),
                    tier.check_and_insert(&replay_key("did:example:other", "n", 9_000), 1_000)
                )
                .await
                .is_err(),
                "another actor still reaches the store"
            );
        });
    }

    /// The charge an abandoned insert keeps is not permanent. It is committed against the
    /// same `retain_until` as the entry it may have created, so it drains with the
    /// freshness window rather than accumulating for the life of the process.
    #[test]
    fn an_abandoned_insert_s_charge_expires_with_the_entry_it_may_have_created() {
        let tier = AsyncReplayTier::new(
            Arc::new(NeverAnsweringStore),
            crate::config_state::test_support::freshness(0),
        )
        .with_max_retained_entries(10_000);
        const ACTOR: &str = "did:example:quitter";
        block(async {
            for i in 0..8 {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(1),
                    tier.check_and_insert(&replay_key(ACTOR, &format!("n-{i}"), 1_500), 1_000),
                )
                .await;
            }
            assert!(
                tier.ledger.held_by(ACTOR) > 0,
                "held while it may be retained"
            );
            // A prune at a `now` past the retain-until reclaims them.
            tier.ledger.state.lock().expect("ledger").prune(2_000);
            assert_eq!(
                tier.ledger.held_by(ACTOR),
                0,
                "an indeterminate charge drains with the freshness window"
            );
        });
    }

    /// The charge is released with the retention it accounts for, so a busy actor is
    /// not permanently penalised for traffic that has long since expired.
    #[test]
    fn the_tier_releases_charges_once_their_retention_expires() {
        let tier = AsyncReplayTier::new(
            Arc::new(UnboundedDurableStore::default()),
            crate::config_state::test_support::freshness(0),
        )
        .with_max_retained_entries(10_000);
        const ACTOR: &str = "did:example:busy";
        block(async {
            // A prune runs on the 64th reservation; the first 63 retain until 1_500.
            for i in 0..(ASYNC_PRUNE_EVERY_N_INSERTS - 1) {
                tier.check_and_insert(&replay_key(ACTOR, &format!("nonce-{i}"), 1_500), 1_000)
                    .await
                    .unwrap();
            }
            assert_eq!(
                tier.ledger.held_by(ACTOR) as u64,
                ASYNC_PRUNE_EVERY_N_INSERTS - 1
            );

            // Past their retain-until, the next reservation triggers the cadence.
            tier.check_and_insert(&replay_key(ACTOR, "nonce-live", 9_000), 2_000)
                .await
                .unwrap();
            assert_eq!(
                tier.ledger.held_by(ACTOR),
                1,
                "only the still-live entry is still charged"
            );
        });
    }
}
