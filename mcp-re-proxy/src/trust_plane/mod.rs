// SPDX-License-Identifier: Apache-2.0
//! The trust plane (ADR-MCPRE-056 §8): who may sign a request, and how fast a
//! revocation reaches this replica.
//!
//! # What it owns
//!
//! The swappable trust store, the freshness flag the resolver fails closed on, and the
//! workers that keep both moving — the `--trust` reloader and, on the push tier, the
//! trust-epoch poller. All private. Nothing outside can swap the store or stop a
//! refresh, because the authority to CHANGE trust state belongs with the thing that
//! also stops changing it.
//!
//! # What it hands out
//!
//! Two live handles, each carrying only the authority its consumer needs:
//!
//! - [`TrustPlane::resolver`] — the tier-wrapped, staleness-guarded verification
//!   resolver the PEP consults for every signature.
//! - [`TrustPlane::signers`] — a [`SignerDirectory`], the kid -> identity coordinate the
//!   actor seam reads, with no ability to swap the map it reads from.
//!
//! `response_kid` is deliberately an INPUT. It names the root issuer the delegated
//! credential chains to (ADR-MCPRE-052), so the invariant that makes it valid is
//! signing's; trust only enforces two consequences of it — that the issuer key is never
//! enrolled as a request signer, and that it answers the Response slot.
//!
//! # Lifetime
//!
//! Dropping the plane stops refreshing trust, and the two handles behave DIFFERENTLY
//! afterwards, on purpose:
//!
//! - the resolver fails closed. A frozen store still holds a key that may since have
//!   been revoked, so answering from it is the one outcome that must not happen.
//! - the directory keeps answering from the last snapshot. That is safe only because a
//!   directory lookup is descriptive, not authoritative (see [`SignerDirectory`]).
//!
//! The store is marked PERMANENTLY stale on every path by which refreshing ends while
//! the process keeps serving: the plane's own `Drop`, the reload thread panicking, and
//! the reload loop observing its halt — which `Halt` raises for the deployment's shutdown
//! flag as well as for the plane's retirement, and deliberately does not tell the worker
//! apart. A graceful drain therefore fails verification closed rather than leaving a
//! surviving resolver as an indefinitely-valid frozen verifier.

/// The Tier-3 invalidation seam: the event vocabulary and the source contract.
mod invalidation_channel;
/// Tier 2: consult the store on every call, so a revocation is visible on the next request.
mod live_trust;
/// Tier 3: a bounded cache an external event may evict early.
mod push_trust;

/// Whether the trust store is still being maintained, and the resolver that refuses to
/// answer once it is not.
mod freshness;
mod reload;
/// Re-reading `--trust` on a cadence, and the bounded budget that stops it pretending.
/// What a `--trust` document becomes: one read, two products that cannot disagree.
mod snapshot;
use reload::spawn_trust_reload_task;
use snapshot::load_trust_snapshot;

/// What revocation window this deployment actually DELIVERS, as the operator is told it at
/// startup.
pub(in crate::trust_plane) mod delivered_window;
use delivered_window::delivered_revocation_window;
use delivered_window::store_change_cadence;
use freshness::StaleFailsClosed;
use freshness::TrustStoreFreshness;
/// Materialisation of a revocation policy as runtime resolver behaviour — WHICH structure
/// implements the declared tier. Private: the tier is a policy choice a deployment
/// declares, and the wiring that honours it is nobody else's business.
mod revocation_resolver;
/// Tier 1 and the bounded window `T` every caching tier runs under.
mod trust_cache;
/// WHICH window a deployment may use — as distinct from the cache that honours one.
mod window_policy;

/// The Tier-3 invalidation seam and its events.
///
/// The reason at the point of widening: the ADR-MCPS-021 Tier-3 guarantee is established
/// end to end by `tests/integration_ext/redis_trust_epoch_e2e_test.rs`, which drives a
/// real Redis trust-epoch source through the cache. That lane cannot run inside the owning
/// module — it needs a live Redis and is feature-gated — so the seam is reachable rather
/// than the test being weakened to something it can prove in-process.
pub use invalidation_channel::InvalidationChannel;
pub use invalidation_channel::InvalidationEvent;
pub use push_trust::PushInvalidationTrustCache;

/// The deployment-wide default trust-propagation window, read by the argv parser when no
/// tier is declared. A named projection rather than a path into the cache: the parser
/// needs the DEFAULT, not the cache.
pub(crate) use trust_cache::DEFAULT_T_SECS;

use crate::managed_worker::WorkerSet;
use crate::reloading_trust::SignerDirectory;
use crate::RevocationTier;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// The trust domain's materialized state and the workers that keep it fresh.
pub struct TrustPlane {
    resolver: Arc<dyn mcp_re_core::TrustResolver + Send + Sync>,
    signers: SignerDirectory,
    freshness: Arc<TrustStoreFreshness>,
    /// Owns the `--trust` reloader and the trust-epoch poller. Declared last so the
    /// halt in `Drop` runs before it, but the ORDER GUARANTEE is `WorkerSet`'s
    /// termination semantics, not this field's position: there is no cross-worker
    /// shutdown dependency here today, and if one is introduced it must become an
    /// explicit drain rather than an inference from declaration order.
    workers: WorkerSet,
}

impl TrustPlane {
    /// The verification resolver the PEP consults, tier-wrapped and staleness-guarded.
    pub fn resolver(&self) -> Arc<dyn mcp_re_core::TrustResolver + Send + Sync> {
        Arc::clone(&self.resolver)
    }

    /// A live read-only view of the kid -> signer-identity coordinate.
    pub fn signers(&self) -> SignerDirectory {
        self.signers.clone()
    }

    /// Number of workers this plane owns. For the lifecycle tests.
    #[cfg(test)]
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// A plane over an in-memory store whose single worker runs `body`, for the ownership
    /// and teardown tests.
    ///
    /// `body` receives the worker's [`Halt`](crate::managed_worker::Halt) rather than
    /// polling it itself, so a test picks which of the three shapes teardown must survive
    /// it is: a worker that stops when asked, one that ignores the halt, or one that
    /// panics. Nothing else about this plane is contrived — the store, the freshness flag
    /// and the fail-closed resolver wrapper are the production ones.
    #[cfg(test)]
    pub(crate) fn for_teardown_test(
        body: impl FnOnce(crate::managed_worker::Halt) + Send + 'static,
    ) -> Self {
        Self::over_freshness(Arc::new(TrustStoreFreshness::default()), body)
    }

    /// The same plane, over a freshness flag the caller already holds.
    ///
    /// Only the terminal-race test needs this: to stage a reload landing after `Drop` it
    /// must hand the worker the very flag the plane will stale, and observe that flag
    /// after the plane is gone. `TrustPlane` deliberately has no accessor for it —
    /// authority over trust freshness belongs to the reload worker and to `Drop`, and an
    /// accessor would hand it to anyone (ADR-MCPRE-057 §6).
    #[cfg(test)]
    fn over_freshness(
        freshness: Arc<TrustStoreFreshness>,
        body: impl FnOnce(crate::managed_worker::Halt) + Send + 'static,
    ) -> Self {
        let mut signers = std::collections::HashMap::new();
        signers.insert(TEST_KID.to_string(), TEST_SIGNER.to_string());
        let store = Arc::new(crate::reloading_trust::ReloadingTrustStore::new(
            mcp_re_core::InMemoryTrustResolver::new(),
            signers,
        ));
        let mut workers = WorkerSet::new(Arc::new(AtomicBool::new(false)));
        let halt = workers.halt();
        workers.spawn("test trust reload", move || body(halt));
        let inner: Arc<dyn mcp_re_core::TrustResolver + Send + Sync> =
            Arc::new(crate::reloading_trust::SharedTrustStore(Arc::clone(&store)));
        TrustPlane {
            resolver: Arc::new(StaleFailsClosed {
                inner,
                freshness: Arc::clone(&freshness),
            }),
            signers: store.signer_directory(),
            freshness,
            workers,
        }
    }
}

/// The one enrolled coordinate [`TrustPlane::for_teardown_test`] carries. Shared so a test
/// in another module can ask the resolver about a signer the plane actually knows.
#[cfg(test)]
pub(crate) const TEST_KID: &str = "kid-1";
/// The signer identity [`TEST_KID`] resolves to.
#[cfg(test)]
pub(crate) const TEST_SIGNER: &str = "did:example:client";

impl Drop for TrustPlane {
    fn drop(&mut self) {
        // Written out, in this order, rather than left to field-drop order. The first
        // step is a security property and the second is a lifecycle one, and neither
        // should read as an accident of struct layout.
        //
        // 1. Stale BEFORE the workers stop, so no resolver that outlives this plane can
        //    answer from a snapshot nothing is re-reading. A clean stop leaves the store
        //    in exactly the condition `StaleFailsClosed` describes.
        //
        //    PERMANENTLY, because step 2 does not stop the reload worker instantly: it
        //    observes its halt only between cycles, so a read already under way could
        //    otherwise complete after this line and report the store fresh again.
        self.freshness.mark_stale_permanently();
        // 2. Halt and reclaim. There is no cross-worker shutdown dependency inside this
        //    plane today, so `WorkerSet`'s own termination semantics are the whole
        //    guarantee; if one is introduced it must become an explicit drain here
        //    rather than an inference from the order these were spawned in.
        self.workers.halt_and_reclaim();
    }
}

impl TrustPlane {
    /// Establish the trust plane: read `--trust`, apply the classified revocation posture,
    /// and start the workers that keep both fresh.
    ///
    /// Takes a [`TrustPlan`](crate::startup_plan::TrustPlan) and NOT a configuration. Which
    /// posture this deployment is in was decided by layer A and normalized by planning;
    /// what is left here is establishing it. Every refusal below is therefore a statement
    /// about the build or the environment — never about whether the request was coherent.
    ///
    /// `deployment` is the caller's shutdown flag; the workers started here stop on it,
    /// and also when this plane is dropped.
    pub fn materialize(
        plan: &crate::startup_plan::TrustPlan,
        deployment: Arc<AtomicBool>,
    ) -> Result<TrustPlane, String> {
        let response_kid = plan.response_kid();
        let mut workers = WorkerSet::new(deployment);
        // ADR-MCPS-021 Axis 2: the base trust store the revocation tiers resolve against.
        //
        // It is a SNAPSHOT the reload task can swap, not a map deserialised once and
        // frozen for the process lifetime. Every tier describes itself in terms of "the
        // store" — Tier 2 consults it per verification, Tier 3 evicts and forces a
        // re-resolve against it — and none of those descriptions was a true statement
        // about the deployment while the store could not change: revoking a client
        // signing key meant editing the file and restarting every replica, so the
        // exposure window was unbounded while the startup line advertised near-zero.
        // `response_kid` is the deployment's own issuer key id, passed in rather than
        // derived here: it is excluded from the request-signer set so the root can never be
        // presented as a client credential.
        let trust_store = Arc::new(load_trust_snapshot(plan.document_path(), response_kid)?);

        // ADR-MCPS-021 Axis 2: surface the DECLARED revocation tier and its honest
        // guarantee at startup. The proxy emits the tier's OWN guarantee string — never
        // a hardcoded stronger one — so it cannot surface a revocation window stronger
        // than the configured tier proves (the tier-claim ceiling). Tier 1
        // (bounded-cache) is the default when --revocation-tier is absent.
        // The tier's window is a claim about how fast a REVOKED key stops resolving, and
        // nothing resolves faster than `--trust` is re-read. The qualifier belongs on the
        // tier line itself: as a separate line further down it was routinely read as being
        // about something else, and the tier line was quoted on its own.
        eprintln!(
            "mcp-re-proxy: {} store-change-cadence={}",
            plan.revocation().tier().startup_audit_line("trust-store"),
            store_change_cadence(plan.reload())
        );
        // ADR-MCPS-021 Axis 2: APPLY the declared tier to the resolver so the runtime
        // behavior actually matches the surfaced guarantee (Tier 1 bounds cached active
        // trust to T; Tier 2 consults the store live every request; Tier 3 evicts on a
        // pushed event, else falls back to bounded T). Without this wrapping the tier
        // line above would be a claim the resolver does not enforce.
        // MCPS-84: connect the networked trust-epoch invalidation channel if one is
        // configured (only under --revocation-tier push; enforced at parse time).
        let push_channel = build_trust_epoch_channel(plan.epoch(), &mut workers)?;
        if plan.revocation().push_channel_is_inert() {
            // Honesty (Tier 3): with no networked source wired, the in-process
            // reference channel is inert — Tier 3 runs at its bounded-`T` fallback
            // (already reflected in the tier's `guarantee()` string above), NOT an
            // active near-zero push channel. Configure --trust-epoch-redis-url to
            // activate the networked source (MCPS-84).
            //
            // Read off the classification rather than off `push_channel.is_none()`: the
            // channel comes back absent in more than one way, and only one of them is the
            // deployment having asked for an inert push tier.
            eprintln!(
                "mcp-re-proxy: NOTE: revocation-tier PUSH has no networked event source (no \
                 --trust-epoch-redis-url), so it runs at its bounded-T fallback; set \
                 --trust-epoch-redis-url to activate the trust-epoch push source."
            );
        }
        let resolver = crate::trust_plane::revocation_resolver::build_revocation_resolver(
            &plan.revocation().tier(),
            Box::new(crate::reloading_trust::SharedTrustStore(Arc::clone(
                &trust_store,
            ))),
            trust_clock(),
            push_channel,
        );
        // Re-read `--trust` on a cadence so a key removed from the file stops resolving on
        // a RUNNING replica. Without it the tier wrappers above wrap an immutable map and
        // the guarantee printed a few lines up is not one the data plane can keep.
        // Whether the store behind the resolver is still being maintained. Two distinct
        // sources set it, and only one of them is the reload's: exhausting the reload
        // failure budget (recoverable) and the plane's own retirement in `Drop`
        // (terminal). The second exists in every configuration, including one with no
        // `--trust-reload-secs`, so this flag is meaningful there too.
        let trust_freshness = Arc::new(TrustStoreFreshness::default());
        if let Some(interval_secs) = plan.reload().cadence_secs() {
            spawn_trust_reload_task(
                &mut workers,
                Arc::clone(&trust_store),
                plan.document_path().to_string(),
                response_kid.to_string(),
                interval_secs.get(),
                Arc::clone(&trust_freshness),
            );
            // The window is stated as the SUM, not as the cadence. The cadence alone is
            // true only where the tier caches no positive trust; under bounded-cache and
            // push an entry cached just before the swap survives it by a further T, and
            // this is the line an operator greps for after removing a key.
            eprintln!(
                "mcp-re-proxy: trust store reload ACTIVE every {interval_secs}s: a key removed \
                 from {} stops resolving within {}, with no restart.",
                plan.document_path(),
                delivered_revocation_window(&plan.revocation().tier(), plan.reload())
            );
        } else {
            eprintln!(
                "mcp-re-proxy: trust store reload OFF: --trust is read once at startup, so              revoking a request-signer key requires restarting every replica. The              revocation-tier guarantee above bounds CACHING, not the store itself. Set              --trust-reload-secs to bound it."
            );
        }

        // Build the RFC 9421 serving PEP (ADR-MCPRE-050 sole carrier). The trust file
        // supplies the ActorResolver: each trusted key_id resolves to a structured
        // ResolvedActor — client keys for the Request slot, the server key for the
        // Response slot (slot discipline, MCPRE-100).
        //
        // The Request slot resolves its verification key through the ADR-MCPS-021
        // revocation-tier resolver built above, so the tier whose guarantee is printed
        // at startup is the tier the data plane actually runs: a `Revoked`/`NotFound`
        // binding rejects the request, and an `Unavailable` fails closed rather than
        // serving a key. The trust file supplies only the kid -> signer identity
        // coordinate; the KEY comes from the resolver on every request.
        let resolver: Arc<dyn mcp_re_core::TrustResolver + Send + Sync> = Arc::from(resolver);
        // OUTSIDE the tier wrappers, so a bounded-cache hit cannot answer from a snapshot
        // the reload has stopped being able to refresh — and UNCONDITIONAL, because the
        // latch it reads is set by the plane's `Drop` in every configuration, not only
        // where a reload runs. A resolver handed out unwrapped reads no latch at all, so
        // the plane's documented post-owner transition would not exist for a deployment
        // that configured no cadence, which is the default tier's accepted shape. Where no
        // reload runs the flag is only ever set by `Drop`, so the standing cost is one
        // relaxed atomic load per verification.
        let resolver: Arc<dyn mcp_re_core::TrustResolver + Send + Sync> =
            Arc::new(StaleFailsClosed {
                inner: resolver,
                freshness: Arc::clone(&trust_freshness),
            });

        Ok(TrustPlane {
            resolver,
            signers: trust_store.signer_directory(),
            freshness: trust_freshness,
            workers,
        })
    }
}

/// How often the trust-epoch counter is polled, in seconds.
///
/// The Tier-3 guarantee is "flush within one poll interval of an advance", so this is
/// the revocation latency the push tier actually delivers. Kept well inside the
/// bounded-`T` fallback so the push tier is still the faster of the two.
pub const TRUST_EPOCH_POLL_SECS: u64 = 5;
/// The production [`UnixClock`] the revocation-tier resolver wrapping uses to bound
/// the propagation window `T` (ADR-MCPS-021). Delegates to the trust-cache's
/// system clock so production and the unit-tested helper share one clock type.
fn trust_clock() -> crate::trust_plane::trust_cache::UnixClock {
    crate::trust_plane::trust_cache::system_clock()
}
/// MCPS-84 (ADR-MCPS-049 W2): build the networked trust-epoch invalidation channel
/// for the ADR-021 Push tier when `--trust-epoch-redis-url` is configured. Under
/// the `redis_replay` feature this connects the Redis trust-epoch source; without
/// it, a configured URL fails closed (a networked backend was requested but not
/// compiled in). Returns `None` when no URL is set (Push runs inert / bounded-`T`).
#[cfg(feature = "redis_replay")]
fn build_trust_epoch_channel(
    epoch: &crate::startup_plan::TrustEpochPlan,
    workers: &mut crate::managed_worker::WorkerSet,
) -> Result<Option<Box<dyn crate::InvalidationChannel + Send + Sync>>, String> {
    match epoch {
        crate::startup_plan::TrustEpochPlan::Redis { url, key } => {
            // Layer B, asked of the PLAN rather than of `cfg!` here. In this lane the
            // answer is always yes; it is asked anyway so the question has one owner in
            // every build rather than an owner only in the build where it refuses.
            if let Some(refusal) = epoch.unsupported_by_build() {
                return Err(refusal);
            }
            let source = std::sync::Arc::new(
                crate::trust_epoch::redis_trust_epoch_source(url, key)
                    .map_err(|e| format!("trust-epoch source: {e}"))?,
            );
            // The epoch read is a blocking network round trip behind ONE connection
            // mutex, and the resolver that would trigger it runs before signature
            // verification on every request. Polled from a dedicated thread instead,
            // so the request path costs a mutex acquisition and the whole per-core
            // fleet is not serialized on one Redis connection.
            let halt = workers.halt();
            workers.spawn(
                "trust epoch poll",
                crate::trust_epoch::trust_epoch_poller_body(
                    std::sync::Arc::clone(&source),
                    TRUST_EPOCH_POLL_SECS,
                    move || halt.requested(),
                ),
            );
            eprintln!(
                "mcp-re-proxy: revocation-tier PUSH: networked trust-epoch source ACTIVE (redis, \
                 epoch key {key:?}, polled every {TRUST_EPOCH_POLL_SECS}s off the request path); \
                 the trust cache flushes within one poll interval of an epoch advance and \
                 reverts to the bounded-T guarantee on a read outage."
            );
            Ok(Some(Box::new(crate::trust_epoch::SharedEpochChannel(
                source,
            ))))
        }
        crate::startup_plan::TrustEpochPlan::NoNetworkChannel => Ok(None),
    }
}
/// The same, in a build with no Redis client. The refusal is the plan's own (CF-09): both
/// consumers of the epoch state it identically, so which plane materializes first stops
/// deciding which half of the consequence an operator is told about.
#[cfg(not(feature = "redis_replay"))]
fn build_trust_epoch_channel(
    epoch: &crate::startup_plan::TrustEpochPlan,
    _workers: &mut crate::managed_worker::WorkerSet,
) -> Result<Option<Box<dyn crate::InvalidationChannel + Send + Sync>>, String> {
    match epoch.unsupported_by_build() {
        Some(refusal) => Err(refusal),
        None => Ok(None),
    }
}

/// The `--fleet` per-tier cross-replica revocation-lag bound, derived from real config.
///
/// This is the one operator-facing line whose stated purpose is to bound revocation lag
/// HONESTLY, so each clause has to name a mechanism that exists. Two floors sit under
/// every tier's number:
///
///   * the trust epoch is read by a BACKGROUND POLLER on a
///     [`TRUST_EPOCH_POLL_SECS`] cadence, never on the request path, so a push-tier
///     flush lands within one poll interval of an advance — not "on the next request
///     after an epoch advance", which is a mechanism the data plane no longer has;
///   * a key removed from `--trust` cannot stop resolving faster than the file is
///     re-read, whatever the tier does with its cache.
pub fn fleet_trust_bound(plan: &crate::startup_plan::TrustPlan) -> String {
    let tier = &plan.revocation().tier();
    let epoch_source_configured = plan.revocation().has_networked_epoch();
    let reload_floor = match plan.reload().cadence_secs() {
        Some(secs) => format!("--trust re-read every {secs}s"),
        None => "--trust read once at startup (no --trust-reload-secs), so the store itself \
                 changes only on a restart"
            .to_string(),
    };
    let poll = TRUST_EPOCH_POLL_SECS;
    // The two floors COMPOSE by addition, so the total is stated as arithmetic on the same
    // line rather than left to the reader of "over".
    let delivered = delivered_revocation_window(tier, plan.reload());
    match (tier, epoch_source_configured) {
        (RevocationTier::Push { t_secs }, true) => format!(
            "cache flush within one {poll}s trust-epoch poll interval of an \
             advance while the source is healthy, bounded {t_secs}s on a source read-outage \
             (fail-closed), over {reload_floor}; {delivered}"
        ),
        (RevocationTier::Push { t_secs }, false) => format!(
            "bounded {t_secs}s (no --trust-epoch-redis-url; the push channel is inert), over \
             {reload_floor}; {delivered}"
        ),
        (RevocationTier::BoundedCache { t_secs }, _) => {
            format!("bounded {t_secs}s, over {reload_floor}; {delivered}")
        }
        (RevocationTier::Live, _) => {
            format!(
                "per-request live re-resolution (no positive cache), over {reload_floor}; \
                 {delivered}"
            )
        }
    }
}
#[cfg(test)]
mod store_cadence_tests {
    use super::fleet_trust_bound;
    use super::store_change_cadence;
    use super::TrustStoreFreshness;
    use crate::config_state::test_support::trust_plan as plan;
    use crate::revocation_tier::RevocationTier;
    use crate::startup_plan::TrustReloadPlan;
    use std::sync::Arc;

    /// The networked epoch source these postures use when they have one.
    const EPOCH: Option<(&str, &str)> = Some(("redis://127.0.0.1:6379", "mcp-re:trust:epoch"));

    /// R7-C126: the `--fleet` push-tier line must not claim a mechanism that was
    /// removed. The epoch is read by a 5s background poller, never on the request path,
    /// so "flush on the next request after an epoch advance" was a guarantee the data
    /// plane could not keep — an operator sizing a revocation SLO from it got a number
    /// short by up to the poll interval.
    #[test]
    fn the_push_tier_bound_states_the_poll_interval_not_the_next_request() {
        let line = fleet_trust_bound(&plan(RevocationTier::Push { t_secs: 90 }, Some(5), EPOCH));
        assert!(
            !line.contains("next request"),
            "the per-request flush no longer exists: {line}"
        );
        assert!(
            line.contains(&format!(
                "{}s trust-epoch poll interval",
                super::TRUST_EPOCH_POLL_SECS
            )),
            "the honest bound is one poll interval: {line}"
        );
        assert!(
            line.contains("90s"),
            "the outage fallback is still named: {line}"
        );
    }

    /// A push tier with no networked source is inert, and says so rather than quoting
    /// the healthy-source number.
    #[test]
    fn a_push_tier_without_a_source_reports_the_fallback_only() {
        let line = fleet_trust_bound(&plan(RevocationTier::Push { t_secs: 90 }, Some(5), None));
        assert!(line.contains("inert"), "got: {line}");
        assert!(
            !line.contains("poll interval"),
            "no source means no poll to bound anything: {line}"
        );
    }

    /// Every tier's number sits over the same floor: nothing resolves faster than the
    /// store is re-read.
    ///
    /// The postures are enumerated as DEPLOYMENTS. Iterating `(tier, epoch-configured)`
    /// pairs would name combinations layer A refuses — a bounded-cache tier with an epoch
    /// source is X8 — and pairing a posture with a reload cadence of the test's choosing,
    /// as this did before `TrustPlan` was sealed, names plans no configuration reaches:
    /// three of the four states CARRY their cadence, so `Every { 15 }` beside a state
    /// holding 5 was asserting the wording of a line the proxy never prints.
    #[test]
    fn every_posture_names_the_reload_floor_under_its_number() {
        for tier in [
            RevocationTier::Live,
            RevocationTier::BoundedCache { t_secs: 60 },
            RevocationTier::Push { t_secs: 60 },
        ] {
            let line = fleet_trust_bound(&plan(tier.clone(), Some(15), None));
            assert!(
                line.contains("--trust re-read every 15s"),
                "{tier:?}: {line}"
            );
        }
        let networked =
            fleet_trust_bound(&plan(RevocationTier::Push { t_secs: 60 }, Some(15), EPOCH));
        assert!(
            networked.contains("--trust re-read every 15s"),
            "a networked push tier states the same floor: {networked}"
        );
    }

    /// A frozen store is named on the same line — and only bounded-cache can be in it.
    ///
    /// `ReadOnceAtStartup` is not a posture every tier can reach: the Required column of
    /// `Live` and `Push` names a cadence, so a plan without one exists for bounded-cache
    /// alone. Asserting the frozen wording for all four, as this test used to, described a
    /// deployment layer A refuses.
    #[test]
    fn a_bounded_cache_with_no_cadence_names_the_frozen_store() {
        let plan = plan(RevocationTier::BoundedCache { t_secs: 60 }, None, None);
        assert_eq!(
            plan.reload(),
            TrustReloadPlan::ReadOnceAtStartup,
            "no cadence is the posture under test"
        );
        let frozen = fleet_trust_bound(&plan);
        assert!(
            frozen.contains("only on a restart"),
            "a frozen store must be named on the same line: {frozen}"
        );
    }

    /// R7-C129: `bounded-cache` is the tier a deployment gets by omission, and it is
    /// accepted with no `--trust-reload-secs` while still printing "revocation enforced
    /// fleet-wide within T". Without a reload the base store is frozen for the process
    /// lifetime, so the qualifier has to be ON that line — not a separate one further
    /// down that an operator quoting the tier line never reads.
    #[test]
    fn a_tier_with_no_reload_cadence_says_the_store_cannot_change() {
        let line = store_change_cadence(TrustReloadPlan::ReadOnceAtStartup);
        assert!(line.contains("NONE"), "got: {line}");
        assert!(
            line.contains("CACHING"),
            "the line must say what the tier's window actually bounds: {line}"
        );
        assert!(
            line.contains("restart"),
            "and what changing the store actually costs: {line}"
        );
    }

    /// With a cadence the same line names it, so the tier window and the store window
    /// are read together.
    #[test]
    fn a_configured_cadence_is_named_on_the_tier_line() {
        let line = store_change_cadence(TrustReloadPlan::Every {
            secs: crate::config_state::TrustRevocationState::cadence(30),
        });
        assert!(line.starts_with("30s"), "got: {line}");
        assert!(line.contains("--trust"), "got: {line}");
    }

    /// R7-C072/C104: keep-last-good must be BOUNDED. A trust file that becomes
    /// permanently unreadable otherwise restores the unbounded revocation window the
    /// reload exists to close, silently — an `InMemoryTrustResolver` carries no expiry,
    /// so nothing makes a frozen snapshot stop being honoured on its own.
    ///
    /// The bound has to be a state the RESOLVER reads, not a warning on stderr: a log
    /// line changes nothing about which keys keep verifying.
    #[test]
    fn a_frozen_store_stops_answering_instead_of_serving_the_revoked_key() {
        use mcp_re_core::TrustResolver;

        struct AlwaysResolves;
        impl TrustResolver for AlwaysResolves {
            fn resolve(
                &self,
                _signer: &str,
                _key_id: &str,
            ) -> Result<mcp_re_core::VerificationKey, mcp_re_core::TrustResolverError> {
                Ok(mcp_re_core::SigningKey::from_seed_bytes(&[9u8; 32]).public_key())
            }
        }

        let freshness = Arc::new(TrustStoreFreshness::default());
        let resolver = super::StaleFailsClosed {
            inner: Arc::new(AlwaysResolves),
            freshness: Arc::clone(&freshness),
        };

        assert!(
            resolver.resolve("signer-a", "kid-a").is_ok(),
            "a fresh store answers normally"
        );

        // The reload has failed its budget: the snapshot behind this resolver can no
        // longer be trusted to reflect a revocation.
        freshness.mark_stale();
        assert!(
            matches!(
                resolver.resolve("signer-a", "kid-a"),
                Err(mcp_re_core::TrustResolverError::Unavailable { .. })
            ),
            "a frozen store still HOLDS the revoked key, so answering from it is the \
             one outcome that must not happen — and it must be reported as an outage, \
             not as an unknown keyid"
        );

        freshness.mark_fresh();
        assert!(
            resolver.resolve("signer-a", "kid-a").is_ok(),
            "a recovered reload serves again"
        );
    }
}

/// The trust child machine's terminal transition (ADR-MCPRE-057 §5.1).
///
/// `Stale(terminal) -> Fresh` is illegal; `RecoverableStale -> Fresh` is not. These assert
/// the difference, because collapsing the two in either direction is a real failure: one
/// way revives a resolver that must refuse, the other turns a transient bad read into a
/// permanent outage.
#[cfg(test)]
mod freshness_transition_tests {
    use super::StaleFailsClosed;
    use super::TrustPlane;
    use super::TrustStoreFreshness;
    use super::TEST_KID;
    use super::TEST_SIGNER;
    use mcp_re_core::TrustResolver;
    use std::sync::Arc;
    use std::time::Duration;

    /// The transition this guards: `Stale(terminal) -> Fresh` must not exist.
    ///
    /// `TrustPlane::drop` marks the store stale and THEN halts the reload worker, which
    /// observes its halt only between cycles. A read already under way therefore
    /// completes after the plane is gone, and reported the store fresh — reviving a
    /// resolver whose whole purpose past that point is to refuse. The two steps are on
    /// different threads, so no ordering at the drop site can close it; only making the
    /// state unrevivable can.
    #[test]
    fn a_reload_landing_after_the_owner_is_gone_cannot_report_the_store_fresh() {
        let freshness = Arc::new(TrustStoreFreshness::default());
        freshness.mark_fresh();
        assert!(!freshness.is_stale(), "a healthy store starts fresh");

        // The owner goes away while a reload is mid-read.
        freshness.mark_stale_permanently();
        // The straggler finishes that read and reports success.
        freshness.mark_fresh();

        assert!(
            freshness.is_stale(),
            "a reload that outlived its plane reported the store fresh; the resolver the \
             plane left behind would answer from a snapshot nothing is re-reading"
        );
    }

    /// The consequence, at the surface that enforces it: the resolver stays closed.
    ///
    /// Separate from the flag test because `StaleFailsClosed` is what a request meets,
    /// and a latch nothing consults would satisfy the assertion above while changing
    /// nothing about what gets served.
    #[test]
    fn the_resolver_stays_closed_even_after_a_straggler_reports_fresh() {
        let freshness = Arc::new(TrustStoreFreshness::default());
        let inner = Arc::new(mcp_re_core::InMemoryTrustResolver::new());
        let resolver = StaleFailsClosed {
            inner,
            freshness: Arc::clone(&freshness),
        };
        freshness.mark_stale_permanently();
        freshness.mark_fresh();
        match resolver.resolve(TEST_SIGNER, TEST_KID) {
            Err(mcp_re_core::TrustResolverError::Unavailable { .. }) => {}
            other => panic!("must stay unavailable, got {other:?}"),
        }
    }

    /// Negative control: the RECOVERABLE staleness is still recoverable.
    ///
    /// Without this, a latch applied to both would pass the test above while turning
    /// every exhausted-failure-budget episode into a permanent outage — a replica that
    /// never serves again after five bad reads of a file that has since been fixed.
    #[test]
    fn exhausting_the_failure_budget_is_still_undone_by_a_successful_reload() {
        let freshness = TrustStoreFreshness::default();
        freshness.mark_stale();
        assert!(freshness.is_stale());
        freshness.mark_fresh();
        assert!(
            !freshness.is_stale(),
            "a recovered reload must serve again; only the owner's retirement is terminal"
        );
    }

    /// The same race, staged through the REAL `TrustPlane::drop`.
    ///
    /// The tests above drive the flag directly, which proves the latch works but not that
    /// teardown uses it. Here the reload worker is still running when the plane is
    /// dropped, and finishes its read — successfully — during the join window `Drop`
    /// itself opens between marking the store stale and halting the workers. The
    /// interleaving is forced rather than hoped for: the worker reports fresh only after
    /// observing the halt, which `Drop` raises strictly after it has staled the store.
    ///
    /// The broken implementation this catches: `Drop` calling `mark_stale` instead of
    /// `mark_stale_permanently` — which is what it did, and which leaves the store fresh
    /// at the end of this test with every direct-flag assertion above still passing.
    #[test]
    fn a_reload_completing_inside_the_drop_join_window_cannot_revive_the_resolver() {
        let freshness = Arc::new(TrustStoreFreshness::default());
        freshness.mark_fresh();
        let straggler = Arc::clone(&freshness);

        let plane = TrustPlane::over_freshness(Arc::clone(&freshness), move |halt| {
            // Mid-read when the owner goes away: the worker learns of the halt only
            // between cycles, so it necessarily lands after `Drop` staled the store.
            while !halt.requested() {
                std::thread::sleep(Duration::from_millis(2));
            }
            straggler.mark_fresh();
        });
        // The resolver a request would meet, taken while the plane was live. It answers
        // on its own terms — `NotFound` for a signer with no enrolled material is a
        // definitive answer, and definitively not the `Unavailable` asserted below.
        let resolver = plane.resolver();
        assert!(
            !matches!(
                resolver.resolve(TEST_SIGNER, TEST_KID),
                Err(mcp_re_core::TrustResolverError::Unavailable { .. })
            ),
            "a live plane must not report its trust store as unavailable"
        );

        drop(plane);

        assert!(
            freshness.is_stale(),
            "the reload that completed during teardown reported the store fresh again"
        );
        match resolver.resolve(TEST_SIGNER, TEST_KID) {
            Err(mcp_re_core::TrustResolverError::Unavailable { .. }) => {}
            other => panic!(
                "a resolver outliving its plane answered from a snapshot nothing is \
                 re-reading, got {other:?}"
            ),
        }
    }
}

/// The lifetime contract of the two handles the plane hands out.
///
/// These assert the DIFFERENCE between them after the plane is gone, because that
/// difference is the security argument: the resolver must stop answering, and the
/// directory may keep answering only because a directory answer is not authority.
#[cfg(test)]
mod handle_lifetime_tests {
    use super::*;

    const KID: &str = TEST_KID;
    const SIGNER: &str = TEST_SIGNER;

    /// A plane whose one worker only waits to be halted — the cooperative shape, enough to
    /// assert the ownership relationship without standing up a trust file.
    fn plane() -> TrustPlane {
        TrustPlane::for_teardown_test(|halt| {
            while !halt.requested() {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        })
    }

    /// A resolver that outlives its plane must NOT become an indefinitely-valid frozen
    /// verifier. Nothing is re-reading `--trust`, so a key revoked in it would still
    /// resolve from the snapshot — the one outcome that must not happen.
    ///
    /// Before v0.16 this could not arise: the reloader stopped only with the process, or
    /// on a panic that marked the store stale. The structural halt made a clean stop
    /// possible while the process continues, and `Drop` is what closes it.
    #[test]
    fn a_resolver_that_outlives_the_plane_fails_closed() {
        let plane = plane();
        let resolver = plane.resolver();
        assert_eq!(plane.worker_count(), 1);

        // Alive: the resolver answers on its own terms. An unknown signer is NotFound,
        // which is a definitive answer — not the Unavailable asserted below.
        assert!(
            !matches!(
                resolver.resolve(SIGNER, KID),
                Err(mcp_re_core::TrustResolverError::Unavailable { .. })
            ),
            "a live plane must not report its trust store as unavailable"
        );

        drop(plane);

        match resolver.resolve(SIGNER, KID) {
            Err(mcp_re_core::TrustResolverError::Unavailable { .. }) => {}
            other => panic!("a resolver outliving its plane must fail closed, got {other:?}"),
        }
    }

    /// The directory may keep answering, and that is intentional: it yields only the
    /// kid -> identity coordinate, never verification material, so a frozen directory
    /// cannot admit anything by itself. See [`SignerDirectory`] for why that makes it
    /// safe — and why widening it would invalidate this test's premise rather than
    /// merely changing its expectation.
    #[test]
    fn a_directory_that_outlives_the_plane_still_answers_from_the_last_snapshot() {
        let plane = plane();
        let signers = plane.signers();
        assert_eq!(signers.signer_for(KID).as_deref(), Some(SIGNER));

        drop(plane);

        assert_eq!(
            signers.signer_for(KID).as_deref(),
            Some(SIGNER),
            "the directory must stay readable rather than emptying or panicking"
        );
        assert_eq!(signers.signer_for("unknown-kid"), None);
    }

    /// The same contract, on a plane built by [`TrustPlane::materialize`] from a
    /// configuration that set NO `--trust-reload-secs`.
    ///
    /// The tests above go through `for_teardown_test`, which constructs the plane's
    /// resolver directly. That fixture cannot see which resolver `materialize` decides to
    /// hand out, and `materialize` used to install the staleness guard only when a reload
    /// cadence was configured — so on the default tier, which validation accepts with no
    /// cadence, the latch `Drop` sets was read by nothing and a surviving resolver kept
    /// answering from the frozen snapshot. This drives the production constructor in
    /// exactly that shape.
    #[test]
    fn a_plane_materialized_without_a_reload_cadence_still_fails_closed_after_drop() {
        let key = mcp_re_core::SigningKey::from_seed_bytes(&[4u8; 32]).public_key();
        let path = std::env::temp_dir().join(format!(
            "mcp_re_trust_plane_no_cadence_{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            format!(
                r#"[{{"signer":"{SIGNER}","key_id":"{KID}","public_key":"{}"}}]"#,
                key.to_b64url()
            ),
        )
        .expect("write trust file");

        let argv: Vec<String> = [
            "--bind",
            "127.0.0.1:0",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "response-kid",
            "--delegated-trust-epoch",
            "epoch-1",
            "--signing-key-seed",
            "/nonexistent/seed",
            "--tls-cert",
            "/nonexistent/cert",
            "--tls-key",
            "/nonexistent/key",
            "--client-ca",
            "/nonexistent/ca",
            "--target-uri",
            "https://localhost/",
            "--trust-domain",
            "example.org",
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
            "--replay-durability-tier",
            "redis-wait-quorum:1:100",
            "--inner-http-url",
            "http://127.0.0.1:9/mcp",
            "--trust",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .chain(std::iter::once(path.to_string_lossy().into_owned()))
        .collect();

        let config = crate::cli::parse_args(&argv).expect("args parse");
        assert!(
            config.request_signer_currency.reload_secs().is_none(),
            "the shape under test is the one with NO reload cadence"
        );
        let config = crate::config_state::validation::ValidatedDeployment::try_from(config)
            .expect("config validates");
        let plan = crate::startup_plan::TrustPlan::from_validated(
            &config,
            "response-kid".to_string(),
            crate::startup_plan::TrustEpochPlan::from_validated(&config),
        );
        let plane = TrustPlane::materialize(&plan, Arc::new(AtomicBool::new(false)))
            .expect("the trust plane materializes");

        let resolver = plane.resolver();
        assert!(
            resolver.resolve(SIGNER, KID).is_ok(),
            "a live plane resolves an enrolled request signer"
        );

        drop(plane);
        let _ = std::fs::remove_file(&path);

        match resolver.resolve(SIGNER, KID) {
            Err(mcp_re_core::TrustResolverError::Unavailable { .. }) => {}
            other => panic!(
                "a resolver outliving a plane materialized without --trust-reload-secs \
                 answered from a snapshot nothing is re-reading, got {other:?}"
            ),
        }
    }

    /// A handle held past the plane's life must not keep the refresh machinery running.
    /// The halt lives in the `WorkerSet`, not in the store, which is what makes this
    /// true — moving the flag into the store "for convenience" would break it.
    #[test]
    fn surviving_handles_do_not_keep_the_refresh_workers_alive() {
        let plane = plane();
        let (resolver, signers) = (plane.resolver(), plane.signers());

        drop(plane);

        // Both handles are still alive here, holding the store; the workers are not.
        assert!(matches!(
            resolver.resolve(SIGNER, KID),
            Err(mcp_re_core::TrustResolverError::Unavailable { .. })
        ));
        assert!(signers.signer_for(KID).is_some());
    }
}
