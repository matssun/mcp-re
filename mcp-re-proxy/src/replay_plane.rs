// SPDX-License-Identifier: Apache-2.0
//! Materialize the authoritative replay tier (ADR-MCPRE-056 §6; ADR-MCPRE-051 §4).
//!
//! Given a [`ReplayPlan`] — pure intent, decided in `startup_plan` — this establishes the
//! tier the per-core serving path awaits, plus the dispatch posture that goes with it.
//!
//! # This plane owns nothing
//!
//! Unlike `trust_plane`, which owns background workers and has a `Drop` that stops them,
//! this is a MATERIALIZER: it constructs, hands the result over by value, and has nothing
//! left. Both are "planes"; the word does not imply a uniform shape, and pretending it
//! does would put a `Drop` here with nothing to do in it.
//!
//! What it produces is moved into `HttpProfileProxy`, which becomes an
//! `Arc<HttpProfileProxy>` shared by every per-core handler. No handle is retained here,
//! so none can outlive this plane.
//!
//! # The control runtime must outlive every USE, not just the connect
//!
//! The Redis arm connects on the shared control runtime, and that is not merely where the
//! connect happens. `redis`'s `ConnectionManager` captures the runtime it is CREATED in
//! (`Runtime::locate()`) and schedules its disconnect-watch and its reconnect attempts
//! there for the rest of its life. A call site reading `rt.block_on(connect)` looks like
//! "connect here, done"; it is actually a permanent binding.
//!
//! So the substrate must outlive every use of the store. Two things discharge that, and
//! neither is field-declaration order:
//!
//! - **On a later startup failure**, nothing here needs cleaning up. Neither the store nor
//!   its `ConnectionManager` has a `Drop`; the detached reconnect work lives on the
//!   control runtime and dies with it, and the control runtime provably does not escape a
//!   later `?` (see `control_runtime`'s property-4 test). This plane's failure path is
//!   therefore INHERITED from the substrate's, not established locally — which is worth
//!   stating, because it is the reason there is no guard type here.
//! - **On normal shutdown**, `serve_fleet` drains the fleet before any drop runs. Once
//!   the drain returns, no request can be using the tier, so the order in which the proxy
//!   and the runtime are dropped is immaterial. DRAIN-BEFORE-RECLAIM is the property to
//!   preserve when a later owner holds both in one struct — not a field order.

// Only the feature-gated backends construct a store; a default build refuses both arms
// before it would need one.
#[cfg(any(feature = "cpstore_etcd", feature = "redis_replay"))]
use std::sync::Arc;

use crate::async_replay::AsyncReplayTier;
use crate::control_runtime::ControlRuntime;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::startup_plan::{PlannedStore, ReplayPlan};

/// The established replay tier and the dispatch posture it implies.
///
/// By value: the caller moves both into the proxy. Nothing here is shared back.
pub struct MaterializedReplay {
    /// The authoritative tier the per-core request path awaits.
    pub tier: AsyncReplayTier,
    /// Fleet-strict dispatch and the declared durability tier, which the serving path
    /// reports. Set together with the tier so a deployment cannot advertise a durability
    /// claim the store it actually holds does not implement.
    pub dispatch: ProxyDispatchConfig,
}

impl MaterializedReplay {
    /// The handover value, or the refusal.
    ///
    /// #78 (ADR-MCPS-020): the durability guard runs HERE, so producing the value and
    /// checking it are one step. A construction site cannot obtain a `MaterializedReplay`
    /// without the check having passed, which is stronger than a check the producer
    /// remembers to run after building one.
    fn new(tier: AsyncReplayTier, dispatch: ProxyDispatchConfig) -> Result<Self, String> {
        assert_durable(&tier)?;
        Ok(MaterializedReplay { tier, dispatch })
    }
}

/// Establish the planned tier.
///
/// Every refusal raised here is a statement about the BUILD or the ENVIRONMENT — a
/// backend that was not compiled in, a store that would not answer. Refusals knowable
/// from configuration alone were already decided by layer A, and the plan is a projection
/// of that decision rather than a second chance to refuse it.
///
/// `control` must be present when the plan declared it needed (see
/// `startup_plan::control_runtime_requirement`); its absence there is a wiring error in
/// this process, not an operator mistake.
// In a build with NEITHER backend compiled, both arms below refuse, so the code after the
// match never runs and `max_clock_skew` is never read. That is the honest shape of such a
// build — it can establish no live replay state at all — rather than a wart to work
// around, so it is named here instead of being silenced everywhere.
#[cfg_attr(
    not(any(feature = "cpstore_etcd", feature = "redis_replay")),
    allow(unreachable_code, unused_variables)
)]
pub fn materialize(
    plan: &ReplayPlan,
    freshness: crate::config_state::FreshnessWindow,
    control: Option<&ControlRuntime>,
) -> Result<MaterializedReplay, String> {
    // The tier is READ from the plan, never chosen beside it: the replay owner paired this
    // store with the only tier it can serve, and materialization has no standing to re-pair
    // them.
    let tier = plan.tier();
    let (established, dispatch): (AsyncReplayTier, ProxyDispatchConfig) = match plan.store() {
        PlannedStore::Etcd { endpoint } => {
            #[cfg(feature = "cpstore_etcd")]
            {
                eprintln!(
                    "mcp-re-proxy: replay tier = shared (CP/linearizable; async etcd backend)"
                );
                eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("etcd"));
                // The etcd store drives its own requests, so it needs no share of the
                // control runtime — which is why the plan does not declare one for it.
                let store = Arc::new(
                    crate::async_etcd_store::EtcdAsyncAtomicReplayStore::connect(endpoint),
                );
                (
                    AsyncReplayTier::new(store, freshness),
                    ProxyDispatchConfig {
                        fleet_strict: true,
                        tier: Some(tier.clone()),
                    },
                )
            }
            #[cfg(not(feature = "cpstore_etcd"))]
            {
                let _ = (endpoint, tier);
                return Err("--replay-durability-tier linearizable requires a build with the `cpstore_etcd` feature".to_string());
            }
        }
        PlannedStore::Redis { url } => {
            #[cfg(feature = "redis_replay")]
            {
                eprintln!(
                    "mcp-re-proxy: replay tier = shared (horizontally-scaled; async Redis backend)"
                );
                eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("redis"));
                let rt = control
                    .expect("the plan declared the redis replay tier needs the control runtime")
                    .handle();
                // The client-side response timeout is sized for the DECLARED WAIT timeout
                // BEFORE connecting: the library defaults to 500ms per command, and `WAIT`
                // is an ordinary command — so a declared `redis-wait-quorum:2:2000` could
                // never wait 2000ms, and any replica ack slower than 500ms failed the
                // request closed while the startup line advertised the fuller window.
                let wait_timeout_ms = tier.wait_quorum_params().map(|(_, ms)| ms);
                let mut store = rt
                    .block_on(
                        crate::RedisAsyncAtomicReplayStore::connect_with_wait_timeout(
                            url,
                            crate::redis_store::system_clock(),
                            wait_timeout_ms,
                        ),
                    )
                    .map_err(|e| format!("connect redis async replay store: {e:?}"))?;
                // Apply the DECLARED durability tier to the store that actually serves.
                // `startup_audit_line` above promises "WAIT timeout or insufficient acks
                // fail closed" for REDIS_WAIT_QUORUM; without this the store would run
                // plain SET NX PX and the promise would be audited but unenforced.
                if let Some((quorum, timeout_ms)) = tier.wait_quorum_params() {
                    store = store.with_wait_quorum(quorum, timeout_ms);
                }
                (
                    AsyncReplayTier::new(Arc::new(store), freshness),
                    ProxyDispatchConfig {
                        fleet_strict: true,
                        tier: Some(tier.clone()),
                    },
                )
            }
            #[cfg(not(feature = "redis_replay"))]
            {
                let _ = (url, tier, control);
                return Err("--replay-cache shared (redis) requires a build with the `redis_replay` feature".to_string());
            }
        }
    };
    MaterializedReplay::new(established, dispatch)
}

/// #78 (ADR-MCPS-020): refuse to hand over a tier that self-declares the volatile
/// single-process reference posture.
///
/// It runs inside [`MaterializedReplay::new`], the only place in this module that builds
/// the handover value, so the check is part of producing it. `--replay-cache
/// memory` never reaches here — validation refuses it outright (pinned by
/// `startup_plan`'s `the_memory_tier_is_refused_by_validation_before_planning_sees_it`) —
/// which makes this defense in depth rather than the memory tier's terminal refusal: it
/// also catches a store reached by some other selection path, and mcp-re-core's
/// `durability_class()` defaults to the single-process reference, so an UNDECLARED
/// backend is refused here too.
fn assert_durable(tier: &AsyncReplayTier) -> Result<(), String> {
    if tier.durability_class() == mcp_re_core::ReplayDurabilityClass::SingleProcessReference {
        return Err(
            "the configured replay cache self-declares the volatile single-process reference \
             posture (admitted nonces are lost on restart and invisible to peer verifiers); \
             a durable replay store is required — use --replay-cache shared with an accepted \
             durability tier, or inject a cache that declares ReplayDurabilityClass::Durable"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay_tier::ReplayDurabilityTier;

    /// The volatile tier cannot be handed over, even though it can be constructed.
    ///
    /// No plan produces it any more — `ReplayPlan` has two variants and both are shared —
    /// so this asserts the guard directly rather than through a plan. It is the backstop
    /// that fires from inside the producer, so an INJECTED cache cannot reach the serving
    /// path without meeting it either, which is the case a configuration refusal cannot
    /// cover.
    #[test]
    fn a_volatile_tier_is_never_handed_over() {
        let volatile = AsyncReplayTier::new(
            std::sync::Arc::new(crate::async_replay::InMemoryAsyncAtomicReplayStore::new()),
            crate::config_state::test_support::freshness(60),
        );
        let err = assert_durable(&volatile).expect_err("the volatile tier must be refused");
        assert!(err.contains("single-process reference"), "{err}");
    }

    /// A store that declares the cross-process posture, so the accepting half of the
    /// guard is exercised by something other than a feature-gated backend.
    struct DurableStore;

    impl crate::async_replay::AsyncAtomicReplayStore for DurableStore {
        fn atomic_insert_if_absent<'a>(
            &'a self,
            _insert: crate::async_replay::ReplayInsert<'a>,
        ) -> crate::async_replay::ReplayDecisionFuture<'a> {
            Box::pin(async move { Ok(mcp_re_core::ReplayDecision::Fresh) })
        }

        fn durability_class(&self) -> mcp_re_core::ReplayDurabilityClass {
            mcp_re_core::ReplayDurabilityClass::Durable
        }
    }

    fn linearizable_dispatch() -> ProxyDispatchConfig {
        ProxyDispatchConfig {
            fleet_strict: true,
            tier: Some(ReplayDurabilityTier::Linearizable),
        }
    }

    /// The handover value cannot be BUILT around a volatile tier, whatever durability the
    /// dispatch posture beside it advertises.
    ///
    /// This is the guard's INVOCATION, not its predicate: `MaterializedReplay::new` is the
    /// only producer of the value in this module, so a volatile store cannot be paired
    /// with a `fleet_strict`, linearizable-claiming posture and handed to the serving path.
    #[test]
    fn the_handover_value_cannot_be_built_around_a_volatile_tier() {
        let volatile = AsyncReplayTier::new(
            std::sync::Arc::new(crate::async_replay::InMemoryAsyncAtomicReplayStore::new()),
            crate::config_state::test_support::freshness(60),
        );
        let err = match MaterializedReplay::new(volatile, linearizable_dispatch()) {
            Ok(_) => panic!("a volatile tier must not produce a handover value"),
            Err(e) => e,
        };
        assert!(err.contains("single-process reference"), "{err}");
    }

    /// The guard admits what it is supposed to admit: a durable store yields the value
    /// with the posture it was given, so the refusal above is about durability and not a
    /// constructor that refuses everything.
    #[test]
    fn a_durable_tier_produces_the_handover_value_with_its_posture() {
        let durable = AsyncReplayTier::new(
            std::sync::Arc::new(DurableStore),
            crate::config_state::test_support::freshness(60),
        );
        let materialized = MaterializedReplay::new(durable, linearizable_dispatch())
            .unwrap_or_else(|e| panic!("a durable tier must be handed over: {e}"));
        assert!(materialized.dispatch.fleet_strict);
        assert_eq!(
            materialized.dispatch.tier,
            Some(ReplayDurabilityTier::Linearizable)
        );
        assert_eq!(
            materialized.tier.durability_class(),
            mcp_re_core::ReplayDurabilityClass::Durable
        );
    }

    /// A backend the build does not contain is refused by NAME. This is the refusal class
    /// that deliberately stayed with materialization: it is a fact about the build, not
    /// about the request, so planning must not raise it.
    #[test]
    fn a_backend_the_build_lacks_is_refused_and_named() {
        let etcd = materialize(
            &crate::config_state::test_support::linearizable_replay_plan(),
            crate::config_state::test_support::freshness(60),
            None,
        );
        if cfg!(feature = "cpstore_etcd") {
            // The etcd store is lazy: establishing it contacts nothing, so a TEST-NET-3
            // endpoint still materializes. Whether it ANSWERS is a request-path fact.
            let ok = etcd.expect("the etcd tier materializes without contacting anything");
            assert!(
                ok.dispatch.fleet_strict,
                "a shared tier serves fleet-strict"
            );
            assert_eq!(ok.dispatch.tier, Some(ReplayDurabilityTier::Linearizable));
        } else {
            let err = etcd.err().expect("refused without the backend");
            assert!(err.contains("cpstore_etcd"), "{err}");
        }

        // The redis arm's refusal is reachable without a control runtime only in a build
        // without the backend; with it, the connect would be attempted first.
        if !cfg!(feature = "redis_replay") {
            let err = materialize(
                &crate::config_state::test_support::redis_replay_plan(),
                crate::config_state::test_support::freshness(60),
                None,
            )
            .err()
            .expect("refused without the backend");
            assert!(err.contains("redis_replay"), "{err}");
        }
    }

    /// **BF-01** (atlas §D.2): with neither backend linked, EVERY plan refuses — so the
    /// build can reach no replay state at all.
    ///
    /// The test above says each arm names the feature it wants. This says what those
    /// refusals amount to TOGETHER, which is the finding: `ReplayPlan` has exactly two
    /// variants and both are shared, so a build carrying neither `redis_replay` nor
    /// `cpstore_etcd` has no reachable replay state. Layer A independently refuses every
    /// other input form — `Memory` (also the value when `--replay-cache` is omitted) and
    /// `File` — so no command line reaches a state such a build can materialize, and a
    /// default build is therefore not a serving binary. The README and the sidecar
    /// deployment guide both state this; this is where it is enforced.
    ///
    /// If this ever fails, the question to ask is which replay state became reachable.
    /// The fix is NOT to restore an in-memory arm: that would make materialization
    /// describe a state layer A refuses to represent, which is the defect CF-01 removed.
    #[test]
    fn a_build_with_no_replay_backend_can_reach_no_replay_state() {
        let etcd = crate::config_state::test_support::linearizable_replay_plan();
        let redis = crate::config_state::test_support::redis_replay_plan();

        if cfg!(feature = "cpstore_etcd") {
            // Only the etcd arm can be probed without a control runtime once its backend
            // is linked; the Redis arm CONSUMES one, and handing it `None` would assert
            // the runtime contract rather than reachability. One reachable state is
            // enough to show the build is a serving binary.
            assert!(
                materialize(
                    &etcd,
                    crate::config_state::test_support::freshness(60),
                    None
                )
                .is_ok(),
                "a build linking cpstore_etcd must reach the linearizable state"
            );
            return;
        }
        if cfg!(feature = "redis_replay") {
            // Redis linked, etcd not: the etcd arm refuses for want of ITS backend, which
            // says nothing about BF-01 either way. Reachability of the Redis arm needs a
            // runtime, so it is asserted where a runtime exists, not here.
            return;
        }

        for plan in [&etcd, &redis] {
            assert!(
                materialize(plan, crate::config_state::test_support::freshness(60), None).is_err(),
                "BF-01: with neither backend linked, no replay state may be reachable"
            );
        }
    }
}
