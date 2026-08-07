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

use std::sync::Arc;

use crate::async_replay::AsyncReplayTier;
use crate::control_runtime::ControlRuntime;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::startup_plan::ReplayPlan;

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

/// Establish the planned tier.
///
/// Every refusal raised here is a statement about the BUILD or the ENVIRONMENT — a
/// backend that was not compiled in, a store that would not answer. Refusals knowable
/// from configuration alone were already raised by [`ReplayPlan::from_config`].
///
/// `control` must be present when the plan declared it needed (see
/// `startup_plan::control_runtime_requirement`); its absence there is a wiring error in
/// this process, not an operator mistake.
pub fn materialize(
    plan: &ReplayPlan,
    max_clock_skew: i64,
    control: Option<&ControlRuntime>,
) -> Result<MaterializedReplay, String> {
    let materialized = match plan {
        ReplayPlan::Memory => MaterializedReplay {
            tier: AsyncReplayTier::new(
                Arc::new(crate::async_replay::InMemoryAsyncAtomicReplayStore::new()),
                max_clock_skew,
            ),
            dispatch: ProxyDispatchConfig {
                fleet_strict: false,
                tier: None,
            },
        },
        ReplayPlan::Etcd { endpoint, tier } => {
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
                MaterializedReplay {
                    tier: AsyncReplayTier::new(store, max_clock_skew),
                    dispatch: ProxyDispatchConfig {
                        fleet_strict: true,
                        tier: Some(tier.clone()),
                    },
                }
            }
            #[cfg(not(feature = "cpstore_etcd"))]
            {
                let _ = (endpoint, tier);
                return Err("--replay-durability-tier linearizable requires a build with the `cpstore_etcd` feature".to_string());
            }
        }
        ReplayPlan::Redis { url, tier } => {
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
                MaterializedReplay {
                    tier: AsyncReplayTier::new(Arc::new(store), max_clock_skew),
                    dispatch: ProxyDispatchConfig {
                        fleet_strict: true,
                        tier: Some(tier.clone()),
                    },
                }
            }
            #[cfg(not(feature = "redis_replay"))]
            {
                let _ = (url, tier, control);
                return Err("--replay-cache shared (redis) requires a build with the `redis_replay` feature".to_string());
            }
        }
    };
    assert_durable(&materialized.tier)?;
    Ok(materialized)
}

/// #78 (ADR-MCPS-020): refuse to hand over a tier that self-declares the volatile
/// single-process reference posture.
///
/// The producer checks its own output, so no caller can forget to. `--replay-cache
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
             a durable replay store is required — use --replay-cache file or --replay-cache \
             shared, or inject a cache that declares ReplayDurabilityClass::Durable"
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
    /// Validation already refuses `--replay-cache memory` before planning sees it, so this
    /// is the backstop firing rather than the operator-facing refusal — and it fires from
    /// inside the producer, so a future caller cannot acquire the tier without it.
    #[test]
    fn a_volatile_tier_is_never_handed_over() {
        let err = materialize(&ReplayPlan::Memory, 60, None)
            .err()
            .expect("the volatile tier must be refused");
        assert!(err.contains("single-process reference"), "{err}");
    }

    /// A backend the build does not contain is refused by NAME. This is the refusal class
    /// that deliberately stayed with materialization: it is a fact about the build, not
    /// about the request, so planning must not raise it.
    #[test]
    fn a_backend_the_build_lacks_is_refused_and_named() {
        let etcd = materialize(
            &ReplayPlan::Etcd {
                endpoint: "http://203.0.113.1:2379".to_string(),
                tier: ReplayDurabilityTier::Linearizable,
            },
            60,
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
                &ReplayPlan::Redis {
                    url: "redis://203.0.113.1:6379".to_string(),
                    tier: ReplayDurabilityTier::SingleStoreFailClosed,
                },
                60,
                None,
            )
            .err()
            .expect("refused without the backend");
            assert!(err.contains("redis_replay"), "{err}");
        }
    }
}
