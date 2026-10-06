// SPDX-License-Identifier: Apache-2.0
//! Establishing one concrete backend, and refusing the ones this build does not carry.
//!
//! Every refusal here is a statement about the BUILD — a backend that was not compiled in —
//! or about the ENVIRONMENT — a store that would not answer. Refusals knowable from
//! configuration alone were already decided by layer A.
//!
//! The two backends differ in more than their protocol. The etcd store drives its own
//! requests, so it needs no share of the control runtime and the plan declares none for it;
//! the Redis one does, and its `WAIT` window has to be sized BEFORE connecting or the
//! declared durability would be advertised and not enforced.

use crate::async_replay::AsyncReplayTier;
use crate::control_runtime::ControlRuntime;
use crate::http_profile_dispatch::ProxyDispatchConfig;
use crate::replay_tier::ReplayDurabilityTier;

/// The retention padding this deployment's shared store applies, stated at startup.
///
/// An operator told the replay window is `--max-clock-skew` is told something shorter than
/// what the store keeps, so the extra retention is announced beside the tier.
#[cfg(any(feature = "redis_replay", feature = "cpstore_etcd"))]
fn divergence_audit_line(freshness: crate::config_state::FreshnessWindow) -> String {
    format!(
        "replay retention padded by {}s for replica clock divergence \
         (--replay-clock-divergence-secs)",
        freshness.replica_clock_divergence().secs()
    )
}

/// The CP/linearizable backend: an async etcd CAS per admitted nonce.
///
/// The store drives its own requests, so it needs no share of the control runtime — which
/// is why the plan does not declare one for it.
#[cfg_attr(not(feature = "cpstore_etcd"), allow(unused_variables))]
pub(super) fn establish_etcd(
    endpoint: &str,
    tier: &ReplayDurabilityTier,
    freshness: crate::config_state::FreshnessWindow,
) -> Result<(AsyncReplayTier, ProxyDispatchConfig), String> {
    #[cfg(feature = "cpstore_etcd")]
    {
        let store = std::sync::Arc::new(
            crate::async_etcd_store::EtcdAsyncAtomicReplayStore::connect_with(
                endpoint,
                freshness
                    .replica_clock_divergence()
                    .retention_clock(crate::async_etcd_store::system_clock()),
            )
            .map_err(|e| e.to_string())?,
        );
        eprintln!("mcp-re-proxy: replay tier = shared (CP/linearizable; async etcd backend)");
        eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("etcd"));
        eprintln!("mcp-re-proxy: {}", divergence_audit_line(freshness));
        Ok((
            AsyncReplayTier::new(store, freshness),
            ProxyDispatchConfig {
                fleet_strict: true,
                tier: Some(tier.clone()),
            },
        ))
    }
    #[cfg(not(feature = "cpstore_etcd"))]
    Err(
        "--replay-durability-tier linearizable requires a build with the `cpstore_etcd` feature"
            .to_string(),
    )
}

/// The horizontally-scaled backend: async Redis `SET NX PX`, connected in the tier the
/// plan declares.
///
/// The declared WAIT quorum is a construction parameter of the store that serves:
/// `startup_audit_line` has already promised "WAIT timeout or insufficient acks fail
/// closed", so a store built without it would run plain `SET NX PX` and the promise would
/// be audited but unenforced. The same value sizes the client-side response timeout, so a
/// declared `redis-wait-quorum:2:2000` can actually wait 2000ms.
#[cfg_attr(not(feature = "redis_replay"), allow(unused_variables))]
pub(super) fn establish_redis(
    url: &str,
    tier: &ReplayDurabilityTier,
    freshness: crate::config_state::FreshnessWindow,
    control: Option<&ControlRuntime>,
) -> Result<(AsyncReplayTier, ProxyDispatchConfig), String> {
    #[cfg(feature = "redis_replay")]
    {
        let connection = redis_connection(tier, freshness, control)?;
        let store = connection
            .runtime
            .block_on(
                crate::RedisAsyncAtomicReplayStore::connect_with_wait_quorum(
                    url,
                    connection.clock,
                    connection.wait_quorum,
                ),
            )
            .map_err(|e| format!("connect redis async replay store: {e:?}"))?;
        eprintln!("mcp-re-proxy: replay tier = shared (horizontally-scaled; async Redis backend)");
        eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("redis"));
        eprintln!("mcp-re-proxy: {}", divergence_audit_line(freshness));
        Ok((
            AsyncReplayTier::new(std::sync::Arc::new(store), freshness),
            ProxyDispatchConfig {
                fleet_strict: true,
                tier: Some(tier.clone()),
            },
        ))
    }
    #[cfg(not(feature = "redis_replay"))]
    Err(
        "--replay-cache shared (redis) requires a build with the `redis_replay` feature"
            .to_string(),
    )
}

/// What connecting the Redis store needs, read off the plan before anything is contacted:
/// the control runtime's handle, the clock held back by the declared divergence, and the
/// declared `WAIT` quorum. Separate from the connect so the refusal and the quorum are
/// assertable in the `redis_replay` lane without a live server.
#[cfg(feature = "redis_replay")]
struct RedisConnection {
    runtime: tokio::runtime::Handle,
    clock: crate::async_redis_store::UnixClock,
    wait_quorum: Option<(u32, u64)>,
}

/// Refuse, do not panic: the caller reports a startup refusal, and a panic in the
/// composition root would reach an operator as a backtrace rather than as the sentence that
/// says which part of the plan disagreed with which.
#[cfg(feature = "redis_replay")]
fn redis_connection(
    tier: &ReplayDurabilityTier,
    freshness: crate::config_state::FreshnessWindow,
    control: Option<&ControlRuntime>,
) -> Result<RedisConnection, String> {
    let runtime = control
        .ok_or_else(|| {
            "the plan declared the redis replay tier, which needs the control runtime, \
             and none was established"
                .to_owned()
        })?
        .handle();
    Ok(RedisConnection {
        runtime,
        clock: freshness
            .replica_clock_divergence()
            .retention_clock(crate::async_redis_store::system_clock()),
        wait_quorum: tier.wait_quorum_params(),
    })
}

#[cfg(test)]
mod tests {
    /// Each shared backend is connected on the clock held back by the declared replica
    /// clock divergence. The padding lives in that clock, so a backend connected on the bare
    /// system clock is a store whose records lapse early on a fast replica, and nothing in
    /// the store can tell.
    #[test]
    fn both_shared_backends_are_connected_on_the_held_back_clock() {
        let source = include_str!("backends.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("a production half");
        for backend in ["fn establish_etcd", "fn establish_redis"] {
            let from = production
                .find(backend)
                .expect("the backend is established here");
            let body = &production[from + backend.len()..];
            let body = body.split("pub(super) fn ").next().expect("a body");
            assert_eq!(
                body.matches(".retention_clock(").count(),
                1,
                "{backend} must derive its store's clock from the declared divergence exactly once"
            );
        }
    }
    /// The Redis arm reads its `WAIT` quorum off the plan before contacting anything, so
    /// the store that serves is built in the tier the startup audit line advertises. The
    /// fixture declares `redis-wait-quorum:1:100`; a connection built with no quorum would
    /// run plain `SET NX PX` under a fail-closed claim.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn the_redis_arm_connects_in_the_declared_wait_quorum() {
        let plan = crate::config_state::test_support::redis_replay_plan();
        let control = crate::control_runtime::ControlRuntime::start(
            crate::control_runtime::ControlRuntimeRequirement::Required,
        )
        .expect("the control runtime starts")
        .expect("a required runtime is established");
        let connection = super::redis_connection(
            plan.tier(),
            crate::config_state::test_support::freshness(60),
            Some(&control),
        )
        .unwrap_or_else(|e| panic!("a planned redis tier with a runtime connects: {e}"));
        assert_eq!(connection.wait_quorum, Some((1, 100)));
    }

    /// Without the control runtime the Redis arm refuses, before any connect, with the
    /// sentence that names what the plan was missing.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn the_redis_arm_refuses_without_the_control_runtime() {
        let plan = crate::config_state::test_support::redis_replay_plan();
        let err = match super::redis_connection(
            plan.tier(),
            crate::config_state::test_support::freshness(60),
            None,
        ) {
            Ok(_) => panic!("the redis arm needs the control runtime"),
            Err(e) => e,
        };
        assert!(err.contains("control runtime"), "{err}");
    }
}
