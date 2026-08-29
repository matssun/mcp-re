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
        eprintln!("mcp-re-proxy: replay tier = shared (CP/linearizable; async etcd backend)");
        eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("etcd"));
        let store = std::sync::Arc::new(
            crate::async_etcd_store::EtcdAsyncAtomicReplayStore::connect(endpoint),
        );
        return Ok((
            AsyncReplayTier::new(store, freshness),
            ProxyDispatchConfig {
                fleet_strict: true,
                tier: Some(tier.clone()),
            },
        ));
    }
    #[cfg(not(feature = "cpstore_etcd"))]
    Err(
        "--replay-durability-tier linearizable requires a build with the `cpstore_etcd` feature"
            .to_string(),
    )
}

/// The horizontally-scaled backend: async Redis `SET NX PX`, with the declared WAIT quorum
/// applied to the store that actually serves.
///
/// Two things are ordered here and both matter. The client-side response timeout is sized
/// for the DECLARED wait timeout BEFORE connecting: the library defaults to 500ms per
/// command and `WAIT` is an ordinary command, so a declared `redis-wait-quorum:2:2000`
/// could never wait 2000ms, and any replica ack slower than 500ms failed the request closed
/// while the startup line advertised the fuller window. And the tier is applied to the
/// store afterwards: `startup_audit_line` has already promised "WAIT timeout or
/// insufficient acks fail closed", and without this the store would run plain `SET NX PX`
/// and the promise would be audited but unenforced.
#[cfg_attr(not(feature = "redis_replay"), allow(unused_variables))]
pub(super) fn establish_redis(
    url: &str,
    tier: &ReplayDurabilityTier,
    freshness: crate::config_state::FreshnessWindow,
    control: Option<&ControlRuntime>,
) -> Result<(AsyncReplayTier, ProxyDispatchConfig), String> {
    #[cfg(feature = "redis_replay")]
    {
        eprintln!("mcp-re-proxy: replay tier = shared (horizontally-scaled; async Redis backend)");
        eprintln!("mcp-re-proxy: {}", tier.startup_audit_line("redis"));
        let rt = control
            .expect("the plan declared the redis replay tier needs the control runtime")
            .handle();
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
        if let Some((quorum, timeout_ms)) = tier.wait_quorum_params() {
            store = store.with_wait_quorum(quorum, timeout_ms);
        }
        return Ok((
            AsyncReplayTier::new(std::sync::Arc::new(store), freshness),
            ProxyDispatchConfig {
                fleet_strict: true,
                tier: Some(tier.clone()),
            },
        ));
    }
    #[cfg(not(feature = "redis_replay"))]
    Err(
        "--replay-cache shared (redis) requires a build with the `redis_replay` feature"
            .to_string(),
    )
}
