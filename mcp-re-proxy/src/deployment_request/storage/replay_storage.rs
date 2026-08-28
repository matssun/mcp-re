// SPDX-License-Identifier: Apache-2.0
//! Where admitted nonces live, and what durability the deployment claims for them.

use super::{EtcdStoreRequest, RedisStoreRequest};
use crate::replay_tier::ReplayDurabilityTier;

/// The replay store this deployment asks for.
///
/// Two INDEPENDENT facts, deliberately not one. The durability tier is a deployment
/// assertion about the guarantee (ADR-MCPS-020) and the store is where that guarantee must
/// be delivered; a request can name a tier its store cannot serve, and the configuration
/// boundary says so. Folding the store into the tier would make that mismatch
/// unrepresentable at the cost of the tier no longer being a claim a deployment states.
///
/// What IS unrepresentable is the cross-backend pair. There used to be two sibling
/// locators — `replay_redis_url` and `cpstore_etcd_endpoint` — and a configuration could
/// set both, so the boundary carried two refusals explaining that one of them had no
/// effect. One tagged slot removes the pair: naming etcd is how Redis stops being named
/// (ADR-MCPRE-067 §7).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplayStorageRequest {
    /// The declared durability tier. `None` names no state at all, which the boundary
    /// refuses rather than treating as a weaker default.
    pub durability: Option<ReplayDurabilityTier>,
    /// Where admitted nonces live. `None` is a missing locator, refused beside the tier
    /// that required one.
    pub store: Option<ReplayStoreRequest>,
}

/// Which store admits nonces.
///
/// Replay chooses between two backends today, which is why it has its own selection rather
/// than [`SharedStoreRequest`](super::SharedStoreRequest): the CP store is not
/// interchangeable with Redis, and the tier says which one the claim needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayStoreRequest {
    /// A Redis store, which can serve the quorum-acknowledged tiers.
    Redis(RedisStoreRequest),
    /// A CP / linearizable store, which serves the linearizable tier.
    Etcd(EtcdStoreRequest),
}

impl ReplayStoreRequest {
    /// A Redis store at `url`.
    pub fn redis(url: impl Into<String>) -> Self {
        ReplayStoreRequest::Redis(RedisStoreRequest { url: url.into() })
    }

    /// A CP store at `endpoint`.
    pub fn etcd(endpoint: impl Into<String>) -> Self {
        ReplayStoreRequest::Etcd(EtcdStoreRequest {
            endpoint: endpoint.into(),
        })
    }

    /// The locator, whichever store this is.
    pub fn locator(&self) -> &str {
        match self {
            ReplayStoreRequest::Redis(redis) => &redis.url,
            ReplayStoreRequest::Etcd(etcd) => &etcd.endpoint,
        }
    }

    /// The flag an operator would have typed to name this store, for a refusal that has to
    /// tell them which one they gave.
    pub fn flag(&self) -> &'static str {
        match self {
            ReplayStoreRequest::Redis(_) => "--replay-redis-url",
            ReplayStoreRequest::Etcd(_) => "--cpstore-etcd-endpoint",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Disjointness: one slot, so naming one store is how the other stops being named.
    /// The pair the boundary used to refuse cannot be built.
    #[test]
    fn a_replay_store_is_one_backend_and_carries_only_its_own_locator() {
        let redis = ReplayStoreRequest::redis("redis://h:6379");
        let etcd = ReplayStoreRequest::etcd("http://h:2379");
        assert_eq!(redis.locator(), "redis://h:6379");
        assert_eq!(etcd.locator(), "http://h:2379");
        assert_ne!(redis.flag(), etcd.flag());
    }

    /// The tier is independent of the store, which is what lets a deployment declare a
    /// claim its store cannot deliver — and lets the boundary say so.
    #[test]
    fn the_durability_claim_and_the_store_are_separately_stated() {
        let request = ReplayStorageRequest {
            durability: Some(ReplayDurabilityTier::Linearizable),
            store: Some(ReplayStoreRequest::redis("redis://h:6379")),
        };
        assert!(matches!(request.store, Some(ReplayStoreRequest::Redis(_))));
        assert_eq!(request.durability, Some(ReplayDurabilityTier::Linearizable));
    }
}
