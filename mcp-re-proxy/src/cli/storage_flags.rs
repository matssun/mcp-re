// SPDX-License-Identifier: Apache-2.0
//! The storage locators, assembled into the typed requests — ADR-MCPRE-067 §16.
//!
//! Four semantic roles each name a store, and an operator names each one with its own flat
//! flag because a command line is flat. This is the adapter: it reads the flags and hands
//! back one typed value per role, so nothing below it sees a locator whose meaning depends
//! on a flag beside it.
//!
//! **Two refusals live here, and both are argv-shaped.** Naming two replay backends at
//! once, and naming a trust-epoch key with no store to find it in, were configuration-
//! boundary clauses; the typed requests make both unrepresentable, so the boundary has no
//! configuration left to refuse and the parser is the one place that still sees the pair
//! (ADR-MCPRE-067 §7, and the owner ruling on stray CLI values).

use crate::deployment_request::ContinuationStoreRequest;
use crate::deployment_request::{
    ReplayStorageRequest, ReplayStoreRequest, SharedStoreRequest, TrustEpochSource,
    TrustEpochStoreRequest,
};
use crate::replay_tier::ReplayDurabilityTier;

/// The storage inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct StorageFlags {
    replay_redis_url: Option<String>,
    cpstore_etcd_endpoint: Option<String>,
    durability: Option<ReplayDurabilityTier>,
    continuation_url: Option<String>,
    trust_epoch_url: Option<String>,
    trust_epoch_key: Option<String>,
}

/// Where one deployment's shared state lives.
pub(super) struct SharedState {
    pub(super) replay: ReplayStorageRequest,
    pub(super) continuation: ContinuationStoreRequest,
    pub(super) trust_epoch: TrustEpochStoreRequest,
}

impl StorageFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--replay-redis-url"
                | "--cpstore-etcd-endpoint"
                | "--replay-durability-tier"
                | "--continuation-control-redis-url"
                | "--trust-epoch-redis-url"
                | "--trust-epoch-key"
        )
    }

    /// Read one flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        let held = || Some(value.to_string());
        match flag {
            "--replay-redis-url" => self.replay_redis_url = held(),
            // #69: the CP / etcd endpoint for the LINEARIZABLE durability tier.
            "--cpstore-etcd-endpoint" => self.cpstore_etcd_endpoint = held(),
            "--replay-durability-tier" => {
                self.durability = Some(ReplayDurabilityTier::parse(value)?)
            }
            "--continuation-control-redis-url" => self.continuation_url = held(),
            "--trust-epoch-redis-url" => self.trust_epoch_url = held(),
            _ => self.trust_epoch_key = held(),
        }
        Ok(())
    }

    /// Where each role's state lives. The trust epoch is handed to the currency family
    /// rather than kept here: only the pushing posture reads one, and that family owns the
    /// selection it belongs to.
    pub(super) fn finish(self) -> Result<SharedState, String> {
        Ok(SharedState {
            replay: replay(
                self.durability,
                self.replay_redis_url,
                self.cpstore_etcd_endpoint,
            )?,
            continuation: ContinuationStoreRequest {
                shared: shared(self.continuation_url),
            },
            trust_epoch: trust_epoch(self.trust_epoch_url, self.trust_epoch_key)?,
        })
    }
}

/// The replay store and the durability claimed for it.
///
/// The two are independent: a deployment states a tier and states a store, and whether the
/// store can deliver the tier is the configuration boundary's relation. What cannot be
/// stated at all is two stores.
fn replay(
    durability: Option<ReplayDurabilityTier>,
    redis_url: Option<String>,
    etcd_endpoint: Option<String>,
) -> Result<ReplayStorageRequest, String> {
    let store = match (redis_url, etcd_endpoint) {
        (Some(_), Some(_)) => {
            return Err(
                "--replay-redis-url and --cpstore-etcd-endpoint both name the replay \
                 store: a deployment has one replay store, and the durability tier says \
                 which kind it must be. Give the one the declared \
                 --replay-durability-tier requires. If a shared MRTR continuation store \
                 is wanted alongside a CP replay store, configure it separately with \
                 --continuation-control-redis-url"
                    .to_string(),
            )
        }
        (Some(url), None) => Some(ReplayStoreRequest::redis(url)),
        (None, Some(endpoint)) => Some(ReplayStoreRequest::etcd(endpoint)),
        (None, None) => None,
    };
    Ok(ReplayStorageRequest { durability, store })
}

/// The trust-epoch source, with the key as a coordinate INSIDE it.
///
/// A key with no store names a place in a store this deployment does not have. That was
/// CF-04 at the boundary; the coordinate now travels inside the source, so only a command
/// line can still say it.
fn trust_epoch(
    redis_url: Option<String>,
    key: Option<String>,
) -> Result<TrustEpochStoreRequest, String> {
    match (redis_url, key) {
        (None, Some(_)) => Err(
            "--trust-epoch-key names a key in a trust-epoch store this configuration does \
             not have; set --trust-epoch-redis-url under --revocation-tier push, or remove \
             --trust-epoch-key"
                .to_string(),
        ),
        (Some(url), key) => Ok(TrustEpochStoreRequest {
            source: Some(TrustEpochSource::redis(url, key)),
        }),
        (None, None) => Ok(TrustEpochStoreRequest::default()),
    }
}

/// A role served by whichever shared store the operator named, or by none.
fn shared(url: Option<String>) -> Option<SharedStoreRequest> {
    url.map(SharedStoreRequest::redis)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two replay backends at once is the pair the request can no longer hold, so the
    /// adapter answers it.
    #[test]
    fn naming_two_replay_stores_is_refused_by_the_adapter() {
        let err = replay(
            Some(ReplayDurabilityTier::Linearizable),
            Some("redis://h:6379".to_string()),
            Some("http://h:2379".to_string()),
        )
        .expect_err("one deployment, one replay store");
        assert!(err.contains("both name the replay store"), "{err}");
    }

    /// The negative controls: either backend alone is a coherent command line, and so is
    /// neither — the tier then has no store, which the boundary refuses with every other
    /// violation rather than the parser cutting the parse short.
    #[test]
    fn either_replay_store_alone_and_neither_are_coherent() {
        let redis = replay(None, Some("redis://h:6379".to_string()), None).expect("one store");
        assert!(matches!(redis.store, Some(ReplayStoreRequest::Redis(_))));
        let etcd = replay(None, None, Some("http://h:2379".to_string())).expect("one store");
        assert!(matches!(etcd.store, Some(ReplayStoreRequest::Etcd(_))));
        assert_eq!(replay(None, None, None).expect("none").store, None);
    }

    /// A coordinate with no store is refused; with one, it travels inside it.
    #[test]
    fn a_trust_epoch_key_needs_the_store_it_names_a_place_in() {
        let err = trust_epoch(None, Some("epoch".to_string())).expect_err("no store");
        assert!(err.contains("--trust-epoch-key"), "{err}");
        let named = trust_epoch(
            Some("redis://h:6379".to_string()),
            Some("epoch".to_string()),
        )
        .expect("a store and a key")
        .source
        .expect("configured");
        assert_eq!(named.key(), Some("epoch"));
        assert_eq!(named.locator(), "redis://h:6379");
        assert_eq!(trust_epoch(None, None).expect("neither").source, None);
    }
}
