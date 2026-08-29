// SPDX-License-Identifier: Apache-2.0
//! Where this deployment's shared state lives — ADR-MCPRE-067 §7, §10.
//!
//! Several semantic roles keep shared state: replay admits a nonce once, continuation
//! retains a base across replicas, the trust epoch carries the operator's invalidation
//! signal, and an applied admission gate holds the authoritative record a revocation is
//! written to. **They are separate propositions, not one.** That three of them are usually served by the same Redis
//! is a deployment choice; it is not evidence that they are the same fact, and merging
//! their owners would make one outage three.
//!
//! ```text
//! semantic storage requirement    ReplayStorageRequest / ContinuationStoreRequest /
//!                                 TrustEpochStoreRequest / an applied admission gate
//!         ↓
//! durability / consistency fact   ReplayDurabilityTier  (replay's alone; the others make
//!                                                        no durability claim)
//!         ↓
//! typed backend selection         ReplayStoreRequest / SharedStoreRequest / TrustEpochSource
//!         ↓
//! backend payload                 RedisStoreRequest / EtcdStoreRequest
//!         ↓
//! adapter                         redis_store.rs / etcd_store.rs / the in-memory store
//! ```
//!
//! **What is shared is the mechanism layer, and only that.** One `RedisStoreRequest` is
//! reused by every role that can be served by Redis, because a Redis URL is a Redis URL.
//! The roles above it stay separate types, so nothing can read one role's store where
//! another's was meant.

mod continuation_storage;
mod replay_storage;
mod shared_store;
mod trust_epoch_storage;

pub use continuation_storage::ContinuationStoreRequest;
pub use replay_storage::{ReplayStorageRequest, ReplayStoreRequest};
pub use shared_store::{EtcdStoreRequest, RedisStoreRequest, SharedStoreRequest};
pub use trust_epoch_storage::{TrustEpochSource, TrustEpochStoreRequest};
