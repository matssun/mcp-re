// SPDX-License-Identifier: Apache-2.0
//! The backend payloads, and the selection between them.
//!
//! The mechanism layer of [`storage`](super). Several semantic roles reach the same kind
//! of store, and this is the level at which sharing is correct: a Redis URL means the same
//! thing to replay, continuation, admission and the trust epoch, while what each role does
//! with its store does not (ADR-MCPRE-067 §10).

/// A Redis endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedisStoreRequest {
    /// A scheme-bearing URL, e.g. `redis://host:6379`. Whether it resolves is
    /// materialization's; whether it has a scheme is the configuration boundary's.
    pub url: String,
}

/// An etcd v3 JSON-gateway endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EtcdStoreRequest {
    /// A scheme-bearing URL, e.g. `http://host:2379`.
    pub endpoint: String,
}

/// Which store serves a role that needs one shared across replicas.
///
/// One variant today, and an enum rather than a bare [`RedisStoreRequest`] on purpose:
/// this is the seam a second backend arrives at, and its consumers — three separate
/// semantic owners — already read a selection rather than a Redis URL. Adding a store adds
/// a variant here and changes none of them (ADR-MCPRE-067 §5).
///
/// Replay does NOT use this type: it already chooses between two backends, and its
/// selection is [`ReplayStoreRequest`](super::ReplayStoreRequest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedStoreRequest {
    /// A Redis store.
    Redis(RedisStoreRequest),
}

impl SharedStoreRequest {
    /// A Redis store at `url`, for the adapters that spell one.
    pub fn redis(url: impl Into<String>) -> Self {
        SharedStoreRequest::Redis(RedisStoreRequest { url: url.into() })
    }

    /// The locator, whichever store this is.
    ///
    /// The one projection every consumer of a shared store needs: it connects to what the
    /// operator named. A consumer that matched the variant to find the string would be
    /// asking which product this is, and would need editing for a second one that changes
    /// nothing about what it does.
    pub fn locator(&self) -> &str {
        match self {
            SharedStoreRequest::Redis(redis) => &redis.url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The projection names no product, so a consumer of it needs no case for one.
    #[test]
    fn the_locator_projection_names_no_backend() {
        assert_eq!(
            SharedStoreRequest::redis("redis://h:6379").locator(),
            "redis://h:6379"
        );
    }

    /// The replacement negative control: a store this repository does not have answers the
    /// same question, and the consumer of the answer is unchanged.
    #[test]
    fn a_store_that_does_not_exist_drives_the_same_consumer() {
        enum HypotheticalStore {
            ConsistentKeyValue { endpoint: String },
        }
        impl HypotheticalStore {
            fn locator(&self) -> &str {
                match self {
                    HypotheticalStore::ConsistentKeyValue { endpoint } => endpoint,
                }
            }
        }
        /// The consumer: it needs a locator and no product name.
        fn is_configured(locator: &str) -> bool {
            locator.contains("://")
        }
        assert!(is_configured(
            SharedStoreRequest::redis("redis://h:6379").locator()
        ));
        assert!(is_configured(
            HypotheticalStore::ConsistentKeyValue {
                endpoint: "ckv://h:1234".to_string(),
            }
            .locator()
        ));
    }
}
