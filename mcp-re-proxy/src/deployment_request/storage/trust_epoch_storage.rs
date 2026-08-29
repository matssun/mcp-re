// SPDX-License-Identifier: Apache-2.0
//! Where the monotonic trust epoch lives — the operator's invalidation signal.

use super::RedisStoreRequest;

/// The trust-epoch source this deployment asks for.
///
/// `None` is the inert posture: the Push tier then runs at its bounded-`T` fallback rather
/// than watching anything. Which tier may consume a configured source at all is relation
/// X8's, at the configuration boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustEpochStoreRequest {
    /// The store the epoch is watched in, where one is configured.
    pub source: Option<TrustEpochSource>,
}

impl TrustEpochStoreRequest {
    /// The store's locator, where a source is configured.
    pub fn locator(&self) -> Option<&str> {
        self.source.as_ref().map(TrustEpochSource::locator)
    }

    /// The coordinate within it, where the operator named one.
    pub fn key(&self) -> Option<&str> {
        self.source.as_ref().and_then(TrustEpochSource::key)
    }
}

/// Which store carries the epoch, and the coordinate within it.
///
/// The key travels INSIDE the variant, which is the point of the type: it names a location
/// in a store, so a request naming a key with no store had to be refused by a boundary
/// clause (CF-04) and now cannot be built at all (ADR-MCPRE-067 §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEpochSource {
    /// A Redis store whose monotonic key the Push tier watches.
    Redis {
        /// Where the epoch lives.
        store: RedisStoreRequest,
        /// The key holding it. `None` takes this machine's default, so nothing downstream
        /// can tell an omitted key from a named one.
        key: Option<String>,
    },
}

impl TrustEpochSource {
    /// A Redis epoch source at `url`, optionally at a named key.
    pub fn redis(url: impl Into<String>, key: Option<String>) -> Self {
        TrustEpochSource::Redis {
            store: RedisStoreRequest { url: url.into() },
            key,
        }
    }

    /// The locator, whichever store this is.
    pub fn locator(&self) -> &str {
        match self {
            TrustEpochSource::Redis { store, .. } => &store.url,
        }
    }

    /// The coordinate within it, where the operator named one.
    pub fn key(&self) -> Option<&str> {
        match self {
            TrustEpochSource::Redis { key, .. } => key.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key with no store cannot be stated. The CF-04 refusal that existed to say so has
    /// no configuration left to examine.
    #[test]
    fn a_coordinate_cannot_exist_without_the_store_it_names_a_place_in() {
        let absent = TrustEpochStoreRequest::default();
        assert!(absent.source.is_none());
        let named = TrustEpochSource::redis("redis://h:6379", Some("epoch".to_string()));
        assert_eq!(named.locator(), "redis://h:6379");
        assert_eq!(named.key(), Some("epoch"));
    }

    /// An omitted key is still a configured source: the default is the machine's to apply.
    #[test]
    fn a_source_without_a_named_key_is_still_a_source() {
        let source = TrustEpochSource::redis("redis://h:6379", None);
        assert_eq!(source.key(), None);
        assert_eq!(source.locator(), "redis://h:6379");
    }
}
