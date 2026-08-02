// SPDX-License-Identifier: Apache-2.0
//! A trust store that can be re-read while the proxy is running (ADR-MCPS-021 Axis 2).
//!
//! The revocation tiers ([`crate::BoundedTrustCache`], [`crate::live_trust`],
//! [`crate::push_trust`]) all describe themselves in terms of "the store": Tier 2
//! consults it on every verification, Tier 3 evicts a cache entry and forces a
//! re-resolve against it. Those descriptions are only true statements about the
//! deployment if the store can CHANGE.
//!
//! It could not. The base resolver was an [`InMemoryTrustResolver`] deserialised once
//! from `--trust` at startup and never re-read, so every tier wrapped an immutable
//! process-lifetime map: a Tier-3 `FlushAll` evicted entries that immediately
//! re-resolved to the identical `Active` key, and `--revocation-tier live` advertised
//! a near-zero revocation window while revoking a client signing key actually required
//! editing the file and restarting every replica. The exposure window was unbounded,
//! not near-zero.
//!
//! This type is the missing half: a snapshot the reload task swaps atomically, read
//! per resolve. It is the same shape as [`crate::config_snapshot`] — a
//! `RwLock<Arc<…>>` whose read path clones the `Arc` under a short read lock — for the
//! same reason: an in-flight verification must never block on a writer, and a writer
//! must never wait on the request path.
//!
//! **A failed reload keeps the last good store.** A truncated or malformed trust file
//! mid-write must not empty the trust map: that would reject every request, turning an
//! editor's save into a fleet-wide outage. The previous snapshot stays live and the
//! failure is named on the diagnostic channel.

use std::sync::Arc;
use std::sync::RwLock;

use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::TrustResolver;
use mcp_re_core::TrustResolverError;
use mcp_re_core::VerificationKey;

/// The atomically-swappable trust store the revocation tiers resolve against.
pub struct ReloadingTrustStore {
    current: RwLock<Arc<InMemoryTrustResolver>>,
    /// The key ids the CURRENT store knows, for the actor resolver's slot map.
    /// Carried alongside the resolver because both must move in the same swap: a
    /// key removed from the file has to disappear from the request-signer set at
    /// the same instant it stops resolving, or the two disagree for a window.
    signers: RwLock<Arc<std::collections::HashMap<String, String>>>,
}

impl ReloadingTrustStore {
    /// Seed the store with the startup snapshot.
    pub fn new(
        resolver: InMemoryTrustResolver,
        signers: std::collections::HashMap<String, String>,
    ) -> Self {
        ReloadingTrustStore {
            current: RwLock::new(Arc::new(resolver)),
            signers: RwLock::new(Arc::new(signers)),
        }
    }

    /// Swap in a freshly-read store. Subsequent resolves observe it.
    pub fn store(
        &self,
        resolver: InMemoryTrustResolver,
        signers: std::collections::HashMap<String, String>,
    ) {
        // Order matters only in that both are swapped before either is read again;
        // each swap is individually atomic and neither blocks the other's readers.
        match self.current.write() {
            Ok(mut guard) => *guard = Arc::new(resolver),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(resolver),
        }
        match self.signers.write() {
            Ok(mut guard) => *guard = Arc::new(signers),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(signers),
        }
    }

    /// The signer identity enrolled for `key_id`, or `None` when this store does not
    /// know it. `None` is a refusal at the actor seam: a kid never introduces trust.
    pub fn signer_for(&self, key_id: &str) -> Option<String> {
        let map = match self.signers.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        };
        map.get(key_id).cloned()
    }

    fn resolver(&self) -> Arc<InMemoryTrustResolver> {
        match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            // A poisoned lock still yields the last value: the request path must not
            // panic because a writer paniced mid-swap, and the last-good store is the
            // fail-closed-correct answer.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }
}

impl TrustResolver for ReloadingTrustStore {
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        self.resolver().resolve(signer, key_id)
    }
}

/// A `TrustResolver` handle over a shared [`ReloadingTrustStore`].
///
/// The tier wrappers take `Box<dyn TrustResolver + Send + Sync>` by value, while the
/// reload task needs to keep writing to the same store — so the store lives behind an
/// `Arc` and this is the boxable view of it.
pub struct SharedTrustStore(pub Arc<ReloadingTrustStore>);

impl TrustResolver for SharedTrustStore {
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        self.0.resolve(signer, key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn store_with(kid: &str) -> (InMemoryTrustResolver, HashMap<String, String>) {
        let key = mcp_re_core::SigningKey::from_seed_bytes(&[9u8; 32]).public_key();
        let mut resolver = InMemoryTrustResolver::default();
        resolver.insert("signer-a", kid, key);
        let mut signers = HashMap::new();
        signers.insert(kid.to_owned(), "signer-a".to_owned());
        (resolver, signers)
    }

    /// The defect this type exists for: a key removed from the trust file must stop
    /// resolving on a RUNNING proxy, with no restart.
    #[test]
    fn a_swapped_store_revokes_without_a_restart() {
        let (resolver, signers) = store_with("kid-1");
        let store = ReloadingTrustStore::new(resolver, signers);

        store
            .resolve("signer-a", "kid-1")
            .expect("enrolled at startup");
        assert_eq!(store.signer_for("kid-1").as_deref(), Some("signer-a"));

        // The operator removes kid-1 from trust.json; the reload task swaps.
        store.store(InMemoryTrustResolver::default(), HashMap::new());

        assert!(
            store.resolve("signer-a", "kid-1").is_err(),
            "the revoked key must not resolve after the swap"
        );
        assert_eq!(
            store.signer_for("kid-1"),
            None,
            "and it must leave the request-signer set in the same swap"
        );
    }

    /// The shared handle the tier wrappers hold observes the same swap — otherwise
    /// the tier would resolve against a copy taken at boot, which is the original
    /// defect wearing a different type.
    #[test]
    fn the_shared_handle_observes_the_swap() {
        let (resolver, signers) = store_with("kid-2");
        let store = Arc::new(ReloadingTrustStore::new(resolver, signers));
        let handle = SharedTrustStore(Arc::clone(&store));

        handle.resolve("signer-a", "kid-2").expect("enrolled");
        store.store(InMemoryTrustResolver::default(), HashMap::new());
        assert!(handle.resolve("signer-a", "kid-2").is_err());
    }
}
