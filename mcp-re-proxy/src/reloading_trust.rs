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
//!
//! # What one read of `--trust` produces is one value (M9)
//!
//! The verification keys and the kid -> signer coordinate are two views of the SAME read
//! of the trust file, and they are published as one [`TrustSnapshot`]. They used to be
//! two `RwLock`s swapped in sequence, under a comment saying they "must move in the same
//! swap" — which the implementation did not do. Between the two writes the store itself
//! held a resolver from read N and a signer map from read N-1.
//!
//! That happened to fail closed, because resolution consumes the composite
//! `(signer, key_id)` and a torn pair does not resolve. But safe-by-consequence is not
//! the mechanism the code claimed, and it made the guarantee depend on a downstream
//! property in another crate rather than on the publication itself. One lock over one
//! value removes the window instead of arguing about it.
//!
//! What remains, and is not a defect: the request path calls [`SignerDirectory::signer_for`]
//! and [`TrustResolver::resolve`] at two different moments, so a reload landing between
//! them is observable. That is ordinary — the same as a reload landing just before the
//! request — and it fails closed in both directions, because each call answers from a
//! snapshot that was internally coherent and neither answer admits anything alone
//! (see [`SignerDirectory`]).

use std::sync::Arc;
use std::sync::RwLock;

use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::TrustResolver;
use mcp_re_core::TrustResolverError;
use mcp_re_core::VerificationKey;

/// One read of the trust file, as one value.
///
/// Both fields describe the same enrollment set: a key removed from the file stops
/// resolving and disappears from the request-signer set at the same instant, because
/// there is no instant between them. Adding a field here is how a future view of the
/// same read stays in step; adding a second lock beside `current` is how it stops.
struct TrustSnapshot {
    resolver: InMemoryTrustResolver,
    /// The key ids this snapshot knows, for the actor resolver's slot map.
    signers: std::collections::HashMap<String, String>,
}

/// The atomically-swappable trust store the revocation tiers resolve against.
pub struct ReloadingTrustStore {
    current: RwLock<Arc<TrustSnapshot>>,
}

impl ReloadingTrustStore {
    /// Seed the store with the startup snapshot.
    pub fn new(
        resolver: InMemoryTrustResolver,
        signers: std::collections::HashMap<String, String>,
    ) -> Self {
        ReloadingTrustStore {
            current: RwLock::new(Arc::new(TrustSnapshot { resolver, signers })),
        }
    }

    /// Swap in a freshly-read store. Subsequent resolves observe it, whole.
    pub fn store(
        &self,
        resolver: InMemoryTrustResolver,
        signers: std::collections::HashMap<String, String>,
    ) {
        let next = Arc::new(TrustSnapshot { resolver, signers });
        match self.current.write() {
            Ok(mut guard) => *guard = next,
            Err(poisoned) => *poisoned.into_inner() = next,
        }
    }

    /// A live read-only view of the signer coordinate, for consumers that must observe
    /// reloads but must not be able to cause one.
    pub fn signer_directory(self: &Arc<Self>) -> SignerDirectory {
        SignerDirectory(Arc::clone(self))
    }

    /// The signer identity enrolled for `key_id`, or `None` when this store does not
    /// know it. `None` is a refusal at the actor seam: a kid never introduces trust.
    pub fn signer_for(&self, key_id: &str) -> Option<String> {
        self.snapshot().signers.get(key_id).cloned()
    }

    /// The current snapshot. The `Arc` is cloned under a short read lock and read
    /// outside it, so a verification never blocks on the reload worker.
    fn snapshot(&self) -> Arc<TrustSnapshot> {
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
        self.snapshot().resolver.resolve(signer, key_id)
    }
}

/// A live, read-only view of the kid -> signer-identity coordinate.
///
/// The actor seam needs to look a kid up on every request and must see reloads as they
/// land, so it needs an ongoing handle rather than a snapshot. What it does NOT need is
/// [`ReloadingTrustStore::store`] — the swap the reload worker performs. Holding the
/// whole `Arc<ReloadingTrustStore>` to call one read method grants the request path the
/// ability to replace the entire trust map; nothing exercises that, but a capability
/// that only the reload worker should have does not belong on the hot path.
///
/// This narrows the grant without hiding the dependency: the actor resolver's signature
/// still says it reads live trust state, which is security-significant and should stay
/// visible.
///
/// # Security invariant
///
/// **A `SignerDirectory` is descriptive, not independently authoritative.** A lookup
/// cannot establish request authenticity: it yields an identity COORDINATE, and that
/// binding is consumed only in conjunction with a successful verification through the
/// trust resolver, which supplies the key. `None` refuses; `Some` admits nothing on its
/// own.
///
/// That invariant is what makes this type's lifetime safe. A directory outliving the
/// plane that produced it keeps answering from the last snapshot — deliberately, and
/// tested in `trust_plane` — while a resolver in the same position fails closed. Only
/// the asymmetry above justifies the difference.
///
/// So widening this type is not a local change. Giving it verification material, a
/// revocation opinion, or any answer that could admit a request on its own would
/// invalidate the reason a frozen directory is harmless, and the lifetime tests would
/// still pass while the argument beneath them had gone.
#[derive(Clone)]
pub struct SignerDirectory(Arc<ReloadingTrustStore>);

impl SignerDirectory {
    /// The signer identity enrolled for `key_id` in the CURRENT snapshot, or `None`.
    pub fn signer_for(&self, key_id: &str) -> Option<String> {
        self.0.signer_for(key_id)
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

    /// M9 — a swap moves BOTH views, in both directions, for every kind of edit an
    /// operator makes: removal, addition, and reassignment to a different kid.
    ///
    /// The broken implementation this catches: a `store` that publishes one half of the
    /// snapshot and leaves the other — the shape the two-lock version could reach
    /// transiently, and the shape a future edit reintroduces permanently by adding a
    /// field beside `current` instead of inside `TrustSnapshot`. Each direction is
    /// asserted separately because a half-swap is visible in only one of them: dropping
    /// the resolver write alone leaves a revoked key resolving, and dropping the signers
    /// write alone leaves it in the request-signer set.
    #[test]
    fn every_edit_moves_the_resolver_and_the_signer_set_together() {
        let (resolver, signers) = store_with("kid-old");
        let store = ReloadingTrustStore::new(resolver, signers);
        let resolves = |s: &ReloadingTrustStore, kid: &str| s.resolve("signer-a", kid).is_ok();

        assert!(resolves(&store, "kid-old") && store.signer_for("kid-old").is_some());

        // Reassignment: the same signer under a different kid.
        let (resolver, signers) = store_with("kid-new");
        store.store(resolver, signers);
        assert!(
            !resolves(&store, "kid-old"),
            "the retired kid still resolves: the resolver half did not move"
        );
        assert_eq!(
            store.signer_for("kid-old"),
            None,
            "the retired kid is still a request signer: the signers half did not move"
        );
        assert!(resolves(&store, "kid-new") && store.signer_for("kid-new").is_some());

        // Removal: the file is emptied.
        store.store(InMemoryTrustResolver::default(), HashMap::new());
        assert!(!resolves(&store, "kid-new"));
        assert_eq!(store.signer_for("kid-new"), None);

        // Addition: back to a populated file.
        let (resolver, signers) = store_with("kid-added");
        store.store(resolver, signers);
        assert!(resolves(&store, "kid-added") && store.signer_for("kid-added").is_some());
    }

    /// A snapshot is a value, so a reader holding one keeps BOTH of its halves across
    /// any number of swaps.
    ///
    /// This is what "one publication unit" buys, stated where it is checkable: the
    /// reload worker cannot reach inside a snapshot a reader is using and move one half
    /// of it. The broken implementation this catches is the mirror of the test above —
    /// publishing by mutating shared maps in place rather than by replacing the value.
    #[test]
    fn a_snapshot_a_reader_already_holds_is_unaffected_by_later_swaps() {
        let (resolver, signers) = store_with("kid-held");
        let store = ReloadingTrustStore::new(resolver, signers);
        let held = store.snapshot();

        store.store(InMemoryTrustResolver::default(), HashMap::new());

        assert!(
            held.resolver.resolve("signer-a", "kid-held").is_ok(),
            "the held snapshot's resolver was mutated by a later swap"
        );
        assert_eq!(
            held.signers.get("kid-held").map(String::as_str),
            Some("signer-a"),
            "the held snapshot's signer set was mutated by a later swap"
        );
        // And the store itself did move on, so the assertions above are not describing
        // a swap that never happened.
        assert!(store.resolve("signer-a", "kid-held").is_err());
    }

    /// ADR-MCPRE-057 §17.3 — under a concurrent reload, a snapshot is never torn.
    ///
    /// The writer alternates between two DISJOINT enrollments, so a snapshot built from
    /// two different reads is detectable: it would resolve one kid while listing the
    /// other. The reader takes one snapshot per iteration and checks that its two halves
    /// agree about both kids.
    ///
    /// Bounded by iteration count rather than by wall clock, so it cannot hang; a
    /// failure names the snapshot that disagreed rather than only that one did.
    #[test]
    fn a_reader_never_observes_a_snapshot_built_from_two_different_reads() {
        let (resolver, signers) = store_with("kid-a");
        let store = Arc::new(ReloadingTrustStore::new(resolver, signers));

        let writer_store = Arc::clone(&store);
        let writer = std::thread::spawn(move || {
            for i in 0..2_000 {
                let (resolver, signers) = store_with(if i % 2 == 0 { "kid-b" } else { "kid-a" });
                writer_store.store(resolver, signers);
            }
        });

        for _ in 0..20_000 {
            let snapshot = store.snapshot();
            for kid in ["kid-a", "kid-b"] {
                let resolves = snapshot.resolver.resolve("signer-a", kid).is_ok();
                let enrolled = snapshot.signers.contains_key(kid);
                assert_eq!(
                    resolves, enrolled,
                    "torn snapshot: {kid} resolves={resolves} but enrolled={enrolled} — the \
                     two halves came from different reads of the trust file"
                );
            }
        }
        writer.join().expect("the reload thread must not panic");
    }
}
