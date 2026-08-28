//! Tier 2 — live strong trust check (ADR-MCPS-021, Axis 2).
//!
//! Where Tier 1 ([`BoundedTrustCache`](crate::BoundedTrustCache)) caches active
//! trust state for up to the propagation window `T`, **Tier 2 caches nothing
//! positive**: every verification consults the inner store-backed
//! [`TrustResolver`] afresh, so a key revoked in the store is rejected on the very
//! next request with NO `T` wait.
//!
//! # The window this tier removes, and the window it does not
//!
//! `T` is the only term Tier 2 removes, and it removes it **against the store**,
//! not against the operator's trust file. What remains is however long the
//! injected inner resolver itself takes to learn of the revocation: Tier 2 neither
//! adds to that term nor shortens it. Behind
//! [`ReloadingTrustStore`](crate::reloading_trust::ReloadingTrustStore) the
//! remaining term is the reload cadence, and it grows while consecutive reloads
//! fail. A deployment-level statement of the form "the Live window is the reload
//! cadence" is therefore a claim about the store's refresh composed with this
//! tier's zero — never a property established by this file alone.
//!
//! Removing `T` costs a store round-trip per request and a **hard dependency on
//! store availability**: a [`TrustResolverError::Unavailable`] always fails closed (it
//! is never softened to a serve-through, because there is no cache to serve from
//! and Tier 2's whole point is that the live answer is authoritative).
//!
//! Optionally, a policy-layer [`RevocationSource`] (ADR-MCPS-013) is consulted as
//! a SECOND, independent revocation authority: even if the trust store still
//! resolves a key as `Active`, a `Revoked` revocation-id rejects it, and a
//! [`RevocationUnavailable`] fails closed. This composes the two revocation
//! signals (key-status binding + grant deny-list) under one live check.
//!
//! This wrapper lives in `mcp-re-proxy`, not `mcp-re-core`: it composes the pure
//! `TrustResolver` trait but performs no networking itself — the store round-trip
//! is the injected inner resolver's concern (an in-memory reference, a Redis
//! adapter, ...). `mcp-re-core` stays pure (ADR-MCPS-011/012).

use mcp_re_core::TrustResolver;
use mcp_re_core::TrustResolverError;
use mcp_re_core::VerificationKey;

use mcp_re_policy::RevocationSource;
use mcp_re_policy::RevocationStatus;

/// A [`TrustResolver`] implementing ADR-MCPS-021 **Tier 2 (live strong check)**.
///
/// `resolve` consults the inner resolver on EVERY call (no positive-trust cache),
/// then — if a [`RevocationSource`] and a `revocation_id` are wired — consults the
/// revocation source as a second authority. Any operational failure on either
/// path (`Unavailable` / `RevocationUnavailable`) fails closed.
///
/// Nothing active is ever cached, so a store-side revocation is visible on the next
/// request and this wrapper contributes no window of its own; what a deployment
/// observes is the inner resolver's own refresh latency. The cost is a per-request
/// round-trip and that an outage is an immediate hard failure (no bounded
/// serve-through).
pub struct LiveTrustResolver {
    inner: Box<dyn TrustResolver + Send + Sync>,
    /// Optional second revocation authority (ADR-MCPS-013 grant deny-list),
    /// consulted live alongside the key-status binding when a `revocation_id` is
    /// supplied to [`resolve_with_revocation_id`](LiveTrustResolver::resolve_with_revocation_id).
    /// **NOT WIRED.** No production path installs one, so Tier 2's revocation check is
    /// whatever the inner store answers — which is the freshness guarantee the tier is
    /// actually sold on (a key removed from the store stops resolving on the next
    /// request), not an identifier denylist. Retained rather than deleted: the seam is the
    /// ADR-MCPS-021 elaboration a networked revocation feed would use, and the composition
    /// root having never installed one is a deployment fact rather than evidence the seam
    /// is wrong.
    #[allow(dead_code)]
    revocation: Option<Box<dyn RevocationSource + Send + Sync>>,
}

impl LiveTrustResolver {
    /// Wrap `inner` as a live (no-cache) resolver with no separate revocation
    /// source. Every `resolve` round-trips the inner store.
    pub fn new(inner: Box<dyn TrustResolver + Send + Sync>) -> Self {
        LiveTrustResolver {
            inner,
            revocation: None,
        }
    }

    /// Wrap `inner` and additionally consult `revocation` (ADR-MCPS-013) as a
    /// second live revocation authority via
    /// [`resolve_with_revocation_id`](LiveTrustResolver::resolve_with_revocation_id).
    #[allow(dead_code)]
    pub(super) fn with_revocation_source(
        inner: Box<dyn TrustResolver + Send + Sync>,
        revocation: Box<dyn RevocationSource + Send + Sync>,
    ) -> Self {
        LiveTrustResolver {
            inner,
            revocation: Some(revocation),
        }
    }

    /// Live-resolve `(signer, key_id)`, then — if a revocation source is wired —
    /// also check `revocation_id` against it as a second authority.
    ///
    /// Fail-closed composition: a store-side binding failure short-circuits; an
    /// `Active` binding is then gated on the revocation source. `Revoked` maps to
    /// [`TrustResolverError::Revoked`]; a [`RevocationUnavailable`] maps to
    /// [`TrustResolverError::Unavailable`] (operational, never an allow).
    #[allow(dead_code)]
    pub(super) fn resolve_with_revocation_id(
        &self,
        signer: &str,
        key_id: &str,
        revocation_id: &str,
    ) -> Result<VerificationKey, TrustResolverError> {
        // 1. Live key-status binding — authoritative, never cached. A binding
        //    failure (Revoked/NotFound/Malformed) or an outage (Unavailable) is
        //    returned verbatim; both fail closed.
        let key = self.inner.resolve(signer, key_id)?;

        // 2. Second live revocation authority (ADR-MCPS-013), if wired.
        if let Some(revocation) = &self.revocation {
            match revocation.revocation_status(revocation_id) {
                Ok(RevocationStatus::NotRevoked) => {}
                Ok(RevocationStatus::Revoked) => return Err(TrustResolverError::Revoked),
                // Operational failure: distinct from a determinate deny, still
                // fail closed (never a stale "active" allow).
                Err(unavailable) => {
                    return Err(TrustResolverError::Unavailable {
                        details: format!("revocation source unavailable: {}", unavailable.details),
                    })
                }
            }
        }

        Ok(key)
    }
}

impl TrustResolver for LiveTrustResolver {
    /// Live key-status resolution with NO positive caching. Equivalent to
    /// [`resolve_with_revocation_id`](LiveTrustResolver::resolve_with_revocation_id)
    /// with no `revocation_id`: only the live key-status binding is consulted (the
    /// `TrustResolver` trait carries no revocation-id, so the second authority is
    /// reached only through the inherent method).
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        self.inner.resolve(signer, key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::LiveTrustResolver;

    use crate::reloading_trust::ReloadingTrustStore;

    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;

    use mcp_re_core::InMemoryTrustResolver;
    use mcp_re_core::SigningKey;
    use mcp_re_core::TrustResolver;
    use mcp_re_core::TrustResolverError;
    use mcp_re_core::VerificationKey;

    use mcp_re_policy::InMemoryRevocationSource;
    use mcp_re_policy::RevocationSource;
    use mcp_re_policy::RevocationStatus;
    use mcp_re_policy::RevocationUnavailable;

    const SEED_A: [u8; 32] = [1u8; 32];

    fn key_from(seed: &[u8; 32]) -> VerificationKey {
        SigningKey::from_seed_bytes(seed).public_key()
    }

    /// A programmable inner resolver that counts how many times the inner
    /// `resolve` actually ran — to PROVE Tier 2 consults the store on every call
    /// (no positive caching). Mirrors the `trust_cache` `ScriptedResolver`.
    struct ScriptedResolver {
        outcome: Mutex<Result<VerificationKey, TrustResolverError>>,
        calls: AtomicUsize,
    }

    impl ScriptedResolver {
        fn new(initial: Result<VerificationKey, TrustResolverError>) -> Self {
            ScriptedResolver {
                outcome: Mutex::new(initial),
                calls: AtomicUsize::new(0),
            }
        }
        fn set(&self, outcome: Result<VerificationKey, TrustResolverError>) {
            *self.outcome.lock().unwrap() = outcome;
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl TrustResolver for ScriptedResolver {
        fn resolve(
            &self,
            _signer: &str,
            _key_id: &str,
        ) -> Result<VerificationKey, TrustResolverError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome.lock().unwrap().clone()
        }
    }

    /// Wrap a shared scripted resolver behind the `LiveTrustResolver` while the
    /// test keeps a handle to drive/inspect it.
    fn live_over(inner: Arc<ScriptedResolver>) -> LiveTrustResolver {
        struct Shared(Arc<ScriptedResolver>);
        impl TrustResolver for Shared {
            fn resolve(
                &self,
                signer: &str,
                key_id: &str,
            ) -> Result<VerificationKey, TrustResolverError> {
                self.0.resolve(signer, key_id)
            }
        }
        LiveTrustResolver::new(Box::new(Shared(inner)))
    }

    #[test]
    fn store_revocation_is_visible_on_the_next_request_with_no_t_wait() {
        // The load-bearing Tier 2 property: a key revoked in the store is rejected
        // on the NEXT request, with no propagation window — because nothing active
        // is cached and the inner store is consulted every time.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let live = live_over(inner.clone());

        // First request: active.
        live.resolve("did:host", "key-1").expect("active resolves");
        // Store flips to Revoked. NO clock advance — there is no T to wait.
        inner.set(Err(TrustResolverError::Revoked));
        assert_eq!(
            live.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "Tier 2 sees a store revocation immediately on the next request"
        );
        // The inner store was consulted on BOTH requests (no positive caching).
        assert_eq!(
            inner.calls(),
            2,
            "Tier 2 round-trips the store every request"
        );
    }

    #[test]
    fn no_positive_caching_consults_inner_every_call() {
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let live = live_over(inner.clone());
        for _ in 0..5 {
            live.resolve("did:host", "key-1").expect("active");
        }
        assert_eq!(inner.calls(), 5, "every verification round-trips the store");
    }

    #[test]
    fn store_outage_fails_closed_never_active() {
        // A store outage is a HARD failure under Tier 2: fail closed, never serve
        // a stale/assumed-active answer.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        let live = live_over(inner.clone());
        live.resolve("did:host", "key-1").expect("active first");
        inner.set(Err(TrustResolverError::Unavailable {
            details: "store down".to_string(),
        }));
        assert!(
            matches!(
                live.resolve("did:host", "key-1"),
                Err(TrustResolverError::Unavailable { .. })
            ),
            "Tier 2 fails closed on store outage; it never serves a cached active"
        );
    }

    #[test]
    fn second_revocation_authority_rejects_even_when_key_status_active() {
        // The optional ADR-MCPS-013 revocation source rejects an otherwise-active
        // key whose grant is revoked.
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        struct Shared(Arc<ScriptedResolver>);
        impl TrustResolver for Shared {
            fn resolve(
                &self,
                signer: &str,
                key_id: &str,
            ) -> Result<VerificationKey, TrustResolverError> {
                self.0.resolve(signer, key_id)
            }
        }
        let mut revocation = InMemoryRevocationSource::new();
        revocation.revoke("grant-1");
        let live = LiveTrustResolver::with_revocation_source(
            Box::new(Shared(inner.clone())),
            Box::new(revocation),
        );

        // A different grant id is fine.
        live.resolve_with_revocation_id("did:host", "key-1", "grant-2")
            .expect("non-revoked grant with active key resolves");
        // The revoked grant id is rejected despite the active key binding.
        assert_eq!(
            live.resolve_with_revocation_id("did:host", "key-1", "grant-1")
                .unwrap_err(),
            TrustResolverError::Revoked,
            "a live revocation source revokes an otherwise-active key"
        );
    }

    /// A revocation source whose every lookup is an operational failure — to prove
    /// the live second-authority path fails closed (the in-memory reference is
    /// always available, so it cannot exercise this arm).
    struct AlwaysUnavailableRevocation;
    impl RevocationSource for AlwaysUnavailableRevocation {
        fn revocation_status(
            &self,
            _revocation_id: &str,
        ) -> Result<RevocationStatus, RevocationUnavailable> {
            Err(RevocationUnavailable::new("revocation feed down"))
        }
    }

    #[test]
    fn revocation_source_outage_fails_closed() {
        let inner = Arc::new(ScriptedResolver::new(Ok(key_from(&SEED_A))));
        struct Shared(Arc<ScriptedResolver>);
        impl TrustResolver for Shared {
            fn resolve(
                &self,
                signer: &str,
                key_id: &str,
            ) -> Result<VerificationKey, TrustResolverError> {
                self.0.resolve(signer, key_id)
            }
        }
        let live = LiveTrustResolver::with_revocation_source(
            Box::new(Shared(inner)),
            Box::new(AlwaysUnavailableRevocation),
        );
        assert!(
            matches!(
                live.resolve_with_revocation_id("did:host", "key-1", "grant-1"),
                Err(TrustResolverError::Unavailable { .. })
            ),
            "a revocation-source outage fails closed, never an allow"
        );
    }

    /// A real swappable store behind the tier, so the two halves of a deployment
    /// window can be observed separately rather than assumed to compose.
    struct StoreHandle(Arc<ReloadingTrustStore>);
    impl TrustResolver for StoreHandle {
        fn resolve(
            &self,
            signer: &str,
            key_id: &str,
        ) -> Result<VerificationKey, TrustResolverError> {
            self.0.resolve(signer, key_id)
        }
    }

    #[test]
    fn the_live_window_is_the_store_swap_because_the_tier_adds_none_of_its_own() {
        let mut enrolled = InMemoryTrustResolver::new();
        enrolled.insert("did:host", "key-1", key_from(&SEED_A));
        let store = Arc::new(ReloadingTrustStore::new(enrolled, HashMap::new()));
        let live = LiveTrustResolver::new(Box::new(StoreHandle(Arc::clone(&store))));

        // Half one, stated honestly: until the store swaps, the tier keeps honouring
        // the key however many requests arrive. The window is NOT zero.
        for _ in 0..3 {
            live.resolve("did:host", "key-1")
                .expect("the tier answers from the store snapshot in force");
        }

        // Half two: the swap is the whole window — the FIRST request after it sees
        // the new map, with no cached-active term on top.
        let mut revoked = InMemoryTrustResolver::new();
        revoked.revoke("did:host", "key-1");
        store.store(revoked, HashMap::new());

        assert_eq!(
            live.resolve("did:host", "key-1").unwrap_err(),
            TrustResolverError::Revoked,
            "the first resolve after the store swap observes it"
        );
    }

    #[test]
    fn a_stale_store_snapshot_is_served_verbatim_by_the_tier() {
        // The tier cannot shorten the store's own refresh latency: a key revoked at
        // the source but not yet swapped into the snapshot still resolves. The
        // deployment window is the store's, not this file's.
        let mut enrolled = InMemoryTrustResolver::new();
        enrolled.insert("did:host", "key-1", key_from(&SEED_A));
        let store = Arc::new(ReloadingTrustStore::new(enrolled, HashMap::new()));
        let live = LiveTrustResolver::new(Box::new(StoreHandle(store)));

        live.resolve("did:host", "key-1")
            .expect("an un-swapped snapshot keeps resolving the key");
        assert_eq!(
            live.resolve("did:host", "key-2").unwrap_err(),
            TrustResolverError::NotFound,
            "the tier answers strictly from the snapshot it is given"
        );
    }
}
