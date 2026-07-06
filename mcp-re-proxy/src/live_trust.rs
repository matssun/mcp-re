//! Tier 2 — live strong trust check (ADR-MCPS-021, Axis 2).
//!
//! Where Tier 1 ([`BoundedTrustCache`](crate::BoundedTrustCache)) caches active
//! trust state for up to the propagation window `T`, **Tier 2 caches nothing
//! positive**: every verification consults the inner store-backed
//! [`TrustResolver`] afresh, so a key revoked in the store is rejected on the very
//! next request with NO `T` wait. The propagation window is near-zero — at the
//! cost of a store round-trip per request and a **hard dependency on store
//! availability**: a [`TrustResolverError::Unavailable`] always fails closed (it
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
/// The near-zero window holds because nothing active is ever cached: a store-side
/// revocation is visible on the next request. The cost is a per-request round-trip
/// and that an outage is an immediate hard failure (no bounded serve-through).
pub struct LiveTrustResolver {
    inner: Box<dyn TrustResolver + Send + Sync>,
    /// Optional second revocation authority (ADR-MCPS-013 grant deny-list),
    /// consulted live alongside the key-status binding when a `revocation_id` is
    /// supplied to [`resolve_with_revocation_id`](LiveTrustResolver::resolve_with_revocation_id).
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
    pub fn with_revocation_source(
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
    pub fn resolve_with_revocation_id(
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

    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;

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
        assert_eq!(inner.calls(), 2, "Tier 2 round-trips the store every request");
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
}
