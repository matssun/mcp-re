//! Trust resolution (MCPS_SPEC §6 / ADR-007).
//!
//! Trust resolution maps a `(signer, key_id)` pair to the [`VerificationKey`]
//! that is **authoritative at verify time**. The injected [`TrustResolver`] is
//! the sole binding authority Core consults:
//!
//! - **Rotation** is modelled as multiple `key_id`s mapped under one `signer`.
//! - **Revocation** is modelled by removing or disabling a mapping.
//! - **Bounded-TTL caching** of resolver results is a *caller* concern; Core
//!   neither caches nor defines a revocation list, OCSP, transparency log, or
//!   key-validity interval. The resolver answer at verify time is final.
//!
//! Failure semantics (fail closed — a resolver failure NEVER falls back to
//! "allow"):
//!
//! - A *binding* failure — not found, revoked, disabled, or a malformed key
//!   mapping — maps to [`McpsError::ActorBindingFailed`] (kept verbatim per
//!   ADR-007 despite the field rename `actor` -> `signer`).
//! - A *transient/operational* resolver failure maps to
//!   [`McpsError::TrustResolverUnavailable`].
//!
//! The trait is the injection point (mirrors the brief §9 abstract resolver):
//! Core stays pure (no networking / async / filesystem); a production resolver
//! lives outside this crate. [`InMemoryTrustResolver`] is the deterministic
//! reference implementation used for tests and conformance vectors.

use std::collections::BTreeMap;

use crate::crypto::VerificationKey;
use crate::error::McpsError;

/// The operational outcome of a trust resolution that did not yield a key.
///
/// Exactly two outcomes are distinguished, matching the two errors the spec
/// requires (MCPS_SPEC §6). [`to_mcps_error`](TrustResolverError::to_mcps_error)
/// (and the equivalent `From` impl) perform the authoritative mapping.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustResolverError {
    /// No binding exists for `(signer, key_id)`. A definitive negative answer
    /// (the resolver is healthy; the mapping simply is not present).
    /// → [`McpsError::ActorBindingFailed`].
    #[error("trust binding not found")]
    NotFound,

    /// A binding existed but is revoked or disabled. Modelled distinctly from
    /// [`TrustResolverError::NotFound`] so the not-found-vs-revoked path is
    /// exercisable, though both map to the same wire error.
    /// → [`McpsError::ActorBindingFailed`].
    #[error("trust binding revoked or disabled")]
    Revoked,

    /// The stored key material for an otherwise-present binding is malformed
    /// (bad length / not a valid curve point). Still a binding failure.
    /// → [`McpsError::ActorBindingFailed`].
    #[error("trust binding key malformed")]
    MalformedKey,

    /// A transient/operational failure prevented the resolver from answering
    /// (e.g. backing store unreachable). Distinct from a definitive negative —
    /// it must NOT be treated as "no binding" and must NOT fall back to allow.
    /// → [`McpsError::TrustResolverUnavailable`].
    #[error("trust resolver unavailable: {details}")]
    Unavailable {
        /// Human-readable diagnostic; never part of any wire token.
        details: String,
    },
}

impl TrustResolverError {
    /// Map this resolver outcome to its frozen [`McpsError`] (MCPS_SPEC §6/§8).
    ///
    /// Binding failures (not found / revoked / disabled / malformed key) →
    /// [`McpsError::ActorBindingFailed`]. Operational failures →
    /// [`McpsError::TrustResolverUnavailable`]. Neither ever maps to "allow".
    pub fn to_mcps_error(&self) -> McpsError {
        match self {
            TrustResolverError::NotFound
            | TrustResolverError::Revoked
            | TrustResolverError::MalformedKey => McpsError::ActorBindingFailed,
            TrustResolverError::Unavailable { .. } => McpsError::TrustResolverUnavailable,
        }
    }
}

impl From<TrustResolverError> for McpsError {
    fn from(err: TrustResolverError) -> McpsError {
        err.to_mcps_error()
    }
}

/// The trust-resolution injection point (MCPS_SPEC §6 / ADR-007).
///
/// Implementations are **authoritative at verify time**: the key returned here
/// is the one used to verify the request/response signature. See the module
/// docs for rotation, revocation, caching, and the deliberate absence of any
/// revocation-list / OCSP / transparency-log / key-validity-interval concept in
/// Core.
///
/// `resolve` returns `Ok(key)` for an active binding, or a
/// [`TrustResolverError`] which the verifier maps to the frozen taxonomy via
/// [`TrustResolverError::to_mcps_error`]. A resolver failure NEVER falls back to
/// "allow".
pub trait TrustResolver {
    /// Resolve the verification key bound to `(signer, key_id)` at verify time.
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError>;
}

/// Internal binding state for a `(signer, key_id)` mapping.
///
/// Active vs revoked is modelled explicitly so the not-found-vs-revoked paths
/// are distinct internally, even though both surface as
/// [`McpsError::ActorBindingFailed`].
#[derive(Debug, Clone)]
enum Binding {
    /// An active mapping carrying its verification key.
    Active(VerificationKey),
    /// A mapping that once existed but has been revoked/disabled.
    Revoked,
}

/// Deterministic, [`BTreeMap`]-backed reference [`TrustResolver`] for tests and
/// conformance vectors (MCPS_SPEC §6).
///
/// Keyed by the `"signer#key_id"` string. Has no operational-failure path: it
/// only ever returns active bindings or [`TrustResolverError::NotFound`] /
/// [`TrustResolverError::Revoked`]. (To exercise the
/// [`McpsError::TrustResolverUnavailable`] mapping, an always-unavailable test
/// resolver is used instead.)
#[derive(Debug, Clone, Default)]
pub struct InMemoryTrustResolver {
    bindings: BTreeMap<String, Binding>,
}

impl InMemoryTrustResolver {
    /// Construct an empty resolver with no bindings.
    pub fn new() -> Self {
        InMemoryTrustResolver {
            bindings: BTreeMap::new(),
        }
    }

    /// Compose the lookup key from a `(signer, key_id)` pair.
    fn compose_key(signer: &str, key_id: &str) -> String {
        format!("{signer}#{key_id}")
    }

    /// Insert (or replace) an active binding for `(signer, key_id)`.
    ///
    /// Inserting under the same `signer` with a different `key_id` models key
    /// rotation; both `key_id`s resolve to their respective keys.
    pub fn insert(&mut self, signer: &str, key_id: &str, key: VerificationKey) {
        self.bindings
            .insert(Self::compose_key(signer, key_id), Binding::Active(key));
    }

    /// Mark the `(signer, key_id)` binding revoked/disabled.
    ///
    /// A subsequent [`resolve`](TrustResolver::resolve) returns
    /// [`TrustResolverError::Revoked`] (→ [`McpsError::ActorBindingFailed`]),
    /// distinct internally from a never-present binding.
    pub fn revoke(&mut self, signer: &str, key_id: &str) {
        self.bindings
            .insert(Self::compose_key(signer, key_id), Binding::Revoked);
    }
}

impl TrustResolver for InMemoryTrustResolver {
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError> {
        match self.bindings.get(&Self::compose_key(signer, key_id)) {
            Some(Binding::Active(key)) => Ok(key.clone()),
            Some(Binding::Revoked) => Err(TrustResolverError::Revoked),
            None => Err(TrustResolverError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryTrustResolver;
    use super::TrustResolver;
    use super::TrustResolverError;
    use crate::crypto::SigningKey;
    use crate::crypto::VerificationKey;
    use crate::error::McpsError;

    // Fixed, documented seeds so keys are reproducible.
    const SEED_A: [u8; 32] = [1u8; 32];
    const SEED_B: [u8; 32] = [2u8; 32];

    fn key_from(seed: &[u8; 32]) -> VerificationKey {
        SigningKey::from_seed_bytes(seed).public_key()
    }

    /// A test-only resolver whose every resolution is a transient/operational
    /// failure. Exists solely to exercise the
    /// [`McpsError::TrustResolverUnavailable`] mapping (the in-memory reference
    /// resolver has no operational-failure path).
    struct AlwaysUnavailableResolver;

    impl TrustResolver for AlwaysUnavailableResolver {
        fn resolve(
            &self,
            _signer: &str,
            _key_id: &str,
        ) -> Result<VerificationKey, TrustResolverError> {
            Err(TrustResolverError::Unavailable {
                details: "backing store unreachable".to_string(),
            })
        }
    }

    #[test]
    fn insert_then_resolve_returns_matching_key() {
        let key = key_from(&SEED_A);
        let mut resolver = InMemoryTrustResolver::new();
        resolver.insert("did:example:host", "key-1", key.clone());

        let resolved = resolver
            .resolve("did:example:host", "key-1")
            .expect("active binding must resolve");
        assert_eq!(resolved.to_bytes(), key.to_bytes());
    }

    #[test]
    fn resolve_unknown_signer_or_key_id_maps_to_actor_binding_failed() {
        let resolver = InMemoryTrustResolver::new();
        let err = resolver
            .resolve("did:example:unknown", "key-1")
            .expect_err("unknown binding must fail");
        assert_eq!(err, TrustResolverError::NotFound);
        assert_eq!(err.to_mcps_error(), McpsError::ActorBindingFailed);

        // Known signer but unknown key_id is equally not-found.
        let mut populated = InMemoryTrustResolver::new();
        populated.insert("did:example:host", "key-1", key_from(&SEED_A));
        let err = populated
            .resolve("did:example:host", "key-other")
            .expect_err("unknown key_id must fail");
        assert_eq!(err, TrustResolverError::NotFound);
        assert_eq!(err.to_mcps_error(), McpsError::ActorBindingFailed);
    }

    #[test]
    fn revoke_then_resolve_maps_to_actor_binding_failed() {
        let mut resolver = InMemoryTrustResolver::new();
        resolver.insert("did:example:host", "key-1", key_from(&SEED_A));
        resolver.revoke("did:example:host", "key-1");

        let err = resolver
            .resolve("did:example:host", "key-1")
            .expect_err("revoked binding must fail");
        assert_eq!(err, TrustResolverError::Revoked);
        assert_eq!(err.to_mcps_error(), McpsError::ActorBindingFailed);
    }

    #[test]
    fn rotation_two_key_ids_resolve_to_their_respective_keys() {
        let key_a = key_from(&SEED_A);
        let key_b = key_from(&SEED_B);
        let mut resolver = InMemoryTrustResolver::new();
        resolver.insert("did:example:host", "key-1", key_a.clone());
        resolver.insert("did:example:host", "key-2", key_b.clone());

        let resolved_a = resolver
            .resolve("did:example:host", "key-1")
            .expect("key-1 resolves");
        let resolved_b = resolver
            .resolve("did:example:host", "key-2")
            .expect("key-2 resolves");
        assert_eq!(resolved_a.to_bytes(), key_a.to_bytes());
        assert_eq!(resolved_b.to_bytes(), key_b.to_bytes());
        // The two rotated keys are genuinely distinct.
        assert_ne!(resolved_a.to_bytes(), resolved_b.to_bytes());
    }

    #[test]
    fn operational_failure_maps_to_trust_resolver_unavailable() {
        let resolver = AlwaysUnavailableResolver;
        let err = resolver
            .resolve("did:example:host", "key-1")
            .expect_err("always-unavailable resolver must fail");
        assert_eq!(err.to_mcps_error(), McpsError::TrustResolverUnavailable);
    }

    #[test]
    fn error_mapping_is_exact_for_both_outcomes() {
        // Binding outcomes -> ActorBindingFailed (verbatim, ADR-007).
        assert_eq!(
            TrustResolverError::NotFound.to_mcps_error(),
            McpsError::ActorBindingFailed
        );
        assert_eq!(
            TrustResolverError::Revoked.to_mcps_error(),
            McpsError::ActorBindingFailed
        );
        assert_eq!(
            TrustResolverError::MalformedKey.to_mcps_error(),
            McpsError::ActorBindingFailed
        );
        // Operational outcome -> TrustResolverUnavailable. Never "allow".
        assert_eq!(
            TrustResolverError::Unavailable {
                details: "x".to_string()
            }
            .to_mcps_error(),
            McpsError::TrustResolverUnavailable
        );

        // The `From` impl agrees with `to_mcps_error` for both variants.
        assert_eq!(
            McpsError::from(TrustResolverError::NotFound),
            McpsError::ActorBindingFailed
        );
        assert_eq!(
            McpsError::from(TrustResolverError::Unavailable {
                details: "y".to_string()
            }),
            McpsError::TrustResolverUnavailable
        );
    }
}
