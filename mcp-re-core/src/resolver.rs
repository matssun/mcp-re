//! Trust resolution (MCP_RE_SPEC §6 / ADR-007).
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
//!   mapping — maps to [`McpReError::ActorBindingFailed`] (kept verbatim per
//!   ADR-007 despite the field rename `actor` -> `signer`).
//! - A *transient/operational* resolver failure maps to
//!   [`McpReError::TrustResolverUnavailable`].
//!
//! The trait is the injection point (mirrors the brief §9 abstract resolver):
//! Core stays pure (no networking / async / filesystem); a production resolver
//! lives outside this crate. [`InMemoryTrustResolver`] is the deterministic
//! reference implementation used for tests and conformance vectors.

use std::collections::BTreeMap;

use crate::crypto::VerificationKey;
use crate::error::McpReError;

/// The operational outcome of a trust resolution that did not yield a key.
///
/// Exactly two outcomes are distinguished, matching the two errors the spec
/// requires (MCP_RE_SPEC §6). [`to_mcp_re_error`](TrustResolverError::to_mcp_re_error)
/// (and the equivalent `From` impl) perform the authoritative mapping.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustResolverError {
    /// No binding exists for `(signer, key_id)`. A definitive negative answer
    /// (the resolver is healthy; the mapping simply is not present).
    /// → [`McpReError::ActorBindingFailed`].
    #[error("trust binding not found")]
    NotFound,

    /// A binding existed but is revoked or disabled. Modelled distinctly from
    /// [`TrustResolverError::NotFound`] so the not-found-vs-revoked path is
    /// exercisable, though both map to the same wire error.
    /// → [`McpReError::ActorBindingFailed`].
    #[error("trust binding revoked or disabled")]
    Revoked,

    /// The stored key material for an otherwise-present binding is malformed
    /// (bad length / not a valid curve point). Still a binding failure.
    /// → [`McpReError::ActorBindingFailed`].
    #[error("trust binding key malformed")]
    MalformedKey,

    /// A transient/operational failure prevented the resolver from answering
    /// (e.g. backing store unreachable). Distinct from a definitive negative —
    /// it must NOT be treated as "no binding" and must NOT fall back to allow.
    /// → [`McpReError::TrustResolverUnavailable`].
    #[error("trust resolver unavailable: {details}")]
    Unavailable {
        /// Human-readable diagnostic; never part of any wire token.
        details: String,
    },
}

impl TrustResolverError {
    /// Map this resolver outcome to its frozen [`McpReError`] (MCP_RE_SPEC §6/§8).
    ///
    /// Binding failures (not found / revoked / disabled / malformed key) →
    /// [`McpReError::ActorBindingFailed`]. Operational failures →
    /// [`McpReError::TrustResolverUnavailable`]. Neither ever maps to "allow".
    pub fn to_mcp_re_error(&self) -> McpReError {
        match self {
            TrustResolverError::NotFound
            | TrustResolverError::Revoked
            | TrustResolverError::MalformedKey => McpReError::ActorBindingFailed,
            TrustResolverError::Unavailable { .. } => McpReError::TrustResolverUnavailable,
        }
    }
}

impl From<TrustResolverError> for McpReError {
    fn from(err: TrustResolverError) -> McpReError {
        err.to_mcp_re_error()
    }
}

/// The trust-resolution injection point (MCP_RE_SPEC §6 / ADR-007).
///
/// Implementations are **authoritative at verify time**: the key returned here
/// is the one used to verify the request/response signature. See the module
/// docs for rotation, revocation, caching, and the deliberate absence of any
/// revocation-list / OCSP / transparency-log / key-validity-interval concept in
/// Core.
///
/// `resolve` returns `Ok(key)` for an active binding, or a
/// [`TrustResolverError`] which the verifier maps to the frozen taxonomy via
/// [`TrustResolverError::to_mcp_re_error`]. A resolver failure NEVER falls back to
/// "allow".
pub trait TrustResolver {
    /// Resolve the verification key bound to `(signer, key_id)` at verify time.
    fn resolve(&self, signer: &str, key_id: &str) -> Result<VerificationKey, TrustResolverError>;
}

/// Internal binding state for a `(signer, key_id)` mapping.
///
/// Active vs revoked is modelled explicitly so the not-found-vs-revoked paths
/// are distinct internally, even though both surface as
/// [`McpReError::ActorBindingFailed`].
#[derive(Debug, Clone)]
enum Binding {
    /// An active mapping carrying its verification key.
    Active(VerificationKey),
    /// A mapping that once existed but has been revoked/disabled.
    Revoked,
}

/// Deterministic, [`BTreeMap`]-backed reference [`TrustResolver`] for tests and
/// conformance vectors (MCP_RE_SPEC §6).
///
/// Keyed by a collision-safe, length-prefixed encoding of the `(signer, key_id)`
/// pair (see `compose_key`) — NOT a naive `"signer#key_id"` join, which is not
/// injective when a field contains the `#` delimiter. Has no operational-failure
/// path: it only ever returns active bindings or [`TrustResolverError::NotFound`] /
/// [`TrustResolverError::Revoked`]. (To exercise the
/// [`McpReError::TrustResolverUnavailable`] mapping, an always-unavailable test
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

    /// Compose a COLLISION-SAFE lookup key from a `(signer, key_id)` pair.
    ///
    /// A naive `"{signer}#{key_id}"` join is NOT injective: a `signer` or
    /// `key_id` containing the delimiter aliases distinct pairs (e.g.
    /// `("a#b", "c")` and `("a", "b#c")` both compose to `"a#b#c"`). Signer
    /// strings are DIDs/URIs that legitimately contain `#`, so two different
    /// bindings could collide and one tenant's `(signer, key_id)` could resolve
    /// a key bound under another's. We length-prefix each field (in BYTES) so the
    /// parse is unambiguous regardless of any delimiter the fields contain,
    /// guaranteeing injectivity of the lookup key. (Same hardening as
    /// `SharedReplayCache::composite_key`.)
    fn compose_key(signer: &str, key_id: &str) -> String {
        format!("{}:{}|{}:{}", signer.len(), signer, key_id.len(), key_id)
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
    /// [`TrustResolverError::Revoked`] (→ [`McpReError::ActorBindingFailed`]),
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
    use crate::error::McpReError;

    // Fixed, documented seeds so keys are reproducible.
    const SEED_A: [u8; 32] = [1u8; 32];
    const SEED_B: [u8; 32] = [2u8; 32];

    fn key_from(seed: &[u8; 32]) -> VerificationKey {
        SigningKey::from_seed_bytes(seed).public_key()
    }

    /// A test-only resolver whose every resolution is a transient/operational
    /// failure. Exists solely to exercise the
    /// [`McpReError::TrustResolverUnavailable`] mapping (the in-memory reference
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
        assert_eq!(err.to_mcp_re_error(), McpReError::ActorBindingFailed);

        // Known signer but unknown key_id is equally not-found.
        let mut populated = InMemoryTrustResolver::new();
        populated.insert("did:example:host", "key-1", key_from(&SEED_A));
        let err = populated
            .resolve("did:example:host", "key-other")
            .expect_err("unknown key_id must fail");
        assert_eq!(err, TrustResolverError::NotFound);
        assert_eq!(err.to_mcp_re_error(), McpReError::ActorBindingFailed);
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
        assert_eq!(err.to_mcp_re_error(), McpReError::ActorBindingFailed);
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
        assert_eq!(err.to_mcp_re_error(), McpReError::TrustResolverUnavailable);
    }

    #[test]
    fn composite_key_is_injective_across_delimiter_containing_pairs() {
        // `("a#b", "c")` and `("a", "b#c")` both collapse to `"a#b#c"` under a
        // naive `#` join. The length-prefixed encoding must keep them distinct so
        // one binding can never shadow or resolve under a different
        // `(signer, key_id)` pair (DIDs/URIs legitimately contain `#`).
        let key_ab = key_from(&SEED_A);
        let key_bc = key_from(&SEED_B);
        let mut resolver = InMemoryTrustResolver::new();
        resolver.insert("a#b", "c", key_ab.clone());
        resolver.insert("a", "b#c", key_bc.clone());

        let resolved_ab = resolver
            .resolve("a#b", "c")
            .expect("(\"a#b\", \"c\") must resolve to its own key");
        let resolved_bc = resolver
            .resolve("a", "b#c")
            .expect("(\"a\", \"b#c\") must resolve to its own key");

        // No collision: each pair keeps its own distinct binding.
        assert_eq!(resolved_ab.to_bytes(), key_ab.to_bytes());
        assert_eq!(resolved_bc.to_bytes(), key_bc.to_bytes());
        assert_ne!(resolved_ab.to_bytes(), resolved_bc.to_bytes());
    }

    #[test]
    fn error_mapping_is_exact_for_both_outcomes() {
        // Binding outcomes -> ActorBindingFailed (verbatim, ADR-007).
        assert_eq!(
            TrustResolverError::NotFound.to_mcp_re_error(),
            McpReError::ActorBindingFailed
        );
        assert_eq!(
            TrustResolverError::Revoked.to_mcp_re_error(),
            McpReError::ActorBindingFailed
        );
        assert_eq!(
            TrustResolverError::MalformedKey.to_mcp_re_error(),
            McpReError::ActorBindingFailed
        );
        // Operational outcome -> TrustResolverUnavailable. Never "allow".
        assert_eq!(
            TrustResolverError::Unavailable {
                details: "x".to_string()
            }
            .to_mcp_re_error(),
            McpReError::TrustResolverUnavailable
        );

        // The `From` impl agrees with `to_mcp_re_error` for both variants.
        assert_eq!(
            McpReError::from(TrustResolverError::NotFound),
            McpReError::ActorBindingFailed
        );
        assert_eq!(
            McpReError::from(TrustResolverError::Unavailable {
                details: "y".to_string()
            }),
            McpReError::TrustResolverUnavailable
        );
    }
}
