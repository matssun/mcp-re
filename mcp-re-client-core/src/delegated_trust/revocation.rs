// SPDX-License-Identifier: Apache-2.0
//! Which credential identifiers are revoked, and the in-memory seam that answers it.
//!
//! One half of the delegated-response trust authority. Revocation is checked in ADDITION
//! to freshness: short delegated-key TTLs bound the exposure window, and this seam narrows
//! it to the moment of report.
//!
//! An EMPTY denylist is a posture, not a default. It says *this deployment relies on TTLs
//! alone*, and it is reachable only through a deliberate constructor — a delegated-required
//! route cannot be built without SOME source.

use std::collections::HashSet;

/// The client-side delegated-credential revocation seam (ADR-MCPRE-052 §3 step 7).
///
/// Consulted during delegated verification with EACH identifier the credential
/// presents — its `delegated_kid`, its `issuer_kid` (root anchor), and its `jti`
/// (per-credential id) — and reports whether ANY of them is revoked at the current
/// trust epoch. Revocation is checked in ADDITION to freshness: short delegated-key
/// TTLs bound the exposure window, and this seam narrows it to the moment of report.
///
/// This is deliberately a narrow, pure interface. The in-memory
/// [`StaticRevocationList`] covers the GKE proof and small deployments; a networked
/// source (a signed revocation feed, an OCSP-style responder with its own freshness
/// proof) implements the same trait later WITHOUT touching the verifier. Implementations
/// MUST be non-blocking — this is consulted on the response-verification path.
pub trait RevocationSource: Send + Sync {
    /// Report whether `identifier` (a `delegated_kid`, `issuer_kid`, or credential
    /// `jti`) is revoked at the current epoch. A conservative source MAY return `true`
    /// for an identifier it cannot resolve; an empty denylist reports `false` for all
    /// (TTL-only reliance — see [`StaticRevocationList::new`]).
    fn is_revoked(&self, identifier: &str) -> bool;
}

/// An in-memory static denylist of revoked identifiers — any mix of `delegated_kid`s,
/// root `issuer_kid`s, and credential `jti`s (ADR-MCPRE-052 §3 step 7). This is the
/// concrete seam a networked revocation feed replaces later; it is enough for the GKE
/// proof (exercise both allow and deny) and for deployments that publish a small,
/// operator-curated denylist.
///
/// An EMPTY list means "no identifier is revoked" — the explicit TTL-only posture. It
/// is a deliberate operator choice (constructed via [`StaticRevocationList::new`]), not
/// a silent default: a `DelegatedRequired` route cannot be built without SOME source.
#[derive(Debug, Clone, Default)]
pub struct StaticRevocationList {
    revoked: HashSet<String>,
}

impl StaticRevocationList {
    /// An empty denylist — nothing is revoked (explicit TTL-only reliance). The
    /// operator chooses this deliberately; it is never the implicit default of a
    /// delegated-required route.
    pub fn new() -> Self {
        StaticRevocationList {
            revoked: HashSet::new(),
        }
    }

    /// Build a denylist from an initial set of revoked identifiers (kids and/or jtis).
    pub fn from_identifiers<I, S>(identifiers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        StaticRevocationList {
            revoked: identifiers.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one revoked identifier (a `delegated_kid`, `issuer_kid`, or `jti`), builder
    /// style.
    pub fn revoke(mut self, identifier: impl Into<String>) -> Self {
        self.revoked.insert(identifier.into());
        self
    }

    /// Whether the denylist is empty (the TTL-only posture).
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

impl RevocationSource for StaticRevocationList {
    fn is_revoked(&self, identifier: &str) -> bool {
        self.revoked.contains(identifier)
    }
}
