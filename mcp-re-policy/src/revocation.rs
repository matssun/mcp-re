//! Revocation lookup (ADR-MCPS-013).
//!
//! Like Core's `TrustResolver` and `ReplayCache`, the revocation source is an
//! injected dependency — the policy layer never reaches a network or a database
//! itself (it stays pure, preserving the ADR-MCPS-011/012 firewall). Core defines
//! no revocation transport, and neither does this profile layer; deployments wire
//! a concrete source (in-memory deny-list, Redis, CRL feed, ...).
//!
//! M-10 (audit follow-up): the lookup returns a `Result<RevocationStatus,
//! RevocationUnavailable>` rather than a bare `bool`. A bare `bool` conflated
//! "revoked" with "could not be determined" — both were forced to `true`, so an
//! UNAVAILABLE backend was indistinguishable on the wire from an actual
//! revocation. The Result keeps the SAME fail-closed posture (both outcomes deny
//! the request) while letting the caller surface DISTINCT error tokens
//! (`mcp-re.authorization_revoked` vs `mcp-re.authorization_revocation_unavailable`),
//! mirroring Core's `TrustResolverUnavailable` / `ReplayCacheUnavailable`
//! operational-vs-verdict split.

use std::collections::BTreeSet;

/// The determinate revocation status of an authorization artifact's
/// `revocation_id`. The INDETERMINATE case (backend unavailable) is NOT a variant
/// here — it is the `Err(RevocationUnavailable)` arm of [`RevocationSource::revocation_status`],
/// so an operational failure can never be silently read as `NotRevoked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The `revocation_id` is not present in the revocation source.
    NotRevoked,
    /// The `revocation_id` has been revoked.
    Revoked,
}

/// The revocation backend could not determine the status (e.g. a network/database
/// feed was unreachable). DISTINCT from [`RevocationStatus::Revoked`]: the caller
/// still fails closed (denies), but surfaces a different, diagnosable wire token.
/// `details` carries human-readable context and is NEVER part of the wire token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("revocation source unavailable: {details}")]
pub struct RevocationUnavailable {
    /// Human-readable context (backend, cause). Never rendered into a wire token.
    pub details: String,
}

impl RevocationUnavailable {
    /// Construct an unavailability with diagnostic `details`.
    pub fn new(details: impl Into<String>) -> Self {
        RevocationUnavailable {
            details: details.into(),
        }
    }
}

/// Resolves whether an authorization artifact's `revocation_id` has been revoked.
///
/// Implementations MUST fail closed. The Result encodes the two distinct denial
/// reasons explicitly:
///   * `Ok(RevocationStatus::Revoked)` — the id is revoked.
///   * `Err(RevocationUnavailable)` — status is indeterminate (backend down).
/// The caller denies the request in BOTH cases, but with distinct wire tokens.
/// Only `Ok(RevocationStatus::NotRevoked)` allows the request to proceed.
pub trait RevocationSource {
    /// The determinate revocation status of `revocation_id`, or
    /// [`RevocationUnavailable`] if the backend could not determine it. A source
    /// MUST NOT return `Ok(NotRevoked)` when it could not actually check.
    fn revocation_status(
        &self,
        revocation_id: &str,
    ) -> Result<RevocationStatus, RevocationUnavailable>;
}

/// Deterministic in-memory deny-list reference source (`BTreeSet`-backed).
#[derive(Debug, Clone, Default)]
pub struct InMemoryRevocationSource {
    revoked: BTreeSet<String>,
}

impl InMemoryRevocationSource {
    /// An empty deny-list (nothing revoked).
    pub fn new() -> Self {
        InMemoryRevocationSource {
            revoked: BTreeSet::new(),
        }
    }

    /// Mark `revocation_id` as revoked.
    pub fn revoke(&mut self, revocation_id: impl Into<String>) {
        self.revoked.insert(revocation_id.into());
    }
}

impl RevocationSource for InMemoryRevocationSource {
    /// An in-memory set is ALWAYS available, so this never returns the
    /// unavailable error — it answers `Ok(Revoked)` / `Ok(NotRevoked)` from the
    /// deny-list membership. (A networked source is where `Err` originates.)
    fn revocation_status(
        &self,
        revocation_id: &str,
    ) -> Result<RevocationStatus, RevocationUnavailable> {
        if self.revoked.contains(revocation_id) {
            Ok(RevocationStatus::Revoked)
        } else {
            Ok(RevocationStatus::NotRevoked)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryRevocationSource;
    use super::RevocationSource;
    use super::RevocationStatus;
    use super::RevocationUnavailable;

    #[test]
    fn empty_source_revokes_nothing() {
        let source = InMemoryRevocationSource::new();
        assert_eq!(
            source.revocation_status("rev-1"),
            Ok(RevocationStatus::NotRevoked)
        );
    }

    #[test]
    fn revoked_id_is_reported_revoked() {
        let mut source = InMemoryRevocationSource::new();
        source.revoke("rev-1");
        assert_eq!(
            source.revocation_status("rev-1"),
            Ok(RevocationStatus::Revoked)
        );
        assert_eq!(
            source.revocation_status("rev-2"),
            Ok(RevocationStatus::NotRevoked)
        );
    }

    /// The in-memory source is always available — it never yields the unavailable
    /// error. (The distinct UNAVAILABLE denial is exercised over a fake source in
    /// the reference-profile and proxy tests, where it maps to its own wire token.)
    #[test]
    fn in_memory_source_is_always_available() {
        let mut source = InMemoryRevocationSource::new();
        source.revoke("rev-1");
        for id in ["rev-1", "rev-2", "anything"] {
            assert!(
                source.revocation_status(id).is_ok(),
                "an in-memory deny-list is always determinate, never unavailable"
            );
        }
    }

    /// `RevocationUnavailable` keeps its diagnostic `details` out of nowhere it
    /// would become a wire token; its `Display` is purely human-readable context.
    #[test]
    fn unavailable_carries_details_for_diagnostics() {
        let err = RevocationUnavailable::new("redis feed timeout");
        assert!(err.to_string().contains("redis feed timeout"));
    }
}
