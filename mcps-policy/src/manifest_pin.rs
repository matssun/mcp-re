//! Rug-pull pin store (issue #3866).
//!
//! Rug-pull detection is trust-on-first-use over tool identity: the FIRST time a
//! client trusts a manifest, it records each tool's `(name) -> (version,
//! schema_hash)`. On a LATER manifest, if a tool's `schema_hash` changed for the
//! SAME `(name, version)` — i.e. the schema changed without a version bump — that
//! is a rug pull. A legitimate version bump that carries a new schema is allowed
//! and UPDATES the pin.
//!
//! Like [`crate::revocation::RevocationSource`] this is an INJECTED trait so the
//! policy layer stays pure (no I/O); deployments wire a persistent store. The
//! [`InMemoryManifestPinStore`] is the deterministic `BTreeMap`-backed reference
//! implementation for tests and conformance (mirrors `InMemoryRevocationSource`).

use std::collections::BTreeMap;

use crate::manifest_error::ManifestError;

/// Records the first-trusted `(version, schema_hash)` per tool name and detects
/// rug pulls on subsequent observations.
///
/// `check_and_record` is the single entry point used by the verifier: it returns
/// `Ok(())` and updates the pin for a first sighting or a legitimate version bump,
/// and `Err(ManifestError::ManifestRugPull)` when the SAME `(name, version)` now
/// carries a different `schema_hash`.
pub trait ManifestPinStore {
    /// Inspect tool `name` at `version` with `schema_hash` against the pinned
    /// first-trusted state, recording it when accepted.
    ///
    /// - First sighting of `name` → record `(version, schema_hash)`, `Ok(())`.
    /// - Same `(version, schema_hash)` as pinned → idempotent, `Ok(())`.
    /// - Same `version` but DIFFERENT `schema_hash` → rug pull,
    ///   `Err(ManifestError::ManifestRugPull)`; the pin is NOT updated.
    /// - DIFFERENT `version` → legitimate bump → update the pin, `Ok(())`.
    fn check_and_record(
        &mut self,
        name: &str,
        version: &str,
        schema_hash: &str,
    ) -> Result<(), ManifestError>;

    /// The currently-pinned `(version, schema_hash)` for `name`, if any. Read-only
    /// accessor for callers that want to inspect the pin without mutating it.
    fn pinned(&self, name: &str) -> Option<(String, String)>;
}

/// The pinned first-trusted state for a single tool name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pin {
    version: String,
    schema_hash: String,
}

/// Deterministic in-memory rug-pull pin store (`BTreeMap`-backed). Mirrors
/// [`crate::revocation::InMemoryRevocationSource`].
#[derive(Debug, Clone, Default)]
pub struct InMemoryManifestPinStore {
    pins: BTreeMap<String, Pin>,
}

impl InMemoryManifestPinStore {
    /// An empty pin store (nothing trusted yet).
    pub fn new() -> Self {
        InMemoryManifestPinStore {
            pins: BTreeMap::new(),
        }
    }
}

impl ManifestPinStore for InMemoryManifestPinStore {
    fn check_and_record(
        &mut self,
        name: &str,
        version: &str,
        schema_hash: &str,
    ) -> Result<(), ManifestError> {
        match self.pins.get(name) {
            // Same identity, same schema → idempotent re-trust.
            Some(pin) if pin.version == version && pin.schema_hash == schema_hash => Ok(()),
            // Same version, different schema → rug pull. Do NOT update the pin.
            Some(pin) if pin.version == version => {
                let _ = pin;
                Err(ManifestError::ManifestRugPull)
            }
            // Different version (legitimate bump) or first sighting → record.
            _ => {
                self.pins.insert(
                    name.to_string(),
                    Pin {
                        version: version.to_string(),
                        schema_hash: schema_hash.to_string(),
                    },
                );
                Ok(())
            }
        }
    }

    fn pinned(&self, name: &str) -> Option<(String, String)> {
        self.pins
            .get(name)
            .map(|pin| (pin.version.clone(), pin.schema_hash.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryManifestPinStore;
    use super::ManifestPinStore;
    use crate::manifest_error::ManifestError;

    #[test]
    fn first_sighting_is_recorded_and_allowed() {
        let mut store = InMemoryManifestPinStore::new();
        assert!(store.check_and_record("echo", "1.0.0", "sha256:aaa").is_ok());
        assert_eq!(
            store.pinned("echo"),
            Some(("1.0.0".to_string(), "sha256:aaa".to_string()))
        );
    }

    #[test]
    fn identical_re_trust_is_idempotent() {
        let mut store = InMemoryManifestPinStore::new();
        store.check_and_record("echo", "1.0.0", "sha256:aaa").unwrap();
        assert!(store.check_and_record("echo", "1.0.0", "sha256:aaa").is_ok());
    }

    #[test]
    fn same_version_changed_hash_is_rug_pull_and_pin_unchanged() {
        let mut store = InMemoryManifestPinStore::new();
        store.check_and_record("echo", "1.0.0", "sha256:aaa").unwrap();
        assert_eq!(
            store.check_and_record("echo", "1.0.0", "sha256:bbb"),
            Err(ManifestError::ManifestRugPull)
        );
        // The pin is NOT moved to the impostor schema.
        assert_eq!(
            store.pinned("echo"),
            Some(("1.0.0".to_string(), "sha256:aaa".to_string()))
        );
    }

    #[test]
    fn version_bump_with_new_schema_updates_the_pin() {
        let mut store = InMemoryManifestPinStore::new();
        store.check_and_record("echo", "1.0.0", "sha256:aaa").unwrap();
        assert!(store.check_and_record("echo", "2.0.0", "sha256:ccc").is_ok());
        assert_eq!(
            store.pinned("echo"),
            Some(("2.0.0".to_string(), "sha256:ccc".to_string()))
        );
    }

    #[test]
    fn distinct_tool_names_are_independent() {
        let mut store = InMemoryManifestPinStore::new();
        store.check_and_record("echo", "1.0.0", "sha256:aaa").unwrap();
        assert!(store.check_and_record("sum", "1.0.0", "sha256:zzz").is_ok());
        assert_eq!(
            store.pinned("echo"),
            Some(("1.0.0".to_string(), "sha256:aaa".to_string()))
        );
        assert_eq!(
            store.pinned("sum"),
            Some(("1.0.0".to_string(), "sha256:zzz".to_string()))
        );
    }
}
