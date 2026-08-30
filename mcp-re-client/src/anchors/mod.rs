// SPDX-License-Identifier: Apache-2.0
//! Loading and REFRESHING the trust anchors from a signed manifest, against a durable
//! rollback floor.
//!
//! This module is the production caller ADR-MCPRE-052's floor never had. Every piece
//! existed — `FileManifestFloor`, `load_signed_manifest_with_floor`, the four-state
//! `TrustedIssuerSet`, the `AnchorSnapshot` behind an atomic swap — and the chain ran
//! end to end only in tests, so restart-durable rollback protection was a property the
//! codebase could demonstrate and no deployment had.
//!
//! ## Refresh keeps the last good anchors, except when they have expired
//!
//! A failed refresh (the file is being rewritten, the volume is briefly gone, the
//! document is truncated) must not withdraw trust: the anchors in force are still the
//! ones an org published, and dropping them would turn a transient read error into a
//! total outage.
//!
//! An EXPIRED manifest is the one case where holding last-good is the wrong answer.
//! `load_signed_manifest` fails closed on expiry precisely so a stale trust picture is
//! never used, and "keep serving under the anchors from the document that expired
//! yesterday" is that same stale trust picture reached by a different route. So once
//! the loaded manifest's own `expires_at` has passed and no newer document has been
//! accepted, [`AnchorRefresher`] publishes an EMPTY set: every response then fails
//! closed as an untrusted issuer, the refresh keeps retrying, and the operator gets a
//! loud line naming the expiry rather than a client that quietly outlived its trust.

use std::path::PathBuf;

use mcp_re_client_core::load_signed_manifest_with_floor;
use mcp_re_client_core::ManifestVersionFloor;
use mcp_re_client_core::SignedTrustAnchorManifest;
use mcp_re_client_core::TrustManifestError;
use mcp_re_client_core::TrustedIssuerSet;
use mcp_re_core::VerificationKey;

use crate::config::FloorConfig;
use crate::config::TrustConfig;

mod refresher;
pub use refresher::refresh_once;
pub use refresher::AnchorRefresher;
pub use refresher::RefreshOutcome;

/// A manifest that could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    /// The manifest file could not be read or parsed.
    Unreadable(String),
    /// A pinned org key is not a valid Ed25519 public key.
    BadOrgKey(String),
    /// The manifest verified against the pins but was refused — rollback, expiry,
    /// profile mismatch, an unreadable or unpersistable floor.
    Refused(TrustManifestError),
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorError::Unreadable(detail) => write!(f, "trust-anchor manifest: {detail}"),
            AnchorError::BadOrgKey(kid) => {
                write!(f, "trust.org_keys: {kid} is not a valid Ed25519 public key")
            }
            AnchorError::Refused(error) => write!(f, "trust-anchor manifest refused: {error:?}"),
        }
    }
}

impl std::error::Error for AnchorError {}

/// What one accepted manifest yielded.
#[derive(Debug, Clone)]
pub struct LoadedAnchors {
    /// The anchors to publish.
    pub issuers: TrustedIssuerSet,
    /// The accepted `manifest_version` — now also the floor.
    pub version: u64,
    /// When this document stops being usable.
    pub expires_at: i64,
}

/// Reads the manifest, checks it against the pinned org keys, and raises the durable
/// floor — in that order, which is `load_signed_manifest_with_floor`'s order and not
/// this module's to get right.
pub struct AnchorLoader {
    manifest_path: PathBuf,
    profile: String,
    org_keys: Vec<(String, VerificationKey)>,
    floor: Box<dyn ManifestVersionFloor + Send>,
}

impl AnchorLoader {
    /// Build a loader from the trust section, opening the configured floor.
    ///
    /// Opening the durable floor here rather than at first use means an unreadable or
    /// unwritable floor directory stops the process at startup, where an operator sees
    /// it, instead of at the first refresh hours later.
    pub fn new(trust: &TrustConfig) -> Result<Self, AnchorError> {
        let mut org_keys = Vec::with_capacity(trust.org_keys.len());
        for key in &trust.org_keys {
            let parsed = VerificationKey::from_b64url(&key.public_key)
                .map_err(|_| AnchorError::BadOrgKey(key.kid.clone()))?;
            org_keys.push((key.kid.clone(), parsed));
        }
        let floor: Box<dyn ManifestVersionFloor + Send> = match &trust.floor {
            FloorConfig::Durable {
                dir,
                bootstrap_version,
                ceiling_version,
            } => Box::new(
                mcp_re_client_proxy::FileManifestFloor::with_bounds(
                    dir,
                    *bootstrap_version,
                    *ceiling_version,
                )
                .map_err(AnchorError::Refused)?,
            ),
            FloorConfig::Ephemeral { bootstrap_version } => Box::new(
                mcp_re_client_core::InMemoryVersionFloor::starting_at(*bootstrap_version),
            ),
        };
        Ok(AnchorLoader {
            manifest_path: trust.manifest_path.clone(),
            profile: trust.profile.clone(),
            org_keys,
            floor,
        })
    }

    /// The floor in force right now — the highest manifest version already accepted.
    pub fn floor_version(&self) -> Result<u64, AnchorError> {
        self.floor.min_version().map_err(AnchorError::Refused)
    }

    /// Read the manifest file and load it: verify the org signature against the pins,
    /// check the profile and expiry, refuse a version at or below the floor, and raise
    /// the floor durably before the anchors are returned.
    pub fn load(&mut self, now: i64) -> Result<LoadedAnchors, AnchorError> {
        let bytes = std::fs::read(&self.manifest_path).map_err(|e| {
            AnchorError::Unreadable(format!("{}: {e}", self.manifest_path.display()))
        })?;
        let signed: SignedTrustAnchorManifest = serde_json::from_slice(&bytes).map_err(|e| {
            AnchorError::Unreadable(format!("{}: {e}", self.manifest_path.display()))
        })?;
        let expires_at = signed.manifest.expires_at;
        let pins = &self.org_keys;
        let loaded = load_signed_manifest_with_floor(
            &signed,
            |kid| {
                pins.iter()
                    .find(|(pinned, _)| pinned == kid)
                    .map(|(_, key)| key.clone())
            },
            &self.profile,
            &mut self.floor,
            now,
        )
        .map_err(AnchorError::Refused)?;
        Ok(LoadedAnchors {
            issuers: loaded.issuer_set,
            version: loaded.version,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OrgKey;
    use mcp_re_client_core::ManifestIssuer;
    use mcp_re_client_core::RevocationSource;
    use mcp_re_client_core::TrustAnchorManifest;
    use mcp_re_client_proxy::AnchorSnapshot;
    use mcp_re_core::SigningKey;

    const NOW: i64 = 1_700_000_000;
    const PROFILE: &str = "mcp-re-http-v1";
    const ROOT_KID: &str = "root-kid";

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mcp-re-client-anchors-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("scratch");
            Scratch(path)
        }
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn org_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[91u8; 32])
    }
    fn root_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[55u8; 32])
    }

    /// Publish a manifest to `path`, exactly as an org distribution job would.
    fn publish(path: &std::path::Path, version: u64, revoke_root: bool, expires_at: i64) {
        let manifest = TrustAnchorManifest {
            profile: PROFILE.into(),
            manifest_version: version,
            current_issuers: vec![ManifestIssuer {
                issuer_kid: ROOT_KID.into(),
                public_key: root_key().public_key().to_b64url(),
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
            }],
            retiring_issuers: vec![],
            revoked_issuers: if revoke_root {
                vec![ROOT_KID.to_string()]
            } else {
                vec![]
            },
            issued_at: NOW - 100,
            expires_at,
        };
        let signed = mcp_re_client_core::sign_manifest(&manifest, &org_key(), "org-admin-1");
        std::fs::write(path, serde_json::to_vec(&signed).expect("serialize")).expect("publish");
    }

    fn trust_config(scratch: &Scratch, durable: bool) -> TrustConfig {
        TrustConfig {
            manifest_path: scratch.join("manifest.json"),
            profile: PROFILE.into(),
            org_keys: vec![OrgKey {
                kid: "org-admin-1".into(),
                public_key: org_key().public_key().to_b64url(),
            }],
            floor: if durable {
                FloorConfig::Durable {
                    dir: scratch.join("floor"),
                    bootstrap_version: 0,
                    ceiling_version: None,
                }
            } else {
                FloorConfig::Ephemeral {
                    bootstrap_version: 0,
                }
            },
            reload_secs: 300,
        }
    }

    #[test]
    fn a_published_manifest_loads_and_raises_the_durable_floor() {
        let scratch = Scratch::new("load");
        let trust = trust_config(&scratch, true);
        publish(&trust.manifest_path, 3, false, NOW + 10_000);

        let mut loader = AnchorLoader::new(&trust).expect("loader");
        assert_eq!(
            loader.floor_version().expect("floor"),
            0,
            "nothing accepted yet"
        );
        let loaded = loader.load(NOW).expect("manifest loads");
        assert_eq!(loaded.version, 3);
        assert_eq!(
            loader.floor_version().expect("floor"),
            3,
            "accepting v3 raises the floor to 3"
        );
    }

    /// The property the whole module exists for: the floor is in the FILESYSTEM, so a
    /// restarted client refuses the manifest its predecessor superseded. A fresh loader
    /// over the same directory is exactly what a restart produces.
    #[test]
    fn a_restarted_client_refuses_a_rolled_back_manifest() {
        let scratch = Scratch::new("rollback");
        let trust = trust_config(&scratch, true);

        // v5 revokes the root and is accepted.
        publish(&trust.manifest_path, 5, true, NOW + 10_000);
        let mut first = AnchorLoader::new(&trust).expect("loader");
        assert_eq!(first.load(NOW).expect("v5 loads").version, 5);
        drop(first);

        // The attacker re-serves v4, which does not revoke it. A restarted client reads
        // the floor from disk and refuses.
        publish(&trust.manifest_path, 4, false, NOW + 10_000);
        let mut restarted = AnchorLoader::new(&trust).expect("loader after restart");
        assert_eq!(
            restarted.floor_version().expect("floor"),
            5,
            "the floor survived the process that wrote it"
        );
        assert_eq!(
            restarted.load(NOW).err(),
            Some(AnchorError::Refused(TrustManifestError::Stale {
                version: 4,
                min_version: 5,
            })),
            "the revocation cannot be walked back by replaying an older document"
        );
    }

    /// The same rollback, against the EPHEMERAL floor — which protects within one
    /// process and, by construction, not across a restart. Pinned because the asymmetry
    /// is the reason the durable floor has to be chosen explicitly.
    #[test]
    fn an_ephemeral_floor_forgets_the_rollback_across_a_restart() {
        let scratch = Scratch::new("ephemeral");
        let trust = trust_config(&scratch, false);

        publish(&trust.manifest_path, 5, true, NOW + 10_000);
        let mut first = AnchorLoader::new(&trust).expect("loader");
        first.load(NOW).expect("v5 loads");

        publish(&trust.manifest_path, 4, false, NOW + 10_000);
        assert_eq!(
            first.load(NOW).err(),
            Some(AnchorError::Refused(TrustManifestError::Stale {
                version: 4,
                min_version: 5,
            })),
            "within the process the ephemeral floor does hold"
        );
        drop(first);
        let mut restarted = AnchorLoader::new(&trust).expect("loader after restart");
        assert_eq!(
            restarted
                .load(NOW)
                .expect("the ephemeral floor reset to 0")
                .version,
            4,
            "an ephemeral floor re-opens the rollback window on restart — the whole \
             reason choosing it has to be a decision"
        );
    }

    /// A refresh that publishes a revocation reaches a RUNNING client: the snapshot is
    /// swapped, so the next verification reads the new set without a restart.
    #[test]
    fn a_refreshed_manifest_reaches_a_running_client() {
        let scratch = Scratch::new("refresh");
        let trust = trust_config(&scratch, true);
        publish(&trust.manifest_path, 1, false, NOW + 10_000);

        let mut loader = AnchorLoader::new(&trust).expect("loader");
        let initial = loader.load(NOW).expect("v1 loads");
        let snapshot = AnchorSnapshot::new(initial.issuers);
        let mut expires_at = initial.expires_at;
        assert!(
            snapshot.load().trusts(ROOT_KID, NOW),
            "the root is live under v1"
        );

        // The org publishes v2, revoking the root.
        publish(&trust.manifest_path, 2, true, NOW + 10_000);
        assert_eq!(
            refresh_once(&mut loader, &snapshot, &mut expires_at, NOW),
            RefreshOutcome::Published { version: 2 }
        );
        assert!(
            snapshot.load().is_revoked(ROOT_KID),
            "the revocation is in force on the running client, with no restart"
        );
    }

    /// A transient read failure must not withdraw trust — dropping the anchors would
    /// turn a truncated file into a total outage.
    #[test]
    fn a_failed_refresh_keeps_the_anchors_in_force() {
        let scratch = Scratch::new("keep");
        let trust = trust_config(&scratch, true);
        publish(&trust.manifest_path, 1, false, NOW + 10_000);

        let mut loader = AnchorLoader::new(&trust).expect("loader");
        let initial = loader.load(NOW).expect("v1 loads");
        let snapshot = AnchorSnapshot::new(initial.issuers);
        let mut expires_at = initial.expires_at;

        std::fs::write(&trust.manifest_path, b"{ truncated").expect("corrupt the file");
        let outcome = refresh_once(&mut loader, &snapshot, &mut expires_at, NOW);
        assert!(
            matches!(outcome, RefreshOutcome::KeptLastGood { .. }),
            "unexpected: {outcome:?}"
        );
        assert!(
            snapshot.load().trusts(ROOT_KID, NOW),
            "a transient read failure does not withdraw a published trust picture"
        );
    }

    /// The one case where last-good is the WRONG answer. Serving under the anchors of a
    /// document that has expired is the stale trust picture the expiry check refuses,
    /// reached by a different route.
    #[test]
    fn an_expired_manifest_withdraws_the_anchors_rather_than_serving_on_them() {
        let scratch = Scratch::new("expired");
        let trust = trust_config(&scratch, true);
        publish(&trust.manifest_path, 1, false, NOW + 100);

        let mut loader = AnchorLoader::new(&trust).expect("loader");
        let initial = loader.load(NOW).expect("v1 loads");
        let snapshot = AnchorSnapshot::new(initial.issuers);
        let mut expires_at = initial.expires_at;

        // Past the expiry, with nothing newer published: the file on disk is now
        // refused by the very expiry check that protects against staleness.
        let later = NOW + 200;
        assert_eq!(
            refresh_once(&mut loader, &snapshot, &mut expires_at, later),
            RefreshOutcome::Withdrawn {
                expired_at: NOW + 100
            }
        );
        assert!(
            !snapshot.load().trusts(ROOT_KID, later),
            "an expired trust picture must stop verifying, not keep serving"
        );

        // And it recovers without a restart when the org publishes a fresh document.
        publish(&trust.manifest_path, 2, false, later + 10_000);
        assert_eq!(
            refresh_once(&mut loader, &snapshot, &mut expires_at, later),
            RefreshOutcome::Published { version: 2 }
        );
        assert!(
            snapshot.load().trusts(ROOT_KID, later),
            "a repaired manifest restores service in place"
        );
    }
}
