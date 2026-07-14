// SPDX-License-Identifier: Apache-2.0
//! The signed TRUST-ANCHOR MANIFEST (ADR-MCPRE-052 root-authority lifecycle).
//!
//! A root key is not just key material — it is a trust anchor. Rotating it therefore
//! has two jobs: select/mint new signing key material (a KMS concern), and DISTRIBUTE
//! trust in the new issuer safely. This module is the second half: an authenticated,
//! versioned document that tells a verifier which ROOT issuers are trusted, which are
//! retiring (with a cutover deadline), and which are revoked — so root rotation is a
//! governed, automatable operation and never a hand-edited config with a `kid` copied
//! from a console.
//!
//! The manifest is signed by a pinned ORG/ADMIN manifest-signing key (a higher
//! authority than the per-issuer roots it lists), so an ordinary serving proxy cannot
//! mint a new root authority: only a holder of the org key can publish a manifest the
//! fleet will accept. The verifier:
//!   * rejects a manifest whose signer it does not pin (`UntrustedSigner`);
//!   * rejects a bad signature (`BadSignature`);
//!   * fails closed on an EXPIRED manifest (`Expired`) — a stale trust picture is
//!     never used;
//!   * rejects a ROLLBACK to a lower `manifest_version` than the highest already seen
//!     (`Stale`) — an attacker cannot replay an old manifest to un-revoke a root or
//!     re-widen an overlap;
//!   * otherwise loads the issuers into a [`TrustedIssuerSet`], whose current /
//!     retiring-`valid_until` / revoked / unknown semantics do the per-credential
//!     decisions (see [`crate::TrustedIssuerSet`]).
//!
//! A manifest load failure is a CONFIG/distribution fault, not a per-request wire
//! rejection, so it has its own [`TrustManifestError`] — it never emits a `mcp-re.*`
//! response wire code.

use serde::Deserialize;
use serde::Serialize;

use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

use crate::response::TrustedIssuerSet;

/// A ROOT issuer listed in a manifest (a trust anchor): its `issuer_kid`, its raw
/// Ed25519 public key (base64url-no-pad), and the actor identity it anchors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestIssuer {
    pub issuer_kid: String,
    /// Raw 32-byte Ed25519 public key, base64url-no-pad.
    pub public_key: String,
    pub role: String,
    pub trust_domain: String,
    pub subject: String,
}

/// A RETIRING root issuer: a [`ManifestIssuer`] plus the `valid_until` cutover
/// deadline after which it is no longer trusted (the overlap window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiringIssuer {
    pub issuer_kid: String,
    pub public_key: String,
    pub role: String,
    pub trust_domain: String,
    pub subject: String,
    /// Unix seconds; the retiring root is trusted only while `now <= valid_until`.
    pub valid_until: i64,
}

/// The trust-anchor document (unsigned form). Serialization is deterministic (no
/// maps, fixed field order), so both signer and verifier hash byte-identical content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorManifest {
    /// The MCP-RE evidence profile this manifest governs.
    pub profile: String,
    /// Monotonic manifest version — the rollback-protection counter.
    pub manifest_version: u64,
    /// Live roots.
    pub current_issuers: Vec<ManifestIssuer>,
    /// Superseded roots inside their overlap window.
    pub retiring_issuers: Vec<RetiringIssuer>,
    /// Withdrawn / compromised roots (by `issuer_kid`).
    pub revoked_issuers: Vec<String>,
    /// When this manifest was issued (unix seconds; informational/audit).
    pub issued_at: i64,
    /// When this manifest STOPS being usable (unix seconds) — a verifier fails closed
    /// past it rather than trust a stale picture.
    pub expires_at: i64,
}

/// A manifest plus the org/admin signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTrustAnchorManifest {
    pub manifest: TrustAnchorManifest,
    /// The org/admin manifest-signing key id the verifier must pin.
    pub signer_kid: String,
    /// base64url-no-pad Ed25519 signature over `serde_json::to_vec(&manifest)`.
    pub signature: String,
}

/// The successful load: the trust-anchor set to verify against, plus the version to
/// record as the new floor for rollback protection.
#[derive(Debug, Clone)]
pub struct LoadedTrustAnchors {
    pub issuer_set: TrustedIssuerSet,
    pub version: u64,
}

/// A manifest load/distribution fault (NOT a wire response rejection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustManifestError {
    /// The manifest's `signer_kid` is not a pinned org/admin key.
    UntrustedSigner,
    /// The org signature does not verify over the manifest bytes.
    BadSignature,
    /// The manifest is expired — a stale trust picture is never used (fail closed).
    Expired { expires_at: i64, now: i64 },
    /// A rollback: the manifest version is below the highest already accepted.
    Stale { version: u64, min_version: u64 },
    /// The manifest governs a different profile than this verifier.
    ProfileMismatch,
    /// A structurally malformed manifest (e.g. an undecodable public key).
    Malformed(&'static str),
}

/// Sign a manifest with the org/admin key, producing the distributable envelope.
pub fn sign_manifest(
    manifest: &TrustAnchorManifest,
    org_key: &SigningKey,
    signer_kid: impl Into<String>,
) -> SignedTrustAnchorManifest {
    let bytes = serde_json::to_vec(manifest).expect("manifest serializes");
    SignedTrustAnchorManifest {
        manifest: manifest.clone(),
        signer_kid: signer_kid.into(),
        // SigningKey::sign returns base64url-no-pad.
        signature: org_key.sign(&bytes),
    }
}

/// Verify + load a signed trust-anchor manifest into a [`TrustedIssuerSet`].
///
/// `resolve_manifest_signer(signer_kid) -> Some(org_pubkey)` is the pin: the verifier
/// trusts ONLY the org/admin keys it returns a key for. `min_version` is the highest
/// manifest version already accepted (0 to accept any first manifest) — a lower
/// version is a rollback and rejected. `expected_profile` must equal the manifest's
/// `profile`. Fails closed on an expired manifest.
pub fn load_signed_manifest(
    signed: &SignedTrustAnchorManifest,
    resolve_manifest_signer: impl Fn(&str) -> Option<VerificationKey>,
    expected_profile: &str,
    min_version: u64,
    now: i64,
) -> Result<LoadedTrustAnchors, TrustManifestError> {
    // 1. Pin the manifest signer.
    let org_key = resolve_manifest_signer(&signed.signer_kid)
        .ok_or(TrustManifestError::UntrustedSigner)?;

    // 2. Verify the org signature over the canonical manifest bytes.
    let bytes = serde_json::to_vec(&signed.manifest)
        .map_err(|_| TrustManifestError::Malformed("manifest serialize"))?;
    verify_ed25519_with(&bytes, &signed.signature, &org_key, McpReError::InvalidSignature)
        .map_err(|_| TrustManifestError::BadSignature)?;

    // 3. Profile gate.
    if signed.manifest.profile != expected_profile {
        return Err(TrustManifestError::ProfileMismatch);
    }

    // 4. Expiry — a stale trust picture fails closed.
    if now > signed.manifest.expires_at {
        return Err(TrustManifestError::Expired {
            expires_at: signed.manifest.expires_at,
            now,
        });
    }

    // 5. Rollback protection — never accept a version below the highest already seen.
    if signed.manifest.manifest_version < min_version {
        return Err(TrustManifestError::Stale {
            version: signed.manifest.manifest_version,
            min_version,
        });
    }

    // 6. Build the trust-anchor set. (Roots verified-in only AFTER the signature +
    //    freshness + version gates above.)
    let mut set = TrustedIssuerSet::new();
    for iss in &signed.manifest.current_issuers {
        set = set.with_current(actor_of(&iss.issuer_kid, &iss.public_key, &iss.role, &iss.trust_domain, &iss.subject)?);
    }
    for r in &signed.manifest.retiring_issuers {
        set = set.with_retired(
            actor_of(&r.issuer_kid, &r.public_key, &r.role, &r.trust_domain, &r.subject)?,
            r.valid_until,
        );
    }
    for kid in &signed.manifest.revoked_issuers {
        set = set.revoke(kid.clone());
    }

    Ok(LoadedTrustAnchors {
        issuer_set: set,
        version: signed.manifest.manifest_version,
    })
}

/// Build the ROOT [`ResolvedActor`] (Response slot) a manifest issuer describes.
fn actor_of(
    issuer_kid: &str,
    public_key_b64url: &str,
    role: &str,
    trust_domain: &str,
    subject: &str,
) -> Result<ResolvedActor, TrustManifestError> {
    let verification_key = VerificationKey::from_b64url(public_key_b64url)
        .map_err(|_| TrustManifestError::Malformed("issuer public key"))?;
    Ok(ResolvedActor {
        identity: ActorIdentity {
            role: role.to_owned(),
            trust_domain: trust_domain.to_owned(),
            subject: subject.to_owned(),
            keyid: issuer_kid.to_owned(),
        },
        verification_key,
        slot: SignerSlot::Response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "mcp-re-http-v1";
    const ORG_KID: &str = "org-admin-root";

    fn org_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[7u8; 32])
    }
    fn root_a() -> SigningKey {
        SigningKey::from_seed_bytes(&[33u8; 32])
    }
    fn root_b() -> SigningKey {
        SigningKey::from_seed_bytes(&[44u8; 32])
    }

    fn issuer(kid: &str, key: &SigningKey) -> ManifestIssuer {
        ManifestIssuer {
            issuer_kid: kid.into(),
            public_key: key.public_key().to_b64url(),
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:issuer".into(),
        }
    }

    fn manifest(version: u64, current: Vec<ManifestIssuer>, retiring: Vec<RetiringIssuer>, revoked: Vec<String>) -> TrustAnchorManifest {
        TrustAnchorManifest {
            profile: PROFILE.into(),
            manifest_version: version,
            current_issuers: current,
            retiring_issuers: retiring,
            revoked_issuers: revoked,
            issued_at: 1_000,
            expires_at: 10_000,
        }
    }

    fn org_resolver(kid: &str) -> Option<VerificationKey> {
        if kid == ORG_KID {
            Some(org_key().public_key())
        } else {
            None
        }
    }

    #[test]
    fn signed_manifest_loads_current_issuers() {
        let m = manifest(1, vec![issuer("root-A", &root_a())], vec![], vec![]);
        let signed = sign_manifest(&m, &org_key(), ORG_KID);
        let loaded = load_signed_manifest(&signed, org_resolver, PROFILE, 0, 5_000).expect("loads");
        assert_eq!(loaded.version, 1);
        assert!(loaded.issuer_set.resolve_root("root-A", 5_000).is_some());
        assert!(loaded.issuer_set.resolve_root("root-B", 5_000).is_none());
    }

    #[test]
    fn overlap_and_revocation_round_trip_through_the_manifest() {
        let retiring = RetiringIssuer {
            issuer_kid: "root-A".into(),
            public_key: root_a().public_key().to_b64url(),
            role: "server".into(),
            trust_domain: "example.com".into(),
            subject: "did:example:issuer".into(),
            valid_until: 6_000,
        };
        let m = manifest(2, vec![issuer("root-B", &root_b())], vec![retiring], vec!["root-X".into()]);
        let signed = sign_manifest(&m, &org_key(), ORG_KID);
        let loaded = load_signed_manifest(&signed, org_resolver, PROFILE, 2, 5_500).expect("loads");
        // B current, A retiring (in window), X revoked.
        assert!(loaded.issuer_set.resolve_root("root-B", 5_500).is_some());
        assert!(loaded.issuer_set.resolve_root("root-A", 5_500).is_some(), "A in window");
        assert!(loaded.issuer_set.resolve_root("root-A", 6_001).is_none(), "A past valid_until");
        assert!(mcp_re_client_core_is_revoked(&loaded.issuer_set, "root-X"));
    }

    fn mcp_re_client_core_is_revoked(set: &TrustedIssuerSet, kid: &str) -> bool {
        use crate::RevocationSource;
        set.is_revoked(kid)
    }

    #[test]
    fn untrusted_signer_is_rejected() {
        let m = manifest(1, vec![issuer("root-A", &root_a())], vec![], vec![]);
        // Signed by a NON-org key, but claims the org kid.
        let signed = sign_manifest(&m, &root_a(), ORG_KID);
        assert_eq!(
            load_signed_manifest(&signed, org_resolver, PROFILE, 0, 5_000).unwrap_err(),
            TrustManifestError::BadSignature
        );
        // Or claims an unknown signer kid.
        let mut wrong = sign_manifest(&m, &org_key(), "someone-else");
        wrong.signer_kid = "someone-else".into();
        assert_eq!(
            load_signed_manifest(&wrong, org_resolver, PROFILE, 0, 5_000).unwrap_err(),
            TrustManifestError::UntrustedSigner
        );
    }

    #[test]
    fn tampered_manifest_fails_the_signature() {
        let m = manifest(1, vec![issuer("root-A", &root_a())], vec![], vec![]);
        let mut signed = sign_manifest(&m, &org_key(), ORG_KID);
        // Attacker swaps in their own root under the same kid AFTER signing.
        signed.manifest.current_issuers[0].public_key = root_b().public_key().to_b64url();
        assert_eq!(
            load_signed_manifest(&signed, org_resolver, PROFILE, 0, 5_000).unwrap_err(),
            TrustManifestError::BadSignature
        );
    }

    #[test]
    fn expired_manifest_fails_closed() {
        let m = manifest(1, vec![issuer("root-A", &root_a())], vec![], vec![]);
        let signed = sign_manifest(&m, &org_key(), ORG_KID);
        match load_signed_manifest(&signed, org_resolver, PROFILE, 0, 10_001).unwrap_err() {
            TrustManifestError::Expired { .. } => {}
            e => panic!("expected Expired, got {e:?}"),
        }
    }

    #[test]
    fn rolled_back_manifest_version_is_rejected() {
        let m = manifest(3, vec![issuer("root-A", &root_a())], vec![], vec![]);
        let signed = sign_manifest(&m, &org_key(), ORG_KID);
        // The verifier has already accepted version 5; a version-3 replay is a rollback.
        assert_eq!(
            load_signed_manifest(&signed, org_resolver, PROFILE, 5, 5_000).unwrap_err(),
            TrustManifestError::Stale { version: 3, min_version: 5 }
        );
        // The same version (idempotent re-apply) is accepted.
        load_signed_manifest(&signed, org_resolver, PROFILE, 3, 5_000).expect("same version ok");
    }

    #[test]
    fn wrong_profile_is_rejected() {
        let mut m = manifest(1, vec![issuer("root-A", &root_a())], vec![], vec![]);
        m.profile = "other-profile".into();
        let signed = sign_manifest(&m, &org_key(), ORG_KID);
        assert_eq!(
            load_signed_manifest(&signed, org_resolver, PROFILE, 0, 5_000).unwrap_err(),
            TrustManifestError::ProfileMismatch
        );
    }
}
