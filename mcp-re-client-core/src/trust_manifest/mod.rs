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

use crate::delegated_trust::TrustedIssuerSet;

mod preimage;
use preimage::manifest_signing_preimage;

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
    /// The org/admin manifest-signing key id the verifier must pin. **Covered by
    /// `signature`** — see [`manifest_signing_preimage`].
    pub signer_kid: String,
    /// base64url-no-pad Ed25519 signature over [`manifest_signing_preimage`].
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
    /// The rollback floor could not be READ, so the version this verifier has already
    /// accepted is unknown. Fails closed: loading against a floor of 0 would accept any
    /// version, which is precisely the rollback the floor exists to prevent.
    FloorUnreadable(&'static str),
    /// The manifest verified but the new floor could not be PERSISTED, so the anchors
    /// are not returned. Using them would leave the accepted version recorded nowhere:
    /// the next start would read the old floor and re-accept the superseded manifest.
    FloorNotPersisted(&'static str),
    /// The stored floor is above the operator-declared ceiling, so the floor storage
    /// disagrees with the trust domain that bounds it and one of the two is lying.
    ///
    /// This is a FAIL-STOP, never a clamp. Lowering the effective floor to the ceiling
    /// would re-open exactly the rollback window the floor exists to close, and would do
    /// it silently — an attacker who can write the floor storage could then choose which
    /// manifest versions to re-admit by overshooting on purpose. Refusing to serve is
    /// the only response that neither trusts the storage nor discards the protection.
    FloorAboveCeiling { floor: u64, ceiling: u64 },
}

/// The durable rollback floor: the highest `manifest_version` this verifier has already
/// accepted (ADR-MCPRE-052 root-authority lifecycle).
///
/// `load_signed_manifest` takes `min_version` as an argument and hands the accepted
/// version back for the caller "to record" — which means the rollback protection is
/// only as good as a caller remembering to persist it. Nothing did, so the floor reset
/// to 0 on every start and an old manifest could be replayed to un-revoke a root or
/// re-widen an overlap window. This trait is where the floor lives; implement it over
/// whatever storage the deployment already trusts, and use
/// [`load_signed_manifest_with_floor`] so the read → verify → persist order is not the
/// caller's to get right.
///
/// `record` MUST be monotonic (never lower the floor) and MUST be durable before it
/// returns `Ok` — the load treats `Ok` as "this version can never be accepted again".
pub trait ManifestVersionFloor {
    /// The highest version already accepted, or 0 if none ever was.
    fn min_version(&self) -> Result<u64, TrustManifestError>;
    /// Durably raise the floor to `version`.
    ///
    /// A lower `version` leaves the floor unchanged. Whether that is reported as `Ok`
    /// depends on what the implementation can observe: an in-memory floor has no other
    /// writer, so a lower version is simply a no-op, while a durable floor shared
    /// between processes cannot distinguish "already at this version" from "another
    /// process raised it past this one after our snapshot" — and returning `Ok` there
    /// would hand back a manifest that only cleared a stale floor.
    fn record(&mut self, version: u64) -> Result<(), TrustManifestError>;
}

/// A boxed floor is a floor. Deployments choose their storage at run time (a durable
/// directory, or the explicit in-memory posture), so the choice arrives as a trait
/// object; without this the caller would have to reintroduce a hand-written enum whose
/// arms both forward to the same two methods.
impl<T: ManifestVersionFloor + ?Sized> ManifestVersionFloor for Box<T> {
    fn min_version(&self) -> Result<u64, TrustManifestError> {
        (**self).min_version()
    }

    fn record(&mut self, version: u64) -> Result<(), TrustManifestError> {
        (**self).record(version)
    }
}

/// A floor held only in memory — the EXPLICIT no-durability posture, for an ephemeral
/// verifier or a test. It protects against rollback within one process lifetime and
/// says nothing about the next one, which is the whole reason it has to be named:
/// choosing it is a decision, not what you get by forgetting to choose.
#[derive(Debug, Clone, Default)]
pub struct InMemoryVersionFloor {
    floor: u64,
}

impl InMemoryVersionFloor {
    /// A floor starting at 0 — any first manifest version is accepted.
    pub fn new() -> Self {
        InMemoryVersionFloor::default()
    }

    /// A floor starting at a known version (e.g. one read from config at boot).
    pub fn starting_at(floor: u64) -> Self {
        InMemoryVersionFloor { floor }
    }
}

impl ManifestVersionFloor for InMemoryVersionFloor {
    fn min_version(&self) -> Result<u64, TrustManifestError> {
        Ok(self.floor)
    }

    fn record(&mut self, version: u64) -> Result<(), TrustManifestError> {
        self.floor = self.floor.max(version);
        Ok(())
    }
}

/// Sign a manifest with the org/admin key, producing the distributable envelope.
pub fn sign_manifest(
    manifest: &TrustAnchorManifest,
    org_key: &SigningKey,
    signer_kid: impl Into<String>,
) -> SignedTrustAnchorManifest {
    let signer_kid = signer_kid.into();
    // Class A: the only failure `manifest_signing_preimage` reports is `serde_json::to_vec`
    // on a `TrustAnchorManifest`, a plain `Serialize` struct of owned strings and integers
    // — an assertion about this crate's own types, never about an input. Every VERIFIER
    // calls the fallible sibling.
    #[allow(clippy::expect_used)]
    let bytes = manifest_signing_preimage(manifest, &signer_kid)
        .expect("this crate's own manifest type serializes");
    SignedTrustAnchorManifest {
        manifest: manifest.clone(),
        signer_kid,
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
    let org_key =
        resolve_manifest_signer(&signed.signer_kid).ok_or(TrustManifestError::UntrustedSigner)?;

    // 2. Verify the org signature over the canonical preimage — which COVERS the
    //    `signer_kid` used to select `org_key` in step 1, so the identity the manifest
    //    claims to be published under is the one that was signed for.
    let bytes = manifest_signing_preimage(&signed.manifest, &signed.signer_kid)?;
    verify_ed25519_with(
        &bytes,
        &signed.signature,
        &org_key,
        McpReError::InvalidSignature,
    )
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
        set = set.with_current(actor_of(
            &iss.issuer_kid,
            &iss.public_key,
            &iss.role,
            &iss.trust_domain,
            &iss.subject,
        )?);
    }
    for r in &signed.manifest.retiring_issuers {
        set = set.with_retired(
            actor_of(
                &r.issuer_kid,
                &r.public_key,
                &r.role,
                &r.trust_domain,
                &r.subject,
            )?,
            r.valid_until,
        );
    }
    for kid in &signed.manifest.revoked_issuers {
        set = set.revoke(kid.clone());
    }

    // The load-time check above proves the manifest was live when it was read. Carrying
    // the expiry into the set makes it a property of every later verification, so a
    // refresher that stops running cannot leave stale anchors trusted indefinitely.
    Ok(LoadedTrustAnchors {
        issuer_set: set.with_manifest_expiry(signed.manifest.expires_at),
        version: signed.manifest.manifest_version,
    })
}

/// Verify + load a signed manifest against a DURABLE rollback floor, raising the floor
/// before the anchors are handed back.
///
/// The order is the point, and it is enforced here so no caller has to reproduce it:
///
///   1. READ the floor. An unreadable floor fails closed ([`TrustManifestError::FloorUnreadable`]) —
///      it is not treated as 0, because "we do not know what we have accepted" and
///      "we have accepted nothing" are opposite statements and only one of them is safe.
///   2. VERIFY + load against that floor (signature, pin, profile, expiry, rollback).
///   3. PERSIST the accepted version, and only then return the anchors. A persist
///      failure discards the load ([`TrustManifestError::FloorNotPersisted`]) rather
///      than using anchors whose version was recorded nowhere — otherwise a crash
///      between using them and writing the floor re-opens the rollback window on the
///      next start, which is the failure this whole mechanism exists to close.
pub fn load_signed_manifest_with_floor(
    signed: &SignedTrustAnchorManifest,
    resolve_manifest_signer: impl Fn(&str) -> Option<VerificationKey>,
    expected_profile: &str,
    floor: &mut impl ManifestVersionFloor,
    now: i64,
) -> Result<LoadedTrustAnchors, TrustManifestError> {
    let min_version = floor.min_version()?;
    let loaded = load_signed_manifest(
        signed,
        resolve_manifest_signer,
        expected_profile,
        min_version,
        now,
    )?;
    floor.record(loaded.version)?;
    Ok(loaded)
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

    fn manifest(
        version: u64,
        current: Vec<ManifestIssuer>,
        retiring: Vec<RetiringIssuer>,
        revoked: Vec<String>,
    ) -> TrustAnchorManifest {
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
    fn the_signer_kid_is_covered_by_the_signature() {
        // `signer_kid` names who published this trust picture AND selects the key it is
        // checked against. Outside the preimage it is unauthenticated, and the failure
        // becomes real the moment a deployment resolves two kids to the same key
        // material — an org-key rename, a rotation overlap — because then rewriting it
        // no longer breaks the signature.
        const ALIAS_KID: &str = "org-admin-root-renamed";
        let two_kids_one_key =
            |kid: &str| (kid == ORG_KID || kid == ALIAS_KID).then(|| org_key().public_key());

        let m = manifest(1, vec![issuer("root-A", &root_a())], vec![], vec![]);
        let signed = sign_manifest(&m, &org_key(), ORG_KID);
        // Signed under its true kid, it loads under the aliasing resolver.
        load_signed_manifest(&signed, two_kids_one_key, PROFILE, 0, 5_000)
            .expect("the genuine manifest loads");

        // Rewritten to claim the other identity — same key, same manifest bytes.
        let forged = SignedTrustAnchorManifest {
            signer_kid: ALIAS_KID.into(),
            ..signed.clone()
        };
        assert_eq!(
            load_signed_manifest(&forged, two_kids_one_key, PROFILE, 0, 5_000).err(),
            Some(TrustManifestError::BadSignature),
            "a manifest must not verify under a signer identity its holder never asserted"
        );
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
    fn the_manifests_deadline_travels_with_the_anchors_it_published() {
        let m = manifest(1, vec![issuer("root-A", &root_a())], vec![], vec![]);
        let signed = sign_manifest(&m, &org_key(), ORG_KID);
        let loaded = load_signed_manifest(&signed, org_resolver, PROFILE, 0, 5_000).expect("loads");
        assert_eq!(
            loaded.issuer_set.manifest_expires_at(),
            Some(m.expires_at),
            "the set must carry the publishing manifest's deadline"
        );
        assert!(loaded.issuer_set.resolve_root("root-A", 5_000).is_some());
        // The load succeeded once, at a moment the manifest was live. A verifier that
        // holds these anchors past the deadline must stop resolving them, because
        // nothing else re-checks: expiry is enforced per verification, not per refresh.
        assert!(
            loaded
                .issuer_set
                .resolve_root("root-A", m.expires_at + 1)
                .is_none(),
            "an anchor from an expired manifest must not resolve"
        );
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
        let m = manifest(
            2,
            vec![issuer("root-B", &root_b())],
            vec![retiring],
            vec!["root-X".into()],
        );
        let signed = sign_manifest(&m, &org_key(), ORG_KID);
        let loaded = load_signed_manifest(&signed, org_resolver, PROFILE, 2, 5_500).expect("loads");
        // B current, A retiring (in window), X revoked.
        assert!(loaded.issuer_set.resolve_root("root-B", 5_500).is_some());
        assert!(
            loaded.issuer_set.resolve_root("root-A", 5_500).is_some(),
            "A in window"
        );
        assert!(
            loaded.issuer_set.resolve_root("root-A", 6_001).is_none(),
            "A past valid_until"
        );
        assert!(mcp_re_client_core_is_revoked(&loaded.issuer_set, "root-X"));
    }

    /// A floor whose read or write fails on demand, so the fail-closed ordering in
    /// `load_signed_manifest_with_floor` can be asserted rather than reasoned about.
    struct BrittleFloor {
        floor: u64,
        read_fails: bool,
        write_fails: bool,
        recorded: Vec<u64>,
    }

    impl ManifestVersionFloor for BrittleFloor {
        fn min_version(&self) -> Result<u64, TrustManifestError> {
            if self.read_fails {
                return Err(TrustManifestError::FloorUnreadable("test"));
            }
            Ok(self.floor)
        }
        fn record(&mut self, version: u64) -> Result<(), TrustManifestError> {
            self.recorded.push(version);
            if self.write_fails {
                return Err(TrustManifestError::FloorNotPersisted("test"));
            }
            self.floor = self.floor.max(version);
            Ok(())
        }
    }

    #[test]
    fn the_floor_rises_on_load_and_then_rejects_the_superseded_manifest() {
        // C076: the version has to be REMEMBERED, or every load starts at 0 and an old
        // manifest can be replayed to un-revoke a root. Load v3, then re-offer v2: the
        // same call that accepted v3 now rejects v2 as a rollback, with no min_version
        // threaded by the caller.
        let mut floor = InMemoryVersionFloor::new();
        let v3 = sign_manifest(
            &manifest(3, vec![issuer("root-A", &root_a())], vec![], vec![]),
            &org_key(),
            ORG_KID,
        );
        let loaded = load_signed_manifest_with_floor(&v3, org_resolver, PROFILE, &mut floor, 5_000)
            .expect("v3 loads");
        assert_eq!(loaded.version, 3);
        assert_eq!(
            floor.min_version().unwrap(),
            3,
            "the floor rose to the accepted version"
        );

        // The rollback: v2 revokes root-A. Accepting it would un-revoke nothing here, but
        // the reverse manifest (an OLD one that has not yet revoked a compromised root) is
        // the real attack, and it is the same replay.
        let v2 = sign_manifest(
            &manifest(2, vec![issuer("root-A", &root_a())], vec![], vec![]),
            &org_key(),
            ORG_KID,
        );
        assert_eq!(
            load_signed_manifest_with_floor(&v2, org_resolver, PROFILE, &mut floor, 5_000).err(),
            Some(TrustManifestError::Stale {
                version: 2,
                min_version: 3
            }),
        );
        // Re-offering v3 is fine (idempotent), and so is moving forward.
        assert!(
            load_signed_manifest_with_floor(&v3, org_resolver, PROFILE, &mut floor, 5_000).is_ok()
        );
    }

    #[test]
    fn an_unreadable_floor_fails_closed_rather_than_defaulting_to_zero() {
        // "We do not know what we have accepted" must not collapse into "we have
        // accepted nothing" — the latter accepts any version.
        let mut floor = BrittleFloor {
            floor: 9,
            read_fails: true,
            write_fails: false,
            recorded: vec![],
        };
        let v1 = sign_manifest(
            &manifest(1, vec![issuer("root-A", &root_a())], vec![], vec![]),
            &org_key(),
            ORG_KID,
        );
        assert_eq!(
            load_signed_manifest_with_floor(&v1, org_resolver, PROFILE, &mut floor, 5_000).err(),
            Some(TrustManifestError::FloorUnreadable("test")),
        );
        assert!(
            floor.recorded.is_empty(),
            "nothing was recorded, because nothing was loaded"
        );
    }

    #[test]
    fn anchors_are_withheld_when_the_floor_cannot_be_persisted() {
        // The anchors verified, but the version could not be written down. Returning them
        // would mean using a trust picture whose version is recorded nowhere: a crash
        // before the next write leaves the old floor, and the superseded manifest is
        // accepted again. So the load fails, and the caller keeps whatever it had.
        let mut floor = BrittleFloor {
            floor: 0,
            read_fails: false,
            write_fails: true,
            recorded: vec![],
        };
        let v4 = sign_manifest(
            &manifest(4, vec![issuer("root-A", &root_a())], vec![], vec![]),
            &org_key(),
            ORG_KID,
        );
        assert_eq!(
            load_signed_manifest_with_floor(&v4, org_resolver, PROFILE, &mut floor, 5_000).err(),
            Some(TrustManifestError::FloorNotPersisted("test")),
        );
        assert_eq!(
            floor.recorded,
            vec![4],
            "the persist WAS attempted before giving up"
        );
    }

    #[test]
    fn the_in_memory_floor_is_monotonic() {
        let mut floor = InMemoryVersionFloor::starting_at(5);
        floor
            .record(2)
            .expect("a lower version is a no-op, not an error");
        assert_eq!(floor.min_version().unwrap(), 5);
        floor.record(6).expect("record");
        assert_eq!(floor.min_version().unwrap(), 6);
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
            TrustManifestError::Stale {
                version: 3,
                min_version: 5
            }
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
