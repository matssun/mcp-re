// SPDX-License-Identifier: Apache-2.0
//! The client-side TRUST-ANCHOR lifecycle: which ROOT issuers anchor a delegation
//! credential, and for how long.
//!
//! The other half of the delegated-response trust authority, and the one with states. A
//! delegated key rotates every few minutes under ONE root; a root rotation swaps the anchor
//! the whole fleet chains to — a rare, high-stakes ceremony needing a controlled OVERLAP so
//! credentials issued under the outgoing root keep verifying until a cutover deadline, then
//! stop. That deadline is what a single `issuer_kid -> key` map cannot express.
//!
//! Revocation of a root is the ONE decisive action that invalidates every descendant
//! delegated credential at once, and this module is where that outranks everything else:
//! `resolve_issuer` fails closed on a revoked issuer WITHOUT consulting any caller-supplied
//! revocation half, so an empty one is never asked rather than merely overruled.

use std::collections::HashMap;
use std::collections::HashSet;

use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;

use super::manifest_validity::ManifestValidity;
use super::DelegatedResponseTrust;
use super::RevocationSource;

/// The client-side TRUST-ANCHOR lifecycle (ADR-MCPRE-052 root rotation + revocation)
/// — which ROOT issuers the verifier trusts to anchor a delegation credential, and
/// for how long. This is the MASTER-key analogue of [`StaticRevocationList`] (which
/// governs individual short-lived DELEGATED keys): this governs the ISSUER itself.
///
/// Trust-anchor rotation is NOT delegated-key rotation. A delegated key rotates every
/// few minutes under ONE root (the hot path); a root rotation swaps the anchor the
/// whole fleet chains to — a rare, high-stakes ceremony that needs a controlled
/// OVERLAP so credentials issued under the outgoing root keep verifying until a
/// cutover deadline, then stop. That overlap deadline is the mechanism a single
/// `issuer_kid -> key` map cannot express.
///
/// Four states per `issuer_kid`, evaluated at `now`:
///   * CURRENT — a live root; its credentials verify (subject to the usual scope /
///     freshness / epoch gates).
///   * RETIRED — a superseded root inside its overlap window; its credentials verify
///     ONLY while `now <= valid_until`, then resolve to untrusted
///     (`delegation_issuer_untrusted`). This is trust-anchor rotation.
///   * REVOKED — a compromised / withdrawn root; the ONE decisive action that
///     invalidates ALL its descendant delegated credentials at once
///     (`delegation_revoked`), even before their own `exp` and WITHOUT chasing each
///     delegated key. (Consulted via the [`RevocationSource`] impl below.)
///   * UNKNOWN — any other issuer; rejected `delegation_issuer_untrusted`.
///
/// The verifier core (`verify_delegation_credential`) is unchanged: this set feeds
/// its two existing seams — the `resolve_root` actor resolver (current + in-window
/// retired) and the `is_revoked` revocation source (revoked issuers). Because the
/// resolver is rebuilt per verification with the caller's injected `now`
/// (the [`DelegatedResponseTrust`] impl takes `now` per call), the overlap window is
/// enforced without
/// the pure verifier ever reading a clock.
#[derive(Debug, Clone, Default)]
pub struct TrustedIssuerSet {
    /// Live roots: `issuer_kid` -> the resolved ROOT actor (identity + pubkey).
    current: HashMap<String, ResolvedActor>,
    /// Superseded-but-overlapping roots: `issuer_kid` -> (actor, `valid_until` unix).
    retired: HashMap<String, (ResolvedActor, i64)>,
    /// Withdrawn / compromised roots (by `issuer_kid`).
    revoked: HashSet<String>,
    /// The publishing document's own lifetime, which outranks every root in the set.
    manifest: ManifestValidity,
}

impl TrustedIssuerSet {
    /// An empty set — trusts no root (every issuer is UNKNOWN → rejected). Roots are
    /// added deliberately; a delegated-required verifier cannot silently trust one.
    pub fn new() -> Self {
        TrustedIssuerSet::default()
    }

    /// Add a CURRENT (live) root, keyed by the actor's `keyid` (= the credential
    /// `issuer_kid`). The actor MUST be for the `Response` slot (it anchors the
    /// server/response signer).
    pub fn with_current(mut self, root: ResolvedActor) -> Self {
        self.current.insert(root.identity.keyid.clone(), root);
        self
    }

    /// Add a RETIRED root that remains trusted only through `valid_until` (unix
    /// seconds) — the overlap deadline. After it, credentials under this root resolve
    /// to untrusted.
    pub fn with_retired(mut self, root: ResolvedActor, valid_until: i64) -> Self {
        self.retired
            .insert(root.identity.keyid.clone(), (root, valid_until));
        self
    }

    /// Mark an `issuer_kid` REVOKED — one decisive action invalidating every
    /// descendant delegated credential immediately (`delegation_revoked`).
    pub fn revoke(mut self, issuer_kid: impl Into<String>) -> Self {
        self.revoked.insert(issuer_kid.into());
        self
    }

    /// Carry the publishing document's `expires_at` INTO the set.
    ///
    /// See [`ManifestValidity`] for why the deadline travels with the picture rather than
    /// staying at the loader. Every root resolves to `None` once `now` passes it, so
    /// responses fail closed as `delegation_issuer_untrusted` until a newer document is
    /// accepted.
    pub fn with_manifest_expiry(mut self, expires_at: i64) -> Self {
        self.manifest = ManifestValidity::Until(expires_at);
        self
    }

    /// When the document behind this trust picture stops being usable, if it came from
    /// one.
    pub fn manifest_expires_at(&self) -> Option<i64> {
        self.manifest.expires_at()
    }

    /// Whether the document that published this set has expired at `now`. A set with no
    /// document behind it never expires.
    pub fn is_expired(&self, now: i64) -> bool {
        self.manifest.is_expired(now)
    }

    /// Whether this set vouches for `issuer_kid` at `now` — the public yes/no.
    ///
    /// Fails closed on revocation, on a retired root past its overlap deadline, on an
    /// unknown issuer, and on an expired publishing document. It is the only trust
    /// question this type answers in public, and it answers it whole.
    pub fn trusts(&self, issuer_kid: &str, now: i64) -> bool {
        !self.is_revoked(issuer_kid) && self.resolve_root(issuer_kid, now).is_some()
    }

    /// The LIFECYCLE lookup: a current root, or a retired root still inside its overlap
    /// window (`now <= valid_until`). A retired root past its window, an unknown issuer,
    /// or ANY issuer once the publishing document's
    /// [`manifest_expires_at`](Self::manifest_expires_at) has passed, resolves to `None`.
    ///
    /// **It answers rotation, not revocation, and it is `pub(crate)` for that reason.** A
    /// revoked-but-still-current root resolves here, so this is not a trust verdict and
    /// must never be exposed as one: a caller holding it could pair it with an empty
    /// revocation source and verify a credential beneath a root this very set marks
    /// REVOKED. The public verdict is [`resolve_issuer`](DelegatedResponseTrust::resolve_issuer),
    /// which fails closed, and [`trusts`](Self::trusts) for a plain yes/no.
    pub(crate) fn resolve_root(&self, issuer_kid: &str, now: i64) -> Option<ResolvedActor> {
        // The whole picture has a deadline, and it outranks any individual root's:
        // past the publishing document's `expires_at` nothing in it resolves, so a
        // verifier that never refreshes fails closed instead of serving forever on
        // anchors the org stopped standing behind.
        if self.is_expired(now) {
            return None;
        }
        // RETIREMENT WINS. A kid listed as both current and retiring is a contradiction
        // in the manifest, and reading `current` first resolved it in the permissive
        // direction: the root stayed trusted unconditionally and its `valid_until`
        // cutover was never evaluated — so a retirement an org published could be
        // undone by leaving the same kid in the current list. Checking the deadline
        // first makes the contradiction fail safe: past `valid_until` nothing resolves.
        if let Some((actor, valid_until)) = self.retired.get(issuer_kid) {
            return (now <= *valid_until).then(|| actor.clone());
        }
        self.current.get(issuer_kid).cloned()
    }
}

impl DelegatedResponseTrust for TrustedIssuerSet {
    /// Resolve the credential's root issuer for the RESPONSE slot at `now`. The Request
    /// slot is never resolved on the response-verification path.
    ///
    /// **A REVOKED issuer resolves to nothing here, structurally.** This is the only
    /// public resolution interface on the type, so a revoked root cannot yield a usable
    /// [`ResolvedActor`] through any public path — including one composed into a
    /// [`CompositeResponseTrust`] beside an empty revocation source. The refusal does not
    /// depend on which revocation half the caller supplied, because it does not consult
    /// the caller's half at all.
    ///
    /// The cost is the error's precision: the rejection reads `delegation_issuer_untrusted`
    /// rather than `delegation_revoked`, because the credential's signature is never
    /// reached. That is the right trade. A diagnostic distinction is worth less than a
    /// structural guarantee, and the honest reason was only available while a caller
    /// could still get the pairing wrong.
    fn resolve_issuer(&self, issuer_kid: &str, slot: SignerSlot, now: i64) -> ResolverOutcome {
        match slot {
            SignerSlot::Response if !self.is_revoked(issuer_kid) => {
                self.resolve_root(issuer_kid, now).into()
            }
            _ => ResolverOutcome::NotTrusted,
        }
    }
}

impl RevocationSource for TrustedIssuerSet {
    fn is_revoked(&self, identifier: &str) -> bool {
        self.revoked.contains(identifier)
    }
}
