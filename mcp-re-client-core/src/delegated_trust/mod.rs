// SPDX-License-Identifier: Apache-2.0
//! The delegated-response TRUST AUTHORITY seam (MCPRE-172).
//!
//! One value answering both *which root issuer resolves* and *which identifiers are
//! revoked*, so the two can never be supplied independently. The census that produced it
//! is `docs/architecture/components/client-response-verification.md`.

use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;

/// Which ROOT issuers anchor a credential, and for how long — the other half.
mod anchors;
/// The trust document's own lifetime, which outranks every root inside it.
mod manifest_validity;
/// Which credential identifiers are revoked — one half of the authority.
mod revocation;

pub use anchors::TrustedIssuerSet;
pub use revocation::RevocationSource;
pub use revocation::StaticRevocationList;

/// The delegated-response TRUST AUTHORITY: one value that answers both *which root
/// issuer resolves* and *which identifiers are revoked* (MCPRE-172, from the #580
/// census).
///
/// # Why this is one trait and not two arguments
///
/// The public verifier used to take a root resolver and a [`RevocationSource`] as
/// INDEPENDENT arguments. A caller could then derive a resolver from a
/// [`TrustedIssuerSet`] and pair it with an unrelated — or empty — revocation source,
/// and verify a delegated credential beneath a root **that same set marks REVOKED**.
/// Nothing indicated the revocation was inert.
///
/// Revocation of a trust anchor is the one decisive action that invalidates every
/// descendant delegated credential at once. It must not depend on remembering to pass a
/// value twice, so the two facts are supplied by one authority and the bad pairing is
/// not expressible.
///
/// [`RevocationSource`] is the supertrait rather than a duplicated method: an
/// implementation already answering revocation keeps doing so, and gains the resolution
/// half it was always meant to be paired with.
///
/// A deployment whose resolution and revocation genuinely come from different systems —
/// a live directory plus a separately maintained denylist — uses
/// [`CompositeResponseTrust`], which owns both internally and is itself one authority.
/// # The pairing this replaced is not expressible
///
/// Two doors had to close, not one.
///
/// `TrustedIssuerSet` no longer hands out a resolver on its own:
///
/// ```compile_fail
/// use mcp_re_client_core::TrustedIssuerSet;
/// let set = TrustedIssuerSet::new();
/// // `response_resolver` is gone: there is no resolver to pair with a foreign
/// // revocation source, which is what made verifying under a REVOKED root possible.
/// let _resolver = set.response_resolver(0);
/// ```
///
/// And it no longer exposes the raw lifecycle lookup, which returns a revoked root's
/// actor and would rebuild the same pairing through [`CompositeResponseTrust`]:
///
/// ```compile_fail
/// use mcp_re_client_core::TrustedIssuerSet;
/// let set = TrustedIssuerSet::new();
/// // `resolve_root` is pub(crate): it answers ROTATION, not revocation, and a caller
/// // holding it could compose it beside an empty revocation source.
/// let _actor = set.resolve_root("some-kid", 0);
/// ```
///
/// What remains public is [`resolve_issuer`](Self::resolve_issuer), which fails closed on
/// a revoked issuer without consulting the caller's revocation half at all — so composing
/// it beside an empty one changes nothing.
pub trait DelegatedResponseTrust: RevocationSource {
    /// Resolve `issuer_kid` for `slot` at `now`.
    ///
    /// Rebuilt per verification with the caller's `now`, so a trust-anchor overlap
    /// window is honoured without the pure verifier ever reading a clock.
    fn resolve_issuer(&self, issuer_kid: &str, slot: SignerSlot, now: i64) -> ResolverOutcome;
}

/// A [`DelegatedResponseTrust`] assembled from genuinely separate resolution and
/// revocation systems — a live directory plus an independently fed denylist.
///
/// The two sources are owned INTERNALLY. The verifier still receives one authority, so
/// this is a legitimate composition rather than a way back to the two free arguments:
/// building one is an explicit statement that these two systems are the trust picture,
/// not an accident of argument order.
pub struct CompositeResponseTrust<'a> {
    resolver: &'a (dyn Fn(&str, SignerSlot, i64) -> ResolverOutcome + Send + Sync),
    revocation: &'a dyn RevocationSource,
}

impl<'a> CompositeResponseTrust<'a> {
    /// Compose a resolver and a revocation source into one trust authority.
    pub fn new(
        resolver: &'a (dyn Fn(&str, SignerSlot, i64) -> ResolverOutcome + Send + Sync),
        revocation: &'a dyn RevocationSource,
    ) -> Self {
        CompositeResponseTrust {
            resolver,
            revocation,
        }
    }
}

impl RevocationSource for CompositeResponseTrust<'_> {
    fn is_revoked(&self, identifier: &str) -> bool {
        self.revocation.is_revoked(identifier)
    }
}

impl DelegatedResponseTrust for CompositeResponseTrust<'_> {
    fn resolve_issuer(&self, issuer_kid: &str, slot: SignerSlot, now: i64) -> ResolverOutcome {
        (self.resolver)(issuer_kid, slot, now)
    }
}
