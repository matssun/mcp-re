// SPDX-License-Identifier: Apache-2.0
//! The validity a response signed under a delegated credential may advertise.
//!
//! ADR-MCPRE-052 §4 gives the delegated snapshot a fail-closed bound: a signer MUST stop
//! signing off it once `now >= exp`. A signature that advertised validity beyond that bound
//! would be asserting a window the verifier refuses the moment the credential's own window
//! closes — the signature is still well-formed, so the client learns nothing until it
//! fails.
//!
//! The bound is therefore not a step the signing paths perform. It is what a
//! [`SigningWindow`] IS: `expires` is private, the only constructor derives it, and the
//! delegated signing key is crate-private, reachable only through the emitters in
//! [`super::window_emission`], which take a window. Holding the means to sign under a
//! credential therefore means holding a validity that does not outlive it, whichever crate
//! obtained it.

use std::sync::Arc;

use super::ActiveDelegatedKey;

/// A delegated credential snapshotted for one exchange, with the response validity it
/// authorizes.
///
/// The snapshot is taken once per exchange because `now` is fixed for its whole duration:
/// a key valid when the exchange opened is valid when its reply is signed.
pub struct SigningWindow {
    /// The credential the signature is made under.
    key: Arc<ActiveDelegatedKey>,
    /// Unix seconds this response's validity runs FROM — the exchange's one clock
    /// reading, which is also what the signature advertises as `created`.
    ///
    /// Kept because the freshness rule is about the window, not about its far end alone:
    /// asking whether a verifier still admits this window at some instant needs both
    /// bounds, and reconstructing `created` at the asking site would be the second copy
    /// this type exists to prevent.
    created: i64,
    /// Unix seconds this response may claim validity until.
    ///
    /// Never later than `key.exp`, and always after `created`. There is no constructor
    /// that takes this value, so both relations hold for every window that exists rather
    /// than for the ones whose caller remembered to clamp.
    expires: i64,
}

impl SigningWindow {
    /// Open a window over a credential snapshotted at `now`, or `None` when no window can
    /// exist over it.
    ///
    /// A credential already past its `exp`, or a non-positive TTL, leaves nothing to
    /// advertise, so no window is made — as [`ActiveDelegatedKey::issued`] refuses
    /// `nbf >= exp`.
    pub fn over(key: Arc<ActiveDelegatedKey>, now: i64, ttl_secs: i64) -> Option<Self> {
        // `now + ttl_secs` is the configured window; `exp` is the credential's own.
        // The response advertises whichever closes first.
        let expires = now.saturating_add(ttl_secs).min(key.exp());
        (now < expires).then_some(Self {
            key,
            created: now,
            expires,
        })
    }

    /// Would a conforming verifier still admit a response advertising this window, at
    /// `instant`?
    ///
    /// Asked through [`crate::verify::window_is_fresh`] — the §5.1 rule ITSELF, the same
    /// function the request floor applies — rather than through a formula written here that
    /// agrees with it. A signer and a verifier disagreeing about freshness is precisely the
    /// failure this asks about, so the two must not be two statements.
    ///
    /// Skew is ZERO on purpose, and that is the conservative direction: the signer does not
    /// know the client's policy, and a verifier configured with any tolerance at all admits
    /// everything a zero-tolerance one does.
    pub fn admissible_at(&self, instant: i64) -> bool {
        crate::verify::window_is_fresh(self.created, self.expires, instant, 0)
    }

    /// The credential this window authorizes signing under.
    pub fn key(&self) -> &ActiveDelegatedKey {
        &self.key
    }

    /// The shared snapshot, for an exchange that must carry it to a later stage.
    pub fn shared(&self) -> Arc<ActiveDelegatedKey> {
        Arc::clone(&self.key)
    }

    /// Unix seconds the signed response advertises its validity FROM.
    pub fn created(&self) -> i64 {
        self.created
    }

    /// Unix seconds the signed response may claim validity until.
    pub fn expires(&self) -> i64 {
        self.expires
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{CustodyConfig, DelegatedKeyWindow, DelegatedSigningCustody};
    use super::*;
    use crate::delegation::issue_delegation_credential;
    use mcp_re_core::SigningKey;

    const TTL: i64 = 300;

    /// A credential expiring at `exp`, minted by a custody over a software root.
    pub(in super::super) fn key(exp: i64) -> Arc<ActiveDelegatedKey> {
        let root = SigningKey::from_seed_bytes(&[33u8; 32]);
        let cfg = CustodyConfig {
            issuer_kid: "root-kid".into(),
            iss: "did:example:server".into(),
            profile: "mcp-re-http-v1".into(),
            aud: "verifier-1".into(),
            audience_hash: "aud-scope-1".into(),
            trust_epoch: "epoch-1".into(),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            window: DelegatedKeyWindow::of(TTL, TTL / 6).expect("0 < overlap < ttl"),
        };
        let root_key = root.public_key();
        let mut custody = DelegatedSigningCustody::new(
            cfg,
            root_key,
            move |h, c| Some(issue_delegation_credential(&root, h, c)),
            || SigningKey::from_seed_bytes(&[7u8; 32]),
        );
        custody
            .ensure_active(exp - TTL)
            .expect("the software root issues");
        let active = custody.active_snapshot().expect("an issuance published");
        assert_eq!(active.exp(), exp, "the fixture window is the credential's");
        Arc::new(active)
    }

    /// The configured TTL wins while it closes first — the ordinary case, in which the
    /// credential has plenty of life left.
    #[test]
    fn the_configured_ttl_bounds_a_window_inside_the_credential() {
        let window = SigningWindow::over(key(10_000), 1_000, 60).expect("a live credential");
        assert_eq!(window.expires(), 1_060);
    }

    /// ADR-MCPRE-052 §4: past the credential's own `exp` the signature authorizes
    /// nothing, so no configured TTL can advertise validity there.
    #[test]
    fn the_credential_bounds_a_ttl_that_would_outlive_it() {
        let window = SigningWindow::over(key(1_030), 1_000, 60).expect("a live credential");
        assert_eq!(window.expires(), 1_030);
    }

    /// A credential at or past its bound opens no window rather than one running
    /// backwards from the configured TTL.
    #[test]
    fn an_expired_credential_opens_no_window() {
        assert!(SigningWindow::over(key(900), 1_000, 60).is_none());
        assert!(SigningWindow::over(key(1_000), 1_000, 60).is_none());
    }

    /// A TTL that leaves no time after `created` opens no window.
    #[test]
    fn a_non_positive_ttl_opens_no_window() {
        assert!(SigningWindow::over(key(10_000), 1_000, 0).is_none());
        assert!(SigningWindow::over(key(10_000), 1_000, -1).is_none());
    }

    /// The window advertises the instant it was opened at.
    #[test]
    fn the_window_advertises_the_instant_it_was_opened_at() {
        let window = SigningWindow::over(key(10_000), 1_000, 60).expect("a live credential");
        assert_eq!(window.created(), 1_000);
    }

    /// The clamp is arithmetic that cannot be skipped by choosing a large TTL: a
    /// deployment configuring an absurd window still advertises the credential's.
    #[test]
    fn a_saturating_ttl_does_not_wrap_past_the_credential() {
        let window = SigningWindow::over(key(2_000), 1_000, i64::MAX).expect("a live credential");
        assert_eq!(window.expires(), 2_000);
    }

    /// The window's own far end is the verifier's rule and not a local comparison: at
    /// `expires` itself the response is no longer admissible.
    #[test]
    fn admissibility_ends_at_expires_exactly_as_the_floor_says_it_does() {
        let window = SigningWindow::over(key(1_030), 1_000, 300).expect("a live credential");
        assert!(window.admissible_at(1_029));
        assert!(!window.admissible_at(1_030));
        assert!(!window.admissible_at(1_031));
    }
}
