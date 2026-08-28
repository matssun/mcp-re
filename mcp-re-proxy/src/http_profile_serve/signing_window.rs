// SPDX-License-Identifier: Apache-2.0
//! The validity a response signed under a delegated credential may advertise.
//!
//! ADR-MCPRE-052 §4 gives the delegated snapshot a fail-closed bound: a signer MUST stop
//! signing off it once `now >= exp`. A receipt that advertised validity beyond that bound
//! would be asserting a window the verifier refuses the moment the credential's own window
//! closes — the signature is still well-formed, so the client learns nothing until it
//! fails.
//!
//! The bound is therefore not a step the signing paths perform. It is what a
//! [`SigningWindow`] IS: `expires` is private, no constructor accepts one, and the two
//! that exist derive it. Holding a window means holding a validity that does not outlive
//! the credential authorizing it, whichever path obtained it.

use std::sync::Arc;

use mcp_re_http_profile::ActiveDelegatedKey;

use crate::delegated_server_signer::DelegatedServerSigner;

/// A delegated credential snapshotted for one exchange, with the response validity it
/// authorizes.
///
/// The snapshot is taken once per exchange because `now` is fixed for its whole duration:
/// a key valid when the exchange opened is valid when its reply is signed.
pub(crate) struct SigningWindow {
    /// The credential the signature is made under.
    key: Arc<ActiveDelegatedKey>,
    /// Unix seconds this response may claim validity until.
    ///
    /// Never later than `key.exp`. There is no constructor that takes this value, so the
    /// relation holds for every window that exists rather than for the ones whose caller
    /// remembered to clamp.
    expires: i64,
}

impl SigningWindow {
    /// Open a window over the signer's current credential, or `None` when the deployment
    /// has no valid delegated key — the fail-closed posture, since delegated signing is
    /// the only response-signing mode there is.
    pub(crate) fn open(signer: &DelegatedServerSigner, now: i64, ttl_secs: i64) -> Option<Self> {
        signer
            .current(now)
            .map(|key| Self::over(key, now, ttl_secs))
    }

    /// Open a window over a credential already snapshotted earlier in this exchange.
    ///
    /// The same derivation as [`SigningWindow::open`]: a refusal minted late in an
    /// exchange signs under the credential that exchange took, and advertises no more
    /// validity for having been reached by a different path.
    pub(crate) fn over(key: Arc<ActiveDelegatedKey>, now: i64, ttl_secs: i64) -> Self {
        let exp = key.exp;
        Self {
            key,
            // `now + ttl_secs` is the configured window; `exp` is the credential's own.
            // The response advertises whichever closes first.
            expires: now.saturating_add(ttl_secs).min(exp),
        }
    }

    /// The credential this window authorizes signing under.
    pub(crate) fn key(&self) -> &ActiveDelegatedKey {
        &self.key
    }

    /// The shared snapshot, for an exchange that must carry it to a later stage.
    pub(crate) fn shared(&self) -> Arc<ActiveDelegatedKey> {
        Arc::clone(&self.key)
    }

    /// Unix seconds the signed response may claim validity until.
    pub(crate) fn expires(&self) -> i64 {
        self.expires
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(exp: i64) -> Arc<ActiveDelegatedKey> {
        Arc::new(ActiveDelegatedKey {
            key: Arc::new(mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32])),
            delegated_kid: "delegated-1".into(),
            server_signer: mcp_re_http_profile::ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: "delegated-1".into(),
            },
            credential: "credential".into(),
            nbf: 0,
            exp,
        })
    }

    /// The configured TTL wins while it closes first — the ordinary case, in which the
    /// credential has plenty of life left.
    #[test]
    fn the_configured_ttl_bounds_a_window_inside_the_credential() {
        assert_eq!(SigningWindow::over(key(10_000), 1_000, 60).expires(), 1_060);
    }

    /// ADR-MCPRE-052 §4: past the credential's own `exp` the signature authorizes
    /// nothing, so no configured TTL can advertise validity there.
    #[test]
    fn the_credential_bounds_a_ttl_that_would_outlive_it() {
        assert_eq!(SigningWindow::over(key(1_030), 1_000, 60).expires(), 1_030);
    }

    /// A credential already past its bound yields a window claiming no validity at all
    /// rather than one running backwards from the configured TTL.
    #[test]
    fn an_expired_credential_advertises_no_future_validity() {
        assert_eq!(SigningWindow::over(key(900), 1_000, 60).expires(), 900);
    }

    /// The clamp is arithmetic that cannot be skipped by choosing a large TTL: a
    /// deployment configuring an absurd window still advertises the credential's.
    #[test]
    fn a_saturating_ttl_does_not_wrap_past_the_credential() {
        assert_eq!(
            SigningWindow::over(key(2_000), i64::MAX - 1, i64::MAX).expires(),
            2_000
        );
    }
}
