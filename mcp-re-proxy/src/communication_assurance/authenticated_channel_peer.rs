// SPDX-License-Identifier: Apache-2.0
//! The channel-side predecessor a request binding may be formed over —
//! ADR-MCPRE-064, Slice 4.
//!
//! # Why this is an enum and not just the current peer
//!
//! Slice 3 established that a deployment configuring neither a lifetime ceiling nor CRLs
//! evaluates currency at all — and that such a deployment still serves, exactly as it did
//! before. Requiring [`CurrentAuthenticatedRelationshipPeerFacts`] here would therefore
//! refuse every request in that deployment, which is a regression introduced by tidiness.
//!
//! Accepting the authenticated peer and silently treating it as current would be worse: it
//! would flatten the one distinction Slice 3 exists to make, one level above the authority
//! that makes it. So both are carried, named, and distinguishable by a consumer:
//!
//! ```text
//! Current               currency was evaluated, and the credential is acceptable now
//! CurrencyNotEvaluated  the deployment configures no currency control — UNEXAMINED
//! ```
//!
//! A binding formed over the second is a true statement about a peer nobody checked the
//! currency of, and it says so.
//!
//! # What it is not
//!
//! Not a bag holding both, and not an `Option<CurrentCredentialFacts>` beside a peer. Each
//! variant owns a complete predecessor product, so there is no combination in which a
//! currency fact belongs to one relationship and an authentication to another.

use crate::communication_assurance::authenticated_relationship_peer::AuthenticatedRelationshipPeerFacts;
use crate::communication_assurance::certificate_identity_policy::CertificateIdentitySource;
use crate::communication_assurance::current_authenticated_peer::CurrentAuthenticatedRelationshipPeerFacts;
use crate::communication_assurance::mechanism_verified_credential::EstablishmentPath;
use crate::communication_assurance::peer_identity_value::PeerIdentityValue;

/// An authenticated peer of one relationship, with whatever currency assurance the
/// deployment's controls established about its credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatedChannelPeer {
    /// Currency was evaluated and the credential is acceptable at the instant the product
    /// carries.
    Current(CurrentAuthenticatedRelationshipPeerFacts),
    /// The deployment configures no currency control, so the credential is unexamined —
    /// not thereby current. See ADR-MCPRE-064 §14.
    CurrencyNotEvaluated(AuthenticatedRelationshipPeerFacts),
}

impl AuthenticatedChannelPeer {
    /// The identity this peer authenticated as.
    ///
    /// The same fact on both arms, and the ONLY one the binding relation reads. Currency
    /// does not change who the peer is; it changes what may be concluded about the
    /// credential they authenticated with.
    pub fn identity(&self) -> &PeerIdentityValue {
        match self {
            AuthenticatedChannelPeer::Current(peer) => peer.identity(),
            AuthenticatedChannelPeer::CurrencyNotEvaluated(peer) => peer.identity(),
        }
    }

    /// The certificate field that identity was read from.
    pub fn identity_source(&self) -> CertificateIdentitySource {
        match self {
            AuthenticatedChannelPeer::Current(peer) => peer.identity_source(),
            AuthenticatedChannelPeer::CurrencyNotEvaluated(peer) => peer.identity_source(),
        }
    }

    /// The path on which the authentication was reached, projected through unchanged.
    pub fn establishment_path(&self) -> EstablishmentPath {
        match self {
            AuthenticatedChannelPeer::Current(peer) => peer.establishment_path(),
            AuthenticatedChannelPeer::CurrencyNotEvaluated(peer) => peer.establishment_path(),
        }
    }

    /// Whether the deployment's controls examined this credential's currency.
    ///
    /// A consumer that needs *the credential was checked and is good now* must branch on
    /// this. One that only needs *this peer authenticated as this identity* need not, and
    /// the type refuses to choose for either.
    pub fn currency_was_evaluated(&self) -> bool {
        matches!(self, AuthenticatedChannelPeer::Current(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use crate::communication_assurance::authenticate_relationship_peer;
    use crate::communication_assurance::certificate_identity_policy::CertificateIdentityPolicy;
    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
    use crate::communication_assurance::credential_currency::CredentialCurrencyPolicy;
    use crate::communication_assurance::current_authenticated_peer::current_authenticated_peer;
    use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;

    const NOW: i64 = 1_800_000_000;

    fn authenticated() -> AuthenticatedRelationshipPeerFacts {
        let peers = mutually_authenticated_peers();
        let accepted =
            verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");
        authenticate_relationship_peer(accepted, CertificateIdentityPolicy::DnsSan)
            .expect("the harness leaf carries a DNS SAN")
    }

    #[test]
    fn both_arms_agree_on_who_the_peer_is_and_disagree_on_what_was_checked() {
        // The whole reason the enum exists. Currency does not change the identity, so a
        // binding relation reads one fact on both arms — while a consumer that needs the
        // credential to have been examined can still tell the two apart.
        let peer = authenticated();
        let identity = peer.identity().clone();
        let path = peer.establishment_path();

        let unexamined = AuthenticatedChannelPeer::CurrencyNotEvaluated(peer.clone());
        let current = AuthenticatedChannelPeer::Current(
            current_authenticated_peer(
                peer,
                &CredentialCurrencyPolicy::Ceiling(Duration::from_secs(365 * 24 * 3600 * 100_000)),
                NOW,
            )
            .expect("current"),
        );

        assert_eq!(unexamined.identity(), &identity);
        assert_eq!(current.identity(), &identity);
        assert_eq!(unexamined.identity_source(), current.identity_source());
        assert_eq!(unexamined.establishment_path(), path);
        assert_eq!(current.establishment_path(), path);

        assert!(!unexamined.currency_was_evaluated());
        assert!(current.currency_was_evaluated());
        assert_ne!(
            unexamined, current,
            "a peer whose currency nobody evaluated is not the same fact as one that was"
        );
    }
}
