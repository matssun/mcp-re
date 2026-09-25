// SPDX-License-Identifier: Apache-2.0
//! The channel-side predecessor a request binding may be formed over —
//! ADR-MCPRE-064, Slice 4.
//!
//! # Why this is two cases and not just the current peer
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
//! # Why the cases are not a caller's choice
//!
//! Naming both is only half the distinction. If a caller may also PICK one, the weak label
//! is reachable for a credential the controls examined and refused, and the audit record
//! then says `currency_was_evaluated() == false` about a revoked peer — the one reading an
//! operator of a CRL-configured deployment would take as impossible. So the representation
//! is private and [`AuthenticatedChannelPeer::resolve`] is the only way in: the case is a
//! consequence of the policy and the evaluation, and a refusal leaves as an error.
//!
//! # What it is not
//!
//! Not a bag holding both, and not an `Option<CurrentCredentialFacts>` beside a peer. Each
//! case owns a complete predecessor product, so there is no combination in which a
//! currency fact belongs to one relationship and an authentication to another.

use crate::communication_assurance::authenticated_relationship_peer::AuthenticatedRelationshipPeerFacts;
use crate::communication_assurance::certificate_identity_policy::CertificateIdentitySource;
use crate::communication_assurance::credential_currency::CredentialCurrencyPolicy;
use crate::communication_assurance::credential_currency::CredentialCurrencyRefusal;
use crate::communication_assurance::current_authenticated_peer::current_authenticated_peer;
use crate::communication_assurance::current_authenticated_peer::CurrentAuthenticatedRelationshipPeerFacts;
use crate::communication_assurance::current_authenticated_peer::CurrentPeerRefusal;
use crate::communication_assurance::mechanism_verified_credential::EstablishmentPath;
use crate::communication_assurance::peer_identity_value::PeerIdentityValue;

/// An authenticated peer of one relationship, with whatever currency assurance the
/// deployment's controls established about its credential.
///
/// The representation is PRIVATE to this module and the arms are not a caller's choice.
/// See [`AuthenticatedChannelPeer::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedChannelPeer(ChannelPeerAssurance);

/// Which of the two predecessor products this peer is, private to the owner.
///
/// Were these public variants, any in-crate caller could write
/// `current_authenticated_peer(..).map(Current).unwrap_or(CurrencyNotEvaluated(peer))`,
/// which type-checks and turns an expired or revoked credential into a bound channel peer
/// labelled *unexamined*. The label is a CONSEQUENCE of the policy and the evaluation, so
/// the only thing that may choose it is the operation that performs them.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChannelPeerAssurance {
    /// Currency was evaluated and the credential is acceptable at the instant the product
    /// carries.
    Current(CurrentAuthenticatedRelationshipPeerFacts),
    /// The deployment configures no currency control, so the credential is unexamined —
    /// not thereby current. See ADR-MCPRE-064 §14.
    CurrencyNotEvaluated(AuthenticatedRelationshipPeerFacts),
}

impl AuthenticatedChannelPeer {
    /// THE construction operation: evaluate this peer's credential under the deployment's
    /// policy and pair the verdict with the peer in one step.
    ///
    /// The weak arm is reachable from exactly one place — [`CurrentPeerRefusal::CurrencyNotEvaluated`],
    /// which the currency authority returns only when the deployment configured no control.
    /// A credential that WAS examined and refused leaves as `Err` and becomes no peer at
    /// all. There is therefore no inhabitant of this type that says *unexamined* about a
    /// credential the controls refused, and deleting the evaluation does not produce one —
    /// it produces code that does not compile.
    pub fn resolve(
        peer: AuthenticatedRelationshipPeerFacts,
        policy: &CredentialCurrencyPolicy,
        now: i64,
    ) -> Result<Self, CredentialCurrencyRefusal> {
        // Kept because the fallible step takes the peer BY VALUE — the unexamined arm
        // carries the same authentication the evaluation was asked about, never a second
        // one re-derived from the acceptance.
        let unexamined = peer.clone();
        match current_authenticated_peer(peer, policy, now) {
            Ok(current) => Ok(AuthenticatedChannelPeer(ChannelPeerAssurance::Current(
                current,
            ))),
            Err(CurrentPeerRefusal::CurrencyNotEvaluated) => Ok(AuthenticatedChannelPeer(
                ChannelPeerAssurance::CurrencyNotEvaluated(unexamined),
            )),
            Err(CurrentPeerRefusal::CredentialNotCurrent(refusal)) => Err(refusal),
        }
    }

    /// The identity this peer authenticated as.
    ///
    /// The same fact on both arms, and the ONLY one the binding relation reads. Currency
    /// does not change who the peer is; it changes what may be concluded about the
    /// credential they authenticated with.
    pub fn identity(&self) -> &PeerIdentityValue {
        match &self.0 {
            ChannelPeerAssurance::Current(peer) => peer.identity(),
            ChannelPeerAssurance::CurrencyNotEvaluated(peer) => peer.identity(),
        }
    }

    /// The certificate field that identity was read from.
    pub fn identity_source(&self) -> CertificateIdentitySource {
        match &self.0 {
            ChannelPeerAssurance::Current(peer) => peer.identity_source(),
            ChannelPeerAssurance::CurrencyNotEvaluated(peer) => peer.identity_source(),
        }
    }

    /// The path on which the authentication was reached, projected through unchanged.
    pub fn establishment_path(&self) -> EstablishmentPath {
        match &self.0 {
            ChannelPeerAssurance::Current(peer) => peer.establishment_path(),
            ChannelPeerAssurance::CurrencyNotEvaluated(peer) => peer.establishment_path(),
        }
    }

    /// Whether the deployment's controls examined this credential's currency.
    ///
    /// A consumer that needs *the credential was checked and is good now* must branch on
    /// this. One that only needs *this peer authenticated as this identity* need not, and
    /// the type refuses to choose for either.
    pub fn currency_was_evaluated(&self) -> bool {
        matches!(self.0, ChannelPeerAssurance::Current(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use crate::communication_assurance::authenticate_relationship_peer;
    use crate::communication_assurance::certificate_identity_policy::CertificateIdentityPolicy;
    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
    use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;

    const NOW: i64 = 1_800_000_000;

    /// Past the rcgen default `notAfter` (year 4096), so every harness credential has
    /// expired at this instant however wide the configured ceiling.
    const AFTER_YEAR_4096: i64 = 100_000_000_000;

    /// Wide enough that no harness credential trips it, so a refusal is never the
    /// ceiling's own doing.
    fn generous() -> CredentialCurrencyPolicy {
        CredentialCurrencyPolicy::Ceiling(Duration::from_secs(365 * 24 * 3600 * 100_000))
    }

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

        let unexamined = AuthenticatedChannelPeer::resolve(
            peer.clone(),
            &CredentialCurrencyPolicy::NotEvaluated,
            NOW,
        )
        .expect("a deployment that configures no control still serves");
        let current = AuthenticatedChannelPeer::resolve(peer, &generous(), NOW)
            .expect("a credential inside its validity window under a generous ceiling");

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

    /// THE control for the seal. A credential the deployment's controls EXAMINED and
    /// REFUSED must not become a channel peer at all — least of all one labelled
    /// unexamined, which is what a caller picking the arm could produce. Reverting the
    /// `CredentialNotCurrent` arm of `resolve` to an `unwrap_or` of the weak case makes
    /// this fail: `resolve` returns `Ok` and `currency_was_evaluated()` reads `false`
    /// about a credential outside its validity window.
    #[test]
    fn a_refused_credential_becomes_no_peer_rather_than_an_unexamined_one() {
        let refusal =
            AuthenticatedChannelPeer::resolve(authenticated(), &generous(), AFTER_YEAR_4096)
                .expect_err("an expired credential is not a channel peer");
        assert!(
            matches!(
                refusal,
                CredentialCurrencyRefusal::LeafOutsideValidityWindow { .. }
            ),
            "the currency authority's own reason must travel out unchanged, got {refusal:?}"
        );
    }

    /// The weak case is reachable from the policy and from nothing else. Under a policy
    /// that DOES configure a control, no input to `resolve` yields `currency_was_evaluated()
    /// == false`: the credential is either acceptable (the strong case) or an error.
    #[test]
    fn the_unexamined_label_is_reachable_only_where_the_deployment_configured_no_control() {
        let evaluated = AuthenticatedChannelPeer::resolve(authenticated(), &generous(), NOW)
            .expect("a current credential");
        assert!(evaluated.currency_was_evaluated());

        let unexamined = AuthenticatedChannelPeer::resolve(
            authenticated(),
            &CredentialCurrencyPolicy::NotEvaluated,
            NOW,
        )
        .expect("no control configured");
        assert!(!unexamined.currency_was_evaluated());

        // The same credential, the same instant: only the POLICY moved the label.
        assert_ne!(evaluated, unexamined);
    }
}
