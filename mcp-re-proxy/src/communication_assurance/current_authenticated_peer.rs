// SPDX-License-Identifier: Apache-2.0
//! An authenticated peer whose credential is still acceptable NOW — ADR-MCPRE-064, Slice 3.
//!
//! # The proposition
//!
//! Possession of [`CurrentAuthenticatedRelationshipPeerFacts`] means:
//!
//! > This relationship's peer authenticated as this identity, on this establishment path,
//! > and at this instant the credential it authenticated with is still acceptable under the
//! > deployment's configured currency controls.
//!
//! # The composition rule, a third time
//!
//! The rejected composition is the ADR-MCPRE-063 L-5 shape again:
//!
//! ```text
//! AuthenticatedRelationshipPeerFacts(A)                              # REJECTED
//!         + CurrentCredentialFacts(for B)
//!         -> current authenticated peer
//! ```
//!
//! Both operands are honest, and a proxy holds many relationships at once, so a caller can
//! pair the authentication of one with the currency of another and get a true-looking
//! sentence about a peer whose credential expired an hour ago. As in Slice 2 the derivation
//! therefore takes the predecessor and a POLICY — never a currency product, never a
//! credential, never a chain — and reaches the currency itself, from the acceptance the
//! authenticated peer already carries. No fingerprint comparison and no linkage token: the
//! relation is structural, so there is nothing to compare.
//!
//! # Why `NotEvaluated` is a refusal HERE and not in the currency authority
//!
//! [`super::credential_currency`] answers *what did the configured controls conclude*, and
//! for a deployment configuring none the truthful answer is `NotEvaluated` — not a verdict.
//! This type's proposition contains the words *still acceptable*, and an unexamined
//! credential has not earned them. So the composition refuses rather than admitting a
//! product whose name would claim a check that never ran.
//!
//! That is a claim about this TYPE, not about what a deployment may serve. The serving path
//! consumes the currency authority directly and keeps admitting an unexamined credential
//! exactly as it does today; what it cannot do is call the result current.
//!
//! # Why the establishment path survives
//!
//! Projected through from the authenticated peer, never flattened. A resumed relationship
//! whose credential is current is *authenticated earlier, carried forward, and acceptable
//! now* — three facts, and a product that reported the first as fresh would be the sentence
//! ADR-MCPRE-055 exists to forbid.

use super::credential_currency::evaluation::evaluate_credential_currency;
use super::credential_currency::CredentialCurrencyOutcome;
use super::credential_currency::CredentialCurrencyPolicy;
use super::credential_currency::CredentialCurrencyRefusal;
use super::credential_currency::CurrencyControls;
use crate::communication_assurance::authenticated_relationship_peer::AuthenticatedRelationshipPeerFacts;
use crate::communication_assurance::certificate_identity_policy::CertificateIdentitySource;
use crate::communication_assurance::mechanism_verified_credential::EstablishmentPath;
use crate::communication_assurance::peer_identity_value::PeerIdentityValue;

/// An authenticated peer whose credential the deployment's controls found acceptable at a
/// named instant.
///
/// Sealed: the representation is private to this module, so the only inhabitants are the
/// ones [`current_authenticated_peer`] produced. A caller cannot pair an authentication it
/// obtained from one relationship with currency it obtained from another, because there is
/// no constructor that would accept the pair. Measured: a sibling authority under
/// `communication_assurance` fails to compile the struct literal with E0451.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentAuthenticatedRelationshipPeerFacts {
    /// Slice 2's product, carried WHOLE rather than destructured (R-COMPOSE).
    peer: AuthenticatedRelationshipPeerFacts,
    /// The instant the currency evaluation was made. Carried because currency is a claim
    /// about a moment: a product that omitted it would be read as a standing property, and
    /// this one is read again on the very next request.
    evaluated_at: i64,
    /// Which optional controls actually ran. `Lifetime` and `Revocation` are different
    /// assurances, and a consumer that needed the second must not be told it got it.
    applied: CurrencyControls,
}

impl CurrentAuthenticatedRelationshipPeerFacts {
    /// The identity the peer authenticated as.
    pub fn identity(&self) -> &PeerIdentityValue {
        self.peer.identity()
    }

    /// The certificate field that identity was read from.
    pub fn identity_source(&self) -> CertificateIdentitySource {
        self.peer.identity_source()
    }

    /// The path on which the authentication was reached.
    pub fn establishment_path(&self) -> EstablishmentPath {
        self.peer.establishment_path()
    }

    /// The instant the credential was found acceptable.
    pub fn evaluated_at(&self) -> i64 {
        self.evaluated_at
    }

    /// Which optional currency controls ran.
    pub fn applied_controls(&self) -> CurrencyControls {
        self.applied
    }
}

/// Why an authenticated peer is not a CURRENT authenticated peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentPeerRefusal {
    /// The deployment configures no currency control, so the credential was never
    /// examined. Not a verdict about the credential — a statement that none was reached.
    CurrencyNotEvaluated,
    /// The credential was examined and refused. Carries the currency authority's reason
    /// unchanged rather than re-deciding it.
    CredentialNotCurrent(CredentialCurrencyRefusal),
}

/// Establish that this authenticated peer's own credential is acceptable now.
///
/// THE construction operation. It takes the authenticated peer BY VALUE, the deployment
/// policy and the instant — never a currency product, never a credential — evaluates the
/// currency of the acceptance that peer already carries, and pairs the two in one closure.
pub fn current_authenticated_peer(
    peer: AuthenticatedRelationshipPeerFacts,
    policy: &CredentialCurrencyPolicy,
    now: i64,
) -> Result<CurrentAuthenticatedRelationshipPeerFacts, CurrentPeerRefusal> {
    let (evaluated_at, applied) =
        match evaluate_credential_currency(Some(peer.accepted_credential()), policy, now) {
            CredentialCurrencyOutcome::NotEvaluated => {
                return Err(CurrentPeerRefusal::CurrencyNotEvaluated)
            }
            CredentialCurrencyOutcome::Refused(refusal) => {
                return Err(CurrentPeerRefusal::CredentialNotCurrent(refusal))
            }
            CredentialCurrencyOutcome::Current(facts) => {
                (facts.evaluated_at(), facts.applied_controls())
            }
        };
    Ok(CurrentAuthenticatedRelationshipPeerFacts {
        peer,
        evaluated_at,
        applied,
    })
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use rustls::HandshakeKind;

    use crate::client_revocation::ClientRevocationIndex;
    use crate::communication_assurance::authenticate_relationship_peer;
    use crate::communication_assurance::certificate_identity_policy::CertificateIdentityPolicy;
    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
    use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;

    /// Wide enough that no real handshake credential trips it, so a refusal below is never
    /// the ceiling's doing. The harness mints rcgen defaults, whose span runs to the year
    /// 4096 — a "generous" hundred-year ceiling refuses every one of them.
    fn generous() -> CredentialCurrencyPolicy {
        CredentialCurrencyPolicy::Ceiling(Duration::from_secs(365 * 24 * 3600 * 100_000))
    }

    /// 2027-01-15 — inside the harness certificates' validity windows.
    const NOW: i64 = 1_800_000_000;

    /// Past the rcgen default `notAfter` (year 4096), so every harness credential has
    /// expired at this instant however small its span.
    const AFTER_YEAR_4096: i64 = 100_000_000_000;

    fn authenticated() -> AuthenticatedRelationshipPeerFacts {
        let peers = mutually_authenticated_peers();
        let accepted =
            verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");
        authenticate_relationship_peer(accepted, CertificateIdentityPolicy::DnsSan)
            .expect("the harness leaf carries a DNS SAN")
    }

    #[test]
    fn an_authenticated_peer_with_a_current_credential_is_a_current_authenticated_peer() {
        let peer = authenticated();
        let identity = peer.identity().clone();
        let current = current_authenticated_peer(peer, &generous(), NOW).expect("current");

        assert_eq!(
            current.identity(),
            &identity,
            "the identity is not re-derived"
        );
        assert_eq!(current.evaluated_at(), NOW);
        assert_eq!(current.applied_controls(), CurrencyControls::Lifetime);
        assert_eq!(
            current.establishment_path(),
            EstablishmentPath::FullHandshake
        );
    }

    #[test]
    fn a_deployment_that_evaluates_nothing_yields_no_current_peer() {
        // The finding, at the composition. An unexamined credential has not earned the
        // words *still acceptable*, so this type refuses rather than admitting a product
        // whose name would claim a check that never ran. What a deployment may SERVE is a
        // different question and is unchanged — the serving path consumes the currency
        // authority directly.
        assert_eq!(
            current_authenticated_peer(
                authenticated(),
                &CredentialCurrencyPolicy::NotEvaluated,
                NOW
            ),
            Err(CurrentPeerRefusal::CurrencyNotEvaluated)
        );
    }

    #[test]
    fn an_expired_credential_refuses_and_carries_the_authoritys_own_reason() {
        // Past every harness certificate's notAfter — rcgen defaults run to the year 4096,
        // so this instant is well beyond it. The refusal must name the validity window
        // rather than being flattened into "not current".
        let refusal = current_authenticated_peer(authenticated(), &generous(), AFTER_YEAR_4096)
            .expect_err("an expired credential is not current");
        assert!(
            matches!(
                refusal,
                CurrentPeerRefusal::CredentialNotCurrent(
                    CredentialCurrencyRefusal::LeafOutsideValidityWindow { .. }
                )
            ),
            "expected a validity-window refusal, got {refusal:?}"
        );
    }

    #[test]
    fn a_ceiling_below_the_credentials_span_refuses_as_a_lifetime_breach() {
        let refusal = current_authenticated_peer(
            authenticated(),
            &CredentialCurrencyPolicy::Ceiling(Duration::from_secs(1)),
            NOW,
        )
        .expect_err("a 1-second ceiling admits nothing a handshake produced");
        assert!(
            matches!(
                refusal,
                CurrentPeerRefusal::CredentialNotCurrent(
                    CredentialCurrencyRefusal::LeafExceedsConfiguredLifetime { .. }
                )
            ),
            "expected a lifetime refusal, got {refusal:?}"
        );
    }

    /// A real relationship whose peer authenticates as `uri_san`.
    fn authenticated_as(uri_san: &str) -> AuthenticatedRelationshipPeerFacts {
        let root = make_ca("currency-root");
        let server_ca = make_ca("currency-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_uri_leaf(&root, uri_san);
        let server = server_config(&[root.der()], vec![server_leaf], server_key);
        let client = client_config(&server_ca.der(), Some((vec![client_leaf], client_key)));
        let accepted = verified_credential(&handshake(&client, &server)).expect("accepts");
        authenticate_relationship_peer(accepted, CertificateIdentityPolicy::UriSan)
            .expect("the leaf carries the configured field")
    }

    #[test]
    fn each_relationships_currency_is_evaluated_against_its_own_credential() {
        // THE L-5 CONTROL, third application. Two live relationships with DIFFERENT peers
        // and one policy: a composition that reached past its own authentication would have
        // to answer with the other peer's identity. There is no parameter through which
        // relationship B's currency could be supplied for peer A, so the substitution is
        // unconstructible — what this measures is that the derivation reads its OWN
        // acceptance, and that pairing does not silently collapse the two into one fact.
        let a = current_authenticated_peer(
            authenticated_as("spiffe://example.org/A"),
            &generous(),
            NOW,
        )
        .expect("A is current");
        let b = current_authenticated_peer(
            authenticated_as("spiffe://example.org/B"),
            &generous(),
            NOW,
        )
        .expect("B is current");

        assert_eq!(a.identity().as_str(), "spiffe://example.org/A");
        assert_eq!(b.identity().as_str(), "spiffe://example.org/B");
        assert_ne!(a, b);
    }

    #[test]
    fn a_resumed_relationship_stays_resumed_after_the_currency_evaluation() {
        // Currency is about the credential; the establishment path is about how the
        // authentication was reached. A composition that flattened the second while
        // establishing the first would report the configured verifier as having run on a
        // resumption where it did not — the one sentence ADR-MCPRE-055 forbids.
        let peers = mutually_authenticated_peers();
        let full = verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");
        let resumed_conn = handshake(&peers.client, &peers.server);
        assert_eq!(
            resumed_conn.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "without a real resumption this control is a second full handshake"
        );
        let resumed = verified_credential(&resumed_conn).expect("accepts");
        let policy = CredentialCurrencyPolicy::Revocation(Arc::new(ClientRevocationIndex::empty()));

        let from_full = current_authenticated_peer(
            authenticate_relationship_peer(full, CertificateIdentityPolicy::DnsSan).expect("auth"),
            &policy,
            NOW,
        )
        .expect("current");
        let from_resumed = current_authenticated_peer(
            authenticate_relationship_peer(resumed, CertificateIdentityPolicy::DnsSan)
                .expect("auth"),
            &policy,
            NOW,
        )
        .expect("current");

        assert_eq!(from_full.identity(), from_resumed.identity());
        assert_eq!(
            from_full.establishment_path(),
            EstablishmentPath::FullHandshake
        );
        assert_eq!(
            from_resumed.establishment_path(),
            EstablishmentPath::ResumedSession,
            "a current credential does not make a resumed authentication a fresh one"
        );
        assert_ne!(from_full, from_resumed);
    }

    #[test]
    fn an_authentication_that_never_happened_cannot_be_made_current() {
        // Not a runtime control — a note on what the types already refuse. There is no
        // constructor taking an identity plus currency, and no way to build
        // `CurrentAuthenticatedRelationshipPeerFacts` without an
        // `AuthenticatedRelationshipPeerFacts` to consume. Measured: a sibling authority
        // attempting the struct literal fails with E0451.
        let peer = authenticated();
        assert!(current_authenticated_peer(peer, &generous(), NOW).is_ok());
    }
}
