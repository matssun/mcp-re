// SPDX-License-Identifier: Apache-2.0
//! The peer of an established relationship, authenticated — ADR-MCPRE-064, Slice 2.
//!
//! # The proposition
//!
//! Possession of [`AuthenticatedRelationshipPeerFacts`] means:
//!
//! > The establishment mechanism accepted a credential for this relationship, on this
//! > establishment path, and the configured certificate-identity rule reads this identity
//! > from the leaf of **that same** credential. The party at the far end of this
//! > relationship is bound to that credential by the proof the path required — current
//! > control of its private key on a full handshake, continuity from an earlier
//! > authenticated handshake on a resumed one.
//!
//! # Why this one may say `authenticated`, and the two earlier ones may not
//!
//! ADR-MCPRE-064 §5 rule 1 is that a name is a claim, and Slice 5 of ADR-MCPRE-063 and
//! Slice 1 of this ADR each refused the word for a specific missing half:
//!
//! ```text
//! ChannelAssociatedCertificatePeerIdentityEvidence   which identity a relationship's
//!                                                    credential denotes — but nothing said
//!                                                    the mechanism accepted that credential
//! MechanismVerifiedCredentialEvidence                the mechanism accepted this credential
//!                                                    — but nothing said which identity it is
//! ```
//!
//! Authentication is exactly the conjunction of those two over ONE credential, plus the
//! premise that acceptance entailed a proof binding the peer to it (ASM-0036 — a fresh
//! private-key proof on a full handshake, carried-forward continuity on a resumed one). Neither predecessor is
//! strengthened here and no third fact is invented: what this authority adds is that the
//! identity and the acceptance are about the same credential, which is the only thing the
//! word was ever waiting for.
//!
//! # What the word still does not extend to
//!
//! **Not current.** Acceptance happened during establishment. Whether the credential is
//! still inside its validity window, still unrevoked, and inside the configured lifetime
//! ceiling is a different authority answering *is it still good now* — recovered per
//! request, and only where a ceiling or CRLs are configured.
//!
//! **Not freshly verified, on the resumed path.** The establishment path is carried, never
//! flattened. `FullHandshake` means the configured verifier ran in this establishment;
//! `ResumedSession` means it did not, and the authentication is inherited from an earlier
//! full handshake admitted now only because the ADR-MCPRE-055 anchor epoch is unchanged.
//! A consumer that needs the first must branch, and the type refuses to choose for it.
//!
//! **Not admitted, not authorized, not bound.** Whether an authenticated peer may open a
//! session, what it may do, and whether it is the actor that signed a particular request
//! are three further authorities that do not exist yet.
//!
//! # The composition rule, applied a second time
//!
//! The rejected composition is the ADR-MCPRE-063 L-5 shape, one level up:
//!
//! ```text
//! MechanismVerifiedCredentialEvidence(A)                                   # REJECTED
//!         + ChannelAssociatedCertificatePeerIdentityEvidence(from B)
//!         -> authenticated peer
//! ```
//!
//! Both operands are honest products of authorities that really established them, and both
//! ultimately arose from *a* connection — which establishes nothing, because it does not
//! establish the SAME connection. A caller holding two relationships can pair the
//! acceptance of one with the identity of the other and get a true-looking sentence about a
//! peer that never authenticated as that identity.
//!
//! So the derivation takes the acceptance and a deployment policy — never an identity
//! product, never a certificate — and reaches the identity itself, through the Slice-5
//! operation, from the credential the acceptance is about. There is no parameter through
//! which a foreign identity could enter, which is what makes the substitution
//! unconstructible rather than merely refused at runtime. A fingerprint comparison would
//! have been the weaker answer: it still lets the caller do the pairing and merely rejects
//! some of them.
//!
//! # Why this authority is a SIBLING of both predecessors
//!
//! Placed inside `mechanism_verified_credential` it would be a descendant of that module
//! and would reach the private `accept` constructor that THM-0030 claims only the mechanism
//! adapter reaches; placed inside `channel_associated_credential` it would reach `associate`
//! and falsify THM-0028 the same way. Consumer placement is part of a producer's seal — the
//! rule Slice 5 established and measured — so this module is a sibling of both and consumes
//! only their public products and named operations.
//!
//! # Why the refusal algebra is the interpreter's, unchanged
//!
//! Nothing new can fail here. The acceptance is already in hand and cannot be re-refused,
//! and the only fallible step is reading the configured field from the accepted credential's
//! leaf — whose algebra Slice 1 owns and Slice 5 already narrowed to the leaf-level one. A
//! wrapper enum would advertise a decision this authority does not take.

use crate::communication_assurance::certificate_identity_policy::CertificateIdentityPolicy;
use crate::communication_assurance::certificate_identity_policy::CertificateIdentitySource;
use crate::communication_assurance::certificate_identity_refusal::LeafIdentityRefusal;
use crate::communication_assurance::channel_associated_identity::interpret_associated_identity;
use crate::communication_assurance::channel_associated_identity::ChannelAssociatedCertificatePeerIdentityEvidence;
use crate::communication_assurance::mechanism_verified_credential::EstablishmentPath;
use crate::communication_assurance::mechanism_verified_credential::MechanismVerifiedCredentialEvidence;
use crate::communication_assurance::peer_identity_value::PeerIdentityValue;

/// An authenticated peer of one established relationship: the mechanism's acceptance, and
/// the identity read from the leaf of the very credential it accepted.
///
/// Sealed: the representation is private to this module, so the only inhabitants are the
/// ones [`authenticate_relationship_peer`] produced. A caller cannot pair an acceptance it
/// obtained from one relationship with an identity it obtained from another, because there
/// is no constructor that would accept the pair. Measured: a sibling authority under
/// `communication_assurance` fails to compile the struct literal with E0451.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRelationshipPeerFacts {
    /// Slice 1's product, carried WHOLE rather than destructured. Keeping the predecessor
    /// intact is R-COMPOSE: copying its establishment path out and discarding the rest
    /// would make this type a second place where an acceptance is represented.
    accepted: MechanismVerifiedCredentialEvidence,
    /// Slice 5's product, derived inside this module from `accepted`'s own credential. It
    /// is not accepted from outside, which is the whole difference between this type and
    /// the pair of facts it is made of.
    identity: ChannelAssociatedCertificatePeerIdentityEvidence,
}

impl AuthenticatedRelationshipPeerFacts {
    /// The identity the peer authenticated as.
    pub fn identity(&self) -> &PeerIdentityValue {
        self.identity.value()
    }

    /// The certificate field that identity was read from.
    pub fn identity_source(&self) -> CertificateIdentitySource {
        self.identity.source()
    }

    /// The path on which the authentication was reached.
    ///
    /// Projected from the predecessor rather than stored again. A consumer that needs *the
    /// configured verifier ran in this establishment* must branch on this; one that needs
    /// only *authenticated at some point under an unchanged anchor set* need not.
    pub fn establishment_path(&self) -> EstablishmentPath {
        self.accepted.establishment_path()
    }
}

/// Authenticate the peer of the relationship `accepted` describes, under `policy`.
///
/// THE construction operation. It takes the acceptance BY VALUE and a deployment policy —
/// never a certificate, never an identity product — reads the identity from the accepted
/// credential's own leaf through the Slice-5 operation, and pairs the two in one closure.
/// Every refusal is the leaf interpreter's, reported for the credential this relationship
/// actually authenticated with.
///
/// It is `pub`: this is the entrance, and reaching it requires already holding an
/// acceptance, which only the mechanism adapter can produce. The struct it builds has a
/// private representation, so a caller that can invoke the derivation still cannot produce
/// the fact any other way.
pub fn authenticate_relationship_peer(
    accepted: MechanismVerifiedCredentialEvidence,
    policy: CertificateIdentityPolicy,
) -> Result<AuthenticatedRelationshipPeerFacts, LeafIdentityRefusal> {
    let identity = interpret_associated_identity(accepted.credential(), policy)?;
    Ok(AuthenticatedRelationshipPeerFacts { accepted, identity })
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;

    use rustls::HandshakeKind;
    use rustls::ServerConnection;

    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
    use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;

    const IDENTITY_A: &str = "spiffe://example.org/A";
    const IDENTITY_B: &str = "spiffe://example.org/B";

    /// A real relationship whose client chain is `[leaf(uri_san), intermediate(decoy)]`.
    ///
    /// The decoy carries a DIFFERENT identity in the same field, so a derivation that
    /// reached any certificate other than the accepted credential's leaf returns the wrong
    /// identity rather than merely a different-looking success.
    fn accepted_relationship_with(
        uri_san: &str,
        decoy: &str,
    ) -> MechanismVerifiedCredentialEvidence {
        let root = make_ca("slice6-root");
        let intermediate = make_intermediate(&root, "slice6-intermediate", decoy);
        let server_ca = make_ca("slice6-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_uri_leaf(&intermediate, uri_san);

        // The server trusts the ROOT only, so the client must present the intermediate as
        // well: the decoy is in the chain the mechanism accepted, not merely minted.
        let server = server_config(&[root.der()], vec![server_leaf], server_key);
        let client = client_config(
            &server_ca.der(),
            Some((vec![client_leaf, intermediate.der()], client_key)),
        );
        let conn: ServerConnection = handshake(&client, &server);
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Full),
            "the control needs an accepted relationship"
        );
        verified_credential(&conn).expect("an established relationship accepts")
    }

    #[test]
    fn the_authenticated_identity_comes_from_the_credential_the_mechanism_accepted() {
        let accepted = accepted_relationship_with(IDENTITY_A, IDENTITY_B);
        let peer = authenticate_relationship_peer(accepted, CertificateIdentityPolicy::UriSan)
            .expect("the accepted credential's leaf carries the configured field");

        assert_eq!(peer.identity().as_str(), IDENTITY_A);
        assert_eq!(peer.identity_source(), CertificateIdentitySource::UriSan);
        assert_eq!(peer.establishment_path(), EstablishmentPath::FullHandshake);
    }

    #[test]
    fn an_issuer_in_the_accepted_chain_is_never_the_authenticated_peer() {
        // Two certificates in the accepted chain answer a URI-SAN policy. Only the leaf is
        // the peer; reading "some certificate the mechanism accepted" would authenticate an
        // issuer, and a deployment would bind requests to the CA rather than the workload.
        let accepted = accepted_relationship_with(IDENTITY_A, IDENTITY_B);
        let peer = authenticate_relationship_peer(accepted, CertificateIdentityPolicy::UriSan)
            .expect("interpretation succeeds");
        assert_ne!(peer.identity().as_str(), IDENTITY_B);
    }

    #[test]
    fn each_relationship_authenticates_its_own_peer() {
        // Two relationships, each accepted with a different credential, under one policy. A
        // derivation that reached anything other than ITS OWN acceptance would have to
        // return the same identity twice. This is the L-5 control: the failure it excludes
        // is one relationship's acceptance wearing the other's identity.
        let first = accepted_relationship_with(IDENTITY_A, IDENTITY_B);
        let second = accepted_relationship_with(IDENTITY_B, IDENTITY_A);

        let from_first = authenticate_relationship_peer(first, CertificateIdentityPolicy::UriSan)
            .expect("first authenticates");
        let from_second = authenticate_relationship_peer(second, CertificateIdentityPolicy::UriSan)
            .expect("second authenticates");

        assert_eq!(from_first.identity().as_str(), IDENTITY_A);
        assert_eq!(from_second.identity().as_str(), IDENTITY_B);
        assert_ne!(from_first, from_second);
    }

    #[test]
    fn a_resumed_authentication_is_not_reported_as_a_freshly_verified_one() {
        // The same peer, authenticated twice: once with the verifier running, once with it
        // not. The identity is the same fact and the establishment path is not, and a
        // product that flattened them would tell a consumer the configured verifier ran on
        // a resumption where it did not.
        let peers = mutually_authenticated_peers();
        let full = verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");
        let resumed_conn = handshake(&peers.client, &peers.server);
        assert_eq!(
            resumed_conn.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "without a real resumption this control is a second full handshake"
        );
        let resumed = verified_credential(&resumed_conn).expect("accepts");

        let from_full = authenticate_relationship_peer(full, CertificateIdentityPolicy::DnsSan)
            .expect("the full handshake's peer authenticates");
        let from_resumed =
            authenticate_relationship_peer(resumed, CertificateIdentityPolicy::DnsSan)
                .expect("the resumed relationship's peer authenticates");

        assert_eq!(
            from_full.identity(),
            from_resumed.identity(),
            "resumption restores the same credential, so it is the same peer"
        );
        assert_eq!(
            from_full.establishment_path(),
            EstablishmentPath::FullHandshake
        );
        assert_eq!(
            from_resumed.establishment_path(),
            EstablishmentPath::ResumedSession
        );
        assert_ne!(
            from_full, from_resumed,
            "the same peer authenticated on different paths is not the same fact"
        );
    }

    #[test]
    fn a_leaf_without_the_configured_field_refuses_rather_than_falling_back() {
        // The accepted credential's leaf carries a DNS SAN; the deployment configured URI
        // SANs. The no-fallback law is Slice 1's and is reused unchanged — what this pins
        // is that an acceptance in hand is not a reason to authenticate a peer whose
        // credential does not carry the configured identity.
        let peers = mutually_authenticated_peers();
        let accepted =
            verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");

        assert_eq!(
            authenticate_relationship_peer(accepted, CertificateIdentityPolicy::UriSan),
            Err(LeafIdentityRefusal::SelectedFieldAbsent {
                selected: CertificateIdentityPolicy::UriSan
            }),
            "acceptance authenticates nobody when the configured identity field is absent"
        );
    }
}
