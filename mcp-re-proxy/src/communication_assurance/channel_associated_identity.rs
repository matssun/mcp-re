// SPDX-License-Identifier: Apache-2.0
//! The identity interpreted from the credential an established relationship carries —
//! ADR-MCPRE-063, Slice 5.
//!
//! # The proposition
//!
//! Possession of [`ChannelAssociatedCertificatePeerIdentityEvidence`] means:
//!
//! > For the certificate credential that the communication-establishment mechanism
//! > associated with this relationship, the configured certificate-identity rule yields
//! > this identity value, read from this field of that credential's leaf.
//!
//! That is strictly more than either predecessor. Slice 1 says *some* certificate evidence
//! denoted this identity; Slice 4 says this credential came from this relationship's
//! mechanism report. Neither says the identity came from the relationship's own credential,
//! and it is the linkage — not either fact — that a consumer binding a peer to a
//! relationship needs.
//!
//! # What it still does not mean
//!
//! It is NOT authentication. Slice 4 deliberately refuses to establish that the associated
//! credential is trusted, current, unrevoked, or issued by the configured authority, and
//! Slice 1 deliberately establishes only which identity a certificate representation
//! carries. Two deliberately weaker facts do not compose into a stronger one: nothing here
//! establishes that the peer is authenticated, admitted, authorized, or bound to the actor
//! that signed any request, and the type is not called `AuthenticatedPeerIdentity` because
//! the premise that word needs does not exist yet.
//!
//! # Why the caller supplies only a policy
//!
//! The rejected composition is
//!
//! ```text
//! ChannelAssociatedCertificateCredentialEvidence(A) + CertificatePeerIdentityEvidence(B)
//!         -> some combined fact                                            # REJECTED
//! ```
//!
//! Both operands are honest products of authorities that really established them, and the
//! composition is still wrong: identity evidence interpreted from certificate **B** can be
//! paired with relationship credential **A**, and it is the caller that does the pairing.
//! So the derivation takes the credential and a policy, reaches its OWN leaf, and reuses
//! the Slice-1 interpreter inside one construction closure. There is no parameter through
//! which another certificate or another identity product could enter, which is what makes
//! credential substitution unconstructible rather than merely tested against.
//!
//! # Why this authority is a SIBLING of the credential, not a child
//!
//! Rust privacy is the defining module and its descendants, so a module placed inside the
//! credential's tree would reach the credential's PRIVATE CONSTRUCTOR — and THM-0028 claims
//! the mechanism adapter is the only thing in the crate that can. Measured: as a second
//! child, this module compiled a call to `associate` with an arbitrary chain. That is the
//! same defect the Slice-4 review caught in the opposite direction, and the rule it teaches
//! is symmetric: **a consumer's placement is part of the producer's seal.** What this
//! authority needs from the credential is a named projection, and a projection is
//! `pub(super)` on the owner's side; it never needs to be a descendant.
//!
//! # Why the refusal algebra has no absence state
//!
//! [`LeafIdentityRefusal`] is the algebra of a leaf that exists. Slice 1 needs a *no leaf
//! was presented* refusal because arbitrary certificate evidence may carry none; this
//! authority's predecessor has already excluded that state — an associated credential's
//! chain is non-empty by construction — so advertising it here would describe a state the
//! input cannot be in. The predecessor invariant buys exactly one thing, and this is it.

use super::channel_associated_credential::ChannelAssociatedCertificateCredentialEvidence;
use crate::communication_assurance::certificate_chain_evidence::interpret_presented_leaf_identity;
use crate::communication_assurance::certificate_identity_policy::CertificateIdentityPolicy;
use crate::communication_assurance::certificate_identity_policy::CertificateIdentitySource;
use crate::communication_assurance::certificate_identity_refusal::LeafIdentityRefusal;
use crate::communication_assurance::certificate_peer_identity_evidence::CertificatePeerIdentityEvidence;
use crate::communication_assurance::peer_identity_value::PeerIdentityValue;

/// A peer identity interpreted from the leaf of the credential an established relationship
/// carries.
///
/// Sealed: the representation is private to this module, so the only inhabitants are the
/// ones [`interpret_associated_identity`] produced from a channel-associated credential. A
/// caller cannot pair an identity it obtained elsewhere with a relationship it obtained
/// elsewhere, because there is no constructor that would accept the pair. Measured: a
/// sibling authority under `communication_assurance` fails to compile with E0451.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAssociatedCertificatePeerIdentityEvidence {
    /// The Slice-1 product, derived inside this module from the relationship's own
    /// credential. It is not accepted from outside, which is the whole difference between
    /// this type and the pair of facts it is made of.
    identity: CertificatePeerIdentityEvidence,
}

impl ChannelAssociatedCertificatePeerIdentityEvidence {
    /// The identity value the relationship's credential denoted.
    pub fn value(&self) -> &PeerIdentityValue {
        self.identity.value()
    }

    /// The certificate field that value was read from.
    pub fn source(&self) -> CertificateIdentitySource {
        self.identity.source()
    }
}

/// Interpret the identity of the credential this relationship carries, under `policy`.
///
/// THE construction closure. It takes the predecessor product and a deployment policy —
/// never a certificate, never an identity — reads that credential's own leaf, and reuses
/// the Slice-1 interpreter unchanged. Every refusal is the interpreter's, reported for the
/// leaf this relationship actually presented.
///
/// It is `pub`: this is the entrance, and reaching it requires already holding the
/// predecessor product. The CONSTRUCTOR it calls is private to this module, so a caller
/// that can invoke the derivation still cannot produce the fact any other way.
pub fn interpret_associated_identity(
    credential: &ChannelAssociatedCertificateCredentialEvidence,
    policy: CertificateIdentityPolicy,
) -> Result<ChannelAssociatedCertificatePeerIdentityEvidence, LeafIdentityRefusal> {
    let identity = interpret_presented_leaf_identity(credential.associated_leaf_der(), policy)?;
    Ok(ChannelAssociatedCertificatePeerIdentityEvidence { identity })
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustls::HandshakeKind;

    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
    use crate::communication_assurance::channel_associated_credential::rustls_adapter::associated_credential;

    const IDENTITY_A: &str = "spiffe://example.org/A";
    const IDENTITY_B: &str = "spiffe://example.org/B";

    /// A relationship established with a client credential whose chain is
    /// `[leaf(uri_san), intermediate(decoy)]` — the decoy carries a DIFFERENT identity in
    /// the same field, so a derivation that reads any certificate other than the leaf
    /// returns the wrong identity rather than merely a different-looking success.
    fn relationship_with(
        uri_san: &str,
        decoy: &str,
    ) -> ChannelAssociatedCertificateCredentialEvidence {
        let root = make_ca("slice5-root");
        let intermediate = make_intermediate(&root, "slice5-intermediate", decoy);
        let server_ca = make_ca("slice5-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_uri_leaf(&intermediate, uri_san);

        // The server trusts the ROOT only, so the client must present the intermediate as
        // well: the decoy is in the chain the mechanism reports, not merely minted.
        let server = server_config(&[root.der()], vec![server_leaf], server_key);
        let client = client_config(
            &server_ca.der(),
            Some((vec![client_leaf, intermediate.der()], client_key)),
        );
        let conn = handshake(&client, &server);
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Full),
            "the control needs an established relationship"
        );
        associated_credential(&conn).expect("an established relationship associates")
    }

    #[test]
    fn the_identity_is_read_from_the_leaf_of_the_relationships_own_credential() {
        let credential = relationship_with(IDENTITY_A, IDENTITY_B);
        assert_eq!(
            credential.credential_chain_der().len(),
            2,
            "without the intermediate in the reported chain the decoy proves nothing"
        );

        let evidence =
            interpret_associated_identity(&credential, CertificateIdentityPolicy::UriSan)
                .expect("the leaf carries the configured field");
        assert_eq!(evidence.value().as_str(), IDENTITY_A);
        assert_eq!(evidence.source(), CertificateIdentitySource::UriSan);
    }

    #[test]
    fn an_intermediate_carrying_a_rival_identity_is_never_the_answer() {
        // The chain holds two certificates that both answer a URI-SAN policy. Only the
        // leaf is the peer; reading "some certificate in the associated chain" would let
        // an intermediate — an issuer, not the peer — choose the identity the proxy binds.
        let credential = relationship_with(IDENTITY_A, IDENTITY_B);
        let evidence =
            interpret_associated_identity(&credential, CertificateIdentityPolicy::UriSan)
                .expect("interpretation succeeds");
        assert_ne!(
            evidence.value().as_str(),
            IDENTITY_B,
            "the identity must belong to the peer's leaf, not to a certificate that signed it"
        );
    }

    #[test]
    fn each_relationship_yields_its_own_identity() {
        // Two relationships, established with different credentials, interpreted under one
        // policy. A derivation that reached anything other than ITS OWN credential would
        // have to return the same value twice.
        let first = relationship_with(IDENTITY_A, IDENTITY_B);
        let second = relationship_with(IDENTITY_B, IDENTITY_A);

        let from_first = interpret_associated_identity(&first, CertificateIdentityPolicy::UriSan)
            .expect("first interprets");
        let from_second = interpret_associated_identity(&second, CertificateIdentityPolicy::UriSan)
            .expect("second interprets");
        assert_eq!(from_first.value().as_str(), IDENTITY_A);
        assert_eq!(from_second.value().as_str(), IDENTITY_B);
        assert_ne!(from_first, from_second);
    }

    #[test]
    fn a_leaf_without_the_configured_field_refuses_rather_than_falling_back() {
        // The credential's leaf carries a DNS SAN; the deployment configured URI SANs. The
        // no-fallback law is Slice 1's and is reused unchanged — what this control pins is
        // that the composition reports it for the relationship's own leaf.
        let root = make_ca("slice5-root");
        let server_ca = make_ca("slice5-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_leaf(&root, "peer.example.org", true);
        let server = server_config(&[root.der()], vec![server_leaf], server_key);
        let client = client_config(&server_ca.der(), Some((vec![client_leaf], client_key)));
        let credential = associated_credential(&handshake(&client, &server)).expect("associates");

        assert_eq!(
            interpret_associated_identity(&credential, CertificateIdentityPolicy::UriSan),
            Err(LeafIdentityRefusal::SelectedFieldAbsent {
                selected: CertificateIdentityPolicy::UriSan
            }),
            "a present DNS SAN is not a reason to accept it under a URI-SAN policy"
        );
    }

    #[test]
    fn the_derivation_reads_the_first_certificate_of_the_associated_chain() {
        // Leaf-first is the mechanism's order, measured in the adapter's controls. This
        // pins the half that belongs to THIS authority: which position of the associated
        // chain the identity is read from.
        let credential = relationship_with(IDENTITY_A, IDENTITY_B);
        let chain = credential.credential_chain_der();
        assert_eq!(
            Some(credential.associated_leaf_der()),
            chain.first().copied(),
            "the leaf projection must be the chain's first certificate, not any other"
        );
    }
}
