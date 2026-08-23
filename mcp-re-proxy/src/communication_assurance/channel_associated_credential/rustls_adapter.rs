// SPDX-License-Identifier: Apache-2.0
//! The `rustls` mechanism adapter for channel-associated credential evidence — the ONLY
//! module in the authority that knows a TLS connection exists, and the only module in the
//! crate that can construct the product.
//!
//! It is a CHILD of the product's module rather than a sibling of it: the constructor is
//! private to the owner, so descendants reach it and nothing else does. See the parent's
//! note on where the producer boundary is drawn.
//!
//! # Where the boundary is
//!
//! Each serving path crosses its own successful-establishment boundary before anything
//! here is called:
//!
//! ```text
//! ASYNC     TlsAcceptor::accept(tcp).await  -- success
//! BLOCKING  the request read that drives the rustls handshake -- success
//!                       |
//!                       v
//!            associated_credential(..)
//!                       |
//!    ChannelAssociatedCertificateCredentialEvidence
//! ```
//!
//! # Why this takes a connection and still claims nothing about establishment
//!
//! A `ServerConnection` is constructed BEFORE its handshake — the blocking path builds one
//! and then drives the handshake by reading the request — so the type proves nothing, and
//! a contract of the form *give me a connection whose relationship is established* would
//! be a claim the caller has to remember to honour. This function makes no such contract:
//! it asks the mechanism, through `is_handshaking`, and refuses when the mechanism says
//! establishment has not completed. Deciding whether establishment occurred stays with the
//! mechanism; this authority only declines to speak before it has.

use rustls::ServerConnection;

use super::ChannelAssociatedCertificateCredentialEvidence;
use super::ChannelCredentialAssociationRefusal;

/// The credential `rustls` associated with this relationship, or the boundary
/// inconsistency that stopped the association.
///
/// `pub(crate)`: the two serving paths live outside this module tree and each must reach
/// its own establishment boundary. The widening buys exactly one capability — turning a
/// mechanism's report into the semantic product — and it is the reason
/// `peer_certificates()` need appear nowhere else in the crate. The CONSTRUCTOR it calls
/// stays private to the owner, so widening this entrance does not widen production.
pub(crate) fn associated_credential(
    conn: &ServerConnection,
) -> Result<ChannelAssociatedCertificateCredentialEvidence, ChannelCredentialAssociationRefusal> {
    if conn.is_handshaking() {
        return Err(ChannelCredentialAssociationRefusal::EstablishmentIncomplete);
    }
    let chain = conn
        .peer_certificates()
        .map(|chain| chain.iter().map(|cert| cert.as_ref().to_vec()).collect())
        .unwrap_or_default();
    ChannelAssociatedCertificateCredentialEvidence::associate(chain)
}

// Everything below is test code. The `

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod establishment {
    //! What the MECHANISM associates, on each path a production relationship can take.
    //! The handshake harness is the authority's, one level up: the identity derivation
    //! establishes its own proposition over the same relationships.

    use super::*;

    use std::sync::Arc;

    use rustls::HandshakeKind;

    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;

    #[test]
    fn an_established_relationship_associates_the_credential_the_peer_presented() {
        let peers = mutually_authenticated_peers();
        let conn = handshake(&peers.client, &peers.server);
        assert_eq!(conn.handshake_kind(), Some(HandshakeKind::Full));

        let evidence =
            associated_credential(&conn).expect("an established relationship associates");
        assert_eq!(
            evidence.credential_chain_der(),
            vec![peers.client_leaf.as_ref()],
            "the evidence must carry the credential THIS relationship was established with"
        );
    }

    #[test]
    fn a_resumed_relationship_associates_the_same_credential_as_the_full_handshake() {
        // The claim under test is that both establishment paths establish the SAME
        // proposition. If they did not, L-2 would require the seam to carry which one — so
        // this control is what decides whether the product needs a provenance field, and
        // it says it does not.
        let peers = mutually_authenticated_peers();
        let full = handshake(&peers.client, &peers.server);
        let resumed = handshake(&peers.client, &peers.server);
        assert_eq!(full.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(
            resumed.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "without a real resumption this control is a second full handshake"
        );

        let from_full = associated_credential(&full).expect("full handshake associates");
        let from_resumed =
            associated_credential(&resumed).expect("resumed relationship associates");
        assert_eq!(
            from_full, from_resumed,
            "a resumed relationship restores its stored chain verbatim; association is the \
             same proposition on both paths, and the product must not read as a claim that \
             the credential was verified in THIS handshake"
        );
    }

    #[test]
    fn a_connection_that_has_not_established_associates_nothing() {
        // The structural half of this — that no production caller can be here — is the
        // placement of the two call sites after their own boundaries. What this pins is
        // that the authority declines to speak rather than reading a chain out of a
        // connection whose mechanism has not finished.
        let peers = mutually_authenticated_peers();
        let fresh = ServerConnection::new(Arc::clone(&peers.server)).expect("server conn");
        assert!(
            fresh.is_handshaking(),
            "a fresh connection has not established"
        );
        assert_eq!(
            associated_credential(&fresh),
            Err(ChannelCredentialAssociationRefusal::EstablishmentIncomplete)
        );
    }

    #[test]
    fn a_peer_with_no_credential_never_reaches_an_established_relationship() {
        // Characterization, kept as a control: this is WHY `NoCredentialAssociated` is a
        // mechanism-boundary inconsistency rather than a domain state. The mandatory
        // client-cert verifier refuses during establishment, so there is no established
        // relationship for the missing credential to be missing from. Should a change make
        // client auth optional, this control goes red at the state it was measured on —
        // which is the point at which the refusal would have to become a domain state.
        let client_ca = make_ca("slice4-client-ca");
        let server_ca = make_ca("slice4-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let server = server_config(&[client_ca.der()], vec![server_leaf], server_key);
        let client = client_config(&server_ca.der(), None);

        let conn = handshake(&client, &server);
        assert!(
            conn.peer_certificates().is_none(),
            "the mechanism reports no credential"
        );
        assert_eq!(
            associated_credential(&conn),
            Err(ChannelCredentialAssociationRefusal::EstablishmentIncomplete),
            "the relationship was refused DURING establishment: there is no established \
             relationship here, which is a different fact from an established one carrying \
             no credential"
        );
    }
}
