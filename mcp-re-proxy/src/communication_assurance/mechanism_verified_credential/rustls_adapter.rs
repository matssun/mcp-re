// SPDX-License-Identifier: Apache-2.0
//! The `rustls` mechanism adapter for verified-credential evidence — the one producer, and
//! a CHILD of the product's module so that it is the only descendant reaching the private
//! constructor.
//!
//! # Why both components are read here, in one operation
//!
//! The credential and the establishment path are two facts about one relationship, and a
//! derivation taking a credential plus a path VALUE would let a caller pair credential A
//! with the path of connection B. That is ADR-MCPRE-063 L-5's failure shape, so both are
//! read from the SAME `&ServerConnection` in the same call, and there is no parameter
//! through which either could be supplied.
//!
//! The credential is not re-derived: this asks the Slice-4 authority for it, so
//! `peer_certificates()` stays confined to that authority's own adapter and THM-0028's
//! producer boundary is untouched. What this module adds is one further mechanism report —
//! `handshake_kind()` — which Slice 4 measured, deliberately did not carry, and named as
//! entering the representation when a consumer appeared.

use rustls::HandshakeKind;
use rustls::ServerConnection;

use super::EstablishmentPath;
use super::MechanismVerificationRefusal;
use super::MechanismVerifiedCredentialEvidence;
use crate::communication_assurance::channel_associated_credential::rustls_adapter::associated_credential;

/// The credential `rustls` accepted for this relationship, and the path it was accepted on.
///
/// `pub(crate)`: the serving paths live outside this module tree and each reaches its own
/// establishment boundary. The widening buys exactly one capability — turning a mechanism's
/// report into the semantic product — and the CONSTRUCTOR it calls stays private to the
/// owner, so widening this entrance does not widen production.
pub(crate) fn verified_credential(
    conn: &ServerConnection,
) -> Result<MechanismVerifiedCredentialEvidence, MechanismVerificationRefusal> {
    let credential = associated_credential(conn)
        .map_err(MechanismVerificationRefusal::NoAssociatedCredential)?;
    let path = match conn.handshake_kind() {
        Some(HandshakeKind::Full) | Some(HandshakeKind::FullWithHelloRetryRequest) => {
            EstablishmentPath::FullHandshake
        }
        Some(HandshakeKind::Resumed) => EstablishmentPath::ResumedSession,
        None => return Err(MechanismVerificationRefusal::EstablishmentPathUnreported),
    };
    Ok(MechanismVerifiedCredentialEvidence::accept(
        credential, path,
    ))
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod acceptance {
    //! Real handshakes on both establishment paths. What a synthetic value would prove
    //! about which path a mechanism took is nothing.

    use super::*;

    use std::sync::Arc;

    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;

    #[test]
    fn a_full_handshake_reports_the_path_its_verifier_ran_on() {
        let peers = mutually_authenticated_peers();
        let conn = handshake(&peers.client, &peers.server);

        let evidence = verified_credential(&conn).expect("an established relationship accepts");
        assert_eq!(
            evidence.establishment_path(),
            EstablishmentPath::FullHandshake,
            "the configured verifier ran in this establishment"
        );
        assert_eq!(
            evidence.credential().credential_chain_der(),
            vec![peers.client_leaf.as_ref()],
            "the acceptance is about the credential THIS relationship presented"
        );
    }

    #[test]
    fn a_resumed_relationship_reports_a_resumed_path_not_a_full_one() {
        // The control the whole product exists for. Slice 4 measured that both paths
        // associate byte-identical credentials; here the two are DIFFERENT propositions,
        // and a product that reported `FullHandshake` for a resumption would tell a
        // consumer the verifier ran when it did not.
        let peers = mutually_authenticated_peers();
        let full = handshake(&peers.client, &peers.server);
        let resumed = handshake(&peers.client, &peers.server);

        let from_full = verified_credential(&full).expect("full accepts");
        let from_resumed = verified_credential(&resumed).expect("resumed accepts");

        assert_eq!(
            from_resumed.establishment_path(),
            EstablishmentPath::ResumedSession,
            "without a real resumption this control is a second full handshake"
        );
        assert_eq!(
            from_full.credential(),
            from_resumed.credential(),
            "the credential is the same on both paths — Slice 4's measurement, unchanged"
        );
        assert_ne!(
            from_full, from_resumed,
            "the same credential accepted on different paths is not the same evidence: \
             the verification fact behind each differs"
        );
    }

    #[test]
    fn a_connection_that_has_not_established_carries_slice_fours_refusal() {
        // Acceptance is not decided here. When the mechanism has not established, this
        // authority declines to speak and reports the association authority's reason
        // rather than inventing one of its own.
        let peers = mutually_authenticated_peers();
        let fresh = rustls::ServerConnection::new(Arc::clone(&peers.server)).expect("conn");
        let refusal = verified_credential(&fresh).expect_err("nothing is accepted yet");
        assert!(
            matches!(
                refusal,
                MechanismVerificationRefusal::NoAssociatedCredential(_)
            ),
            "the reason belongs to the authority that owns it"
        );
    }

    #[test]
    fn a_peer_the_verifier_refused_never_reaches_this_authority() {
        // Characterization, kept as a control: acceptance is a PREDECESSOR. The mandatory
        // client-certificate verifier refuses during establishment, so there is no
        // established relationship whose credential was not accepted. Should client auth
        // ever become optional, this goes red at the state it was measured on — which is
        // the point at which "established but unverified" would become a domain state this
        // product has to model rather than refuse.
        let client_ca = make_ca("phase2-client-ca");
        let server_ca = make_ca("phase2-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let server = server_config(&[client_ca.der()], vec![server_leaf], server_key);
        let client = client_config(&server_ca.der(), None);

        let conn = handshake(&client, &server);
        assert!(verified_credential(&conn).is_err());
    }
}
