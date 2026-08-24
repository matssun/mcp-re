// SPDX-License-Identifier: Apache-2.0
//! The request and the relationship it arrived over are the same principal —
//! ADR-MCPRE-064, Slice 4.
//!
//! # The proposition
//!
//! Possession of [`RequestPeerBindingFacts`] means:
//!
//! > The peer that authenticated this communication relationship, and the actor the request
//! > verifier resolved for this request's signature, are the same principal.
//!
//! # The relation, and the coordinate it is taken over
//!
//! ```text
//! channel:  AuthenticatedChannelPeer::identity()          who the peer authenticated as
//! request:  resolved actor's identity.subject             who the resolved actor is
//! ```
//!
//! **Not `ActorIdentity::actor_id()`.** That is the injective
//! `role:trust_domain:subject:keyid` join, and it is the canonical coordinate for replay
//! keys, audit records and trusted-key identity — not a communication-peer identifier.
//! Binding over it forced the certificate naming scheme to serialize the request verifier's
//! internal trust record, which had two concrete costs: `keyid` in a SAN couples TLS
//! certificate issuance to every signing-key rotation, and `trust_domain` in a SAN asserts
//! a relation the channel side never independently established. The adapter's own controls
//! measure both.
//!
//! Nothing is weakened. The role, the trust domain, the signing key and the signer slot
//! were established by the request verifier and the trust seam BEFORE this relation is
//! evaluated, and they remain facts owned by those authorities. A key that is not trusted
//! for a subject fails at request verification and is never rescued by matching a
//! certificate; equally, a key the resolver DOES trust for that subject is not overturned
//! here because the signing credential rotated.
//!
//! # What this is not
//!
//! Not a cross-namespace mapping. Exact-subject equality is the only relation here; a
//! deployment needing `(trust-domain X, subject Y) <-> SPIFFE Z` gets an explicit mapped
//! binding authority, not a looser reading of this one.
//!
//! Not admission and not authorization. That a request and a channel are the same principal
//! says nothing about what that principal may do.
//!
//! Not RFC 8705 `x5t#S256`. That primitive binds a request artifact to certificate BYTES,
//! and it is a different proposition: a signer can commit to the thumbprint of a
//! certificate whose key it does not hold. Principal equality is this authority's; neither
//! substitutes for the other, and production supplies no mTLS artifact material today.
//!
//! # Why this composition is a binary relation and not an L-5 substitution
//!
//! Slices 2, 3 and 5 of ADR-MCPRE-063 all faced *two honest facts that might be about
//! different objects*, and each resolved it by deriving the successor from the predecessor
//! so no second object could enter. Here the two operands are genuinely independent — one
//! comes from a TLS relationship, the other from a request signature — and their being
//! about the same principal is the CONCLUSION rather than a premise. This is the
//! ADR-MCPRE-063 Slice 2 shape (credential/key correspondence), not the Slice 5 one.
//!
//! What still has to hold is that neither operand can be fabricated by the caller. Both are
//! sealed products: the channel peer descends from a mechanism adapter's acceptance, and
//! the subject has exactly one producer, the request adapter next door.

pub(crate) mod http_profile_adapter;

use crate::communication_assurance::authenticated_channel_peer::AuthenticatedChannelPeer;
use crate::communication_assurance::certificate_identity_policy::CertificateIdentitySource;
use crate::communication_assurance::mechanism_verified_credential::EstablishmentPath;
use crate::communication_assurance::peer_identity_value::PeerIdentityValue;

/// The subject the request verifier resolved for a request's signer.
///
/// Sealed: the representation and the constructor are private to this module, so the only
/// inhabitants are the ones [`http_profile_adapter`] — a CHILD of this module, and
/// therefore the one descendant that reaches the constructor — produced from a
/// `ResolvedActor` the verifier built. A caller cannot assert a subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRequestSubject {
    subject: String,
}

impl VerifiedRequestSubject {
    /// Record the subject the verifier resolved. PRIVATE to this authority: reachable by
    /// this module and its descendants — the request adapter, which is the one PRODUCTION
    /// call site — and this module's own tests.
    fn resolved(subject: String) -> Self {
        VerifiedRequestSubject { subject }
    }

    /// The resolved subject.
    pub fn as_str(&self) -> &str {
        &self.subject
    }
}

/// The request's resolved actor and the relationship's authenticated peer are one principal.
///
/// Sealed: the representation is private to this module, so the only inhabitants are the
/// ones [`bind_request_to_peer`] produced from two operands it compared itself. A caller
/// cannot assert that a request and a channel agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPeerBindingFacts {
    /// The channel-side product, carried WHOLE rather than destructured (R-COMPOSE): the
    /// establishment path and the currency assurance stay reachable through it.
    peer: AuthenticatedChannelPeer,
    /// The request-side product, carried whole for the same reason.
    subject: VerifiedRequestSubject,
}

impl RequestPeerBindingFacts {
    /// The principal both sides denote.
    ///
    /// One value, not two that happen to agree: it is projected from the channel peer, and
    /// the only inhabitants of this type are ones whose two sides compared equal.
    pub fn principal(&self) -> &PeerIdentityValue {
        self.peer.identity()
    }

    /// The certificate field the channel identity was read from.
    pub fn identity_source(&self) -> CertificateIdentitySource {
        self.peer.identity_source()
    }

    /// The path on which the peer's authentication was reached.
    pub fn establishment_path(&self) -> EstablishmentPath {
        self.peer.establishment_path()
    }

    /// Whether the deployment's controls examined the bound credential's currency.
    ///
    /// A binding over an unexamined credential is a true statement about a peer nobody
    /// checked, and it says so rather than being reported as the stronger fact.
    pub fn currency_was_evaluated(&self) -> bool {
        self.peer.currency_was_evaluated()
    }
}

/// Why a request is not bound to the relationship it arrived over.
///
/// One variant, because there is one way to fail: the two sides name different principals.
/// An algebra with more arms would advertise decisions this authority does not take —
/// whether the key was trusted, whether the credential is current, whether the peer may act
/// are all owned elsewhere and are all already settled when this runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestPeerBindingRefusal {
    /// The authenticated peer and the resolved request actor denote different principals.
    DifferentPrincipals {
        /// Who the communication peer authenticated as.
        peer: String,
        /// Who the request verifier resolved for the signature.
        request: String,
    },
}

/// Bind this request's resolved actor to the peer that authenticated its relationship.
///
/// THE construction operation. It takes the two sealed predecessor products — never two
/// strings, and never an identity a caller chose — compares them on the one coordinate that
/// means *the same principal*, and pairs them in one closure.
pub fn bind_request_to_peer(
    peer: AuthenticatedChannelPeer,
    subject: VerifiedRequestSubject,
) -> Result<RequestPeerBindingFacts, RequestPeerBindingRefusal> {
    if peer.identity().as_str() != subject.as_str() {
        return Err(RequestPeerBindingRefusal::DifferentPrincipals {
            peer: peer.identity().as_str().to_owned(),
            request: subject.as_str().to_owned(),
        });
    }
    Ok(RequestPeerBindingFacts { peer, subject })
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    //! ADR-MCPRE-064 Slice 4 (#623) — the binding stage relates the authenticated peer to
    //! the resolved request actor's SUBJECT.
    //!
    //! Every control drives a real mutual-TLS handshake for the channel side. The operand
    //! cannot be fabricated, which is the whole difference from the `TransportIdentity` it
    //! replaces — and the control this slice exists to correct fabricated exactly that
    //! operand, building it out of `actor_id()` so the comparison could not fail.

    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::ResolvedActor;
    use mcp_re_http_profile::SignerSlot;

    use super::http_profile_adapter::verified_request_subject;
    use crate::communication_assurance::authenticate_relationship_peer;
    use crate::communication_assurance::certificate_identity_policy::CertificateIdentityPolicy;
    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
    use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;
    use crate::communication_assurance::AuthenticatedChannelPeer;
    use crate::transport::TransportBinding;

    const PRINCIPAL: &str = "spiffe://example.org/agent-1";

    /// A peer that authenticated over a REAL handshake with `uri_san` as its leaf's URI SAN
    /// — the certificate an operator mints when told the SAN carries the request signer.
    fn peer_authenticated_as(uri_san: &str) -> AuthenticatedChannelPeer {
        let root = make_ca("binding-root");
        let server_ca = make_ca("binding-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_uri_leaf(&root, uri_san);
        let server = server_config(&[root.der()], vec![server_leaf], server_key);
        let client = client_config(&server_ca.der(), Some((vec![client_leaf], client_key)));
        let accepted = verified_credential(&handshake(&client, &server)).expect("accepts");
        AuthenticatedChannelPeer::CurrencyNotEvaluated(
            authenticate_relationship_peer(accepted, CertificateIdentityPolicy::UriSan)
                .expect("the leaf carries the configured field"),
        )
    }

    /// What the request verifier resolves for a signature, through the ONE producer.
    fn resolved(role: &str, trust_domain: &str, subject: &str, keyid: &str) -> ResolvedActor {
        ResolvedActor {
            identity: ActorIdentity {
                role: role.to_string(),
                trust_domain: trust_domain.to_string(),
                subject: subject.to_string(),
                keyid: keyid.to_string(),
            },
            verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[5u8; 32]).public_key(),
            slot: SignerSlot::Request,
        }
    }

    #[test]
    fn a_certificate_naming_the_resolved_subject_binds() {
        // THE POSITIVE. A certificate whose URI SAN is the resolved SUBJECT binds — which
        // is what the operator documentation has always described, and what the previous
        // implementation could not accept because it compared against the composite.
        let bound = TransportBinding::exact_match()
            .bind(
                Some(&peer_authenticated_as(PRINCIPAL)),
                verified_request_subject(&resolved("client", "example.org", PRINCIPAL, "key-a")),
            )
            .expect("the peer and the resolved actor are one principal");
        assert_eq!(bound.principal().as_str(), PRINCIPAL);
        assert!(
            !bound.currency_was_evaluated(),
            "this deployment configures no currency control, and the binding says so \
             rather than reporting the stronger fact"
        );
    }

    #[test]
    fn a_certificate_naming_a_different_subject_is_refused() {
        assert!(TransportBinding::exact_match()
            .bind(
                Some(&peer_authenticated_as(PRINCIPAL)),
                verified_request_subject(&resolved(
                    "client",
                    "example.org",
                    "spiffe://example.org/agent-2",
                    "key-a",
                )),
            )
            .is_err());
    }

    #[test]
    fn a_rotated_signing_key_does_not_break_the_binding() {
        // THE CONTROL THAT PINS THE RULING. The trust seam decides whether a key
        // legitimately represents a subject; by the time this stage runs it already has.
        // Transport binding must not overturn that because the signing credential rotated —
        // and it would, under `actor_id()`, since `keyid` is one of its four components.
        // A key NOT trusted for the subject fails at request verification and is never
        // rescued here.
        let peer = peer_authenticated_as(PRINCIPAL);
        for keyid in ["key-a", "key-b-rotated", "key-c-rotated-again"] {
            assert!(
                TransportBinding::exact_match()
                    .bind(
                        Some(&peer),
                        verified_request_subject(&resolved(
                            "client",
                            "example.org",
                            PRINCIPAL,
                            keyid,
                        )),
                    )
                    .is_ok(),
                "{keyid}: rotating a signing credential is not a change of principal"
            );
        }
    }

    #[test]
    fn a_different_trust_domain_does_not_break_the_binding_and_a_different_subject_does() {
        // The other half of the ruling. `trust_domain` is request-side resolution CONTEXT,
        // and the channel has established no corresponding fact — string-encoding it into a
        // SAN would assert a relation nothing proved. So it does not enter the relation,
        // while the subject remains decisive under an otherwise identical configuration.
        let peer = peer_authenticated_as(PRINCIPAL);
        assert!(TransportBinding::exact_match()
            .bind(
                Some(&peer),
                verified_request_subject(&resolved("client", "other.example", PRINCIPAL, "key-a")),
            )
            .is_ok());
        assert!(TransportBinding::exact_match()
            .bind(
                Some(&peer),
                verified_request_subject(&resolved(
                    "client",
                    "other.example",
                    "spiffe://example.org/agent-2",
                    "key-a",
                )),
            )
            .is_err());
    }

    #[test]
    fn a_certificate_naming_the_composite_actor_id_no_longer_binds() {
        // The defect, inverted into a control. A fleet whose certificates carry the
        // escaped `role:trust_domain:subject:keyid` composite — which is what
        // `DemoFixtures` minted so the old comparison could succeed — must now be REFUSED,
        // because the composite is not who the peer is.
        let composite = format!(
            "client:example.org:{}:key-a",
            PRINCIPAL.replace('%', "%25").replace(':', "%3A")
        );
        assert!(TransportBinding::exact_match()
            .bind(
                Some(&peer_authenticated_as(&composite)),
                verified_request_subject(&resolved("client", "example.org", PRINCIPAL, "key-a")),
            )
            .is_err());
    }

    #[test]
    fn a_request_presenting_no_authenticated_peer_is_refused() {
        // The `identity.map(check).unwrap_or(true)` defect: a configured binding claims
        // every served request is bound, and an absence does not satisfy that claim.
        assert!(TransportBinding::exact_match()
            .bind(
                None,
                verified_request_subject(&resolved("client", "example.org", PRINCIPAL, "key-a")),
            )
            .is_err());
    }
}
