// SPDX-License-Identifier: Apache-2.0
//! Communication assurance — ADR-MCPRE-063 and ADR-MCPRE-064.
//!
//! The architecture this module belongs to models communication security as a composition
//! of semantic products: evidence is verified, verified evidence is interpreted into facts
//! about a peer, facts acquire assurance, assurance is bound, and only then does anything
//! get admitted or authorized. Each arrow is a named authority, and each product is a
//! type. A component consumes its predecessor's product and produces its own; it does not
//! reach past an authority to reconstruct a fact from raw representation.
//!
//! # What exists here today
//!
//! ```text
//! CertificateChainEvidence --[X.509 adapter — ASSUMED]--> CertificateIdentityFields
//!                          --[identity interpreter]-----> CertificatePeerIdentityEvidence
//!
//! established relationship --[mechanism adapter — ASSUMED]-->
//!                              ChannelAssociatedCertificateCredentialEvidence
//!                          --[+ establishment path, one connection]-->
//!                              MechanismVerifiedCredentialEvidence
//!                          --[+ CertificateIdentityPolicy, one closure]-->
//!                              AuthenticatedRelationshipPeerFacts
//!
//! AuthenticatedRelationshipPeerFacts
//!                          --[+ CredentialCurrencyPolicy, one instant]-->
//!                              CurrentAuthenticatedRelationshipPeerFacts
//!
//! CredentialPublicKeyEvidence + CryptographicSigningKeyEvidence
//!                          --[correspondence]-----------> CredentialKeyCorrespondenceFacts
//! ```
//!
//! and one product shared by every identity provenance: [`PeerIdentityValue`], the generic
//! identity-value invariant.
//!
//! # What deliberately does not exist here
//!
//! Admission and authorization. Their absence is the point: each authority establishes
//! exactly one proposition, and the missing ones are missing rather than being implied by a
//! type whose name claims them. `AuthenticatedRelationshipPeerFacts` is the first product
//! entitled to the word *authenticated*, and it is entitled to no more than that word — see
//! its own module.
//!
//! Per-request credential currency and channel binding DO exist here now, as their own
//! authorities: `credential_currency` evaluates what a deployment's controls concluded
//! about an accepted credential, `current_authenticated_peer` composes that verdict with
//! the peer who authenticated with that same credential, and `request_peer_binding` binds
//! the result to one request. Each is a separate product for the same reason the others
//! are — a peer being authenticated does not make its credential current, and a current
//! credential does not make it this request's.
//!
//! # The public entrances
//!
//! `CertificateChainEvidence::interpret_identity` is the only public route from a
//! certificate to identity evidence; `interpret_associated_identity` and
//! `authenticate_relationship_peer` are the only routes to their products, and each takes
//! its predecessor plus a deployment policy and nothing else. The certificate field set and
//! the pure selector are private to this module tree: both are separately testable and both
//! are the formal-verification candidates, and neither is therefore a public composition
//! edge. A published selector would let a caller fabricate a field set and interpret it
//! into evidence without presenting a certificate — a route the diagram above says does not
//! exist, and the diagram is meant to be the type graph rather than a description of it.
//!
//! # Dependency firewall
//!
//! Nothing here depends on MCP types, HTTP headers, a listener, or a request. The two
//! mechanism dependencies are confined to adapters and are ADR-MCPRE-059 assumed
//! boundaries: the X.509 parser to [`certificate_chain_evidence`], and `rustls` to the
//! `rustls_adapter` child of each authority that relays a mechanism report.

pub mod authenticated_channel_peer;
pub mod authenticated_relationship_peer;
pub mod certificate_chain_evidence;
pub mod certificate_identity_policy;
pub mod certificate_identity_refusal;
pub mod certificate_peer_identity_evidence;
pub mod channel_associated_credential;
pub mod channel_associated_identity;
pub mod credential_currency;
pub mod credential_key_correspondence;
pub mod credential_public_key_evidence;
pub mod current_authenticated_peer;
pub mod ed25519_public_key;
pub mod mechanism_verified_credential;
pub mod peer_identity_provenance;
pub mod peer_identity_value;
pub mod request_peer_binding;
pub mod signing_key_evidence;

// PRIVATE to the authority. These two are the block's internal machinery: the
// representation seam and the pure selector over it.
//
// They are unit-tested directly and are the formal-verification candidates, and neither is
// a reason to publish them. **Public visibility is part of the legal authority graph, not a
// testing convenience.** Exported, they would be a second entrance: a caller could
// fabricate a field set and interpret it into evidence without ever presenting a
// certificate, which is a route the architecture says does not exist. The theorem would
// survive that — it is scoped over the selector — but the connector would not, and the
// connector is what ADR-MCPRE-063 §5 makes structural.
//
// The one public production route from certificate representation to the evidence product
// is `CertificateChainEvidence::interpret_identity`.
mod certificate_identity_fields;
mod certificate_identity_interpreter;

pub use authenticated_channel_peer::AuthenticatedChannelPeer;
pub use authenticated_relationship_peer::authenticate_relationship_peer;
pub use authenticated_relationship_peer::AuthenticatedRelationshipPeerFacts;
pub use certificate_chain_evidence::CertificateChainEvidence;
pub use credential_currency::CredentialCurrencyOutcome;
pub use credential_currency::CredentialCurrencyPolicy;
pub use credential_currency::CredentialCurrencyRefusal;
pub use credential_currency::CurrencyControls;
pub use credential_currency::CurrentCredentialFacts;
pub use current_authenticated_peer::current_authenticated_peer;
pub use current_authenticated_peer::CurrentAuthenticatedRelationshipPeerFacts;
pub use current_authenticated_peer::CurrentPeerRefusal;

pub use certificate_identity_policy::CertificateIdentityPolicy;
pub use certificate_identity_policy::CertificateIdentitySource;
pub use certificate_identity_refusal::CertificateIdentityRefusal;
pub use certificate_identity_refusal::LeafIdentityRefusal;
pub use certificate_peer_identity_evidence::CertificatePeerIdentityEvidence;
pub use channel_associated_credential::ChannelAssociatedCertificateCredentialEvidence;
pub use channel_associated_credential::ChannelCredentialAssociationRefusal;
pub use channel_associated_identity::interpret_associated_identity;
pub use channel_associated_identity::ChannelAssociatedCertificatePeerIdentityEvidence;
pub use credential_key_correspondence::establish_credential_key_correspondence;
pub use credential_key_correspondence::CredentialKeyCorrespondenceFacts;
pub use credential_key_correspondence::CredentialKeyCorrespondenceRefusal;
pub use credential_public_key_evidence::CredentialKeyRefusal;
pub use credential_public_key_evidence::CredentialPublicKeyEvidence;
pub use ed25519_public_key::Ed25519PublicKeyValue;
pub use ed25519_public_key::Rfc8410SpkiRefusal;
pub use ed25519_public_key::ED25519_PUBLIC_KEY_LEN;
pub use ed25519_public_key::ED25519_SIGNATURE_LEN;
pub use mechanism_verified_credential::EstablishmentPath;
pub use mechanism_verified_credential::MechanismVerificationRefusal;
pub use mechanism_verified_credential::MechanismVerifiedCredentialEvidence;
pub use peer_identity_value::PeerIdentityValue;
pub use peer_identity_value::PeerIdentityValueRefusal;
pub use peer_identity_value::MAX_PEER_IDENTITY_LEN;
pub use request_peer_binding::bind_request_to_peer;
pub use request_peer_binding::RequestPeerBindingFacts;
pub use request_peer_binding::RequestPeerBindingRefusal;
pub use request_peer_binding::VerifiedRequestSubject;
pub use signing_key_evidence::CryptographicSigningKeyEvidence;
pub use signing_key_evidence::SigningKeyExportEvidence;
pub use signing_key_evidence::SigningKeyRefusal;
