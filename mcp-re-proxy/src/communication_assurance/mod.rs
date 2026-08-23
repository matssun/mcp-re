// SPDX-License-Identifier: Apache-2.0
//! Communication assurance — ADR-MCPRE-063, Slice 1.
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
//! One transformation, complete:
//!
//! ```text
//! CertificateChainEvidence  --[ X.509 adapter — ASSUMED ]-->  CertificateIdentityFields
//!                           --[ identity interpreter ]------>  CertificatePeerIdentityEvidence
//!                                                          |   or CertificateIdentityRefusal
//! ```
//!
//! and one product it shares with every other identity provenance:
//! [`PeerIdentityValue`], the generic identity-value invariant.
//!
//! # What deliberately does not exist here
//!
//! Chain verification, revocation, freshness, authenticated-peer facts, channel binding,
//! admission, and authorization. Their absence is the point of the slice: this module
//! establishes exactly one proposition, and the missing authorities are missing rather
//! than being implied by a type whose name claims them.
//!
//! # The one public entrance
//!
//! `CertificateChainEvidence::interpret_identity` is the only public route from a
//! certificate to the evidence product. The field set and the pure selector are private to
//! this module tree: both are separately testable and both are the formal-verification
//! candidates, and neither is therefore a public composition edge. A published selector
//! would let a caller fabricate a field set and interpret it into evidence without
//! presenting a certificate — a route the diagram above says does not exist, and the
//! diagram is meant to be the type graph rather than a description of it.
//!
//! # Dependency firewall
//!
//! Nothing here depends on MCP types, HTTP headers, `rustls`, a connection, a listener, or
//! a request. The one mechanism dependency — the X.509 parser — is confined to
//! [`certificate_chain_evidence`], the adapter, and is an ADR-MCPRE-059 assumed boundary.

pub mod certificate_chain_evidence;
pub mod certificate_identity_policy;
pub mod certificate_identity_refusal;
pub mod certificate_peer_identity_evidence;
pub mod channel_associated_credential;
pub mod channel_associated_identity;
pub mod credential_key_correspondence;
pub mod credential_public_key_evidence;
pub mod ed25519_public_key;
pub mod peer_identity_value;
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

pub use certificate_chain_evidence::CertificateChainEvidence;
pub use certificate_identity_policy::CertificateIdentityPolicy;
pub use certificate_identity_policy::CertificateIdentitySource;
pub use certificate_identity_refusal::CertificateIdentityRefusal;
pub use certificate_identity_refusal::LeafIdentityRefusal;
pub use certificate_peer_identity_evidence::CertificatePeerIdentityEvidence;
pub(crate) use channel_associated_credential::associated_chain_der;
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
pub use peer_identity_value::PeerIdentityValue;
pub use peer_identity_value::PeerIdentityValueRefusal;
pub use peer_identity_value::MAX_PEER_IDENTITY_LEN;
pub use signing_key_evidence::CryptographicSigningKeyEvidence;
pub use signing_key_evidence::SigningKeyExportEvidence;
pub use signing_key_evidence::SigningKeyRefusal;
