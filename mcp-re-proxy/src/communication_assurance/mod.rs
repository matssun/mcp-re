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
//! # Dependency firewall
//!
//! Nothing here depends on MCP types, HTTP headers, `rustls`, a connection, a listener, or
//! a request. The one mechanism dependency — the X.509 parser — is confined to
//! [`certificate_chain_evidence`], the adapter, and is an ADR-MCPRE-059 assumed boundary.

pub mod certificate_chain_evidence;
pub mod certificate_identity_fields;
pub mod certificate_identity_interpreter;
pub mod certificate_identity_policy;
pub mod certificate_identity_refusal;
pub mod certificate_peer_identity_evidence;
pub mod peer_identity_value;

pub use certificate_chain_evidence::CertificateChainEvidence;
pub use certificate_identity_fields::CertificateIdentityFields;
pub use certificate_identity_interpreter::interpret_certificate_identity;
pub use certificate_identity_policy::CertificateIdentityPolicy;
pub use certificate_identity_policy::CertificateIdentitySource;
pub use certificate_identity_refusal::CertificateIdentityRefusal;
pub use certificate_peer_identity_evidence::CertificatePeerIdentityEvidence;
pub use peer_identity_value::PeerIdentityValue;
pub use peer_identity_value::PeerIdentityValueRefusal;
pub use peer_identity_value::MAX_PEER_IDENTITY_LEN;
