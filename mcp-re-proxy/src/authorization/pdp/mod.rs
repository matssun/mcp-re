// SPDX-License-Identifier: Apache-2.0
//! The PDP-decision authorization mechanism — ADR-MCPRE-065 Slice 2.
//!
//! The first production `AuthorizationEvaluator`. An external authority decides permission;
//! MCP-RE enforces it. MCP-RE does not become a policy-language product, and the authority
//! does not have to be reachable at serving time.
//!
//! # The chain, and why it is a chain
//!
//! ```text
//! pdp-decision / opaque-digest  +  inline decision JWS
//!         v
//! exact-byte digest correspondence          evidence.rs
//!         v
//! configured authorization-authority trust  the profile's resolver
//!         v
//! JWS authentication + typed claims         mcp_re_http_profile::pdp_decision
//!         v
//! actor relation, at the decision's scope   relation.rs
//!         v
//! signed-body action relation               relation.rs
//!         v
//! explicit Permit                           relation.rs
//!         v
//! AuthorizedRequestFacts
//! ```
//!
//! Each step earns the next proposition and none of them is authorization on its own.
//! Digest matching is not authorization. A valid signature is not authorization. A matching
//! actor and action are not authorization until the signed decision itself says permit. A
//! design that collapsed them would be unable to say which link failed, and every link is a
//! different thing for an operator to do about it.
//!
//! # The other binding form produces nothing
//!
//! ```text
//! pdp-decision / reference-digest
//!         v
//! signed linkage only
//!         v
//! NO AuthorizedRequestFacts
//! ```
//!
//! A reference binding names an external decision. MCP-RE binds it into the signed call and
//! authenticates nothing about it, so an EMA-native backend remains the enforcement point.
//! `evidence.rs` does not even treat it as a candidate, which is why it cannot be selected
//! and then rejected: it never enters.
//!
//! # Authority trust is its own boundary
//!
//! The key that authenticates a decision is resolved through a resolver this deployment
//! configures FOR AUTHORIZATION. It is not the request-signer trust seam, and a deployment
//! that happens to use one key infrastructure for both still declares the roles separately:
//! *this key signs requests* and *this key decides permission* are different authorities,
//! and inferring the second from the first is how a workload credential becomes a policy
//! authority.

pub mod evidence;
pub mod policy;
pub mod refusal;
pub mod relation;

pub use evidence::bound_decision_evidence;
pub use evidence::BoundDecisionEvidence;
pub use evidence::DecisionEvidenceRefusal;
pub use policy::AuthorizationAuthorityResolver;
pub use policy::PdpDecisionPolicy;
pub use refusal::PdpRelationRefusal;
pub use relation::PdpDecisionEvaluator;
