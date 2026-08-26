// SPDX-License-Identifier: Apache-2.0
//! Authorization over verified request evidence — ADR-MCPRE-065.
//!
//! # The proposition, and why it is a new authority
//!
//! ADR-MCPRE-064 ends at admission. Everything in that chain is a statement about a
//! **relationship and a request**:
//!
//! ```text
//! communication relationship
//!     -> authenticated peer
//!     -> credential current
//!     -> request <-> peer bound
//!     -> admission
//!     ================================
//!     AUTHORIZATION   "may this actor perform this action?"
//! ```
//!
//! Below that line is a statement about **permission**, which no amount of assurance about
//! the first produces. The three products are distinct and none substitutes for another:
//!
//! ```text
//! RequestPeerBindingFacts = "request signer and communication peer are the same principal"
//! AdmissionDecision       = "this actor/request satisfied admission requirements"
//! AuthorizationDecision   = "this admitted actor may perform this requested action
//!                            under this policy"
//! ```
//!
//! # What this authority may not do
//!
//! - It must not reconstruct peer identity from certificate fields, `TransportIdentity`, or
//!   raw TLS state. The ADR-MCPRE-064 product arrives whole and is carried, not reopened.
//! - It must not re-derive the request actor from strings where the verifier already owns
//!   the semantic fact.
//! - It must not read its action coordinate from transport routing hints (Law A-1), and its
//!   correctness must not depend on the MCP transport contract being enforced.
//! - It must not report an unconfigured deployment as an authorized one.
//!
//! # The pieces
//!
//! ```text
//! VerifiedMcpRequest
//!       |
//!       +-- VerifiedAuthorizationActor   role, trust_domain, subject, keyid, together
//!       +-- VerifiedAuthorizationAction  operation and target, from the signed body
//!       +-- RequestPeerBindingFacts      the ADR-MCPRE-064 prerequisite, carried whole
//!       v
//!  AuthorizationRequest        one request, so no caller can pair two
//!       v
//!  AuthorizationEvaluator      the mechanism seam — nothing above it knows the mechanism
//!       v
//!  AuthorizationPosture | AuthorizationRefusal
//! ```
//!
//! # The mechanism, and what is still absent
//!
//! ADR-MCPS-013 selected Biscuit for the native/JCS carrier ADR-MCPRE-050 replaced, and
//! ADR-MCPRE-065 R-1 rules that the selection does not carry forward as a normative
//! requirement here. No Biscuit, UCAN, OPA or Cedar is in this tree. The mechanism chosen
//! UNDER this architecture is the carried PDP decision ([`pdp`], ADR-MCPRE-065 §8).
//!
//! What is absent is its INSTALLATION: no configuration value selects it, and the
//! composition root never attaches an evaluator, so every deployment serves with
//! [`AuthorizationPosture::NoPolicyConfigured`] — which claims nothing, and is not an allow.

#[cfg(test)]
pub(crate) mod action_harness;
pub mod audit;
pub mod decide;
pub(crate) mod dispatch;
pub mod evaluator;
pub mod grant;
pub mod pdp;
pub mod posture;
pub mod request;
pub(crate) mod serving;
pub mod verified_action;
pub mod verified_actor;

pub use audit::AuthorizationAttribution;
pub use audit::AuthorizationFacet;
pub use audit::AuthorizationRefusalFacet;
pub use decide::authorize;
pub use decide::AuthorizationRefusal;
pub(crate) use dispatch::AuthorizedRequestBody;
pub use evaluator::AuthorizationEvaluator;
pub use grant::GrantAttribution;
pub use pdp::PdpDecisionEvaluator;
pub use pdp::PdpDecisionPolicy;
pub use posture::AuthorizationPosture;
pub use posture::AuthorizedRequestFacts;
pub use request::authorization_request;
pub use request::AuthorizationRequest;
pub(crate) use serving::AuthorizationStage;
pub use verified_action::interpret_authorization_action;
pub use verified_action::AuthorizationActionRefusal;
pub use verified_action::AuthorizationTarget;
pub use verified_action::VerifiedAuthorizationAction;
pub use verified_actor::interpret_authorization_actor;
pub use verified_actor::VerifiedAuthorizationActor;
