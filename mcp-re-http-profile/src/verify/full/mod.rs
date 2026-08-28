// SPDX-License-Identifier: Apache-2.0
//! Full MCP-RE profile verification.
//!
//! One proposition: **the message a verified floor established is an MCP-RE statement this
//! deployment should act on.** Everything here consumes a floor result or the facts a floor
//! established; nothing re-derives one.
//!
//! ```text
//! full
//!   ├─ request     block validation, audience/target agreement, artifact binding  (THM-0015)
//!   ├─ response    signer correspondence and request-evidence agreement           (THM-0018)
//!   └─ delegated   credential-chain authorization, bound and unbound        (THM-0019/0020)
//! ```
//!
//! `response` and `delegated` are siblings rather than a base and a variant, and that is the
//! architecture rather than file layout: they establish the same thing under two DIFFERENT
//! authorizations — the trust seam, and a credential chain — and there is no field,
//! projection or conversion from a delegated product back to a seam-authorized one. A
//! `compile_fail` control in `http_profile.verifier_result_separation` pins it.

pub(crate) mod delegated;
mod request;
mod response;

pub(crate) use delegated::delegated_bound_response;
pub(crate) use delegated::delegated_unbound_response;
pub use delegated::DelegationExpectations;
pub(crate) use request::enforce_full_profile_bindings;
pub(crate) use request::full_request;
pub(crate) use response::full_bound_response;
