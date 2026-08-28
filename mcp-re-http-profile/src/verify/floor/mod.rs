// SPDX-License-Identifier: Apache-2.0
//! The cryptographic floor.
//!
//! One proposition, in two shapes (request and response): **these bytes are what a key the
//! deployment trusts for this slot signed, inside a current window.** Nothing in this
//! subtree knows what an MCP-RE evidence block is, what an audience is, or what a
//! delegation credential means — those are [`crate::verify::full`]'s, and keeping the line
//! here is what makes possession of a `CryptographicFloorVerified…` value say exactly the
//! floor and no more.
//!
//! # The subordinate authorities
//!
//! ```text
//! floor
//!   ├─ sf_dictionary        RFC 8941: one spelling, one value per label
//!   ├─ signature_input      RFC 9421: the member value's shape
//!   │    ├─ covered_components    the closed identifier set, each named once
//!   │    └─ signature_parameters  the closed, ORDERED parameter set
//!   ├─ components         what the signature must cover
//!   ├─ transport_headers  §4.1: a covered routing claim may not lie about the body
//!   ├─ params             what this verifier ACCEPTS, vs what the signer SAID (THM-0001)
//!   ├─ trust_slot         the keyid was vouched for THIS slot
//!   ├─ signature          the allowlisted algorithm is the one that runs
//!   ├─ request            the request floor  (THM-0014)
//!   └─ response           the response floors, bound and unbound  (THM-0016 / THM-0017)
//! ```
//!
//! Two more subordinates are not here, because they already have owners the whole crate
//! shares: [`crate::digest`] and [`crate::sigbase`]. `sigbase` stays a public module — the
//! conformance KAT oracle reconstructs the exact RFC 9421 signature base through it, which
//! is a real external consumer contract and not an accident of layering.
//!
//! # What is `pub(crate)` here, and why
//!
//! [`crate::bodyless`] verifies message shapes with DIFFERENT required component sets — a
//! bodyless 202 has no body to digest — but under identical parse, coverage, parameter,
//! trust and signature rules. It therefore consumes the subordinates directly rather than a
//! stage. A second parser or a second parameter gate for those shapes would be a second
//! place for the closed allowlists to drift, which is the whole reason these are one copy.

pub(crate) mod components;
mod covered_components;
pub(crate) mod params;
mod request;
mod response;
pub(crate) mod sf_dictionary;
pub(crate) mod signature;
pub(crate) mod signature_input;
mod signature_parameters;
mod transport_headers;
pub(crate) mod trust_slot;

pub(crate) use request::floor_request;
pub(crate) use response::floor_bound_response;
pub(crate) use response::floor_unbound_response;
