// SPDX-License-Identifier: Apache-2.0
//! Verifier side of the proof path. Everything fails closed: missing or duplicated evidence
//! headers, unknown tag, wrong algorithm, stale window, unresolved keyid, digest mismatch,
//! missing covered component, and any cryptographic failure all reject.
//!
//! # The two propositions, and why they are two subtrees
//!
//! A cryptographic floor and full MCP-RE semantic verification are different statements,
//! and EX-003's census found them multiplied into a flat function list: four axes
//! (assurance, direction, binding, policy) crossed into seventeen public items over one
//! module. The axes now live in the things they are about — the products carry assurance,
//! binding and delegation; [`crate::verifier::Verifier`] holds the policy once — and the
//! implementation follows the same line:
//!
//! ```text
//! Verifier                     the sole normal public verification facade
//!   │
//!   ├── floor                  these bytes are what a trusted key signed, window current
//!   │     ├─ evidence_headers  ├─ components   ├─ transport_headers
//!   │     ├─ params            ├─ trust_slot   ├─ signature
//!   │     └─ request / response
//!   │
//!   └── full                   …and it is an MCP-RE statement to act on
//!         └─ request / response / delegated
//! ```
//!
//! Verification ORDER inside a stage is unchanged and is stated where it is enforced
//! (v0.11 grill C.1, in [`floor::request`]): content-digest first, then evidence parse, then
//! keyid resolution through the caller's trust seam, then the signature over the
//! reconstructed base, then handle derivation.
//!
//! # What this module is, and is not
//!
//! It is the assembly, not an API. Every stage is `pub(crate)` and reached through
//! `Verifier`; the one `pub` item is [`DelegationExpectations`], which is an INPUT a
//! deployment supplies, not a verification entry point.

pub(crate) mod bound_request;
pub(crate) mod floor;
pub(crate) mod full;

pub use full::DelegationExpectations;

pub(crate) use floor::floor_bound_response;
pub(crate) use floor::floor_request;
pub(crate) use floor::floor_unbound_response;
pub(crate) use full::delegated_bound_response;
pub(crate) use full::delegated_unbound_response;
pub(crate) use full::enforce_full_profile_bindings;
pub(crate) use full::full_bound_response;
pub(crate) use full::full_request;
