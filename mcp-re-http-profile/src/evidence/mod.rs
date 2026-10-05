// SPDX-License-Identifier: Apache-2.0
//! Evidence handles: SHA-256 over a role-labeled preimage, in split
//! `{digest_alg, digest_value}` form (the draft-02 binding convention — no
//! `sha256:`/`sha-256:` prefix forms on new fields).
//!
//! Four types, one per thing a handle can be:
//!
//! - [`RequestRoleEvidence`] / [`ResponseRoleEvidence`] — DERIVED from a signature base,
//!   sealed, one type per role. A role is a type, so a slot cannot hold the wrong one.
//! - [`RequestEvidenceDigest`] — the wire CLAIM, as read from or written into a block.
//!   Public fields; checked against a role type or a role.
//! - [`UnboundRequestDiagnostic`] — what an unbound rejection records about a request
//!   that never earned a hash. Never a binding.
//!
//! Roles are the closed [`EvidenceRole`], and every derivation goes through its one labeled
//! digest function.

mod diagnostic;
mod digest;
// The prover's view of these types (ADR-MCPRE-059): exists only while `verify` is on.
#[cfg(feature = "verify")]
pub(crate) mod prover_model;
mod request_role;
mod response_role;
mod role;

pub use diagnostic::UnboundRequestDiagnostic;
pub use digest::RequestEvidenceDigest;
pub use request_role::RequestRoleEvidence;
pub use response_role::ResponseRoleEvidence;
pub use role::EvidenceRole;
