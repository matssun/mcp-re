// SPDX-License-Identifier: Apache-2.0
//! Delegated credential composition (ADR-MCPRE-052 §3; THM-0019 / THM-0020).
//!
//! One authority: **a key no trust store vouches for signed this response, and a credential
//! chaining to a root the deployment DOES vouch for says it was allowed to.**
//!
//! # Why this is not "the floor plus a credential"
//!
//! The delegated products do not contain a `CryptographicFloorVerified…` value, and the
//! theorems do not inherit from the direct ones. THM-0016 says *the presented keyid was
//! resolved through the trust seam for the Response slot*; on this path it was NOT — the
//! seam is queried for the credential's ROOT ISSUER kid, while the signing key is a
//! delegated key that appears in no trust map. Nesting the seam-authorized product inside
//! the delegated one made it carry a value whose documented meaning is false of it. What
//! the two paths genuinely share are the authorization-INDEPENDENT signature facts, and
//! that is what these products carry.
//!
//! # The subordinates
//!
//! ```text
//! delegated
//!   ├─ expectations       what the deployment expects of the CREDENTIAL (an input)
//!   ├─ credential_chain   the credential chains to a trusted root  (§3 steps 2-7)
//!   ├─ bound              …and answers THIS request                     (THM-0019)
//!   └─ unbound            …and claims no binding, `;req` refused        (THM-0020)
//! ```
//!
//! `credential_chain` is deliberately ONE copy. The bound and unbound paths differ in what
//! the signature covers, not in how a credential chains to a root, and the two verbatim
//! copies that preceded it were two places for a trust-resolution rule to drift —
//! measurably: a single slot mutation there now breaks all 12 delegated controls at once,
//! where before it took two mutations to reach the same set.
//!
//! # What is deliberately NOT shared
//!
//! The two stage bodies. They repeat a digest/parse/params preamble that the direct
//! response floors also repeat, and folding all four into one helper would collapse eight
//! separately probed conjuncts into two — trading the isolation the V0 mutation battery
//! rests on for a smaller diff. The duplication is legible; the coverage loss would not be.

mod bound;
mod credential_chain;
mod expectations;
mod unbound;

pub use expectations::DelegationExpectations;

pub(crate) use bound::delegated_bound_response;
pub(crate) use unbound::delegated_unbound_response;
