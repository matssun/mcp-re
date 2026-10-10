// SPDX-License-Identifier: Apache-2.0
//! The response verification products — the response half of ADR-MCPRE-061 §2 class 9.
//!
//! One `VerifiedHttpResponseEvidence` used to answer four materially different
//! verification paths, with `bound_request_evidence`, `body_request_evidence`,
//! `server_signer` and `delegation_issuer_kid` documented `None` "on the seam-only path".
//! Holding it told a consumer nothing about which proposition had been established.
//!
//! These are the legal products, and only the legal ones — there is deliberately no
//! Cartesian product of floor × bound × delegated:
//!
//! | product | what a SUCCESSFUL VERIFIER RETURN of it establishes |
//! |---|---|
//! | [`CryptographicFloorVerifiedBoundResponse`] | the bound signature facts, with the signer authorized by the TRUST SEAM |
//! | [`CryptographicFloorVerifiedUnboundResponse`] | the unbound signature facts, with the signer authorized by the TRUST SEAM |
//! | [`VerifiedMcpResponse`] | the seam-authorized bound floor, plus block agreement with the expected request evidence |
//! | [`VerifiedDelegatedMcpResponse`] | the bound signature facts and the same block agreement, with the signer authorized by a verified DELEGATION CHAIN |
//! | [`VerifiedDelegatedUnboundResponse`] | the unbound signature facts, with the signer authorized by a verified DELEGATION CHAIN |
//!
//! # Two authorization propositions, one set of cryptographic facts
//!
//! A response signature is accepted under a key, and something has to make that key
//! acceptable. There are two such somethings and they are NOT the same proposition:
//!
//! ```text
//!   trust-seam authorization ──┐
//!                              ├──> [Bound|Unbound]ResponseSignatureFacts
//!   delegation-chain authorization ─┘
//! ```
//!
//! On the direct path the presented keyid is resolved through the deployment's trust seam
//! for the `Response` slot, and the seam's answer IS the accepted signer. On the delegated
//! path (ADR-MCPRE-052 §3) the seam resolves the credential's ROOT ISSUER; the signing key
//! is a delegated key that appears in no trust map, and what authorizes it is the
//! credential chain. Nesting the direct product inside the delegated one would have made
//! the delegated product carry a value whose documented meaning — "resolved through the
//! trust seam" — is false of it.
//!
//! So the shared layer carries only what is genuinely shared: the digest, parameter and
//! signature facts, and the identity and key the signature was accepted under
//! ([`AcceptedResponseSigner`]) — WHO, never WHY. Each product states its own
//! authorization proposition on top.
//!
//! **Bound and unbound are different propositions, not an API convenience.** A bound
//! response verifies `;req` against a concrete request and compares the block's
//! `request_evidence` with the handle the caller expects. The unbound path has no
//! trustworthy request context: it forbids `;req` outright, and the block's
//! `request_evidence` is diagnostic rather than authoritative. Returning one type for both
//! would put the consumer back to inspecting a value to discover what happened — which is
//! why the shared facts are also two types, one per binding kind, rather than one type
//! with the coverage difference left to prose.
//!
//! # These types state propositions; the verifier is their only producer
//!
//! Every product's representation is private to its module and its sole constructor is
//! `pub(crate)`, called from `crate::verify`. No Verus `ensures` reads a response product,
//! so nothing is traded for the seal (unlike the request products, `docs/dev/sealed-owners.md`
//! "The same trade, measured a second time"). Outside this crate, holding a product
//! therefore means a verifier returned it; inside the crate the producer set is held by the
//! `pub(crate)` constructor, not by type privacy. The shared facts types are plain
//! pub-field value records that establish nothing alone and are reached as projections of
//! a product.
//!
//! What the type split DOES give is non-substitutability: no consumer requiring one
//! proposition can be handed a value of another, by the compiler rather than a runtime
//! check. The registered claims are THM-0016 … THM-0022 and their scopes say the same.

mod bound;
mod delegated_bound;
mod facts;
mod unbound;

pub(crate) use bound::block_agreement;
pub use bound::CryptographicFloorVerifiedBoundResponse;
pub use bound::VerifiedMcpResponse;
pub use delegated_bound::VerifiedDelegatedMcpResponse;
pub use facts::AcceptedResponseSigner;
pub use facts::BoundRequestEvidenceAgreement;
pub use facts::BoundResponseSignatureFacts;
pub use facts::UnboundResponseSignatureFacts;
pub use unbound::CryptographicFloorVerifiedUnboundResponse;
pub use unbound::VerifiedDelegatedUnboundResponse;
