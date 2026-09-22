// SPDX-License-Identifier: Apache-2.0
//! The verified-context carrier (#415 rev 2 §10, issue #429).
//!
//! §10: the trusted verification boundary produces verified context; the carrier
//! between the enforcement boundary and the inner server must be explicitly
//! trusted; reserved verified-context fields in caller input must be rejected or
//! replaced.
//!
//! **The carrier is a reserved `_meta` block, and it is NOT evidence.** Everything
//! else in this crate is evidence: signed, digest-bound, verifiable by anyone
//! holding a key. This is the opposite — it is the PEP's *conclusion*, handed to
//! the inner server on the PEP's authority alone. The inner server cannot verify
//! it and must not try: there is no signature over it, because a signature would
//! imply the inner server could evaluate trust independently, which is exactly the
//! job the PEP exists to have already done.
//!
//! That makes the carrier's trust precondition load-bearing rather than incidental:
//!
//! **The channel PEP → inner server MUST be one only the PEP can write to** — a
//! loopback socket, a sidecar in the same pod, a UNIX socket. If anything else can
//! reach the inner server, it can assert any verified context it likes and the
//! inner server has no way to tell. There is no cryptographic fallback here, which
//! is why enabling the carrier is an explicit deployment act
//! ([`VerifiedContextPolicy::Trusted`]) and never a default.
//!
//! **The reserved-field guard.** Because the inner server trusts this block
//! implicitly, a caller that could seed it would be asserting its own verified
//! context — a total authentication bypass, not a spoofing nuisance. So the
//! reserved key is stripped from caller input at the boundary before the PEP writes
//! its own, unconditionally, whether or not the carrier is enabled: a deployment
//! that leaves it disabled must not be one reserved-key rename away from
//! forwarding attacker-authored context.
//!
//! # Two types, because there are two proof strengths
//!
//! Since the block carries no signature, the TYPE is the only place its provenance
//! can live, so this module keeps the two provenances apart by type rather than by
//! a field a consumer may forget to read:
//!
//! - [`VerifiedContext`] is what THIS verifier concluded. Its representation is
//!   private to its own module, [`VerifiedContext::from_verified`] is its only
//!   producer, and it takes a [`crate::VerifiedMcpRequest`] — so holding one means
//!   a full-profile verification produced it. It serializes; it does not
//!   deserialize.
//! - [`UnauthenticatedContextClaim`] is what an inner server READ off the channel.
//!   It deserializes; nothing about it is established by holding it, and its
//!   projections are named so that reading it as a conclusion takes a deliberate
//!   sentence.
//!
//! # The block declares its own shape
//!
//! Both types carry a `block_schema` discriminator, and `block_schema.rs` owns what it
//! means: the writer emits the one current representation and has no other value it could
//! emit, and a block with no discriminator, or one naming a schema this build does not
//! write, is refused. There is no compatibility mode — Owner Ruling 8 and CLAUDE.md's
//! general form. Without it "absent because the writer predates the member" and "absent
//! because someone removed it" are the same bytes, and a tolerance for the first can never
//! be withdrawn.
//!
//! # The deployment act is a capability, not a selector
//!
//! [`VerifiedContextPolicy::trusted_inner_channel`] is the only producer of a
//! [`TrustedInnerChannel`], and [`insert_verified_context`] requires one. A
//! `Disabled` deployment therefore cannot mint the block: there is no value to pass.
//! What that witness establishes — that a branch was taken, not that an operator
//! configured the deployment — is stated precisely on [`TrustedInnerChannel`].
//!
//! # Strip, then write — by type
//!
//! [`insert_verified_context`] takes a [`StrippedBody`], whose only producer is
//! [`strip_proxy_owned_meta`]. The §10 pair "rejected or replaced" is therefore one
//! sentence the compiler enforces rather than two calls joined by their order in a
//! composer: writing the PEP's conclusion into bytes no guard has walked is
//! unconstructible.
//!
//! # What the boundary does NOT provide
//!
//! The forwarded body is a re-serialization, so it is not byte-identical to the
//! bytes the client signed, under EITHER policy. The inner server therefore cannot
//! re-check a `Content-Digest` over what it received, and no downstream check may
//! assume byte fidelity. This is a consequence of the PEP having to rewrite the
//! body, and it is stated here so a later proposal to "have the inner server verify"
//! is refused on the right ground rather than attempted.
//!
//! # Where the evidence for the serving path lives
//!
//! The composer's own unit tests are in `mcp-re-proxy`'s `body_boundary`, in the
//! default cargo lane. The END-TO-END served-path tests are in
//! `mcp-re-proxy/tests/integration_async/verified_context_carrier_test.rs`, which
//! compiles only under the `async_serve` feature — a plain `cargo test --workspace`
//! builds it to zero tests. Any claim about the served path must name that lane.

mod block_schema;
mod claim;
mod policy;
mod reserved_key_strip;
mod seeded_meta_positions;
mod verified;

pub use claim::extract_verified_context;
pub use claim::UnauthenticatedContextClaim;
pub use policy::TrustedInnerChannel;
pub use policy::VerifiedContextPolicy;
pub use reserved_key_strip::strip_proxy_owned_meta;
pub use reserved_key_strip::StrippedBody;
pub use seeded_meta_positions::SeededMetaPositions;
pub use verified::insert_verified_context;
pub use verified::VerifiedContext;
