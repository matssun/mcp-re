// SPDX-License-Identifier: Apache-2.0
//! MCP-RE authorization vocabulary — the frozen denial taxonomy (ADR-MCPS-013).
//!
//! Two authorities, and nothing else.
//!
//! ```text
//! PolicyError       the authorization-policy taxonomy: one variant per
//!                   `mcp-re.authorization_*` wire token, and the sole authority
//!                   over that mapping
//! RevocationSource  an injected revocation seam (ADR-MCPS-021 Axis 2), DORMANT:
//!                   no production path installs one
//! ```
//!
//! A mechanism adapter cannot mint a wire token; it chooses a [`PolicyError`]. Every layer
//! above delegates to [`PolicyError::wire_code`] rather than keeping a second table beside
//! it — `PdpRelationRefusal` returns a `PolicyError`, `AuthorizationRefusal` asks it for the
//! token, and `RefusalCause` composes without reading either authority's vocabulary.
//!
//! # What this crate is NOT, any more
//!
//! Not an evaluator, and not a profile. The authorization EVALUATOR, the
//! authorization-object PROFILE and the REFERENCE grant profile were built for the native
//! `_meta` carrier that ADR-MCPRE-050 replaced, and were deleted with it. The semantic
//! boundary — verified actor and action facts in, a typed decision out — belongs to
//! ADR-MCPRE-065 and lives in `mcp_re_proxy::authorization`; this crate supplies the
//! vocabulary that boundary refuses in.
//!
//! Three further modules went the same way, because each was a SECOND authority over a fact
//! the RFC 9421 tree already owns and none had a consumer:
//!
//! ```text
//! block.rs     `params._meta` sibling-block extraction, keyed off the native opaque
//!              `authorization_hash`. The carrier is `RequestBlock.artifact_bindings[]`
//!              (docs/architecture/authorization.md §2.5 names this input as one that
//!              must not be reused: it reaches past the verifier into representation).
//! decision.rs  `Allow | Deny(PolicyError)`. Strictly weaker than the ADR-MCPRE-065
//!              boundary's own outcome types: it cannot tell an unconfigured deployment
//!              from a permitting one, and it flattens the two refusing authorities.
//! wire.rs      an UNSIGNED JSON-RPC denial envelope. Refusals are signed, and their
//!              posture is decided by `mcp_re_proxy::receipt::ResponseSigning`.
//! ```
//!
//! ADR-MCPS-013 selected Biscuit as the production policy profile **for that superseded
//! carrier**. ADR-MCPRE-065 R-1 rules that the selection does not carry forward as a
//! normative requirement: Biscuit remains an admissible future mechanism, alongside UCAN,
//! OAuth-bound grants and an external PDP, BEHIND the ADR-MCPRE-065 boundary. No mechanism
//! ships today.
//!
//! Firewall (ADR-MCPS-011/012): this crate depends on nothing but `thiserror`. No
//! networking, async runtime, or filesystem access.

// ADR-MCPRE-061 Amendment 1 §3.1 — this crate holds no production `unsafe`, and `forbid`
// (unlike `deny`) cannot be overridden by an inner `#[allow]` anywhere in it. Acquiring
// `unsafe` here means deleting this line: an architectural decision, reviewed as one.
#![forbid(unsafe_code)]
pub mod error;
pub mod revocation;

pub use error::PolicyError;
pub use error::PolicyResult;
pub use revocation::InMemoryRevocationSource;
pub use revocation::RevocationSource;
pub use revocation::RevocationStatus;
pub use revocation::RevocationUnavailable;
