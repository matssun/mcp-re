// SPDX-License-Identifier: Apache-2.0
//! MCP-RE authorization vocabulary — the frozen denial taxonomy (ADR-MCPS-013).
//!
//! What survives here is profile-agnostic and is what every authorization mechanism denies
//! THROUGH: the [`AuthorizationDecision`] / [`PolicyError`] taxonomy, one variant per
//! `mcp-re.authorization_*` wire token, the injected [`RevocationSource`], and the JSON-RPC
//! error surface. A mechanism adapter cannot mint a wire token; it chooses one of these.
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
//! ADR-MCPS-013 selected Biscuit as the production policy profile **for that superseded
//! carrier**. ADR-MCPRE-065 R-1 rules that the selection does not carry forward as a
//! normative requirement: Biscuit remains an admissible future mechanism, alongside UCAN,
//! OAuth-bound grants and an external PDP, BEHIND the ADR-MCPRE-065 boundary. No mechanism
//! ships today.
//!
//! Firewall (ADR-MCPS-011/012): this crate depends only on `mcp-re-core` plus
//! `serde`/`serde_json`. No networking, async runtime, or filesystem access.

pub mod block;
pub mod decision;
pub mod error;
pub mod revocation;
pub mod wire;

pub use block::extract_authorization_block;
pub use block::AuthorizationBlock;
pub use block::AUTHORIZATION_META_KEY;
pub use decision::AuthorizationDecision;
pub use error::PolicyError;
pub use error::PolicyResult;
pub use revocation::InMemoryRevocationSource;
pub use revocation::RevocationSource;
pub use revocation::RevocationStatus;
pub use revocation::RevocationUnavailable;
pub use wire::json_rpc_authorization_error;
