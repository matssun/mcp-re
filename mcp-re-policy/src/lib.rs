//! MCP-RE delegated authorization (Phase 5 — ADR-MCPS-013).
//!
//! Core (`mcp-re-core`) proves a request is authentic, fresh, non-replayed, and
//! audience-correct, and carries an OPAQUE `authorization_hash`. This crate
//! interprets the authorization artifact behind that hash and renders an
//! allow/deny decision, WITHOUT reopening the frozen Core vocabulary or extending
//! the Core error taxonomy.
//!
//! The artifact travels in a sibling `_meta` block,
//! `se.syncom/mcp-re.authorization = { profile, artifact }`, bound to
//! the request because `authorization_hash == sha256(decoded artifact bytes)`.
//!
//! MCPS-019 lands the abstraction: the [`AuthorizationProfile`] trait, the
//! [`AuthorizationDecision`] / [`PolicyError`] types, the authorization-block
//! types, and the injected [`RevocationSource`]. The Reference Signed
//! Authorization Profile (MCPS-020) and the policy evaluator (MCPS-021) build on
//! it; Biscuit / UCAN / OAuth-bound are later pluggable profiles.
//!
//! Firewall (ADR-MCPS-011/012): this crate depends only on `mcp-re-core` plus
//! `serde`/`serde_json`. No networking, async runtime, or filesystem access.

// PURGE 2026-07-11: the authorization EVALUATOR (`evaluator`), the
// authorization-object PROFILE (`profile`), and the REFERENCE grant profile
// (`reference`) consumed the deleted object model (`VerifiedRequest` /
// `VerifiedAuthorization` / `AuthorizationBinding` / JCS `canonicalize`). They are
// DEFERRED (files retained) and rebuilt on the RFC 9421 request evidence
// (`VerifiedHttpRequestEvidence.request_block.artifact_bindings`) in a follow-up.
// The profile-agnostic pieces below — the decision/error taxonomy, the
// authorization-block wire types, revocation, and the JSON-RPC error surface —
// stay. Policy enforcement is NOT wired into the RFC 9421 serving path yet (the
// serving PEP fails closed if a policy is configured).
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
