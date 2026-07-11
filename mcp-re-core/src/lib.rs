//! MCP-RE Core — pure, dependency-free cryptographic verification crate for the
//! MCP-RE security profile (a clean-room Zero Trust profile for MCP).
//!
//! Scope and invariants are fixed by the MCP-RE ADRs:
//! - ADR-MCPS-001: clean-room; no monorepo trust concepts.
//! - ADR-MCPS-011 / ADR-MCPS-012: no networking, async runtime, or filesystem
//!   access. Callers inject `TrustResolver` and `ReplayCache` implementations.
//!
//! Post-purge (ADR-MCPRE-050), this crate provides ONLY the profile-agnostic
//! primitives the RFC 9421 carrier stands on: the frozen error taxonomy (`error`),
//! Base64URL encoding (`encoding`), SHA-256 hash ids (`hash`), Ed25519 sign/verify
//! (`crypto`), trust resolution (`resolver`), replay detection (`replay`), freshness
//! (`time`), the JSON-RPC error wire (`wire`), and the audit taxonomy (`audit`).

// PURGE 2026-07-11 (owner decision): the object/JCS engine is DELETED. RFC 9421 +
// RFC 9530 (the `mcp-re-http-profile` crate) is the sole carrier and stands ONLY on
// the profile-agnostic primitives below (replay tier, trust resolution, Ed25519
// keys/verify, errors, base64, hashes, freshness, JSON-RPC wire, audit). The
// deleted modules — `canonical` (RFC 8785 JCS), `pipeline` (object verifier),
// `signing` (object `_meta` preimage), `envelope`, `constraints`, `mrt`, `unwrap`
// — carried the object carrier and are gone; no `_meta` signature exists on any
// wire.
pub mod audit;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod hash;
// `ids` retained ONLY for the profile-agnostic constants (the Ed25519 alg string,
// extension id). The object `_meta` key constants it also holds are NOT re-exported
// — nothing on the RFC 9421 path uses them; they are trimmed when the last object
// consumer is gone.
pub mod ids;
pub mod replay;
pub mod resolver;
pub mod time;
pub mod wire;

// Re-export the profile-agnostic public surface at the crate root.
pub use crypto::ensure_ed25519_alg;
pub use crypto::verify_ed25519;
pub use crypto::verify_ed25519_with;
pub use crypto::SigningKey;
pub use crypto::VerificationKey;
pub use encoding::b64url_decode;
pub use encoding::b64url_encode;
pub use error::McpReError;
pub use error::McpReResult;
pub use hash::parse_hash_id;
pub use hash::sha256_hash_id;
pub use ids::EXTENSION_ID;
pub use ids::SIG_ALG_ED25519;
pub use replay::InMemoryReplayCache;
pub use replay::ReplayCache;
pub use replay::ReplayCacheError;
pub use replay::ReplayDecision;
pub use replay::ReplayDurabilityClass;
pub use replay::ReplayKey;
pub use resolver::InMemoryTrustResolver;
pub use resolver::TrustResolver;
pub use resolver::TrustResolverError;
pub use time::check_freshness;
pub use time::parse_rfc3339_utc;
pub use time::unix_to_rfc3339_utc;
pub use wire::json_rpc_error_object;
pub use wire::MCP_RE_JSON_RPC_ERROR_CODE;
