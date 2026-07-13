//! MCP-RE conformance harness library (MCPS-010..013).
//!
//! Phase 3 black-box conformance runner. MCPS-010 lands the in-process **object
//! target**: it runs the committed conformance vectors (the SINGLE SOURCE OF
//! TRUTH at `components/mcp-re/mcp-re-core/tests/vectors/`) directly through
//! `mcp_re_core::verify_request` / `verify_response` and produces a deterministic,
//! machine-readable [`runner::RunReport`].
//!
//! The [`target::ConformanceTarget`] trait is the seam the transport harness
//! reuses: MCPS-013 (Streamable HTTP) implements the same trait so the [`runner`]
//! is transport-agnostic. MCP-RE is HTTP-profile only — the object and HTTP
//! harnesses are the transport conformance surface; stdio is out of scope.
//!
//! Crate boundary (ADR-MCPS-011/012): `mcp-re-conformance` may use `std::fs`
//! (vector loading) — `mcp-re-core` must not, and stays pure.

pub mod http;
pub mod loader;
pub mod vector;

pub use loader::load_from_dir;
pub use loader::parse_case;
pub use loader::parse_manifest;
pub use mcp_re_core::unix_to_rfc3339_utc;
pub use vector::Expected;
pub use vector::ManifestEntry;
pub use vector::ResolverEntry;
pub use vector::VectorCase;
