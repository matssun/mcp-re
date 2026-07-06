//! MCP-RE conformance harness library (MCPS-010..013).
//!
//! Phase 3 black-box conformance runner. MCPS-010 lands the in-process **object
//! target**: it runs the committed conformance vectors (the SINGLE SOURCE OF
//! TRUTH at `components/mcp-re/mcp-re-core/tests/vectors/`) directly through
//! `mcp_re_core::verify_request` / `verify_response` and produces a deterministic,
//! machine-readable [`runner::RunReport`].
//!
//! The [`target::ConformanceTarget`] trait is the seam future transport
//! harnesses reuse: MCPS-012 (stdio) and MCPS-013 (Streamable HTTP) implement
//! the same trait so the [`runner`] is transport-agnostic.
//!
//! Crate boundary (ADR-MCPS-011/012): `mcp-re-conformance` may use `std::fs`
//! (vector loading) — `mcp-re-core` must not, and stays pure. No networking/async
//! is introduced here yet (that is MCPS-012/013).

pub mod echo_server;
pub mod fixtures;
pub mod http;
pub mod http_target;
pub mod loader;
pub mod runner;
pub mod server;
pub mod stdio;
pub mod stdio_target;
pub mod target;
pub mod vector;

pub use echo_server::build_signed_request;
pub use echo_server::EchoServer;
pub use fixtures::documented_echo_server;
pub use fixtures::documented_proxy_server;
pub use fixtures::inbound_resolver;
pub use fixtures::plain_echo_inner;
pub use fixtures::response_resolver;
pub use http_target::HttpHarness;
pub use loader::load_from_dir;
pub use loader::parse_case;
pub use loader::parse_manifest;
pub use mcp_re_core::unix_to_rfc3339_utc;
pub use runner::run_suite;
pub use runner::CaseResult;
pub use runner::RunReport;
pub use server::build_server;
pub use server::McpReServer;
pub use server::ServerKind;
pub use stdio::serve_stdio;
pub use stdio_target::outcome_token;
pub use stdio_target::StdioHarness;
pub use target::canonical_request_hash;
pub use target::now_unix_for_case;
pub use target::ConformanceTarget;
pub use target::ObjectTarget;
pub use target::RunContext;
pub use target::TargetOutcome;
pub use vector::Expected;
pub use vector::ManifestEntry;
pub use vector::ResolverEntry;
pub use vector::VectorCase;
