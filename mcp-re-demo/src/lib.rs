//! `mcp-re-demo` — the MCP-RE single-node demo harness crate (MCP-RE-EPIC-P6.5).
//!
//! This umbrella crate holds the host/ambassador side of the demo. For MCPS-046
//! (Child Issue 2) it provides [`DemoHostClient`], a thin demo client built on
//! the EXISTING `mcp-re-host` [`HostSession`](mcp_re_host::HostSession): it signs
//! MCP-RE requests (nonce from an injected RNG, freshness from an injected clock +
//! configured lifetime), tracks the `request_hash` by JSON-RPC id, and verifies a
//! signed server response against the STORED hash. The language model never holds
//! keys — the client exposes the signer identity but NO private-key accessor.
//!
//! Crate boundary (ADR-MCPS-001): this crate lives INSIDE the `components/mcp-re`
//! workspace and depends only on its sibling in-workspace crates (`mcp-re-host`,
//! `mcp-re-core`) plus the pure serde subset already pinned by the workspace — no
//! crate outside the workspace and no Python component.
//!
//! Transport: the demo client produces and consumes raw JSON-RPC bytes and drives
//! them to a remote `mcp-re-proxy` over the mTLS transport ([`MtlsClientRunner`]).
//! MCP-RE is HTTP-profile only — stdio is out of scope; a stdio-only host uses an
//! external plain-MCP adapter (e.g. FastMCP) that speaks HTTP to MCP-RE.

pub mod client;
pub mod demo_fixtures;
pub mod mtls_client;

pub use client::DemoHostClient;
pub use demo_fixtures::DemoFixtureFiles;
pub use demo_fixtures::DemoFixtureSpec;
pub use demo_fixtures::DemoFixtures;
pub use mtls_client::MtlsClientRunner;
pub use mtls_client::RoundTripOutcome;
pub use mtls_client::RunnerError;
