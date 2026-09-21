//! `mcp-re-demo` — the MCP-RE demo's certificate material (MCP-RE-EPIC-P6.5).
//!
//! One crate, one job: [`DemoFixtures`] mints the demo's mTLS material — a server CA
//! and leaf, a client CA and leaf, a mismatched client identity, `trust.json`, and a
//! signing seed — as the SINGLE source of truth the proxy/client round-trip tests are
//! wired from. Two tests reading two independently minted material sets prove nothing
//! about each other; that is why the set is generated once, here.
//!
//! [`DemoFixtureSpec`] is the request and [`DemoFixtureFiles`] the materialized paths.
//!
//! Crate boundary (ADR-MCPS-001): this crate lives INSIDE the `components/mcp-re`
//! workspace and depends only on `mcp-re-core` plus rcgen/time/serde_json. It holds no
//! client, no session and no transport — MCP-RE is HTTP-profile only, and the stdio demo
//! servers, the bridge and the runnable client binaries were removed with that decision.
//! A stdio-only host uses an external plain-MCP adapter (e.g. FastMCP) speaking HTTP.

// ADR-MCPRE-061 Amendment 1 §3.1 — this crate holds no production `unsafe`, and `forbid`
// (unlike `deny`) cannot be overridden by an inner `#[allow]` anywhere in it. Acquiring
// `unsafe` here means deleting this line: an architectural decision, reviewed as one.
#![forbid(unsafe_code)]
pub mod demo_fixtures;

pub use demo_fixtures::DemoFixtureFiles;
pub use demo_fixtures::DemoFixtureSpec;
pub use demo_fixtures::DemoFixtures;
