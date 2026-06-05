//! `mcps-demo-server` — an ordinary, MCP-S-UNAWARE, LONG-LIVED stdio MCP server
//! (MCPS-062).
//!
//! This is the in-tree demo target for MCPS-EPIC-P6.6B: a PERSISTENT MCP server
//! that the MCP-S sidecar (`mcps-proxy`) will learn to front unchanged. It is
//! the long-lived counterpart of `mcps-demo-fileserver`: a single process
//! serves an `initialize` handshake followed by ANY number of `tools/list` /
//! `tools/call` requests, staying alive until stdin EOF (or a modelled
//! `shutdown`). It knows nothing about signing, envelopes, or verified context.
//!
//! ## Framing
//! Newline-delimited JSON-RPC over stdio (one JSON object per line, UTF-8) —
//! the real MCP stdio convention, NOT LSP `Content-Length`. See [`stdio`].
//!
//! ## Scoped demo tools (for the Phase-5 policy demo, #3959)
//! Three side-effect-free, self-contained tools, each tagging its intended
//! scope as metadata (the server does NOT enforce scopes):
//!   * `echo`        — public,
//!   * `list_items`  — protected,
//!   * `reset_items` — admin.
//!
//! Crate boundary (ADR-MCPS-001): self-contained — depends only on the pure
//! serde subset plus thiserror, no other in-repo crate, no async runtime, no
//! filesystem/network/DB.

pub mod error;
pub mod server;
pub mod stdio;

pub use error::DemoServerError;
pub use server::DemoServer;
pub use server::TOOL_ECHO;
pub use server::TOOL_LIST_ITEMS;
pub use server::TOOL_RESET_ITEMS;
pub use stdio::serve_stdio;
