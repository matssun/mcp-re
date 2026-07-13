// SPDX-License-Identifier: Apache-2.0
//! MCP-RE client-side ambassador (MCPS-014, ADR-MCPS-003), on the RFC 9421 carrier.
//!
//! The host is the agent's local key/actor context. It composes and signs the
//! MCP-RE request evidence ([`HostSigner`], via the `mcp-re-client-core` RFC 9421
//! seam) and verifies signed server responses (re-exported
//! [`verify_signed_response`]). The language model never holds private keys or
//! constructs signatures.
//!
//! ## Deferred host modules (RFC 9421 rebuild in progress)
//! The `session` (HostSession), `verified_result`, and `pending`
//! (request_hash correlation) modules were built on the deleted draft-01/object
//! model. They are **deferred** (files retained) and rebuilt on RFC 9421 evidence in
//! a follow-up; the signer + clock/nonce fixtures below are the working surface.

pub mod clock;
pub mod nonce;
pub mod signer;

pub use signer::HostSigner;

pub use clock::Clock;
pub use clock::SystemClock;
pub use nonce::NonceSource;
pub use nonce::SystemNonceSource;
// Deterministic TEST fixtures: re-exported ONLY under `cfg(test)` or the explicit
// `test-fixtures` feature, so they are absent from the default public surface.
#[cfg(any(test, feature = "test-fixtures"))]
pub use clock::FixedClock;
#[cfg(any(test, feature = "test-fixtures"))]
pub use nonce::SeededNonceSource;
pub use nonce::NONCE_BYTES;

// RFC 9421 response verification via the shared client-core seam (the client-facing
// entry point: verify the server's RFC 9421 signature + the request binding).
pub use mcp_re_client_core::verify_signed_response;
pub use mcp_re_client_core::ResponseExpectation;
pub use mcp_re_core::McpReError;
pub use mcp_re_core::TrustResolver;
