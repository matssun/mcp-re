// SPDX-License-Identifier: Apache-2.0
//! MCP-RE client-side ambassador (MCPS-014, ADR-MCPS-003), on the RFC 9421 carrier.
//!
//! The host is the agent's local key/actor context. It composes and signs the
//! MCP-RE request evidence ([`HostSigner`], via the `mcp-re-client-core` RFC 9421
//! seam) and verifies signed server responses (re-exported
//! [`verify_delegated_response`] — delegated-required is the only response-signing
//! mode). The language model never holds private keys or constructs signatures.
//!
//! ## Deferred host modules (RFC 9421 rebuild in progress)
//! The `session` (HostSession), `verified_result`, and `pending`
//! (request_hash correlation) modules were built on the deleted draft-01/object
//! model. They are **deferred** (files retained) and rebuilt on RFC 9421 evidence in
//! a follow-up; the signer + clock/nonce fixtures below are the working surface.

// ADR-MCPRE-061 Amendment 1 §3.1 — this crate holds no production `unsafe`, and `forbid`
// (unlike `deny`) cannot be overridden by an inner `#[allow]` anywhere in it. Acquiring
// `unsafe` here means deleting this line: an architectural decision, reviewed as one.
#![forbid(unsafe_code)]
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

// RFC 9421 response verification via the shared client-core seam. Delegated-required
// is the only response-signing mode (ADR-MCPRE-052), so the delegated verifier is the
// client-facing entry point: it requires an inline delegation credential chaining to a
// trusted root, consults the revocation seam, and applies the trust-epoch gate.
//
// The pre-052 direct-root verifier is GONE rather than merely unexported. It accepted a
// response signed directly by any key the injected resolver returned for the Response
// slot — no credential chain, no revocation seam on that call — which is exactly the
// downgrade delegated-required forbids. This note used to say it was retained for
// negative-test fixtures; a measurement found no such fixture, and no caller anywhere,
// so what the public API preserved was an unselected second security contract that
// contradicted this one. Removed in the ADR-MCPRE-067 closure.
pub use mcp_re_client_core::verify_delegated_response;
pub use mcp_re_client_core::DelegatedOutcome;
pub use mcp_re_client_core::DelegationPolicy;
pub use mcp_re_client_core::ResponseExpectation;
pub use mcp_re_client_core::RevocationSource;
pub use mcp_re_client_core::StaticRevocationList;
pub use mcp_re_core::McpReError;
pub use mcp_re_core::TrustResolver;
