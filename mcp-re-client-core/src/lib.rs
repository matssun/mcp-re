// SPDX-License-Identifier: Apache-2.0
//! MCP-RE client-side core — the shared RFC 9421 evidence seam consumed by the
//! local client proxy and the SDK (ADR-MCPS-044 §`mcp-re-client-core`).
//!
//! Client-side mirror of the proxy's `verify_request_full` / `sign_response_full`:
//! it constructs a signed **RFC 9421 + RFC 9530** request ([`build_signed_request`])
//! and verifies the bound signed response ([`verify_signed_response`]). There is NO
//! object/JCS `_meta` signature and NO canonicalization preimage anywhere in this
//! crate — the sole carrier is RFC 9421 HTTP Message Signatures + RFC 9530
//! Content-Digest (ADR-MCPRE-050).
//!
//! It depends only on `mcp-re-http-profile` (the carrier) and `mcp-re-core`'s
//! profile-agnostic primitives; it pulls in NO networking/async/fs crate (those are
//! the mode-specific layers above this seam).
//!
//! ## PURGE 2026-07-11 — object/JCS deleted, RFC 9421 rebuild in progress
//! The object-era client policy modules — `authz` (binding providers), `signer`
//! (custody policy), `correlation` (MRT store), `discovery`, `enforcement`,
//! `audit`, `audience` — were built on the deleted draft-02 object model. They are
//! **deferred** from the build (files retained) and rebuilt on RFC 9421 evidence in
//! a follow-up slice; the request/response evidence seam below is the working core.

pub mod request;
pub mod response;

pub use request::build_signed_request;
pub use request::build_signed_request_with_signer;
pub use request::build_signed_tool_call;
pub use request::RequestSigningInputs;
pub use request::SignedRequest;
pub use response::classify_result;
pub use response::verify_and_classify_response;
pub use response::verify_signed_response;
pub use response::ClassifiedResponse;
pub use response::ResponseExpectation;
pub use response::ResultClass;

// Re-export the RFC 9421 carrier types callers construct/consume, so the proxy and
// SDK depend on ONE evidence vocabulary through this seam.
pub use mcp_re_http_profile::ArtifactBinding;
pub use mcp_re_http_profile::ArtifactType;
pub use mcp_re_http_profile::AudienceTuple;
pub use mcp_re_http_profile::BindingType;
pub use mcp_re_http_profile::HttpContinuation;
pub use mcp_re_http_profile::HttpProfileError;
pub use mcp_re_http_profile::HttpRequest;
pub use mcp_re_http_profile::HttpResponse;
pub use mcp_re_http_profile::RequestEvidence;
pub use mcp_re_http_profile::ResolvedActor;
pub use mcp_re_http_profile::SignerSlot;
pub use mcp_re_http_profile::VerifiedHttpResponseEvidence;
