// SPDX-License-Identifier: Apache-2.0
//! MCP-RE client-side core — the shared RFC 9421 evidence seam consumed by the
//! local client proxy and the SDK (ADR-MCPS-044 §`mcp-re-client-core`).
//!
//! Client-side mirror of the proxy's `verify_request_full` / `sign_response_full`:
//! it constructs a signed **RFC 9421 + RFC 9530** request ([`build_signed_request`])
//! and verifies the bound signed response ([`verify_signed_response`]). The sole
//! carrier is RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest
//! (ADR-MCPRE-050) — the signature rides in the HTTP `Signature`/`Signature-Input`
//! and `Content-Digest` headers, not a JSON-RPC `_meta` block.
//!
//! It depends only on `mcp-re-http-profile` (the carrier) and `mcp-re-core`'s
//! profile-agnostic primitives; it pulls in NO networking/async/fs crate (those are
//! the mode-specific layers above this seam).
//!
//! ## Deferred client policy modules (RFC 9421 rebuild in progress)
//! These client policy modules — `authz` (binding providers), `signer`
//! (custody policy), `correlation` (MRT store), `discovery`, `enforcement`,
//! `audit`, `audience` — were built on the deleted draft-02 object model. They are
//! **deferred** from the build (files retained) and rebuilt on RFC 9421 evidence in
//! a follow-up slice; the request/response evidence seam below is the working core.

// ADR-MCPRE-061 Amendment 1 §3.1 — this crate holds no production `unsafe`, and `forbid`
// (unlike `deny`) cannot be overridden by an inner `#[allow]` anywhere in it. Acquiring
// `unsafe` here means deleting this line: an architectural decision, reviewed as one.
#![forbid(unsafe_code)]
pub mod binding_spec;
mod delegated_evidence;
mod delegated_trust;
mod delegation_policy;
/// What a verified rejection receipt says about whether the work ran (ADR-MCPRE-058 §10).
mod execution_contract;
pub mod request;
pub mod request_signing_inputs;
pub mod response;
/// What an MCP result MEANS — as distinct from whether the message carrying it is genuine.
mod result_classification;
pub mod trust_manifest;

pub use binding_spec::build_authorization;
pub use binding_spec::BindingForm;
pub use binding_spec::BindingSpec;
pub use binding_spec::BindingSpecRefusal;
pub use binding_spec::ProvidedAuthorization;
pub use delegated_evidence::DelegatedResponseEvidence;
pub use delegated_trust::CompositeResponseTrust;
pub use delegated_trust::DelegatedResponseTrust;
pub use delegated_trust::RevocationSource;
pub use delegated_trust::StaticRevocationList;
pub use delegated_trust::TrustedIssuerSet;
pub use delegation_policy::DelegationPolicy;
pub use execution_contract::ExecutionContract;
pub use execution_contract::ExecutionStatus;
pub use execution_contract::RetrySafety;
pub use request::build_signed_notification;
pub use request::build_signed_notification_with_signer;
pub use request::build_signed_request;
pub use request::build_signed_request_with_signer;
pub use request::build_signed_tool_call;
pub use request::SignedRequest;
pub use request::MIN_NONCE_CHARS;
pub use request_signing_inputs::RequestSigningInputs;
pub use response::verify_and_classify_response;
pub use response::verify_delegated_accepted_202;
pub use response::verify_delegated_response;
pub use response::verify_signed_response;
pub use response::DelegatedOutcome;
pub use response::ResponseExpectation;
pub use response::VerifiedDelegatedResponse;
pub use result_classification::classify_result;
pub use result_classification::continuation_state;
pub use result_classification::ClassifiedResponse;
pub use result_classification::ResultClass;
pub use trust_manifest::load_signed_manifest;
pub use trust_manifest::load_signed_manifest_with_floor;
pub use trust_manifest::sign_manifest;
pub use trust_manifest::InMemoryVersionFloor;
pub use trust_manifest::LoadedTrustAnchors;
pub use trust_manifest::ManifestIssuer;
pub use trust_manifest::ManifestVersionFloor;
pub use trust_manifest::RetiringIssuer;
pub use trust_manifest::SignedTrustAnchorManifest;
pub use trust_manifest::TrustAnchorManifest;
pub use trust_manifest::TrustManifestError;

// Re-export the RFC 9421 carrier types callers construct/consume, so the proxy and
// SDK depend on ONE evidence vocabulary through this seam.
pub use mcp_re_http_profile::result_class::INPUT_REQUIRED_RESULT_TYPE;
pub use mcp_re_http_profile::ActorIdentity;
pub use mcp_re_http_profile::ArtifactBinding;
pub use mcp_re_http_profile::ArtifactType;
pub use mcp_re_http_profile::AudienceTuple;
pub use mcp_re_http_profile::BindingType;
pub use mcp_re_http_profile::HttpContinuation;
pub use mcp_re_http_profile::HttpProfileError;
pub use mcp_re_http_profile::HttpRequest;
pub use mcp_re_http_profile::HttpResponse;
pub use mcp_re_http_profile::RequestEvidence;
pub use mcp_re_http_profile::RequestEvidenceDigest;
pub use mcp_re_http_profile::ResolvedActor;
pub use mcp_re_http_profile::ResolverOutcome;
pub use mcp_re_http_profile::SignerSlot;
pub use mcp_re_http_profile::VerifiedMcpResponse;
pub use mcp_re_http_profile::PROFILE_TAG;
