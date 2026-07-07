// SPDX-License-Identifier: Apache-2.0
//! MCP-RE HTTP standards profile — minimal proof path (ADR-MCPRE-050, seed Work Item 3).
//!
//! RFC 9421 HTTP Message Signatures + RFC 9530 `Content-Digest` as the
//! cryptographic carrier for MCP-RE over HTTP transports. This crate proves the
//! standards-profile security shape beside the native draft-02 profile:
//!
//! - request: `Content-Digest` (sha-256, unencoded content bytes) + Ed25519
//!   signature over the ratified covered components (`@method`, `@target-uri`,
//!   `content-digest`, `content-type`, plus `authorization`/`dpop` when present),
//!   label `mcp-re`, tag `mcp-re-http-v1`;
//! - response: signature over `@status`, `content-digest`, `content-type` plus
//!   the request components bound via RFC 9421 `;req`, label `mcp-re-response`,
//!   same profile tag;
//! - `request_evidence`: the compact evidence handle — SHA-256 over the
//!   request's signature base, split `{digest_alg, digest_value}` form
//!   (v0.11 grill E-5).
//!
//! Everything fails closed. No new MCP-RE header fields are minted (E-3): the
//! header surface is standard fields only; MCP evidence blocks travel in the
//! JSON-RPC body and are protected because `content-digest` is a covered
//! component.
//!
//! Scope of the proof path: signature-base construction, content binding,
//! response-to-request binding, freshness, and the negative battery from the
//! seed (body tamper, response splice, wrong content-digest, missing covered
//! component, stale window, wrong keyid). Replay-cache integration, artifact
//! bindings, signed rejections, and MRTR continuation reuse the existing
//! machinery and land with the full profile (ADR-MCPRE-050 parity gate).

pub mod artifact;
pub mod block;
pub mod digest;
pub mod error;
pub mod evidence;
pub mod ids;
pub mod message;
pub mod rejection;
pub mod replay;
pub mod sigbase;
pub mod sign;
pub mod verify;

pub use artifact::bearer_token;
pub use artifact::verify_artifact_binding;
pub use artifact::verify_dpop_ath;
pub use artifact::verify_mtls_x5t_s256;
pub use artifact::verify_rar_details;
pub use block::ActorIdentity;
pub use block::ArtifactBinding;
pub use block::ArtifactType;
pub use block::AudienceTuple;
pub use block::BindingType;
pub use block::HttpContinuation;
pub use block::HttpRequestEvidenceBlock;
pub use block::RequestEvidenceDigest;
pub use block::ResolvedActor;
pub use block::SignerSlot;
pub use block::CONTINUATION_TYPE_MCP_MRT;
pub use digest::content_digest_sha256;
pub use error::HttpProfileError;
pub use evidence::RequestEvidence;
pub use ids::ALG_ED25519;
pub use ids::PROFILE_TAG;
pub use ids::REQUEST_EVIDENCE_BLOCK_KEY;
pub use ids::REQUEST_LABEL;
pub use ids::RESPONSE_EVIDENCE_BLOCK_KEY;
pub use ids::RESPONSE_LABEL;
pub use message::HttpRequest;
pub use message::HttpResponse;
pub use rejection::build_signed_rejection;
pub use rejection::verify_signed_rejection;
pub use rejection::RejectionReason;
pub use rejection::SignedRejection;
pub use rejection::JSON_RPC_ERROR_CODE;
pub use replay::HttpReplayKey;
pub use sigbase::CoveredComponent;
pub use sigbase::SignatureParams;
pub use sign::sign_request;
pub use sign::sign_response;
pub use verify::verify_request;
pub use verify::verify_response;
pub use verify::VerifiedHttpRequestEvidence;
pub use verify::VerifiedHttpResponseEvidence;
