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

pub mod admission;
pub mod artifact;
pub mod block;
pub mod bodyless;
pub mod body;
pub mod chain;
pub mod context;
pub mod custody;
pub mod delegation;
pub mod digest;
pub mod dispatch;
pub mod error;
pub mod evidence;
pub mod ids;
pub mod keyid;
pub mod mcp_transport;
pub mod message;
pub mod policy;
pub mod rejection;
pub mod scitt;
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
pub use block::HttpResponseEvidenceBlock;
pub use block::RequestEvidenceDigest;
pub use block::ResolvedActor;
pub use block::SignerSlot;
pub use block::CONTINUATION_TYPE_MCP_MRT;
pub use admission::check_admission;
pub use admission::issue_admission_assertion;
pub use admission::verify_admission_assertion;
pub use admission::AdmissionBinding;
pub use admission::AdmissionClaims;
pub use admission::AdmissionHeader;
pub use admission::AdmissionPolicy;
pub use admission::AdmissionStatus;
pub use admission::AuthoritativeAdmission;
pub use admission::VerifiedAdmission;
pub use chain::reconstruct_chain;
pub use chain::ChainLabel;
pub use chain::ChainReconstruction;
pub use chain::HopEvidence;
pub use chain::HopOutcome;
pub use chain::IncompleteReason;
pub use chain::RetainedHop;
pub use bodyless::sign_accepted_202;
pub use bodyless::sign_bodyless_request;
pub use bodyless::verify_accepted_202;
pub use bodyless::verify_bodyless_request;
pub use ids::BODYLESS_REQUEST_COMPONENTS;
pub use ids::BODYLESS_RESPONSE_COMPONENTS;
pub use ids::STATUS_ACCEPTED;
pub use context::extract_verified_context;
pub use context::insert_verified_context;
pub use context::strip_proxy_owned_meta;
pub use context::VerifiedContext;
pub use context::VerifiedContextPolicy;
pub use ids::VERIFIED_CONTEXT_BLOCK_KEY;
pub use body::authorization_bearer_bytes;
pub use body::extract_meta_block;
pub use body::insert_meta_block;
pub use custody::ActiveDelegatedKey;
pub use custody::CustodyConfig;
pub use custody::CustodyError;
pub use custody::DelegatedSigningCustody;
pub use custody::KeyLifecycleEvent;
pub use delegation::issue_delegation_credential;
pub use delegation::issue_delegation_credential_with_signer;
pub use delegation::verify_delegation_credential;
pub use delegation::Audience;
pub use delegation::Cnf;
pub use delegation::DelegatedJwk;
pub use delegation::DelegationClaims;
pub use delegation::DelegationHeader;
pub use delegation::DelegationVerifyParams;
pub use delegation::VerifiedDelegation;
pub use delegation::DELEGATION_ALG;
pub use delegation::DELEGATION_TYP;
pub use delegation::JWK_CRV_ED25519;
pub use delegation::JWK_KTY_OKP;
pub use delegation::KEY_USE_RESPONSE_SIGNING;
pub use digest::content_digest_sha256;
pub use dispatch::dispatch_request;
pub use dispatch::prepare_http_dispatch;
pub use dispatch::DispatchConfig;
pub use dispatch::DispatchError;
pub use dispatch::DispatchOutcome;
pub use dispatch::RetainedContinuation;
pub use error::HttpProfileError;
pub use evidence::RequestEvidence;
pub use ids::ALG_ED25519;
pub use ids::PROFILE_TAG;
pub use keyid::jwk_thumbprint_ed25519;
pub use mcp_transport::McpNameSource;
pub use mcp_transport::McpTransportPolicy;
pub use policy::ProfileAlgorithm;
pub use policy::VerifierPolicy;
pub use policy::DEFAULT_ALGORITHMS;
pub use ids::REQUEST_EVIDENCE_BLOCK_KEY;
pub use ids::REQUEST_LABEL;
pub use ids::RESPONSE_EVIDENCE_BLOCK_KEY;
pub use ids::RESPONSE_LABEL;
pub use message::HttpRequest;
pub use message::HttpResponse;
pub use scitt::issue_signed_statement;
pub use scitt::verify_receipt_offline;
pub use scitt::EvidenceCommitment;
pub use scitt::PrototypeTransparencyService;
pub use scitt::Receipt;
pub use scitt::SignedStatement;
pub use rejection::build_delegated_rejection;
pub use rejection::build_delegated_rejection_preflight;
pub use rejection::build_signed_rejection;
pub use rejection::verify_signed_rejection;
pub use rejection::RejectionReason;
pub use rejection::SignedRejection;
pub use rejection::JSON_RPC_ERROR_CODE;
pub use replay::HttpReplayKey;
pub use sigbase::CoveredComponent;
pub use sigbase::SignatureParams;
pub use sign::sign_request;
pub use sign::sign_request_full;
pub use sign::sign_request_full_with_signer;
pub use sign::sign_request_with_signer;
pub use sign::sign_delegated_response_full;
pub use sign::sign_delegated_response_unbound;
pub use sign::sign_response;
pub use sign::sign_response_full;
pub use sign::sign_response_with_signer;
pub use verify::verify_delegated_response_bound_full;
pub use verify::verify_delegated_response_full;
pub use verify::verify_delegated_response_unbound;
pub use verify::verify_request;
pub use verify::verify_request_full;
pub use verify::verify_request_full_with_policy;
pub use verify::verify_request_with_policy;
pub use verify::verify_response;
pub use verify::verify_response_bound_full;
pub use verify::verify_response_bound_full_with_policy;
pub use verify::verify_response_full;
pub use verify::verify_response_unbound_with_policy;
pub use verify::verify_response_with_policy;
pub use verify::DelegationExpectations;
pub use verify::VerifiedHttpRequestEvidence;
pub use verify::VerifiedHttpResponseEvidence;
