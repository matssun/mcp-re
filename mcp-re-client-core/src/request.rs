// SPDX-License-Identifier: Apache-2.0
//! RFC 9421 signed request construction (ADR-MCPRE-050, MCPRE-101).
//!
//! Client-side mirror of the proxy's `verify_request_full`: given an ordinary MCP
//! request (method + params) plus the signing inputs (signer/audience/artifact
//! bindings/freshness), it composes the HTTP-profile request evidence block into
//! the JSON-RPC body `_meta` (protected by the covered `Content-Digest`) and signs
//! the RFC 9421 HTTP Message Signature over the reconstructed `HttpRequest`.
//!
//! The signed evidence is `Signature`/`Signature-Input` (RFC 9421) + `Content-Digest`
//! (RFC 9530) on the HTTP message, not a JSON-RPC `_meta` block. The returned
//! [`SignedRequest`] exposes the
//! resulting [`RequestEvidence`] handle so the caller can bind the signed response
//! (`response.request_evidence == request.evidence`).
//!
//! Purity: this module builds and signs in-process only. Nonce generation, clock
//! reads, key custody, and transport live in the mode-specific layers above this
//! seam (ADR-MCPS-044).

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_request_full_with_signer;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::PROFILE_TAG;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

/// The already-resolved inputs for one RFC 9421 signed request.
///
/// Every field is a value the mode-specific layer has already produced: the signer
/// key id (from the key-custody layer), the resolved [`AudienceTuple`] (audience id
/// + `@target-uri` + optional route — MCPS-43), the required, non-empty artifact
/// bindings (from an authorization-binding provider — MCPS-45), and the freshness
/// triple `nonce`/`created`/`expires` (RFC 9421 signature parameters, Unix seconds).
#[derive(Debug, Clone)]
pub struct RequestSigningInputs {
    /// Identifier of the signing key (named in the RFC 9421 `keyid`; never the key).
    pub key_id: String,
    /// The resolved audience tuple (verifier id + absolute `@target-uri` + route).
    pub audience: AudienceTuple,
    /// The authorization/artifact bindings bound into the signed evidence block.
    /// Required, non-empty — a request with no binding fails validation closed.
    pub artifact_bindings: Vec<ArtifactBinding>,
    /// Opaque anti-replay nonce (>= 128 bits entropy), already drawn (RFC 9421
    /// `nonce`).
    pub nonce: String,
    /// Signature creation time, Unix seconds (RFC 9421 `created`).
    pub created: i64,
    /// Signature expiry time, Unix seconds (RFC 9421 `expires`).
    pub expires: i64,
    /// Optional multi-round-trip continuation binding (ADR-MCPS-047). `None` for an
    /// ordinary first-round request. Set via [`RequestSigningInputs::with_continuation`].
    pub continuation: Option<HttpContinuation>,
    /// Additional request headers to include (and cover) in the signed HTTP request
    /// — e.g. `Authorization: Bearer <token>` whose bytes an OAuth-DPoP artifact
    /// binding digests. Empty by default. Set via [`RequestSigningInputs::with_headers`].
    pub extra_headers: Vec<(String, String)>,
}

impl RequestSigningInputs {
    /// Build inputs for an ordinary first-round request.
    pub fn new(
        key_id: impl Into<String>,
        audience: AudienceTuple,
        artifact_bindings: Vec<ArtifactBinding>,
        nonce: impl Into<String>,
        created: i64,
        expires: i64,
    ) -> Self {
        RequestSigningInputs {
            key_id: key_id.into(),
            audience,
            artifact_bindings,
            nonce: nonce.into(),
            created,
            expires,
            continuation: None,
            extra_headers: Vec::new(),
        }
    }

    /// Add request headers to include AND cover in the signature (e.g. an
    /// `Authorization: Bearer` header an OAuth-DPoP artifact binding digests).
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.extra_headers = headers;
        self
    }

    /// Bind this request to the verified `InputRequiredResult` it answers
    /// (ADR-MCPS-047): the continuation rides inside the signed evidence block.
    pub fn with_continuation(mut self, continuation: HttpContinuation) -> Self {
        self.continuation = Some(continuation);
        self
    }

    /// The HTTP-profile request evidence block this input set authors.
    fn evidence_block(&self) -> HttpRequestEvidenceBlock {
        HttpRequestEvidenceBlock {
            profile: PROFILE_TAG.to_owned(),
            audience: self.audience.clone(),
            artifact_bindings: self.artifact_bindings.clone(),
            continuation: self.continuation.clone(),
            admission: None,
        }
    }
}

/// A fully signed RFC 9421 request: the reconstructed [`HttpRequest`] (method +
/// `@target-uri` + headers carrying `Signature`/`Signature-Input`/`Content-Digest`
/// + body with the composed evidence block) plus the [`RequestEvidence`] handle
/// that binds a later signed response.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    request: HttpRequest,
    evidence: RequestEvidence,
}

impl SignedRequest {
    /// The signed HTTP request (method, `@target-uri`, headers, body) to send.
    pub fn request(&self) -> &HttpRequest {
        &self.request
    }

    /// The serialized JSON-RPC request body bytes.
    pub fn body(&self) -> &[u8] {
        &self.request.body
    }

    /// The signed request headers (RFC 9421 `Signature`/`Signature-Input`, RFC 9530
    /// `Content-Digest`) to place on the outbound HTTP request.
    pub fn headers(&self) -> &[(String, String)] {
        &self.request.headers
    }

    /// The [`RequestEvidence`] handle (digest over the RFC 9421 signature base) that
    /// binds a later signed response (`response.request_evidence == this`).
    pub fn evidence(&self) -> &RequestEvidence {
        &self.evidence
    }

    /// Consume the signed request, returning the owned [`HttpRequest`].
    pub fn into_request(self) -> HttpRequest {
        self.request
    }
}

/// Construct and sign an RFC 9421 MCP-RE request with a local in-process key.
///
/// `id`/`method`/`params` are the ordinary MCP request fields. `target_uri` is the
/// canonical absolute `@target-uri` both sides sign over (must equal
/// `inputs.audience.target_uri`). Any caller-supplied top-level `_meta` request
/// evidence block is OVERWRITTEN — the client core is the sole author of the block.
pub fn build_signed_request(
    id: &Value,
    method: &str,
    params: Map<String, Value>,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    signing_key: &SigningKey,
) -> Result<SignedRequest, HttpProfileError> {
    build_signed_request_with(id, method, params, target_uri, inputs, |request, block| {
        sign_request_full(
            request,
            block,
            signing_key,
            &inputs.key_id,
            inputs.created,
            inputs.expires,
            &inputs.nonce,
        )
    })
}

/// The shared request-construction core, generic over HOW the RFC 9421 message is
/// signed. `sign` receives the reconstructed [`HttpRequest`] (body already the
/// clean JSON-RPC) and the evidence block, composes + signs, and returns the
/// [`RequestEvidence`]. This is the single seam every signing mechanism (in-process
/// key, KMS/HSM via [`sign_request_with_signer`], delegated service) flows through.
pub(crate) fn build_signed_request_with(
    id: &Value,
    method: &str,
    params: Map<String, Value>,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    sign: impl FnOnce(
        &mut HttpRequest,
        &HttpRequestEvidenceBlock,
    ) -> Result<RequestEvidence, HttpProfileError>,
) -> Result<SignedRequest, HttpProfileError> {
    // The @target-uri the client signs MUST match the audience tuple's target_uri
    // (the verifier cross-checks them); a mismatch is a client misconfiguration —
    // fail closed rather than emit evidence that can never verify.
    if target_uri != inputs.audience.target_uri {
        return Err(HttpProfileError::AudienceMismatch);
    }

    // Scrub any caller-supplied top-level `_meta` so the client core is the sole
    // author of the evidence block (sign_request_full composes it in).
    let mut params = params;
    params.remove("_meta");
    let body = serde_json::to_vec(&json!({
        "id": id.clone(),
        "jsonrpc": "2.0",
        "method": method,
        "params": Value::Object(params),
    }))
    .map_err(|_| HttpProfileError::MalformedEvidence("request body serialization"))?;

    let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
    headers.extend(inputs.extra_headers.iter().cloned());
    let mut request = HttpRequest {
        method: "POST".to_owned(),
        target_uri: target_uri.to_owned(),
        headers,
        body,
    };
    let block = inputs.evidence_block();
    let evidence = sign(&mut request, &block)?;
    Ok(SignedRequest { request, evidence })
}

/// Non-exporting-custody variant: sign the RFC 9421 request through an external
/// signer closure (Cloud KMS / HSM) that returns the raw 64-byte Ed25519 signature
/// over the exact signature base. Wire-identical to [`build_signed_request`].
pub fn build_signed_request_with_signer(
    id: &Value,
    method: &str,
    params: Map<String, Value>,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    sign_base: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<SignedRequest, HttpProfileError> {
    // sign_request_with_signer signs but does NOT compose the evidence block; the
    // full-profile client composes the block first, then signs over it.
    build_signed_request_with(id, method, params, target_uri, inputs, |request, block| {
        sign_request_full_with_signer(
            request,
            block,
            sign_base,
            &inputs.key_id,
            inputs.created,
            inputs.expires,
            &inputs.nonce,
        )
    })
}

/// Convenience for the common `tools/call` case.
pub fn build_signed_tool_call(
    id: &Value,
    tool_name: &str,
    arguments: Value,
    target_uri: &str,
    inputs: &RequestSigningInputs,
    signing_key: &SigningKey,
) -> Result<SignedRequest, HttpProfileError> {
    let mut params = Map::new();
    params.insert("name".to_string(), Value::String(tool_name.to_string()));
    params.insert("arguments".to_string(), arguments);
    build_signed_request(id, "tools/call", params, target_uri, inputs, signing_key)
}
