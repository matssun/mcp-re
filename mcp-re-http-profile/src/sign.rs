// SPDX-License-Identifier: Apache-2.0
//! Producer side of the proof path: sign a request / a response.
//!
//! The signer is the sole author of `Content-Digest`, `Signature-Input`, and
//! `Signature` — caller-supplied values for those headers are overwritten, so
//! the emitted evidence always matches the body actually carried (mirrors the
//! HostSigner sole-author rule for the native envelope).

use mcp_re_core::SigningKey;

use crate::block::ActorIdentity;
use crate::block::HttpRequestEvidenceBlock;
use crate::block::HttpResponseEvidenceBlock;
use crate::block::RequestEvidenceDigest;
use crate::body::insert_meta_block;
use crate::digest::content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::ALG_ED25519;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::ids::REQUEST_LABEL;
use crate::ids::RESPONSE_EVIDENCE_BLOCK_KEY;
use crate::ids::REQUIRED_REQUEST_COMPONENTS;
use crate::ids::REQUIRED_RESPONSE_COMPONENTS;
use crate::ids::REQUIRED_RESPONSE_REQ_COMPONENTS;
use crate::ids::RESPONSE_LABEL;
use crate::message::reject_content_encoding;
use crate::message::single_header;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::sigbase::signature_base;
use crate::sigbase::CoveredComponent;
use crate::sigbase::SignatureParams;
use crate::sigbase::SourceMessage;

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    headers.push((name.to_owned(), value));
}

fn request_components(request: &HttpRequest) -> Result<Vec<CoveredComponent>, HttpProfileError> {
    let mut components: Vec<CoveredComponent> = REQUIRED_REQUEST_COMPONENTS
        .iter()
        .map(|n| CoveredComponent::new(n))
        .collect();
    // Conditional coverage (v0.11 grill B.1): bind the exact presented
    // credential surface when present, exactly-once enforced by lookup.
    if single_header(&request.headers, "authorization")?.is_some() {
        components.push(CoveredComponent::new("authorization"));
    }
    if single_header(&request.headers, "dpop")?.is_some() {
        components.push(CoveredComponent::new("dpop"));
    }
    Ok(components)
}

/// Sign `request` in place: emit `Content-Digest`, `Signature-Input`, and
/// `Signature` (label `mcp-re`, tag `mcp-re-http-v1`). Returns the
/// [`RequestEvidence`] handle derived from the exact signature base.
pub fn sign_request(
    request: &mut HttpRequest,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
    nonce: &str,
) -> Result<RequestEvidence, HttpProfileError> {
    reject_content_encoding(&request.headers)?;
    set_header(
        &mut request.headers,
        "Content-Digest",
        content_digest_sha256(&request.body),
    );

    let components = request_components(request)?;
    let params = SignatureParams {
        created: Some(created),
        expires: Some(expires),
        nonce: Some(nonce.to_owned()),
        keyid: Some(key_id.to_owned()),
        alg: Some(ALG_ED25519.to_owned()),
        tag: Some(PROFILE_TAG.to_owned()),
    };
    let base = signature_base(&components, &params, &SourceMessage::Request(request))?;
    let signature_b64url = key.sign(&base);
    // RFC 9421 wire form: the Signature byte sequence is standard base64; the
    // core signer returns base64url — transcode via the core codecs so the
    // bytes stay identical.
    let sig_bytes = mcp_re_core::b64url_decode(&signature_b64url)
        .map_err(|_| HttpProfileError::InvalidSignature)?;
    let evidence = RequestEvidence::from_signature_base(&base);

    set_header(
        &mut request.headers,
        "Signature-Input",
        format!("{REQUEST_LABEL}={}", params.serialize_with(&components)),
    );
    set_header(
        &mut request.headers,
        "Signature",
        format!("{REQUEST_LABEL}=:{}:", base64_standard_encode(&sig_bytes)),
    );
    Ok(evidence)
}

/// Full-profile request signing (MCPRE-101): compose the request evidence block
/// (`se.syncom/mcp-re.http.request`) into the JSON-RPC body `_meta` FIRST, then
/// sign — so `content-digest` (a covered component) protects the block. Returns
/// the [`RequestEvidence`] handle over the resulting signature base; pass it to
/// [`sign_response_full`] so the response can carry `request_evidence`.
pub fn sign_request_full(
    request: &mut HttpRequest,
    block: &HttpRequestEvidenceBlock,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
    nonce: &str,
) -> Result<RequestEvidence, HttpProfileError> {
    request.body = insert_meta_block(&request.body, REQUEST_EVIDENCE_BLOCK_KEY, block)?;
    sign_request(request, key, key_id, created, expires, nonce)
}

/// Full-profile response signing (MCPRE-101): compose the response evidence
/// block (`se.syncom/mcp-re.http.response`) carrying the `server_signer` identity
/// and the `request_evidence` this response answers into the body `_meta`, then
/// sign with the `;req` binding to `request`. `request_evidence` is the handle
/// [`sign_request_full`]/`verify_request_full` produced for the originating
/// request.
#[allow(clippy::too_many_arguments)]
pub fn sign_response_full(
    response: &mut HttpResponse,
    request: &HttpRequest,
    request_evidence: &RequestEvidence,
    server_signer: &ActorIdentity,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
) -> Result<(), HttpProfileError> {
    let block = HttpResponseEvidenceBlock {
        profile: PROFILE_TAG.to_owned(),
        server_signer: server_signer.clone(),
        request_evidence: RequestEvidenceDigest {
            digest_alg: request_evidence.digest_alg.clone(),
            digest_value: request_evidence.digest_value.clone(),
        },
    };
    response.body = insert_meta_block(&response.body, RESPONSE_EVIDENCE_BLOCK_KEY, &block)?;
    sign_response(response, request, key, key_id, created, expires)
}

/// Sign `response` in place, binding it to the verified originating request
/// via the `;req` components (v0.11 grill C.1). Label `mcp-re-response`, same
/// profile tag (E-1/E-2 — rejections reuse this path).
pub fn sign_response(
    response: &mut HttpResponse,
    request: &HttpRequest,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
) -> Result<(), HttpProfileError> {
    reject_content_encoding(&response.headers)?;
    set_header(
        &mut response.headers,
        "Content-Digest",
        content_digest_sha256(&response.body),
    );

    let mut components: Vec<CoveredComponent> = REQUIRED_RESPONSE_COMPONENTS
        .iter()
        .map(|n| CoveredComponent::new(n))
        .collect();
    components.extend(
        REQUIRED_RESPONSE_REQ_COMPONENTS
            .iter()
            .map(|n| CoveredComponent::req(n)),
    );
    let params = SignatureParams {
        created: Some(created),
        expires: Some(expires),
        nonce: None,
        keyid: Some(key_id.to_owned()),
        alg: Some(ALG_ED25519.to_owned()),
        tag: Some(PROFILE_TAG.to_owned()),
    };
    let base = signature_base(
        &components,
        &params,
        &SourceMessage::Response { response, request },
    )?;
    let signature_b64url = key.sign(&base);
    let sig_bytes = mcp_re_core::b64url_decode(&signature_b64url)
        .map_err(|_| HttpProfileError::InvalidSignature)?;

    set_header(
        &mut response.headers,
        "Signature-Input",
        format!("{RESPONSE_LABEL}={}", params.serialize_with(&components)),
    );
    set_header(
        &mut response.headers,
        "Signature",
        format!("{RESPONSE_LABEL}=:{}:", base64_standard_encode(&sig_bytes)),
    );
    Ok(())
}

/// Sign `response` in place with NO request binding — for a rejection emitted
/// before a request could be parsed (MCPRE-96). Covers only the response
/// components (`@status`, `content-digest`, `content-type`); no `;req`. Label
/// `mcp-re-response`, same profile tag.
pub fn sign_response_unbound(
    response: &mut HttpResponse,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
) -> Result<(), HttpProfileError> {
    reject_content_encoding(&response.headers)?;
    set_header(
        &mut response.headers,
        "Content-Digest",
        content_digest_sha256(&response.body),
    );

    let components: Vec<CoveredComponent> = REQUIRED_RESPONSE_COMPONENTS
        .iter()
        .map(|n| CoveredComponent::new(n))
        .collect();
    let params = SignatureParams {
        created: Some(created),
        expires: Some(expires),
        nonce: None,
        keyid: Some(key_id.to_owned()),
        alg: Some(ALG_ED25519.to_owned()),
        tag: Some(PROFILE_TAG.to_owned()),
    };
    let base = signature_base(&components, &params, &SourceMessage::ResponseOnly(response))?;
    let signature_b64url = key.sign(&base);
    let sig_bytes = mcp_re_core::b64url_decode(&signature_b64url)
        .map_err(|_| HttpProfileError::InvalidSignature)?;

    set_header(
        &mut response.headers,
        "Signature-Input",
        format!("{RESPONSE_LABEL}={}", params.serialize_with(&components)),
    );
    set_header(
        &mut response.headers,
        "Signature",
        format!("{RESPONSE_LABEL}=:{}:", base64_standard_encode(&sig_bytes)),
    );
    Ok(())
}

pub(crate) fn base64_standard_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}

pub(crate) fn base64_standard_decode(s: &str) -> Result<Vec<u8>, HttpProfileError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD
        .decode(s)
        .map_err(|_| HttpProfileError::InvalidSignature)
}
