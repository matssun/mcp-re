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

/// Bytes in a raw Ed25519 signature (RFC 8032). The external-signer seam MUST
/// return exactly this — a KMS/HSM that hands back a DER-wrapped or truncated
/// signature is a contract violation, caught here rather than emitted as a
/// malformed `Signature` header.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Shared signing tail: obtain the raw signature over `base` via `sign_base`,
/// enforce the Ed25519 length, then emit the `Signature-Input` and `Signature`
/// headers under `label`. Every signer — the local-key path and the external
/// KMS/HSM custody seam alike — routes through here, so base construction,
/// signature encoding, and header assembly stay owned by the profile.
fn emit_signature(
    headers: &mut Vec<(String, String)>,
    label: &str,
    components: &[CoveredComponent],
    params: &SignatureParams,
    base: &[u8],
    sign_base: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
) -> Result<(), HttpProfileError> {
    let sig_bytes = sign_base(base)?;
    if sig_bytes.len() != ED25519_SIGNATURE_LEN {
        return Err(HttpProfileError::InvalidSignature);
    }
    set_header(
        headers,
        "Signature-Input",
        format!("{label}={}", params.serialize_with(components)),
    );
    set_header(
        headers,
        "Signature",
        format!("{label}=:{}:", base64_standard_encode(&sig_bytes)),
    );
    Ok(())
}

/// The local-key signer closure: sign `base` with `key` and return the RAW
/// Ed25519 bytes. The core signer emits base64url; decode so the seam's contract
/// (raw 64-byte signature) holds identically for local and external signers.
fn local_sig(key: &SigningKey, base: &[u8]) -> Result<Vec<u8>, HttpProfileError> {
    mcp_re_core::b64url_decode(&key.sign(base)).map_err(|_| HttpProfileError::InvalidSignature)
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

/// Sign `request` in place with a local in-process [`SigningKey`]: emit
/// `Content-Digest`, `Signature-Input`, and `Signature` (label `mcp-re`, tag
/// `mcp-re-http-v1`). Returns the [`RequestEvidence`] handle derived from the
/// exact signature base. A thin local-key wrapper over
/// [`sign_request_with_signer`].
pub fn sign_request(
    request: &mut HttpRequest,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
    nonce: &str,
) -> Result<RequestEvidence, HttpProfileError> {
    sign_request_with_signer(
        request,
        |base| local_sig(key, base),
        key_id,
        created,
        expires,
        nonce,
    )
}

/// Sign `request` in place with an EXTERNAL signer (Cloud KMS / HSM custody).
///
/// Additive, wire-identical to [`sign_request`]: the profile owns
/// `Content-Digest`, covered-component selection, the RFC 9421 signature base,
/// signature encoding, and header assembly — only the private-key operation is
/// delegated. `sign_base` receives the EXACT signature-base bytes and MUST return
/// exactly the 64 raw Ed25519 signature bytes (enforced; a DER-wrapped or
/// truncated return is rejected as `invalid_signature`). This is the seam a
/// production deployment uses to keep the signing key in a KMS/HSM where it never
/// enters the process.
pub fn sign_request_with_signer(
    request: &mut HttpRequest,
    sign_base: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
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
    emit_signature(
        &mut request.headers,
        REQUEST_LABEL,
        &components,
        &params,
        &base,
        sign_base,
    )?;
    Ok(RequestEvidence::from_signature_base(&base))
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
        // Directly root-signed response; the delegated-signing path (ADR-MCPRE-052,
        // MCPRE-122 custody slice) populates this.
        server_delegation: None,
        request_evidence: RequestEvidenceDigest {
            digest_alg: request_evidence.digest_alg.clone(),
            digest_value: request_evidence.digest_value.clone(),
        },
    };
    response.body = insert_meta_block(&response.body, RESPONSE_EVIDENCE_BLOCK_KEY, &block)?;
    sign_response(response, request, key, key_id, created, expires)
}

/// Full-profile response signing for the DELEGATED-key path (ADR-MCPRE-052 §2,
/// MCPRE-122). Like [`sign_response_full`] except the response evidence block
/// carries the inline `server_delegation` credential (protected by
/// `content-digest`) and the response is signed by the DELEGATED key
/// (`delegated_kid` == the block's `server_signer.keyid`). The root is NOT on this
/// path: it signed only the credential, off the hot path at issuance/rotation.
#[allow(clippy::too_many_arguments)]
pub fn sign_delegated_response_full(
    response: &mut HttpResponse,
    request: &HttpRequest,
    request_evidence: &RequestEvidence,
    server_signer: &ActorIdentity,
    server_delegation: &str,
    delegated_key: &SigningKey,
    delegated_kid: &str,
    created: i64,
    expires: i64,
) -> Result<(), HttpProfileError> {
    let block = HttpResponseEvidenceBlock {
        profile: PROFILE_TAG.to_owned(),
        server_signer: server_signer.clone(),
        server_delegation: Some(server_delegation.to_owned()),
        request_evidence: RequestEvidenceDigest {
            digest_alg: request_evidence.digest_alg.clone(),
            digest_value: request_evidence.digest_value.clone(),
        },
    };
    response.body = insert_meta_block(&response.body, RESPONSE_EVIDENCE_BLOCK_KEY, &block)?;
    sign_response(
        response,
        request,
        delegated_key,
        delegated_kid,
        created,
        expires,
    )
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
    sign_response_with_signer(
        response,
        request,
        |base| local_sig(key, base),
        key_id,
        created,
        expires,
    )
}

/// Sign `response` in place with an EXTERNAL signer (Cloud KMS / HSM custody),
/// bound to `request` via the `;req` components. Additive, wire-identical to
/// [`sign_response`]: `sign_base` receives the exact RFC 9421 signature base and
/// MUST return exactly the 64 raw Ed25519 signature bytes (enforced).
pub fn sign_response_with_signer(
    response: &mut HttpResponse,
    request: &HttpRequest,
    sign_base: impl FnOnce(&[u8]) -> Result<Vec<u8>, HttpProfileError>,
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
    emit_signature(
        &mut response.headers,
        RESPONSE_LABEL,
        &components,
        &params,
        &base,
        sign_base,
    )
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
    emit_signature(
        &mut response.headers,
        RESPONSE_LABEL,
        &components,
        &params,
        &base,
        |b| local_sig(key, b),
    )
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
