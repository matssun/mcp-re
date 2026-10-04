// SPDX-License-Identifier: Apache-2.0
//! Producer side of the proof path: sign a request / a response.
//!
//! The signer is the sole author of `Content-Digest`, `Signature-Input`, and
//! `Signature` — caller-supplied values for those headers are overwritten, so
//! the emitted evidence always matches the body actually carried (mirrors the
//! HostSigner sole-author rule for the native envelope).

use mcp_re_core::SigningKey;

use crate::block::ActorIdentity;
use crate::block::HttpResponseEvidenceBlock;
use crate::block::RequestEvidenceDigest;
use crate::body::insert_meta_block;
use crate::digest::content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::ids::ALG_ED25519;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUIRED_RESPONSE_COMPONENTS;
use crate::ids::REQUIRED_RESPONSE_REQ_COMPONENTS;
use crate::ids::RESPONSE_EVIDENCE_BLOCK_KEY;
use crate::ids::RESPONSE_LABEL;
use crate::message::reject_content_encoding;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::sigbase::signature_base;
use crate::sigbase::CoveredComponent;
use crate::sigbase::SignatureParams;
use crate::sigbase::SourceMessage;

mod request;
pub(crate) use request::conditional_request_components;
pub use request::sign_request;
pub use request::sign_request_as_given;
pub use request::sign_request_full;
pub use request::sign_request_full_with_signer;
pub use request::sign_request_with_signer;

pub(crate) fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
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
/// signature encoding, and header assembly stay owned by the profile. The
/// bodyless signers are its crate-wide consumers.
pub(crate) fn emit_signature(
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
        format!("{label}={}", params.serialize_with(components)?),
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
pub(crate) fn local_sig(key: &SigningKey, base: &[u8]) -> Result<Vec<u8>, HttpProfileError> {
    mcp_re_core::b64url_decode(&key.sign(base)).map_err(|_| HttpProfileError::InvalidSignature)
}

/// Full-profile response signing for the DELEGATED-key path (ADR-MCPRE-052 §2,
/// MCPRE-122). The response evidence block
/// carries the inline `server_delegation` credential (protected by
/// `content-digest`) and the response is signed by the DELEGATED key
/// (`delegated_kid` == the block's `server_signer.keyid`). The root is NOT on this
/// path: it signed only the credential, off the hot path at issuance/rotation.
#[allow(clippy::too_many_arguments)]
pub fn sign_delegated_response_full_with_owned_key(
    response: &mut HttpResponse,
    request: &HttpRequest,
    server_signer: &ActorIdentity,
    server_delegation: &str,
    delegated_key: &SigningKey,
    delegated_kid: &str,
    created: i64,
    expires: i64,
) -> Result<Vec<u8>, HttpProfileError> {
    let request_evidence = crate::verify::bound_request::request_evidence_of(request)?;
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
    // Sign directly through the signer seam (not `sign_response`) so the exact
    // response signature-base is returned to the caller: the delegated serving path
    // records it as the input-required-response base an MRTR continuation binds to
    // (ADR-MCPS-047).
    sign_response_with_signer(
        response,
        request,
        |base| local_sig(delegated_key, base),
        delegated_kid,
        created,
        expires,
    )
}

/// Full-profile response signing for the DELEGATED-key path with NO request
/// binding (ADR-MCPRE-052; the preflight-unbound rejection case, MCPRE-122). Like
/// [`sign_delegated_response_full_with_owned_key`], a delegated-key sibling of
/// [`sign_response_unbound`]: the response evidence block carries the inline
/// `server_delegation` credential and the response is signed by the DELEGATED key,
/// but the signature covers only the response components (`@status`,
/// `content-digest`, `content-type`) — no `;req`. `request_evidence_diagnostic` is
/// recorded in the block for diagnostics ONLY; an unbound response is verified
/// response-only and this handle is never treated as a trusted request binding.
#[allow(clippy::too_many_arguments)]
pub fn sign_delegated_response_unbound_with_owned_key(
    response: &mut HttpResponse,
    server_signer: &ActorIdentity,
    server_delegation: &str,
    request_evidence_diagnostic: &RequestEvidence,
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
            digest_alg: request_evidence_diagnostic.digest_alg.clone(),
            digest_value: request_evidence_diagnostic.digest_value.clone(),
        },
    };
    response.body = insert_meta_block(&response.body, RESPONSE_EVIDENCE_BLOCK_KEY, &block)?;
    sign_response_unbound(response, delegated_key, delegated_kid, created, expires)
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
) -> Result<Vec<u8>, HttpProfileError> {
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
    )?;
    // Return the exact response signature-base bytes so the delegated serving path
    // can record the input-required-response base an MRTR continuation binds to
    // (ADR-MCPS-047). Not secret — derived from the public message.
    Ok(base)
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

#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "delegated-kid-1";

    fn signed(preloaded: &[(&str, &str)]) -> HttpResponse {
        let key = SigningKey::from_seed_bytes(&[0x11; 32]);
        let signer = ActorIdentity {
            role: "server".to_owned(),
            trust_domain: "example.test".to_owned(),
            subject: "srv-1".to_owned(),
            keyid: KID.to_owned(),
        };
        let evidence = RequestEvidence {
            digest_alg: "none".into(),
            digest_value: String::new(),
        };
        let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        headers.extend(
            preloaded
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        let mut response = HttpResponse {
            status: 200,
            headers,
            body: br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec(),
        };
        sign_delegated_response_unbound_with_owned_key(
            &mut response,
            &signer,
            "credential",
            &evidence,
            &key,
            KID,
            1_700_000_000,
            1_700_000_300,
        )
        .expect("emission succeeds");
        response
    }

    fn matching<'a>(response: &'a HttpResponse, name: &str) -> Vec<&'a str> {
        response
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    #[test]
    fn caller_supplied_digest_and_signature_headers_do_not_survive_emission() {
        let response = signed(&[
            ("content-digest", "sha-256=:AAAA:"),
            ("SIGNATURE-INPUT", "mcp-re-response=()"),
            ("signature", "mcp-re-response=:AAAA:"),
        ]);
        let callers = [
            ("Content-Digest", "sha-256=:AAAA:"),
            ("Signature-Input", "mcp-re-response=()"),
            ("Signature", "mcp-re-response=:AAAA:"),
        ];
        for (name, supplied) in callers {
            let found = matching(&response, name);
            assert_eq!(found.len(), 1, "{name} must appear exactly once");
            assert_ne!(found[0], supplied, "{name} must be the emitted value");
        }
        assert_eq!(
            matching(&response, "Content-Digest")[0],
            content_digest_sha256(&response.body)
        );
    }

    fn bound_signer_inputs() -> (HttpRequest, HttpResponse, ActorIdentity, SigningKey) {
        let request = HttpRequest {
            method: "POST".to_owned(),
            target_uri: "https://mcp.example.test/mcp".to_owned(),
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
        };
        let response = HttpResponse {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec(),
        };
        let signer = ActorIdentity {
            role: "server".to_owned(),
            trust_domain: "example.test".to_owned(),
            subject: "srv-1".to_owned(),
            keyid: KID.to_owned(),
        };
        (
            request,
            response,
            signer,
            SigningKey::from_seed_bytes(&[0x11; 32]),
        )
    }

    #[test]
    fn a_bound_response_advertises_the_handle_of_the_request_it_answers() {
        let (mut request, mut response, signer, key) = bound_signer_inputs();
        let handle = sign_request(
            &mut request,
            &SigningKey::from_seed_bytes(&[0x22; 32]),
            "client-key-1",
            1_700_000_000,
            1_700_000_300,
            "nonce-1",
        )
        .expect("request signs");
        sign_delegated_response_full_with_owned_key(
            &mut response,
            &request,
            &signer,
            "credential",
            &key,
            KID,
            1_700_000_000,
            1_700_000_300,
        )
        .expect("response signs");
        let body: serde_json::Value = serde_json::from_slice(&response.body).expect("body is JSON");
        assert_eq!(
            body["_meta"][RESPONSE_EVIDENCE_BLOCK_KEY]["request_evidence"]["digest_value"],
            handle.digest_value
        );
    }

    #[test]
    fn an_unsigned_request_cannot_be_answered_with_a_bound_response() {
        let (request, mut response, signer, key) = bound_signer_inputs();
        let before = response.clone();
        let err = sign_delegated_response_full_with_owned_key(
            &mut response,
            &request,
            &signer,
            "credential",
            &key,
            KID,
            1_700_000_000,
            1_700_000_300,
        )
        .expect_err("a request with no signature has no handle");
        assert_eq!(
            err,
            HttpProfileError::MissingEvidence("request signature-input")
        );
        assert_eq!(response.body, before.body);
        assert_eq!(response.headers, before.headers);
    }

    #[test]
    fn the_delegated_response_block_is_inside_the_digested_body() {
        let response = signed(&[]);
        let body: serde_json::Value = serde_json::from_slice(&response.body).expect("body is JSON");
        assert_eq!(
            body["_meta"][RESPONSE_EVIDENCE_BLOCK_KEY]["server_signer"]["keyid"],
            KID
        );
        assert_eq!(
            matching(&response, "Content-Digest")[0],
            content_digest_sha256(&response.body)
        );
    }
}
