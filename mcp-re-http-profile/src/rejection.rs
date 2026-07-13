// SPDX-License-Identifier: Apache-2.0
//! Signed rejection receipts (ADR-MCPRE-050 §Threat Model + §Resolved-owner
//! ruling 2/6, MCPRE-96). The FIRST signed-rejection implementation anywhere in
//! MCP-RE.
//!
//! A rejection is an ordinary signed HTTP response carrying a JSON-RPC error
//! body. Its trust properties:
//!
//! - the STABLE machine signal is the wire code at
//!   `error.data.mcp_re_error.wire_code` — a frozen `mcp-re.*` token;
//! - `error.message` is human-readable and is NEVER trusted or parsed;
//! - the body is protected by RFC 9530 `Content-Digest`, covered by an RFC 9421
//!   response `Signature` (label `mcp-re-response`);
//! - when request context exists the response binds the request via `;req`
//!   (a rejection spliced onto a different request fails); a rejection emitted
//!   before a request could be parsed is signed response-only;
//! - HTTP status is a signed routing hint only; the wire code is authoritative.
//!
//! Under `require_mcp_re` a client MUST treat an unsigned or unverifiable
//! rejection as untrusted — [`verify_signed_rejection`] returns `Err`, which the
//! caller maps to its client-local `mcp-re.rejection_unsigned` posture.

use serde_json::json;
use serde_json::Value;

use mcp_re_core::SigningKey;

use crate::block::ActorIdentity;
use crate::block::ResolvedActor;
use crate::block::SignerSlot;
use crate::digest::content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::sign::sign_delegated_response_full;
use crate::sign::sign_delegated_response_unbound;
use crate::sign::sign_response;
use crate::sign::sign_response_unbound;
use crate::verify::verify_response;
use crate::verify::verify_response_unbound;

/// The JSON-RPC error code MCP-RE rejections carry (native-profile convention;
/// the wire code in `data`, not this integer, is the stable signal).
pub const JSON_RPC_ERROR_CODE: i64 = -32003;

/// A rejection reason: the stable frozen wire code plus a human-readable,
/// NON-authoritative message.
#[derive(Debug, Clone)]
pub struct RejectionReason {
    /// A frozen `mcp-re.*` wire code (typically `HttpProfileError::wire_code()`
    /// or `McpReError::wire_code()`).
    pub wire_code: &'static str,
    /// Human-readable diagnostic. NEVER trusted or parsed by clients.
    pub message: String,
}

/// The trusted result of verifying a signed rejection: the authoritative wire
/// code and the (advisory) HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRejection {
    pub wire_code: String,
    pub status: u16,
}

/// Build the JSON-RPC error body bytes for a rejection. `id` echoes the
/// rejected request's id when known (else JSON `null`).
fn rejection_body(id: Value, reason: &RejectionReason) -> Vec<u8> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": JSON_RPC_ERROR_CODE,
            "message": reason.message,
            "data": { "mcp_re_error": { "wire_code": reason.wire_code } }
        }
    });
    serde_json::to_vec(&body).expect("rejection body serializes")
}

/// Best-effort extraction of the JSON-RPC `id` from a request body (echoed into
/// the rejection). A body that does not parse yields `null` — the rejection is
/// still valid, just uncorrelated.
fn request_id(request: &HttpRequest) -> Value {
    serde_json::from_slice::<Value>(&request.body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(Value::Null)
}

/// Build a signed rejection response. When `request` is `Some`, the response is
/// bound to it via `;req` (and echoes its id); when `None`, it is signed
/// response-only (a failure before request context).
#[allow(clippy::too_many_arguments)]
pub fn build_signed_rejection(
    request: Option<&HttpRequest>,
    reason: &RejectionReason,
    status: u16,
    key: &SigningKey,
    key_id: &str,
    created: i64,
    expires: i64,
) -> Result<HttpResponse, HttpProfileError> {
    let id = request.map(request_id).unwrap_or(Value::Null);
    let mut response = HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: rejection_body(id, reason),
    };
    match request {
        Some(req) => sign_response(&mut response, req, key, key_id, created, expires)?,
        None => sign_response_unbound(&mut response, key, key_id, created, expires)?,
    }
    Ok(response)
}

/// Build a **request-bound delegated** rejection (ADR-MCPRE-052 required mode,
/// MCPRE-122): the rejection is signed by the active DELEGATED key, carries the
/// inline delegation credential, and is bound via `;req` to `request` — used when
/// the request verified far enough to trust its hash but failed a later gate
/// (replay / revocation / policy / transport binding). It verifies through the
/// delegated chain (`verify_delegated_response_full`), never as a directly
/// root-signed response.
#[allow(clippy::too_many_arguments)]
pub fn build_delegated_rejection(
    request: &HttpRequest,
    request_evidence: &RequestEvidence,
    reason: &RejectionReason,
    status: u16,
    server_signer: &ActorIdentity,
    server_delegation: &str,
    delegated_key: &SigningKey,
    delegated_kid: &str,
    created: i64,
    expires: i64,
) -> Result<HttpResponse, HttpProfileError> {
    let mut response = HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: rejection_body(request_id(request), reason),
    };
    sign_delegated_response_full(
        &mut response,
        request,
        request_evidence,
        server_signer,
        server_delegation,
        delegated_key,
        delegated_kid,
        created,
        expires,
    )?;
    Ok(response)
}

/// Build a **preflight (unbound) delegated** rejection (ADR-MCPRE-052 required
/// mode, MCPRE-122): the request was malformed, invalidly signed, of the wrong
/// audience, or otherwise unverifiable, so no trustworthy request hash exists. The
/// rejection is still signed by the active DELEGATED key and carries the inline
/// credential — its signer chain is fully verifiable
/// (`verify_delegated_response_unbound`) — but it is response-only signed and does
/// NOT pretend to be bound to a valid request. When `received` is present its bytes
/// are recorded as a diagnostic digest (never a binding) and its id is echoed.
#[allow(clippy::too_many_arguments)]
pub fn build_delegated_rejection_preflight(
    received: Option<&HttpRequest>,
    reason: &RejectionReason,
    status: u16,
    server_signer: &ActorIdentity,
    server_delegation: &str,
    delegated_key: &SigningKey,
    delegated_kid: &str,
    created: i64,
    expires: i64,
) -> Result<HttpResponse, HttpProfileError> {
    let id = received.map(request_id).unwrap_or(Value::Null);
    // Diagnostic ONLY: a digest of the received bytes so an operator can correlate,
    // explicitly not a trusted request binding (the response is signed unbound).
    let diagnostic = match received {
        Some(req) => RequestEvidence {
            digest_alg: "sha-256-received".into(),
            digest_value: content_digest_sha256(&req.body),
        },
        None => RequestEvidence {
            digest_alg: "none".into(),
            digest_value: String::new(),
        },
    };
    let mut response = HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: rejection_body(id, reason),
    };
    sign_delegated_response_unbound(
        &mut response,
        server_signer,
        server_delegation,
        &diagnostic,
        delegated_key,
        delegated_kid,
        created,
        expires,
    )?;
    Ok(response)
}

/// Verify a signed rejection and return its authoritative wire code. When
/// `request` is `Some`, the `;req` binding to that request is checked (a spliced
/// rejection fails). Fails closed on any signature/digest/binding problem — a
/// client under `require_mcp_re` treats that failure as an untrusted rejection.
pub fn verify_signed_rejection(
    response: &HttpResponse,
    request: Option<&HttpRequest>,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    now: i64,
) -> Result<SignedRejection, HttpProfileError> {
    // A rejection is a server-signed response: resolve for the RESPONSE slot.
    match request {
        Some(req) => {
            verify_response(response, req, resolve_actor, now)?;
        }
        None => {
            verify_response_unbound(response, resolve_actor, now)?;
        }
    }
    // Only AFTER the signature verifies do we read the body for the wire code.
    let wire_code = extract_wire_code(&response.body)?;
    Ok(SignedRejection {
        wire_code,
        status: response.status,
    })
}

/// Pull `error.data.mcp_re_error.wire_code` from a verified rejection body. The
/// body is already signature-protected when this runs.
fn extract_wire_code(body: &[u8]) -> Result<String, HttpProfileError> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|_| HttpProfileError::MalformedEvidence("rejection body json"))?;
    v.get("error")
        .and_then(|e| e.get("data"))
        .and_then(|d| d.get("mcp_re_error"))
        .and_then(|m| m.get("wire_code"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(HttpProfileError::MalformedEvidence("rejection wire_code"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_SEED: [u8; 32] = [11u8; 32];
    const SERVER_SEED: [u8; 32] = [22u8; 32];
    const NOW: i64 = 1_700_000_100;
    const CREATED: i64 = 1_700_000_000;
    const EXPIRES: i64 = 1_700_000_300;

    fn server_key() -> SigningKey {
        SigningKey::from_seed_bytes(&SERVER_SEED)
    }
    fn client_key() -> SigningKey {
        SigningKey::from_seed_bytes(&CLIENT_SEED)
    }

    /// Slot-aware trust seam: the server key is trusted only for the Response
    /// slot, the client key only for the Request slot (MCPRE-100).
    fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
        move |key_id: &str, slot: SignerSlot| {
            let (role, key) = match (key_id, slot) {
                ("server-key-1", SignerSlot::Response) => ("server", server_key()),
                ("client-key-1", SignerSlot::Request) => ("client", client_key()),
                _ => return None,
            };
            Some(ResolvedActor {
                identity: crate::block::ActorIdentity {
                    role: role.into(),
                    trust_domain: "example.com".into(),
                    subject: format!("did:example:{role}"),
                    keyid: key_id.into(),
                },
                verification_key: key.public_key(),
                slot,
            })
        }
    }

    fn request() -> HttpRequest {
        // A received MCP-RE HTTP request always carries Content-Digest (it is a
        // required covered component), so a rejection can bind it via `;req`.
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{}}"#.to_vec();
        HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                (
                    "Content-Digest".into(),
                    crate::digest::content_digest_sha256(&body),
                ),
            ],
            body,
        }
    }

    fn reason() -> RejectionReason {
        RejectionReason {
            wire_code: "mcp-re.invalid_audience",
            message: "audience did not match this verifier (do not trust this text)".into(),
        }
    }

    #[test]
    fn bound_rejection_verifies_and_exposes_the_wire_code() {
        let req = request();
        let rejection = build_signed_rejection(
            Some(&req),
            &reason(),
            403,
            &server_key(),
            "server-key-1",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        let verdict =
            verify_signed_rejection(&rejection, Some(&req), &resolver(), NOW).expect("verify");
        assert_eq!(verdict.wire_code, "mcp-re.invalid_audience");
        assert_eq!(verdict.status, 403);
        // The body must carry Content-Digest + Signature (label mcp-re-response).
        assert!(rejection
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-digest")));
        let sig = rejection
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
            .unwrap();
        assert!(sig.1.starts_with("mcp-re-response="));
    }

    #[test]
    fn unbound_rejection_verifies_without_request_context() {
        let rejection = build_signed_rejection(
            None,
            &reason(),
            400,
            &server_key(),
            "server-key-1",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        let verdict = verify_signed_rejection(&rejection, None, &resolver(), NOW).expect("verify");
        assert_eq!(verdict.wire_code, "mcp-re.invalid_audience");
        assert_eq!(verdict.status, 400);
    }

    #[test]
    fn spliced_rejection_onto_a_different_request_fails() {
        let req_a = request();
        let mut req_b = request();
        req_b.target_uri = "https://mcp.example.com/mcp?route=b".into();
        let rejection = build_signed_rejection(
            Some(&req_a),
            &reason(),
            403,
            &server_key(),
            "server-key-1",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        // Bound to req_a; presenting it as the answer to req_b must fail.
        let err = verify_signed_rejection(&rejection, Some(&req_b), &resolver(), NOW).unwrap_err();
        assert_eq!(err, HttpProfileError::ResponseSignatureInvalid);
    }

    #[test]
    fn tampered_message_does_not_change_the_trusted_wire_code() {
        // The human message is not authoritative; tampering it breaks the
        // signature (it is under Content-Digest), so a client can never be
        // fooled by an edited message either.
        let req = request();
        let mut rejection = build_signed_rejection(
            Some(&req),
            &reason(),
            403,
            &server_key(),
            "server-key-1",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        rejection.body = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32003,"message":"LIES","data":{"mcp_re_error":{"wire_code":"mcp-re.expired_request"}}}}"#.to_vec();
        let err = verify_signed_rejection(&rejection, Some(&req), &resolver(), NOW).unwrap_err();
        assert_eq!(err, HttpProfileError::ContentDigestMismatch);
    }

    #[test]
    fn unsigned_rejection_is_untrusted() {
        // A bare JSON-RPC error with no signature must not verify — the client
        // treats this as rejection_unsigned under require_mcp_re.
        let unsigned = HttpResponse {
            status: 403,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: rejection_body(json!(7), &reason()),
        };
        assert!(verify_signed_rejection(&unsigned, Some(&request()), &resolver(), NOW).is_err());
    }

    #[test]
    fn wire_code_is_read_only_after_signature_verifies() {
        // A rejection signed by an UNTRUSTED key must fail before the body's
        // wire code is ever surfaced.
        let req = request();
        let rejection = build_signed_rejection(
            Some(&req),
            &reason(),
            403,
            &client_key(),
            "rogue-key",
            CREATED,
            EXPIRES,
        )
        .expect("build");
        let err = verify_signed_rejection(&rejection, Some(&req), &resolver(), NOW).unwrap_err();
        assert_eq!(err, HttpProfileError::UnresolvedKeyId);
    }
}
