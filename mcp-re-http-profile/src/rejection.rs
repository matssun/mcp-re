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
use crate::block::ResolverOutcome;
use crate::digest::content_digest_sha256;
use crate::error::HttpProfileError;
use crate::evidence::RequestEvidence;
use crate::message::HttpRequest;
use crate::message::HttpResponse;
use crate::sign::sign_delegated_response_full;
use crate::sign::sign_delegated_response_unbound;
use crate::sign::sign_response;
use crate::sign::sign_response_unbound;

/// The JSON-RPC error code MCP-RE rejections carry. The wire code in `data`,
/// not this integer, is the stable signal.
///
/// Allocated outside JSON-RPC's reserved band (`-32768..=-32000`), which MCP
/// 2026-07-28 §Error Codes partitions entirely between a legacy sub-range no new
/// implementation may draw from and a sub-range reserved for the MCP
/// specification itself. Mirrors [`mcp_re_core::wire::MCP_RE_JSON_RPC_ERROR_CODE`].
pub const JSON_RPC_ERROR_CODE: i64 = -31000;

/// What the enforcement boundary knows about the refused exchange's effects.
///
/// The wire code alone cannot answer this. `evidence_retention_unavailable` at the
/// pre-dispatch reservation is retry-safe when the exchange carries no continuation, and is
/// NOT retry-safe when it already retired one — same code, same status, opposite advice.
/// The difference lives in the request machine's cross-machine state
/// (ADR-MCPRE-057 §4), so it is supplied here rather than guessed from the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutionDisposition {
    /// Nothing is asserted beyond what the wire code itself implies. The historical
    /// behaviour, and what every caller that has no request machine to consult supplies.
    #[default]
    Unstated,
    /// The backend never acted and no approval was spent. An ordinary retry is correct.
    NothingExecuted,
    /// The backend never acted, but the approval authorizing it was already consumed.
    /// A retry passes replay admission on a fresh nonce and then fails as
    /// already-answered — the action needs a new human elicitation, not a retry.
    ApprovalSpentNothingExecuted,
    /// The exchange crossed the execution threshold: the backend may have acted, and
    /// whatever failed afterwards cannot unmake that (ADR-MCPRE-058 §10, ruling D1).
    ///
    /// The GENERIC post-dispatch statement, and it is generic on purpose. Before it, only
    /// two post-dispatch failures said anything at all: `evidence_retention_indeterminate`,
    /// which `retry_semantics` special-cased by name, and the approval case above, which is
    /// a PRE-dispatch fact. Everything else — an illegal upstream response, a signing
    /// failure, a continuation-record failure at **HTTP 503**, a 202 that could not be
    /// signed — returned a bare status after the tool had already run, and 503 is the status
    /// clients retry.
    ///
    /// Not a reuse of [`ApprovalSpentNothingExecuted`](Self::ApprovalSpentNothingExecuted):
    /// that token means an approval was destroyed and a NEW elicitation is required, which
    /// is a different remedy and, in the ordinary case, simply false here.
    PossiblyExecuted,
}

/// A rejection reason: the stable frozen wire code plus a human-readable,
/// NON-authoritative message.
#[derive(Debug, Clone)]
pub struct RejectionReason {
    /// A frozen `mcp-re.*` wire code (typically `HttpProfileError::wire_code()`
    /// or `McpReError::wire_code()`).
    pub wire_code: &'static str,
    /// Human-readable diagnostic. NEVER trusted or parsed by clients.
    pub message: String,
    /// What is known about the exchange's effects, from the request machine.
    pub execution: ExecutionDisposition,
}

impl RejectionReason {
    /// A reason stating nothing beyond its wire code.
    pub fn new(wire_code: &'static str, message: impl Into<String>) -> Self {
        Self {
            wire_code,
            message: message.into(),
            execution: ExecutionDisposition::Unstated,
        }
    }

    /// The same reason, carrying what the request machine established about effects.
    pub fn with_execution(mut self, execution: ExecutionDisposition) -> Self {
        self.execution = execution;
        self
    }
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
    let mut mcp_re_error = json!({ "wire_code": reason.wire_code });
    // The retry contract is DERIVED — from the frozen token and the request machine's own
    // disposition — never assembled field by field at a call site. Independently-set
    // values can disagree, and the disagreement that matters here is an outcome the
    // client cannot recover from labelled retry-safe.
    if let Some(extra) = retry_semantics(reason.wire_code, reason.execution) {
        if let (Some(target), Some(extra)) = (mcp_re_error.as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": JSON_RPC_ERROR_CODE,
            "message": reason.message,
            "data": { "mcp_re_error": mcp_re_error }
        }
    });
    serde_json::to_vec(&body).expect("rejection body serializes")
}

/// Explicit machine-readable execution/retry state, for the cases where the safe action is
/// not inferable from the HTTP status.
///
/// Two sources, and both are needed. The wire code carries the post-execution case, where
/// the code alone is decisive. The disposition carries the pre-execution case, where it is
/// not: the SAME code at the SAME status is retry-safe or not depending on whether the
/// exchange had already spent a continuation, and only the request machine knows that.
///
/// A disposition of [`ExecutionDisposition::Unstated`] adds nothing, so every caller
/// without a request machine — and every frozen conformance vector — produces exactly the
/// bytes it produced before.
///
/// **The canonical projection, and the only one.** It is public because the unsigned
/// last-resort receipt is built in another crate and must state the same thing: a second
/// projection over the same two inputs is a second authority, and the two drifted before —
/// the copy took only the disposition, so it could not express the wire-code-dependent
/// retention case at all. Adding a wrapper to keep this private would recreate exactly that.
pub fn retry_semantics(wire_code: &str, execution: ExecutionDisposition) -> Option<Value> {
    if execution == ExecutionDisposition::ApprovalSpentNothingExecuted {
        // The action did NOT run, so this is not the indeterminate case — but the human
        // approval that authorized it is gone, and an ordinary retry cannot recover it.
        // Saying only "503, try again" sends the client into a retry that passes replay
        // admission on a fresh nonce and then fails as already-answered, with the approval
        // already destroyed.
        return Some(json!({
            "execution_status": "not_executed",
            "continuation_status": "consumed",
            "retry_safety": "unsafe_without_new_elicitation",
        }));
    }
    if wire_code == mcp_re_core::McpReError::EvidenceRetentionIndeterminate.wire_code() {
        // The backend ran; only the evidence write failed. A client that treats this
        // as an ordinary outage and retries re-executes the action, and the retry's
        // fresh nonce passes replay admission — so the state is stated rather than
        // left to be guessed from a status code.
        //
        // Kept ahead of the generic arm because it says one thing more: WHICH obligation
        // failed. The extra field is the difference between "reconcile" and "reconcile,
        // and know the evidence store has no record of this call".
        return Some(json!({
            "execution_status": "possibly_executed",
            "retention_status": "failed",
            "retry_safety": "unsafe_without_reconciliation",
        }));
    }
    if execution == ExecutionDisposition::PossiblyExecuted {
        // Every other failure below the execution threshold. Derived from the exchange
        // machine, not from an allowlist of wire codes: an allowlist is a thing a NEW
        // post-dispatch exit silently fails to be on, which is exactly how the
        // continuation-record failure ended up returning a bare 503 after the tool ran.
        return Some(json!({
            "execution_status": "possibly_executed",
            "retry_safety": "unsafe_without_reconciliation",
        }));
    }
    None
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
pub fn verify_signed_rejection<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: Option<&HttpRequest>,
    verifier: &crate::verifier::Verifier<'_, R>,
    now: i64,
) -> Result<SignedRejection, HttpProfileError> {
    // A rejection is a server-signed response: resolve for the RESPONSE slot. Which floor
    // applies is decided by whether a trustworthy request context EXISTS, and the two
    // produce different types.
    match request {
        Some(req) => {
            verifier.verify_bound_response_floor(response, req, now)?;
        }
        None => {
            verifier.verify_unbound_response_floor(response, now)?;
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
    use crate::block::SignerSlot;
    use crate::policy::VerifierPolicy;
    use crate::verifier::Verifier;

    /// The indeterminate token must carry its retry contract explicitly.
    ///
    /// A client that reads only the HTTP status cannot tell "nothing happened" from
    /// "it may have happened"; retrying the second re-executes the action, and the
    /// retry's fresh nonce passes replay admission.
    #[test]
    fn the_indeterminate_rejection_states_that_a_retry_is_unsafe() {
        let reason = RejectionReason::new(
            mcp_re_core::McpReError::EvidenceRetentionIndeterminate.wire_code(),
            "retention failed after execution".to_owned(),
        );
        let body = rejection_body(serde_json::json!(1), &reason);
        let v: Value = serde_json::from_slice(&body).expect("body parses");
        let e = &v["error"]["data"]["mcp_re_error"];
        assert_eq!(e["wire_code"], "mcp-re.evidence_retention_indeterminate");
        assert_eq!(e["execution_status"], "possibly_executed");
        assert_eq!(e["retention_status"], "failed");
        assert_eq!(e["retry_safety"], "unsafe_without_reconciliation");
    }

    /// Every OTHER code keeps the exact body shape frozen vectors pin.
    #[test]
    fn an_ordinary_rejection_body_gains_no_new_fields() {
        let reason = RejectionReason::new("mcp-re.invalid_audience", "no".to_owned());
        let body = rejection_body(serde_json::json!(1), &reason);
        let v: Value = serde_json::from_slice(&body).expect("body parses");
        let e = v["error"]["data"]["mcp_re_error"]
            .as_object()
            .expect("object");
        assert_eq!(e.len(), 1, "only wire_code: {e:?}");
    }
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
    fn resolver() -> impl Fn(&str, SignerSlot) -> Option<crate::block::ResolvedActor> {
        move |key_id: &str, slot: SignerSlot| {
            let (role, key) = match (key_id, slot) {
                ("server-key-1", SignerSlot::Response) => ("server", server_key()),
                ("client-key-1", SignerSlot::Request) => ("client", client_key()),
                _ => return None,
            };
            Some(crate::block::ResolvedActor {
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
        RejectionReason::new(
            "mcp-re.invalid_audience",
            "audience did not match this verifier (do not trust this text)",
        )
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
        let verdict = verify_signed_rejection(
            &rejection,
            Some(&req),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .expect("verify");
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
        let verdict = verify_signed_rejection(
            &rejection,
            None,
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .expect("verify");
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
        let err = verify_signed_rejection(
            &rejection,
            Some(&req_b),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .unwrap_err();
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
        rejection.body = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-31000,"message":"LIES","data":{"mcp_re_error":{"wire_code":"mcp-re.expired_request"}}}}"#.to_vec();
        let err = verify_signed_rejection(
            &rejection,
            Some(&req),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .unwrap_err();
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
        assert!(verify_signed_rejection(
            &unsigned,
            Some(&request()),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW
        )
        .is_err());
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
        let err = verify_signed_rejection(
            &rejection,
            Some(&req),
            &Verifier::new(&VerifierPolicy::default(), &resolver()),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, HttpProfileError::UnresolvedKeyId);
    }
}
