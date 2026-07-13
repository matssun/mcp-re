// SPDX-License-Identifier: Apache-2.0
//! RFC 9421 signed-response verification on the client side (ADR-MCPRE-050,
//! MCPRE-101). The return leg of [`crate::request`].
//!
//! Given the received [`HttpResponse`] and the request context the client kept
//! from signing (`SignedRequest`: the sent [`HttpRequest`] and its
//! [`RequestEvidence`] handle), it confirms the response is genuine RFC 9421 +
//! RFC 9530 evidence bound to THIS request:
//! [`mcp_re_http_profile::verify_response_bound_full`] performs the
//! `Content-Digest` check, the RFC 9421 signature verification over the `;req`-bound
//! signature base (a spliced response fails), server-signer trust resolution through
//! the injected actor resolver, and the response-block `request_evidence` binding.
//!
//! The response evidence is an RFC 9421 signature over the `;req`-bound base plus the
//! RFC 9530 Content-Digest, not a JSON-RPC `_meta` block. Trust resolution stays
//! behind the actor-resolver seam, so the proxy/SDK
//! injects the live-trust / OCSP-backed resolver and this pure module never reaches
//! the network.

use mcp_re_http_profile::verify_response_bound_full;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedHttpResponseEvidence;
use serde_json::Value;

/// The MCP-RE round-trip classification of a verified response body
/// (ADR-MCPS-047). Read ONLY from the signed, verified body — never from
/// untrusted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultClass {
    /// An ordinary terminal result.
    Terminal,
    /// An `InputRequiredResult` — a non-terminal leg awaiting client continuation.
    InputRequired,
}

/// What the client expects of the bound response for one outstanding request: the
/// exact request it sent (for the `;req` binding), the [`RequestEvidence`] handle
/// the response must bind, and an optional pinned server signer.
#[derive(Debug, Clone)]
pub struct ResponseExpectation {
    /// The exact [`HttpRequest`] the client signed and sent.
    pub request: HttpRequest,
    /// The [`RequestEvidence`] handle the response's `request_evidence` must equal.
    pub request_evidence: RequestEvidence,
    /// The server signer policy expects for this route/audience, if pinned. When
    /// `Some`, the verified server signer keyid MUST equal it (unexpected → fail
    /// closed) even if some other signer would independently resolve.
    pub expected_server_signer_keyid: Option<String>,
}

impl ResponseExpectation {
    /// Build an expectation from the sent request and its evidence handle, with no
    /// pinned signer (resolver scope governs).
    pub fn new(request: HttpRequest, request_evidence: RequestEvidence) -> Self {
        ResponseExpectation {
            request,
            request_evidence,
            expected_server_signer_keyid: None,
        }
    }

    /// Pin the expected server signer keyid. A verified-but-unexpected signer then
    /// fails closed.
    pub fn with_expected_server_signer(mut self, keyid: impl Into<String>) -> Self {
        self.expected_server_signer_keyid = Some(keyid.into());
        self
    }
}

/// Verify a signed RFC 9421 response and confirm it binds the expected request.
///
/// `resolve_actor` is the client's trust seam (injected by the proxy/SDK; live
/// trust + OCSP live behind it, so this pure module performs no I/O). On success
/// returns the [`VerifiedHttpResponseEvidence`]; on any failure the precise frozen
/// [`HttpProfileError`], fail-closed.
pub fn verify_signed_response(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    expectation: &ResponseExpectation,
    now: i64,
) -> Result<VerifiedHttpResponseEvidence, HttpProfileError> {
    let verified = verify_response_bound_full(
        response,
        &expectation.request,
        &expectation.request_evidence,
        resolve_actor,
        now,
    )?;

    // Unexpected-signer guard (client policy): a signer that verifies but is not
    // the one policy bound to this route/audience fails closed.
    if let Some(expected) = &expectation.expected_server_signer_keyid {
        let signed_keyid = &verified.resolved_server_actor.identity.keyid;
        if signed_keyid != expected {
            return Err(HttpProfileError::ResponseBindingMismatch);
        }
    }

    Ok(verified)
}

/// A verified response plus its multi-round-trip classification (ADR-MCPS-047),
/// read from the signed, verified body.
#[derive(Debug, Clone)]
pub struct ClassifiedResponse {
    /// The verification verdict.
    pub verified: VerifiedHttpResponseEvidence,
    /// Terminal vs `InputRequiredResult`.
    pub class: ResultClass,
}

/// Verify a signed RFC 9421 response AND classify its result body for the
/// multi-round-trip flow. Classification runs ONLY after verification succeeds, so
/// the class is never trusted from unverified bytes.
pub fn verify_and_classify_response(
    response: &HttpResponse,
    resolve_actor: &dyn Fn(&str, SignerSlot) -> Option<ResolvedActor>,
    expectation: &ResponseExpectation,
    now: i64,
) -> Result<ClassifiedResponse, HttpProfileError> {
    let verified = verify_signed_response(response, resolve_actor, expectation, now)?;
    let body: Value =
        serde_json::from_slice(&response.body).map_err(|_| HttpProfileError::MalformedEvidence("response body"))?;
    let class = classify_result(body.get("result"));
    Ok(ClassifiedResponse { verified, class })
}

/// Classify a (verified) `result` body as terminal or `InputRequiredResult`. The
/// `InputRequiredResult` marker is the `resultType == "input_required"` discriminator
/// (ADR-MCPS-047). Absent/other results are terminal.
pub fn classify_result(result: Option<&Value>) -> ResultClass {
    match result.and_then(|r| r.get("resultType")).and_then(|t| t.as_str()) {
        Some("input_required") => ResultClass::InputRequired,
        _ => ResultClass::Terminal,
    }
}
