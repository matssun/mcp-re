// SPDX-License-Identifier: Apache-2.0
//! What a VERIFIED outcome MEANS to a plain MCP client.
//!
//! A verified signature says the server said this. It does not say the exchange is
//! finished, and it does not say the call succeeded — so the reply is CLASSIFIED before it
//! is handed over, and two classes never resolve to success:
//!
//! * an `InputRequiredResult` carrying no usable `requestState` is MALFORMED rather than
//!   terminal. An answer leg could never be honoured, so failing closed is the only honest
//!   outcome;
//! * MCP 2026-07-28 closes the `resultType` set, so an unrecognized one MUST be considered
//!   invalid. It is never resolved to terminal.
//!
//! A verified REJECTION receipt is not an error here. The request was provably denied, and
//! that is an answer: it becomes a plain JSON-RPC error carrying its classification, never a
//! success result.
//!
//! Nothing in this module decides anything about TRUST. It reads a verdict the verifier has
//! already reached — which is why it is a free function over that verdict rather than a
//! method on the proxy that holds the keys.

use mcp_re_client_core::classify_result;
use mcp_re_client_core::continuation_state;
use mcp_re_client_core::DelegatedOutcome;
use mcp_re_client_core::HttpProfileError;
use mcp_re_client_core::HttpResponse;
use mcp_re_client_core::ResultClass;
use serde_json::Value;

use crate::proxy::plain_error_from_rejection;
use crate::proxy::plain_response_from_verified;
use crate::proxy::ProxyResponse;
use crate::proxy::ResponseKind;
use crate::transport::ProxyError;

/// What a VERIFIED outcome means to a plain MCP client.
///
/// A verified signature says the server said this; it does not say the exchange is
/// finished. So the reply is CLASSIFIED before it is handed over, and two classes never
/// resolve to success: an `InputRequiredResult` carrying no usable `requestState` is
/// malformed rather than terminal — an answer leg could never be honoured — and MCP
/// 2026-07-28 closes the `resultType` set, so an unrecognized one MUST be considered
/// invalid.
///
/// A verified REJECTION receipt is not an error here: the request was provably denied, and
/// that is an answer. It becomes a plain JSON-RPC error carrying its classification, never
/// a success result.
pub(crate) fn read_outcome(
    verified: mcp_re_client_core::VerifiedDelegatedResponse,
    response: &HttpResponse,
    request_id: Value,
) -> Result<ProxyResponse, ProxyError> {
    match verified.outcome {
        DelegatedOutcome::Success => {
            let plain = plain_response_from_verified(&response.body, &request_id)?;
            // Classify BEFORE handing the reply over. A verified signature says
            // the server said this; it does not say the exchange is finished.
            let result = plain.get("result");
            // `plain_response_from_verified` has already refused a reply carrying
            // neither member or both, so an `error` here means there is no
            // `result` to classify — and classifying an absent `result` yields
            // Terminal, which is the success label.
            if let Some(code) = plain
                .get("error")
                .map(|e| e.get("code").and_then(Value::as_i64))
            {
                return Ok(ProxyResponse {
                    plain_response: plain,
                    kind: ResponseKind::CallFailed { code },
                });
            }
            let kind = match classify_result(result) {
                ResultClass::Terminal => ResponseKind::Success,
                ResultClass::InputRequired => {
                    // Three-way contract: a reply that announces itself
                    // non-terminal and then carries no usable `requestState` is
                    // MALFORMED, not terminal — an answer leg could never be
                    // honoured, so failing closed is the only honest outcome.
                    let state = continuation_state(&response.body)?.ok_or(
                        ProxyError::FailedClosed(HttpProfileError::MalformedEvidence(
                            "input-required reply carries no requestState",
                        )),
                    )?;
                    ResponseKind::InputRequired {
                        request_state: state,
                    }
                }
                // MCP 2026-07-28 closes the `resultType` set: unrecognized MUST be
                // considered invalid. Never resolved to Terminal.
                ResultClass::Unrecognized => {
                    return Err(ProxyError::FailedClosed(
                        HttpProfileError::UnrecognizedResultType,
                    ))
                }
            };
            Ok(ProxyResponse {
                plain_response: plain,
                kind,
            })
        }
        // A VERIFIED rejection receipt: the request was provably denied. Convert the
        // signed receipt to a plain JSON-RPC error for the local client and report
        // the classification (fail closed — never returned as a success result).
        DelegatedOutcome::Rejection {
            wire_code,
            execution,
        } => Ok(ProxyResponse {
            plain_response: plain_error_from_rejection(
                &request_id,
                wire_code.as_deref(),
                &execution,
            ),
            kind: ResponseKind::VerifiedRejection {
                wire_code,
                bound: verified.verified.is_bound(),
                execution,
            },
        }),
    }
}
