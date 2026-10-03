// SPDX-License-Identifier: Apache-2.0
//! The cryptographic-floor verifier for the pre-ADR-MCPRE-052 direct-root rejections
//! built by [`super::pre_052_direct_root`], retained as a NEGATIVE-TEST fixture only.
//!
//! It checks the signature, digest and `;req` binding and nothing else: no delegation
//! credential, no root entitlement, no record of whether the rejection was bound to the
//! exchange it answers beyond the `request` argument. A directly root-signed response is
//! something `delegated-required` refuses, so this verdict is never a client's trust
//! decision. It is gated like its emitters (`any(test, feature = "pre_052_fixtures")`),
//! so a product build holds no floor-only rejection verifier at all.

use serde_json::Value;

use crate::block::ResolverOutcome;
use crate::error::HttpProfileError;
use crate::message::HttpRequest;
use crate::message::HttpResponse;

/// Verify a pre-052 direct-root rejection against the cryptographic floor and return its
/// wire code. When `request` is `Some`, the `;req` binding to that request is checked (a
/// spliced rejection fails); when `None`, the response-only floor applies. Fails closed
/// on any signature, digest or binding problem.
pub fn verify_pre_052_direct_root_rejection_for_negative_test<R: Into<ResolverOutcome>>(
    response: &HttpResponse,
    request: Option<&HttpRequest>,
    verifier: &crate::verifier::Verifier<'_, R>,
    now: i64,
) -> Result<String, HttpProfileError> {
    // Which floor applies is decided by whether a trustworthy request context EXISTS, and
    // the two produce different types; only the verdict's success matters here.
    match request {
        Some(req) => {
            verifier.verify_bound_response_floor(response, req, now)?;
        }
        None => {
            verifier.verify_unbound_response_floor(response, now)?;
        }
    }
    // Only AFTER the signature verifies is the body read for the wire code.
    extract_wire_code(&response.body)
}

/// Pull `error.data.mcp_re_error.wire_code` from a verified rejection body.
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

    #[test]
    fn a_body_without_a_wire_code_is_malformed() {
        assert!(extract_wire_code(br#"{"error":{"data":{}}}"#).is_err());
        assert!(extract_wire_code(b"not json").is_err());
    }
}
