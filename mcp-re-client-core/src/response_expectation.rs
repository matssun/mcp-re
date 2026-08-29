// SPDX-License-Identifier: Apache-2.0
//! What the client expects of the bound response for one outstanding request.
//!
//! Its own module because the pairing is the invariant: the request and the evidence
//! handle are produced together by [`SignedRequest`], and the verifier next door reads
//! them back through named projections rather than through fields any holder could
//! re-pair.

use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::RequestEvidence;

use crate::request::SignedRequest;

/// What the client expects of the bound response for one outstanding request: the
/// exact request it sent (for the `;req` binding), the [`RequestEvidence`] handle
/// the response must bind, and an optional pinned server signer.
///
/// The request and its evidence handle are one pair, and [`SignedRequest`] is the owner
/// that produced them together. Prefer [`Self::for_signed`], which takes that owner:
/// splitting a signed request into halves and handing them back separately is how one
/// exchange's request comes to be paired with another's handle, and the verifier then
/// binds a verified response to the wrong request.
///
/// The fields are private so no caller can re-pair them after construction. That closes
/// the in-process half of the exposure and not the FFI half: [`Self::new`] exists because
/// the SDK bindings rebuild both halves from scalars crossing a language boundary, where
/// no owner survives to be taken instead.
#[derive(Debug, Clone)]
pub struct ResponseExpectation {
    /// The exact [`HttpRequest`] the client signed and sent.
    request: HttpRequest,
    /// The [`RequestEvidence`] handle the response's `request_evidence` must equal.
    request_evidence: RequestEvidence,
    /// The credential ISSUER policy expects for this route/audience, if pinned.
    ///
    /// The anchor a delegated credential must prove a chain to — not the delegated
    /// response-signing kid, which is an RFC 7638 thumbprint that rotates every TTL by
    /// design, so pinning it would fail on the first rotation and would say nothing about
    /// server identity. When `Some`, a response whose credential chains to any OTHER
    /// trusted anchor fails closed.
    expected_issuer_kid: Option<String>,
}

impl ResponseExpectation {
    /// Build an expectation from the signed request that produced the pair, with no
    /// pinned signer (resolver scope governs).
    ///
    /// The one constructor that cannot pair a request with another exchange's evidence
    /// handle, because it never sees two values to pair.
    pub fn for_signed(signed: &SignedRequest) -> Self {
        ResponseExpectation::new(signed.request().clone(), signed.evidence().clone())
    }

    /// Build an expectation from a request and an evidence handle reconstructed
    /// separately, with no pinned signer (resolver scope governs).
    ///
    /// For the FFI bindings, which receive both halves as scalars and have no
    /// [`SignedRequest`] to take. In-process callers hold that owner and should take it:
    /// see [`Self::for_signed`].
    pub fn new(request: HttpRequest, request_evidence: RequestEvidence) -> Self {
        ResponseExpectation {
            request,
            request_evidence,
            expected_issuer_kid: None,
        }
    }

    /// Pin the expected credential issuer kid. A response chaining to any other trusted
    /// anchor then fails closed.
    pub fn with_expected_issuer_kid(mut self, keyid: impl Into<String>) -> Self {
        self.expected_issuer_kid = Some(keyid.into());
        self
    }

    /// The exact request the response must bind, for the `;req` binding.
    pub(crate) fn request(&self) -> &HttpRequest {
        &self.request
    }

    /// The evidence handle the response's `request_evidence` must equal.
    pub(crate) fn request_evidence(&self) -> &RequestEvidence {
        &self.request_evidence
    }

    /// The credential issuer this route pins, or `None` when resolver scope governs.
    pub(crate) fn expected_issuer_kid(&self) -> Option<&str> {
        self.expected_issuer_kid.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts() -> (HttpRequest, RequestEvidence) {
        (
            HttpRequest {
                method: "POST".to_string(),
                target_uri: "https://mcp.example.com/mcp".to_string(),
                headers: Vec::new(),
                body: b"{}".to_vec(),
            },
            RequestEvidence {
                digest_alg: "sha-256".to_string(),
                digest_value: "abc".to_string(),
            },
        )
    }

    /// The pair goes in and comes back out unchanged: the projections report what was
    /// constructed, which is what makes them usable in place of the fields.
    #[test]
    fn the_projections_report_the_pair_the_expectation_was_built_from() {
        let (request, evidence) = parts();
        let expectation = ResponseExpectation::new(request.clone(), evidence.clone());
        assert_eq!(expectation.request().target_uri, request.target_uri);
        assert_eq!(
            expectation.request_evidence().digest_value,
            evidence.digest_value
        );
    }

    /// An unpinned route reports no pin, and pinning one reports it. The pin is the only
    /// part of an expectation that is set after construction.
    #[test]
    fn a_pin_is_absent_until_it_is_set() {
        let (request, evidence) = parts();
        let expectation = ResponseExpectation::new(request, evidence);
        assert_eq!(expectation.expected_issuer_kid(), None);
        assert_eq!(
            expectation
                .with_expected_issuer_kid("root-kid")
                .expected_issuer_kid(),
            Some("root-kid")
        );
    }
}
