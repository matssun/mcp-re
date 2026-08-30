// SPDX-License-Identifier: Apache-2.0
//! What the client expects of the bound response for one outstanding request.
//!
//! Its own module because the expectation is a value with an invariant of its own: what
//! the client is waiting for on one outstanding request, read back through named
//! projections rather than through fields a holder could rewrite.

use mcp_re_http_profile::HttpRequest;

use crate::request::SignedRequest;

/// What the client expects of the bound response for one outstanding request: the
/// exact request it sent, and an optional pinned server signer.
///
/// It used to carry the request's evidence handle as a second member, and the two were a
/// pair that could be built from unrelated halves. That is no longer a fact about this
/// type at all: the handle is a FUNCTION of the request, and the verification boundary
/// derives it from the request it is given rather than accepting one beside it, so there
/// is nothing left here that could describe a different exchange from the request.
///
/// [`Self::for_signed`] remains the constructor to prefer — it takes the owner rather than
/// a loose request — and [`Self::new`] takes the one operand the FFI bindings rebuild from
/// scalars.
#[derive(Debug, Clone)]
pub struct ResponseExpectation {
    /// The exact [`HttpRequest`] the client signed and sent.
    request: HttpRequest,
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
    /// Build an expectation from the signed request it is about, with no pinned signer
    /// (resolver scope governs).
    pub fn for_signed(signed: &SignedRequest) -> Self {
        ResponseExpectation::new(signed.request().clone())
    }

    /// Build an expectation from a request reconstructed separately, with no pinned
    /// signer (resolver scope governs).
    ///
    /// For the FFI bindings, which rebuild the request from scalars and have no
    /// [`SignedRequest`] to take. In-process callers hold that owner and should take it:
    /// see [`Self::for_signed`].
    pub fn new(request: HttpRequest) -> Self {
        ResponseExpectation {
            request,
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

    /// The credential issuer this route pins, or `None` when resolver scope governs.
    pub(crate) fn expected_issuer_kid(&self) -> Option<&str> {
        self.expected_issuer_kid.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts() -> HttpRequest {
        HttpRequest {
            method: "POST".to_string(),
            target_uri: "https://mcp.example.com/mcp".to_string(),
            headers: Vec::new(),
            body: b"{}".to_vec(),
        }
    }

    /// The request goes in and comes back out unchanged: the projection reports what was
    /// constructed, which is what makes it usable in place of the field.
    #[test]
    fn the_projection_reports_the_request_the_expectation_was_built_from() {
        let request = parts();
        let expectation = ResponseExpectation::new(request.clone());
        assert_eq!(expectation.request().target_uri, request.target_uri);
    }

    /// An unpinned route reports no pin, and pinning one reports it. The pin is the only
    /// part of an expectation that is set after construction.
    #[test]
    fn a_pin_is_absent_until_it_is_set() {
        let request = parts();
        let expectation = ResponseExpectation::new(request);
        assert_eq!(expectation.expected_issuer_kid(), None);
        assert_eq!(
            expectation
                .with_expected_issuer_kid("root-kid")
                .expected_issuer_kid(),
            Some("root-kid")
        );
    }
}
