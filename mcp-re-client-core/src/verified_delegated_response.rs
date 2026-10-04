// SPDX-License-Identifier: Apache-2.0
//! The product of a successful client-side delegated verification.
//!
//! One main type per file: this value owns the invariant that its continuation state is
//! derived, at construction, from the bytes verification's Content-Digest covered. The
//! field is private to this module, so nothing outside it can pair a product with any other
//! answer. Its control lives in `response.rs`, where the verifier mints one: an inhabitant
//! needs http-profile verified products whose constructors are crate-private there.

use crate::delegated_evidence::DelegatedResponseEvidence;
use crate::response::DelegatedOutcome;
use mcp_re_http_profile::HttpProfileError;

/// A verified delegated response: the verification evidence plus the outcome.
#[derive(Debug, Clone)]
pub struct VerifiedDelegatedResponse {
    /// The verified response evidence, bound or unbound.
    pub verified: DelegatedResponseEvidence,
    /// Success vs delegated rejection receipt.
    pub outcome: DelegatedOutcome,
    continuation: Result<Option<String>, HttpProfileError>,
}

impl VerifiedDelegatedResponse {
    /// The sole caller is `response::verify_delegated_response_under`, which passes the
    /// body it just verified.
    pub(super) fn new(
        verified: DelegatedResponseEvidence,
        outcome: DelegatedOutcome,
        verified_body: &[u8],
    ) -> Self {
        Self {
            verified,
            outcome,
            continuation: mcp_re_http_profile::result_class::input_required_state(verified_body),
        }
    }

    /// The continuation state the verified body carries, for a caller acting on a live
    /// exchange: `Some(state)` for an `InputRequiredResult`, `None` for a terminal reply,
    /// and an ERROR for a reply that is non-terminal without a usable `requestState`, has an
    /// unrecognized `resultType`, or is not one response object.
    pub fn continuation_state(&self) -> Result<Option<String>, HttpProfileError> {
        self.continuation.clone()
    }
}
