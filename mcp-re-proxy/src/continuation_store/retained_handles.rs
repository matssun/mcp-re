// SPDX-License-Identifier: Apache-2.0
//! What the correlation store keeps of an open leg.
//!
//! One owner for one fact: the store retains the two role-labeled evidence handles over the
//! open leg's signature bases and never a base. A base carries the value of every covered
//! component, so retaining it would retain a covered `authorization` or `dpop` credential
//! at rest for the continuation TTL; a handle is a one-way digest under a role label and
//! is all the answer leg compares.

use mcp_re_http_profile::evidence::EvidenceRole;
use mcp_re_http_profile::RequestEvidenceDigest;

/// The retained open-leg evidence handles an answer leg binds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedHandles {
    /// The request-role handle over the signature base of the client's request that
    /// opened the `InputRequiredResult` (the open leg).
    pub previous_request_evidence: RequestEvidenceDigest,
    /// The response-role handle over the signature base of the delegated-signed
    /// `InputRequiredResult` response the open leg returned.
    pub input_required_response_evidence: RequestEvidenceDigest,
}

impl RetainedHandles {
    /// The handles for an open leg's two signature bases, each minted under its own role
    /// label; the bases themselves are not kept.
    pub fn over(previous_request_base: &[u8], input_required_response_base: &[u8]) -> Self {
        RetainedHandles {
            previous_request_evidence: RequestEvidenceDigest::over_labeled(
                EvidenceRole::Request,
                previous_request_base,
            ),
            input_required_response_evidence: RequestEvidenceDigest::over_labeled(
                EvidenceRole::Response,
                input_required_response_base,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two handles are minted under distinct role labels, so the same bytes in the two
    /// slots yield different handles and a swapped pair is not the retained one.
    #[test]
    fn the_two_slots_are_minted_under_distinct_role_labels() {
        let h = RetainedHandles::over(b"same", b"same");
        assert_ne!(
            h.previous_request_evidence,
            h.input_required_response_evidence
        );
        assert_eq!(
            h.previous_request_evidence,
            RequestEvidenceDigest::over_labeled(EvidenceRole::Request, b"same")
        );
    }

    /// The bases are not recoverable from what is kept: the handle is a digest, not the base.
    #[test]
    fn a_handle_does_not_contain_the_base_it_commits_to() {
        let base = b"authorization: Bearer secret-token";
        let h = RetainedHandles::over(base, b"resp");
        assert!(!h
            .previous_request_evidence
            .digest_value
            .contains("secret-token"));
    }
}
