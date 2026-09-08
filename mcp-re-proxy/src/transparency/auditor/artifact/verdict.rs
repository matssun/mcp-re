// SPDX-License-Identifier: Apache-2.0
//! The ATTESTATION'S VERDICTS as the artifact spells them.
//!
//! One fact: **how an attestation's outcome is written down for a reader who has not
//! decoded the statement.**
//!
//! Two enums, because an attestation reports two things — whether the record is whole,
//! and which binding the issuer's self-check established — and they are one fact here
//! because the fact is the SPELLING, not either verdict. A reader of an artifact needs
//! both or neither.
//!
//! It is a PROJECTION of `mcp_re_http_profile::ChainLabel`, not a second opinion about it.
//! The source enum carries `HttpProfileError` payloads and is not a wire type; what a
//! reader of an artifact needs is the class of break, the hop, and — where there is one —
//! the already-published `mcp-re.*` wire code. Adding a variant upstream is a compile
//! error in [`ChainVerdict::of`]'s exhaustive match, which is what keeps the two from
//! drifting into disagreement about one record.

use serde::Deserialize;
use serde::Serialize;

use mcp_re_http_profile::ChainLabel;
use mcp_re_http_profile::IncompleteReason;

/// Which binding the issuer's self-check established, as a stable token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorrespondenceVerdict {
    /// The retained bytes are the ones the statement was issued over, and the statement
    /// identifies a verified call.
    BoundToVerifiedCall,
    /// The statement identifies NO verified call. These are the bytes the issuer saw; that
    /// any hop verified is NOT among the things this says.
    BoundToSubmissionOnly,
}

/// WHY a reconstruction stopped being whole — the artifact's serializable projection of
/// `mcp_re_http_profile::IncompleteReason`.
///
/// A projection rather than a copy: the source enum carries `HttpProfileError` payloads
/// and is not a wire type, and the reason a reader of an artifact needs is the CLASS of
/// break plus, where there is one, the already-published wire code. Adding a variant to
/// the source is a compile error in [`ChainVerdict::of`]'s exhaustive match, which is what
/// keeps the two from drifting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IncompleteAt {
    /// The hop's request did not verify on its own.
    RequestUnverifiable,
    /// The hop's response did not verify, or is not bound to its request.
    ResponseUnverifiable,
    /// The hop carries no continuation and is not the first — the missing middle.
    MissingContinuation,
    /// The hop's continuation does not re-link to the previous hop's evidence.
    ContinuationDoesNotLink,
    /// A hop before the last answered terminally.
    NonTerminalExpected,
    /// The last hop is still awaiting input: the record stops mid-call.
    TerminalExpected,
    /// The hop's response declares a `resultType` the reconstruction does not recognize.
    UnrecognizedResultType,
    /// The reconstruction was handed no hops at all.
    EmptyChain,
    /// A message in the hop declares a `created` later than the audit instant.
    HopAfterAuditInstant,
}

/// The chain verdict, as a reader of the artifact sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "label", rename_all = "kebab-case")]
pub enum ChainVerdict {
    /// Every hop verified and re-linked, and the chain ends terminally.
    Complete,
    /// The record is not whole. `hop` is the zero-based index of the first hop that broke
    /// it, so an auditor is told which turn is unaccounted for.
    Incomplete {
        /// The failing hop.
        hop: usize,
        /// Which class of break applied.
        reason: IncompleteAt,
        /// The frozen `mcp-re.*` wire code, when the reason carries a verification
        /// failure. Reused rather than restated: the wire vocabulary is already published
        /// and a second spelling of it here would be a second thing to keep in step.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wire_code: Option<String>,
    },
}

impl ChainVerdict {
    pub(super) fn of(label: &ChainLabel) -> Self {
        let ChainLabel::Incomplete { hop, reason } = label else {
            return ChainVerdict::Complete;
        };
        let (reason, wire_code) = match reason {
            IncompleteReason::RequestUnverifiable(e) => (
                IncompleteAt::RequestUnverifiable,
                Some(e.wire_code().to_owned()),
            ),
            IncompleteReason::ResponseUnverifiable(e) => (
                IncompleteAt::ResponseUnverifiable,
                Some(e.wire_code().to_owned()),
            ),
            IncompleteReason::MissingContinuation => (IncompleteAt::MissingContinuation, None),
            IncompleteReason::ContinuationDoesNotLink => {
                (IncompleteAt::ContinuationDoesNotLink, None)
            }
            IncompleteReason::NonTerminalExpected => (IncompleteAt::NonTerminalExpected, None),
            IncompleteReason::TerminalExpected => (IncompleteAt::TerminalExpected, None),
            IncompleteReason::UnrecognizedResultType => {
                (IncompleteAt::UnrecognizedResultType, None)
            }
            IncompleteReason::EmptyChain => (IncompleteAt::EmptyChain, None),
            IncompleteReason::HopAfterAuditInstant => (IncompleteAt::HopAfterAuditInstant, None),
        };
        ChainVerdict::Incomplete {
            hop: *hop,
            reason,
            wire_code,
        }
    }

    /// Whether this verdict is a complete record.
    pub fn is_complete(&self) -> bool {
        matches!(self, ChainVerdict::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_http_profile::HttpProfileError;

    /// Every reconstruction reason maps to a distinct token, and only the two that carry a
    /// verification failure carry a wire code. A collision here would report two different
    /// failures as one.
    #[test]
    fn every_incomplete_reason_has_its_own_token() {
        let reasons = [
            IncompleteReason::RequestUnverifiable(HttpProfileError::InvalidSignature),
            IncompleteReason::ResponseUnverifiable(HttpProfileError::InvalidSignature),
            IncompleteReason::MissingContinuation,
            IncompleteReason::ContinuationDoesNotLink,
            IncompleteReason::NonTerminalExpected,
            IncompleteReason::TerminalExpected,
            IncompleteReason::UnrecognizedResultType,
            IncompleteReason::EmptyChain,
            IncompleteReason::HopAfterAuditInstant,
        ];
        let mut tokens = std::collections::BTreeSet::new();
        for reason in reasons {
            let carries_error = matches!(
                reason,
                IncompleteReason::RequestUnverifiable(_)
                    | IncompleteReason::ResponseUnverifiable(_)
            );
            let verdict = ChainVerdict::of(&ChainLabel::Incomplete { hop: 1, reason });
            let ChainVerdict::Incomplete {
                hop,
                reason: token,
                wire_code,
            } = verdict
            else {
                panic!("an incomplete label is an incomplete verdict");
            };
            assert_eq!(hop, 1);
            assert_eq!(
                wire_code.is_some(),
                carries_error,
                "{token:?}: a wire code exactly where the reason carries a failure",
            );
            let spelling = serde_json::to_string(&token).expect("a wire token");
            assert!(tokens.insert(spelling.clone()), "{spelling} is used twice");
        }
        assert_eq!(tokens.len(), 9);
        assert!(ChainVerdict::of(&ChainLabel::Complete).is_complete());
    }
}
