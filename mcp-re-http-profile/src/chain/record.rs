// SPDX-License-Identifier: Apache-2.0
//! What makes the SET of retained hops a whole RECORD.
//!
//! Neither fact here is about a hop on its own. A hop that verifies perfectly can still be
//! the second turn of a call whose first turn is missing, or the last turn of a call that
//! has not ended — and every signature in the record would still be valid. §9.1: a complete
//! call record requires re-linking and verifying EVERY hop; §9.3: a terminal response
//! completes only its own request unless the whole chain verifies.
//!
//! The two directions a record can be truncated get two different detections. A missing
//! MIDDLE hop is caught by the link; a truncation at the END is caught by the shape, and at
//! the START by hop 0 having nothing its own continuation could name.

use super::classify_verified_response;
use super::hop::HopPosition;
use super::HopOutcome;
use super::IncompleteReason;

/// Re-link this hop to the one before it.
///
/// Every hop after the first MUST carry a continuation naming its predecessor's two
/// handles. This is where a missing MIDDLE hop is caught: hop *i*'s continuation names hop
/// *i-1*, so if *i-1* is absent from the record the hop that does sit in that slot does not
/// match.
///
/// Hop 0 OPENS the record, and that is a claim about the record, not a licence to skip the
/// check. A hop 0 that carries a continuation names a predecessor the record cannot produce:
/// the call started before the evidence does. Accepting it labelled a front-truncated record
/// `Complete` — submit hops 1 and 2 of a real R0→S0→R1→S1→R2→S2 call and every remaining hop
/// verifies, hop 2 re-links to hop 1, hop 2 is terminal — so a Signed Statement could commit
/// to a whole call record with the opening turns, their audience and their artifact bindings
/// missing. It lands on the same reason as the missing middle, which is what it is: a
/// continuation naming evidence that is not in the record.
pub(super) fn link_to_predecessor(
    position: &HopPosition<'_>,
    continuation: Option<&crate::block::HttpContinuation>,
) -> Result<(), IncompleteReason> {
    match (position.index, continuation, position.previous) {
        (0, None, _) => Ok(()),
        (0, Some(_), _) => Err(IncompleteReason::ContinuationDoesNotLink),
        (_, None, _) => Err(IncompleteReason::MissingContinuation),
        // A hop past the first with no verified predecessor cannot link to one. Unreachable
        // while the reconstruction stops at the first break, and refused rather than
        // assumed away: the alternative is indexing into the prefix.
        (_, Some(_), None) => Err(IncompleteReason::ContinuationDoesNotLink),
        (_, Some(c), Some(prev)) => {
            let links = c.previous_request_evidence.digest_value
                == prev.request_evidence.digest_value
                && c.previous_request_evidence.digest_alg == prev.request_evidence.digest_alg
                && c.input_required_response_evidence.digest_value
                    == prev.response_evidence.digest_value
                && c.input_required_response_evidence.digest_alg
                    == prev.response_evidence.digest_alg;
            if links {
                Ok(())
            } else {
                Err(IncompleteReason::ContinuationDoesNotLink)
            }
        }
    }
}

/// The chain's shape: every hop before the last awaits input, and the last is terminal.
///
/// The classification is read from the response body that has just verified — protected
/// content, not an assertion travelling beside it.
pub(super) fn check_chain_shape(
    is_last: bool,
    response_body: &[u8],
) -> Result<(), IncompleteReason> {
    match (is_last, classify_verified_response(response_body)) {
        (_, HopOutcome::Unrecognized) => Err(IncompleteReason::UnrecognizedResultType),
        (false, HopOutcome::Terminal) => Err(IncompleteReason::NonTerminalExpected),
        (true, HopOutcome::InputRequired) => Err(IncompleteReason::TerminalExpected),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::HopEvidence;

    fn evidence(request: &str, response: &str) -> HopEvidence {
        let handle = |v: &str| crate::evidence::RequestEvidence {
            digest_alg: "sha-256".into(),
            digest_value: v.into(),
        };
        HopEvidence {
            request_evidence: handle(request),
            response_evidence: handle(response),
        }
    }

    fn continuation(request: &str, response: &str) -> crate::block::HttpContinuation {
        let handle = |v: &str| crate::block::RequestEvidenceDigest {
            digest_alg: "sha-256".into(),
            digest_value: v.into(),
        };
        crate::block::HttpContinuation {
            continuation_type: "mcp-mrt".into(),
            previous_request_evidence: handle(request),
            input_required_response_evidence: handle(response),
            request_state_digest: handle("state"),
        }
    }

    /// The hop that OPENS the record may not name a predecessor. A record whose first hop
    /// carries a continuation is front-truncated, and every check after this one would pass
    /// on it.
    #[test]
    fn hop_zero_may_not_name_a_predecessor() {
        let carries = continuation("r0", "s0");
        let position = HopPosition {
            index: 0,
            previous: None,
            is_last: false,
        };
        assert!(matches!(
            link_to_predecessor(&position, Some(&carries)),
            Err(IncompleteReason::ContinuationDoesNotLink)
        ));
        assert!(link_to_predecessor(&position, None).is_ok());
    }

    /// A later hop links only to the exact predecessor handles, and the two are
    /// role-labeled — so a handle cannot be lifted from one field into the other.
    #[test]
    fn a_later_hop_links_only_to_its_own_predecessor() {
        let prev = evidence("r0", "s0");
        let position = HopPosition {
            index: 1,
            previous: Some(&prev),
            is_last: true,
        };
        assert!(link_to_predecessor(&position, Some(&continuation("r0", "s0"))).is_ok());
        assert!(matches!(
            link_to_predecessor(&position, Some(&continuation("s0", "r0"))),
            Err(IncompleteReason::ContinuationDoesNotLink)
        ));
        assert!(matches!(
            link_to_predecessor(&position, Some(&continuation("rX", "s0"))),
            Err(IncompleteReason::ContinuationDoesNotLink)
        ));
        assert!(matches!(
            link_to_predecessor(&position, None),
            Err(IncompleteReason::MissingContinuation)
        ));
    }

    /// An unclassifiable result type breaks the chain wherever it appears. A hop declaring a
    /// result type this profile cannot read is not evidence that the call completed, and
    /// treating it as terminal is the laundering §9.3 forbids.
    #[test]
    fn an_unrecognized_result_type_breaks_the_chain_at_either_end() {
        let unrecognized = br#"{"result":{"resultType":"SomethingElse"}}"#;
        for is_last in [true, false] {
            assert!(matches!(
                check_chain_shape(is_last, unrecognized),
                Err(IncompleteReason::UnrecognizedResultType)
            ));
        }
    }
}
