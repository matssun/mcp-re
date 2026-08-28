// SPDX-License-Identifier: Apache-2.0
//! When two commitments describe the same call.
//!
//! One fact: **whether a commitment derived from retained bytes is the one a statement was
//! issued over.**
//!
//! It is a CHILD of the commitment, rather than a sibling or a function in the
//! retained-evidence authority that calls it, for one reason: a child sees the parent's
//! private representation, so the comparison can be exhaustive without anything outside the
//! owner destructuring it. That is R-COMPOSE's requirement kept both ways — the
//! correspondence authority next door consumes a named verdict, and a field added to the
//! record is a compile error here rather than a comparison that quietly stopped covering
//! it.

use crate::error::HttpProfileError;

use super::EvidenceCommitment;

impl EvidenceCommitment {
    /// Whether `recomputed` — a commitment derived from retained bytes — describes the
    /// same call as this one, or the reason it does not.
    ///
    /// This is [`verify_retained_evidence`]'s whole comparison, moved to the value it is
    /// about. It used to be seven field reads at the call site, which is R-COMPOSE's
    /// failure mode exactly: a security relation recreated by destructuring an owner's
    /// representation, so adding a field to the record left the comparison silently
    /// weaker until somebody remembered to extend it. Here a new field is a compile error
    /// in one place.
    ///
    /// The `submitted_commitment` clause is deliberately asymmetric — see the comment on
    /// it below.
    pub(crate) fn corresponds_to(&self, recomputed: &Self) -> Result<(), HttpProfileError> {
        if !self.commits_to_verified_evidence() || !recomputed.commits_to_verified_evidence() {
            return Err(HttpProfileError::MalformedEvidence(
                "a record with no verified hop commits to no call, so retained evidence cannot be bound to it",
            ));
        }
        if recomputed.request_evidence != self.request_evidence {
            return Err(HttpProfileError::MalformedEvidence(
                "retained request evidence does not match the commitment",
            ));
        }
        if recomputed.response_evidence != self.response_evidence {
            return Err(HttpProfileError::MalformedEvidence(
                "retained response evidence does not match the commitment",
            ));
        }
        if recomputed.chain_commitment != self.chain_commitment {
            return Err(HttpProfileError::MalformedEvidence(
                "retained chain does not match the committed chain shape",
            ));
        }
        if recomputed.chain_label != self.chain_label {
            return Err(HttpProfileError::MalformedEvidence(
                "retained chain label does not match the commitment",
            ));
        }
        if recomputed.bindings_commitment != self.bindings_commitment {
            return Err(HttpProfileError::MalformedEvidence(
                "retained artifact bindings do not match the commitment",
            ));
        }
        if recomputed.verified_context_commitment != self.verified_context_commitment {
            return Err(HttpProfileError::MalformedEvidence(
                "retained verified context does not match the commitment",
            ));
        }
        // The SUBMISSION identity, which is the only field that covers the hops AFTER the
        // verified prefix. Every field above is derived from that prefix, so on an
        // Incomplete record — the records an auditor investigates — the unverified tail
        // contributes to none of them: an archivist holding a statement about
        // `[h0, h1, h2-tampered]` could present `[h0, h1, h2']`, and as long as `h2'` fails
        // at the same hop index for the same reason the label and both digests still match.
        if self.identifies_a_submission() {
            if recomputed.submitted_commitment != self.submitted_commitment {
                return Err(HttpProfileError::MalformedEvidence(
                    "retained submission does not match the commitment",
                ));
            }
        } else if recomputed.identifies_a_submission() {
            // The record predates the submission identity, so the retained tail is bound
            // only as far as the verified prefix reaches. Saying so is the point: this is a
            // weaker result than the one above, and it must not be reported as the same.
            return Err(HttpProfileError::MalformedEvidence(
                "the statement carries no submission identity, so the retained submission cannot be bound to it",
            ));
        }
        Ok(())
    }
}
