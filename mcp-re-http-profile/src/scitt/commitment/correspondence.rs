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

/// WHAT a correspondence establishes, when it establishes anything.
///
/// Two successes rather than one, because the records an auditor investigates most are the
/// ones where only the weaker of them is available — and reporting them as the stronger, or
/// as nothing at all, are both wrong. A statement over a chain that broke at hop 0 commits
/// to two empty handles and a shape digest over zero bytes, which are the same three values
/// for every unrelated call that failed the same way; it also commits to the SUBMISSION,
/// which is not. Naming the two apart is what lets the second be checked without the first
/// being claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedCorrespondence {
    /// The retained bytes are the ones this statement was issued over, and the statement
    /// identifies a verified call: every identity field matched, and so did the submission.
    BoundToVerifiedCall,
    /// The statement identifies NO verified call, and the retained submission is the one it
    /// committed to.
    ///
    /// What is bound is *which bytes were submitted*, not *which call ran*. An auditor may
    /// rely on this to say these are the bytes the issuer saw; it may not rely on it to say
    /// any hop verified, because none did.
    BoundToSubmissionOnly,
}

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
    /// The `submitted_commitment` clause is deliberately asymmetric — see
    /// [`submission_corresponds_to`](Self::submission_corresponds_to).
    pub(crate) fn corresponds_to(
        &self,
        recomputed: &Self,
    ) -> Result<RetainedCorrespondence, HttpProfileError> {
        // A record with no verified hop commits to no CALL — but it still commits to a
        // submission, and that field is call-specific where the identity fields are not.
        // Returning early here is what left the one meaningful binding unexercised on
        // exactly the records an auditor investigates (R9-C103, R9-C128). The weaker
        // verdict is reached through the same submission comparison as the stronger one,
        // so there is no path out of this function that skipped it.
        if !self.commits_to_verified_evidence() || !recomputed.commits_to_verified_evidence() {
            self.submission_corresponds_to(recomputed)?;
            return Ok(RetainedCorrespondence::BoundToSubmissionOnly);
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
        // The SUBMISSION identity is the only field that covers the hops AFTER the verified
        // prefix. Every field above is derived from that prefix, so on an Incomplete record
        // — the records an auditor investigates — the unverified tail contributes to none
        // of them: an archivist holding a statement about `[h0, h1, h2-tampered]` could
        // present `[h0, h1, h2']`, and as long as `h2'` fails at the same hop index for the
        // same reason the label and both digests still match.
        self.submission_corresponds_to(recomputed)?;
        Ok(RetainedCorrespondence::BoundToVerifiedCall)
    }

    /// Whether `recomputed` carries the SUBMISSION this commitment was issued over.
    ///
    /// Split out because both verdicts need it and neither may reach a success without it.
    /// It is the only comparison that covers the hops after the verified prefix, and on a
    /// record with no verified prefix at all it is the only one that covers anything: the
    /// identity fields are then two empty handles and a fold over nothing, identical for
    /// every call that failed the same way.
    fn submission_corresponds_to(&self, recomputed: &Self) -> Result<(), HttpProfileError> {
        // A statement that carries no submission identity cannot bind one, whatever the
        // retained side carries, so it is refused rather than reported as bound on the
        // strength of its verified prefix. The condition is on THIS side alone, and
        // deliberately: a record the statement cannot identify is the same record whether
        // or not the retained half claims an identity, and one result is what that has to
        // produce.
        if !self.identifies_a_submission() {
            return Err(HttpProfileError::MalformedEvidence(
                "the statement carries no submission identity, so the retained submission cannot be bound to it",
            ));
        }
        if recomputed.submitted_commitment != self.submitted_commitment {
            return Err(HttpProfileError::MalformedEvidence(
                "retained submission does not match the commitment",
            ));
        }
        Ok(())
    }
}
