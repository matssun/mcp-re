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
    pub(in crate::scitt) fn corresponds_to(
        &self,
        recomputed: &Self,
    ) -> Result<RetainedCorrespondence, HttpProfileError> {
        // `submitted_commitment` is compared by `submission_corresponds_to` below.
        let EvidenceCommitment {
            request_evidence,
            response_evidence,
            bindings_commitment,
            verified_context_commitment,
            chain_label,
            chain_commitment,
            submitted_commitment: _,
        } = self;
        if recomputed.request_evidence != *request_evidence {
            return Err(HttpProfileError::MalformedEvidence(
                "retained request evidence does not match the commitment",
            ));
        }
        if recomputed.response_evidence != *response_evidence {
            return Err(HttpProfileError::MalformedEvidence(
                "retained response evidence does not match the commitment",
            ));
        }
        if recomputed.chain_commitment != *chain_commitment {
            return Err(HttpProfileError::MalformedEvidence(
                "retained chain does not match the committed chain shape",
            ));
        }
        if recomputed.chain_label != *chain_label {
            return Err(HttpProfileError::MalformedEvidence(
                "retained chain label does not match the commitment",
            ));
        }
        if recomputed.bindings_commitment != *bindings_commitment {
            return Err(HttpProfileError::MalformedEvidence(
                "retained artifact bindings do not match the commitment",
            ));
        }
        if recomputed.verified_context_commitment != *verified_context_commitment {
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
        // The verdict is chosen only after every field matched; it names what the statement
        // identifies.
        if self.commits_to_verified_evidence() {
            Ok(RetainedCorrespondence::BoundToVerifiedCall)
        } else {
            Ok(RetainedCorrespondence::BoundToSubmissionOnly)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ChainLabel, ChainReconstruction, IncompleteReason};
    use crate::scitt::fixtures::*;

    fn broke_at_hop_zero(reason: IncompleteReason) -> ChainReconstruction {
        ChainReconstruction::with_authored_submission_identity(
            ChainLabel::Incomplete { hop: 0, reason },
            Vec::new(),
            "submission-s".to_owned(),
        )
    }

    #[test]
    fn a_statement_over_a_verified_call_does_not_bind_a_reconstruction_that_verified_nothing() {
        let issued = EvidenceCommitment::from_reconstruction(
            &ChainReconstruction::with_authored_submission_identity(
                ChainLabel::Complete,
                recon(ChainLabel::Complete, 2).hop_evidence().to_vec(),
                "submission-s".to_owned(),
            ),
            None,
            None,
        );
        let recomputed = EvidenceCommitment::from_reconstruction(
            &broke_at_hop_zero(IncompleteReason::RequestUnverifiable(
                HttpProfileError::InvalidSignature,
            )),
            None,
            None,
        );
        assert_eq!(
            issued.corresponds_to(&recomputed).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained request evidence does not match the commitment"
            )
        );
    }

    #[test]
    fn the_submission_only_verdict_still_compares_label_and_artifacts() {
        let base = broke_at_hop_zero(IncompleteReason::RequestUnverifiable(
            HttpProfileError::InvalidSignature,
        ));
        let committed = EvidenceCommitment::from_reconstruction(&base, None, None);

        let other_label = EvidenceCommitment::from_reconstruction(
            &broke_at_hop_zero(IncompleteReason::EmptyChain),
            None,
            None,
        );
        assert_eq!(
            committed.corresponds_to(&other_label).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained chain label does not match the commitment"
            )
        );

        let with_bindings =
            EvidenceCommitment::from_reconstruction(&base, Some("bindings-b".to_owned()), None);
        assert_eq!(
            with_bindings.corresponds_to(&committed).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained artifact bindings do not match the commitment"
            )
        );

        assert_eq!(
            committed.corresponds_to(&committed),
            Ok(RetainedCorrespondence::BoundToSubmissionOnly)
        );
    }
}
