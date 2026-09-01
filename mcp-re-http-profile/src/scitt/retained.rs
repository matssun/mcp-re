// SPDX-License-Identifier: Apache-2.0
//! Retained-evidence correspondence — authority F.
//!
//! One fact: **these bytes are the ones that statement was made about.**
//!
//! A verified receipt says a statement was registered; it says nothing whatever about the
//! evidence the statement commits to, which is retained OUTSIDE the log. This is the other
//! half, and it is a separate authority because the two failures are separate: a receipt can
//! verify over a record whose evidence nobody kept, and retained bytes can be genuine while
//! belonging to a different call.
//!
//! The comparison itself is [`EvidenceCommitment::corresponds_to`] — the commitment's rule,
//! not this module's. What belongs here is rebuilding the commitment from retained bytes
//! THROUGH THE SAME CONSTRUCTOR the issuer used, which is what stops the two derivations
//! drifting apart.

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use mcp_re_core::b64url_encode;

use crate::chain::ChainReconstruction;
use crate::error::HttpProfileError;

use super::commitment::EvidenceCommitment;
use super::commitment::RetainedCorrespondence;

/// The digest that names one retained-evidence object — the handle a Signed Statement
/// commits to.
///
/// Content-addressed on purpose: the name IS the digest, so a store cannot return
/// different bytes than the ones asked for without the name changing. There is no
/// separate integrity check to forget.
///
/// This is the STORE's address, not the commitment's handle — the handle a Signed
/// Statement carries is role-labelled (see [`verify_retained_evidence`]). Keeping the
/// object store role-agnostic is what lets the same bytes be retained once and
/// referenced from whichever role committed to them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceDigest(String);

impl EvidenceDigest {
    /// The digest of `evidence` — SHA-256, base64url, matching the commitment form.
    pub fn of(evidence: &[u8]) -> Self {
        EvidenceDigest(b64url_encode(&Sha256::digest(evidence)))
    }

    /// The digest as the base64url token a commitment carries.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A content-addressed store for the evidence a receipt COMMITS to but does not carry.
///
/// The split is §4.6's: a receipt is small and portable and reveals nothing, while the
/// full request/response bytes stay retained. An auditor needs both — the receipt to
/// know a record was registered, the retained bytes to know WHAT was registered. A
/// receipt alone is not the evidence, and this trait exists so that distinction has a
/// place in the code rather than only in prose.
///
/// Deliberately two methods. This is the narrow interface the SCITT commitment needs,
/// not an evidence platform: `put`/`get` over immutable content-addressed objects is
/// implementable over a filesystem now and an object store later without either
/// implementation knowing about the other.
pub trait RetainedEvidenceStore {
    /// The store's own error, so an implementation can surface its transport's faults.
    type Error;

    /// Retain `evidence` and return its digest. Storing the same bytes twice is not an
    /// error and yields the same digest — content addressing makes writes idempotent.
    fn put(&mut self, evidence: &[u8]) -> Result<EvidenceDigest, Self::Error>;

    /// The bytes for `digest`, or `None` if this store does not hold them.
    ///
    /// Absence is `None` rather than an error: a store legitimately does not hold every
    /// object in existence, and the caller — not the store — decides whether a missing
    /// object is fatal for the verification it is attempting.
    fn get(&self, digest: &EvidenceDigest) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// Check that retained evidence reproduces what a statement committed to.
///
/// This is the step that makes the retained/committed split mean something. A verified
/// receipt says a statement was registered; it says nothing about whether the bytes
/// somebody hands you later are the ones that statement was about. Recomputing the
/// handles is what connects them, and a missing or altered object must fail here rather
/// than be waved through because the receipt verified.
///
/// **Two different digests, deliberately.** The store addresses an object by a plain
/// SHA-256 of its bytes; a commitment names it by the §7.1 ROLE-LABELLED handle,
/// `sha256(label ‖ 0x00 ‖ bytes)`. They are not interchangeable, and the labelling is
/// not decoration: the identical signature base in a request role and a response role
/// must be two different values, or a response handle could be presented as a request
/// handle. So the handles here are derived through [`RequestEvidence`], the same code
/// the serving path uses, rather than recomputed from a formula copied to this module —
/// a copy could drift, and a drifted copy would silently accept the wrong bytes.
///
/// **The WHOLE record, not the first hop.** An earlier revision compared only
/// `request_evidence` and `response_evidence`, which
/// [`EvidenceCommitment::from_reconstruction`] takes from `hop_evidence.first()`. On a
/// multi-hop call that proved hop 0 and nothing else: `chain_commitment` — the field
/// whose documented job is to commit to the SHAPE of the retained chain — had no
/// reader anywhere in the workspace, so an archivist could retain hop 0 honestly and
/// drop or substitute every hop after it and still pass. That is exactly the quiet
/// truncation the §9 chain seam exists to prevent, so the check now takes the
/// reconstruction and compares EVERY field.
///
/// **The SUBMISSION, not only the verified prefix.** Every identity field above is
/// derived from the hops that verified, so on an Incomplete record the tail after the
/// break contributes to none of them and could be substituted wholesale for
/// attacker-chosen bytes that fail at the same hop index for the same reason.
/// `submitted_commitment` is the digest over the submitted hops, verified or not, and it
/// is compared here — otherwise the field that exists to close that gap would be inert.
/// A statement issued before the profile carried it
/// ([`EvidenceCommitment::identifies_a_submission`]) cannot bind a submission at all, so
/// it is refused rather than reported as bound on the strength of its verified prefix.
///
/// The comparison is made by REBUILDING the commitment through the same constructor
/// the issuer used and comparing the results, rather than by re-deriving each field
/// here. A second implementation of the same rule is a second thing to keep in sync,
/// and a drifted copy accepts the wrong bytes silently.
///
/// **A record with no verified hop is bound by its SUBMISSION, and says only that.** A
/// reconstruction that broke at hop 0 — and the empty chain — has no verified prefix, so
/// [`EvidenceCommitment::from_reconstruction`] emits two empty handles and a shape
/// digest over zero bytes. Those are the same three values for every unrelated call
/// that failed at hop 0, so comparing them proves nothing, and reporting
/// [`RetainedCorrespondence::BoundToVerifiedCall`] there would announce a binding the
/// check does not have.
///
/// `submitted_commitment` is not one of those three. It is the digest over the submitted
/// hops, verified or not, so it is call-specific on exactly these records — and it was
/// nevertheless never exercised on them, because the whole comparison returned early
/// (R9-C103, R9-C128). It is compared now, and the weaker verdict
/// [`RetainedCorrespondence::BoundToSubmissionOnly`] is what the result says: these are
/// the bytes the issuer saw, and no hop verified. There is no path to a success that
/// skipped the comparison, which is why the caller no longer decides whether to make it.
///
/// `bindings_commitment` / `verified_context_commitment` are passed back in because
/// the issuer supplied them as digests: this module never saw the artifact bytes and
/// so cannot recompute them. Passing `None` for a commitment that carries `Some`
/// fails — an absent artifact is a mismatch, not a waiver.
pub fn verify_retained_evidence(
    commitment: &EvidenceCommitment,
    reconstruction: &ChainReconstruction,
    bindings_commitment: Option<String>,
    verified_context_commitment: Option<String>,
) -> Result<RetainedCorrespondence, HttpProfileError> {
    let recomputed = EvidenceCommitment::from_reconstruction(
        reconstruction,
        bindings_commitment,
        verified_context_commitment,
    );
    commitment.corresponds_to(&recomputed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainLabel;
    use crate::chain::IncompleteReason;
    use crate::evidence::RequestEvidence;
    use crate::scitt::fixtures::*;
    use crate::scitt::offline::verify_receipt_offline;
    use crate::scitt::prototype::PrototypeTransparencyService;

    /// The retained chain reproduces the commitment, and altering any hop breaks it.
    #[test]
    fn retained_evidence_reproduces_the_commitment() {
        let retained = recon(ChainLabel::Complete, 1);
        let commitment = EvidenceCommitment::from_reconstruction(&retained, None, None);

        verify_retained_evidence(&commitment, &retained, None, None)
            .expect("the retained bytes match");

        let mut tampered_request = retained.clone();
        tampered_request.hop_evidence_mut()[0].request_evidence =
            RequestEvidence::from_signature_base(b"req-tampered");
        assert_eq!(
            verify_retained_evidence(&commitment, &tampered_request, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained request evidence does not match the commitment"
            ),
        );

        let mut tampered_response = retained.clone();
        tampered_response.hop_evidence_mut()[0].response_evidence =
            RequestEvidence::from_response_signature_base(b"rsp-tampered");
        assert_eq!(
            verify_retained_evidence(&commitment, &tampered_response, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained response evidence does not match the commitment"
            ),
        );
    }

    /// The defect this check exists for: retain hop 0 honestly, drop the rest. The
    /// first-hop handles still match, so only `chain_commitment` — the field that had
    /// no reader at all — can catch it.
    #[test]
    fn a_truncated_chain_is_refused_even_though_hop_zero_matches() {
        let full = recon(ChainLabel::Complete, 3);
        let commitment = EvidenceCommitment::from_reconstruction(&full, None, None);

        let mut truncated = full.clone();
        truncated.hop_evidence_mut().truncate(1);
        assert_eq!(
            truncated.hop_evidence()[0],
            full.hop_evidence()[0],
            "hop 0 is retained honestly — the old check compared only this"
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &truncated, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained chain does not match the committed chain shape"
            ),
        );

        // Substituting a later hop is the same defect in the other direction.
        let mut substituted = full.clone();
        substituted.hop_evidence_mut()[2].request_evidence =
            RequestEvidence::from_signature_base(b"req-substituted");
        assert!(verify_retained_evidence(&commitment, &substituted, None, None).is_err());
    }

    /// A record that identifies NO submission is refused, not matched.
    ///
    /// The companion to the case where the RETAINED side claims an identity the statement
    /// never made. Both are the same record — one this comparison does not reach past the
    /// verified prefix — so both refuse, and the condition is on the statement alone.
    #[test]
    fn a_statement_that_identifies_no_submission_binds_nothing() {
        let handles = recon(ChainLabel::Complete, 2);
        let without = ChainReconstruction::from_retained_handles(
            handles.label().clone(),
            handles.hop_evidence().to_vec(),
        );
        let commitment = EvidenceCommitment::from_reconstruction(&without, None, None);
        assert!(
            !commitment.identifies_a_submission(),
            "a record built from handles alone identifies no submission"
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &without, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "the statement carries no submission identity, so the retained submission cannot be bound to it"
            ),
            "every other field matches, and that is exactly why Ok would be a false report"
        );
    }

    /// The UNVERIFIED tail of an Incomplete record. Every field derived from the
    /// verified prefix matches — same hop 0, same shape digest, same
    /// `incomplete:1:<reason>` label — so only the submission identity separates the
    /// bytes the statement was issued over from an archivist's substitute.
    #[test]
    fn a_substituted_unverified_tail_is_refused_even_though_the_verified_prefix_matches() {
        let issued = recon(
            ChainLabel::Incomplete {
                hop: 1,
                reason: IncompleteReason::MissingContinuation,
            },
            1,
        );
        let issued = ChainReconstruction::with_authored_submission_identity(
            issued.label().clone(),
            issued.hop_evidence().to_vec(),
            "submission-as-issued".to_owned(),
        );
        let commitment = EvidenceCommitment::from_reconstruction(&issued, None, None);
        verify_retained_evidence(&commitment, &issued, None, None)
            .expect("the retained bytes are the ones the statement was issued over");

        // A different hop 1 — different bytes, failing at the same index for the same
        // reason. The verified prefix is untouched.
        let substituted = ChainReconstruction::with_authored_submission_identity(
            issued.label().clone(),
            issued.hop_evidence().to_vec(),
            "submission-substituted".to_owned(),
        );
        let recomputed = EvidenceCommitment::from_reconstruction(&substituted, None, None);
        assert_eq!(
            recomputed.verified_prefix_fields(),
            commitment.verified_prefix_fields(),
            "the verified prefix is untouched — only the submission identity differs",
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &substituted, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained submission does not match the commitment"
            ),
        );
    }

    /// A statement issued before the profile carried a submission identity binds only
    /// its verified prefix, which is a weaker result than this function reports — so it
    /// is refused rather than answered as if it were the same.
    #[test]
    fn a_statement_with_no_submission_identity_cannot_bind_retained_bytes() {
        let retained = recon(ChainLabel::Complete, 2);
        let issued = EvidenceCommitment::from_reconstruction(&retained, None, None);
        assert!(issued.identifies_a_submission());
        let pre_revision = issued.without_submission_identity();
        assert!(!pre_revision.identifies_a_submission());
        assert_eq!(
            verify_retained_evidence(&pre_revision, &retained, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "the statement carries no submission identity, so the retained submission cannot be bound to it"
            ),
        );
    }

    /// A record with no verified hop is bound by its SUBMISSION, and by nothing else.
    ///
    /// R9-C103 / R9-C128. The identity fields are constants for every hop-0 failure — two
    /// empty handles and a fold over nothing — so a check that compared only those would
    /// report a match between unrelated calls, which is why it used to refuse outright.
    /// Refusing, though, left `submitted_commitment` unexercised on exactly the records an
    /// auditor investigates, and that field is NOT a constant there: it digests the bytes
    /// that were submitted, verified or not.
    ///
    /// So the weaker binding is established and named, and the stronger one is not claimed.
    #[test]
    fn a_record_with_no_verified_hop_is_bound_by_its_submission_and_says_only_that() {
        let label = ChainLabel::Incomplete {
            hop: 0,
            reason: IncompleteReason::RequestUnverifiable(HttpProfileError::InvalidSignature),
        };
        let call_a = ChainReconstruction::with_authored_submission_identity(
            label.clone(),
            Vec::new(),
            "submitted-call-a".to_owned(),
        );
        let commitment = EvidenceCommitment::from_reconstruction(&call_a, None, None);
        assert!(
            !commitment.commits_to_verified_evidence(),
            "nothing verified, so the identity fields identify no call"
        );

        assert_eq!(
            verify_retained_evidence(&commitment, &call_a, None, None)
                .expect("its own submitted bytes bind"),
            RetainedCorrespondence::BoundToSubmissionOnly,
            "the weaker verdict is named rather than reported as a verified call"
        );

        // A DIFFERENT call that failed at hop 0 for the same reason. Every identity field
        // matches — that is the archivist substitution — and the submission separates them.
        let call_b = ChainReconstruction::with_authored_submission_identity(
            label.clone(),
            Vec::new(),
            "submitted-call-b".to_owned(),
        );
        assert_eq!(
            EvidenceCommitment::from_reconstruction(&call_b, None, None).verified_prefix_fields(),
            commitment.verified_prefix_fields(),
            "the identity fields cannot separate them — only the submission can"
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &call_b, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained submission does not match the commitment"
            ),
            "substituting another call's bytes is refused on the one field that is not a constant"
        );

        // The empty chain is a different submission too, and is refused as one.
        let nothing = ChainReconstruction::with_authored_submission_identity(
            ChainLabel::Incomplete {
                hop: 0,
                reason: IncompleteReason::EmptyChain,
            },
            Vec::new(),
            "submitted-nothing".to_owned(),
        );
        assert!(verify_retained_evidence(&commitment, &nothing, None, None).is_err());

        // A statement that carries NO submission identity still binds nothing here: with
        // no verified prefix either, there is no field left that could bind.
        let no_identity = commitment.clone().without_submission_identity();
        assert_eq!(
            verify_retained_evidence(&no_identity, &call_a, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "the statement carries no submission identity, so the retained submission cannot be bound to it"
            ),
        );

        // And a real record still reports the STRONGER verdict — otherwise the weaker one
        // would be satisfied by a check that had stopped distinguishing them.
        let real = recon(ChainLabel::Complete, 2);
        assert_eq!(
            verify_retained_evidence(
                &EvidenceCommitment::from_reconstruction(&real, None, None),
                &real,
                None,
                None,
            )
            .expect("a record with verified hops still binds"),
            RetainedCorrespondence::BoundToVerifiedCall,
        );
    }

    /// A commitment that names artifact bindings or a verified context is not
    /// satisfied by retained evidence that omits them.
    #[test]
    fn absent_bindings_do_not_satisfy_a_commitment_that_names_them() {
        let retained = recon(ChainLabel::Complete, 1);
        let commitment = EvidenceCommitment::from_reconstruction(
            &retained,
            Some("bindings-digest".into()),
            Some("context-digest".into()),
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &retained, None, None).unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained artifact bindings do not match the commitment"
            ),
        );
        assert_eq!(
            verify_retained_evidence(&commitment, &retained, Some("bindings-digest".into()), None)
                .unwrap_err(),
            HttpProfileError::MalformedEvidence(
                "retained verified context does not match the commitment"
            ),
        );
        verify_retained_evidence(
            &commitment,
            &retained,
            Some("bindings-digest".into()),
            Some("context-digest".into()),
        )
        .expect("both artifacts present and matching");
    }

    /// A verified receipt is NOT evidence retention. The receipt verifies with no
    /// retained bytes present at all, and the retained check is a separate refusal —
    /// so a caller cannot present "the receipt verified" as "the evidence is held".
    #[test]
    fn a_verified_receipt_does_not_imply_the_evidence_is_retained() {
        let commitment =
            EvidenceCommitment::from_reconstruction(&recon(ChainLabel::Complete, 1), None, None);
        let st = statement(commitment.clone());
        let mut svc = PrototypeTransparencyService::new(TS_KID);
        let receipt = register(&mut svc, &st);

        // The receipt verifies knowing nothing about the underlying evidence.
        verify_receipt_offline(&st, &receipt, ir(), tr()).expect("receipt verifies");

        // And the evidence check still fails when the bytes are not the committed ones.
        let other = recon(ChainLabel::Complete, 2);
        assert!(verify_retained_evidence(&commitment, &other, None, None).is_err());
    }
}
