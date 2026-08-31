// SPDX-License-Identifier: Apache-2.0
//! What a record commits to — authority A.
//!
//! One fact: **which digests a record names, and whether it identifies a verified call.**
//! Every field is a digest of externally-retained evidence, never the evidence itself, and
//! the type's job is to make the label and the digests inseparable.
//!
//! Whether retained BYTES reproduce a commitment is [`super::retained`]'s; when two
//! commitments describe the same call is the commitment's, and lives in
//! [`correspondence`].

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use mcp_re_core::b64url_encode;

use crate::chain::ChainLabel;
use crate::chain::ChainReconstruction;

mod correspondence;

/// The MCP-RE evidence a receipt commits to (#415 §4.6), as HASH COMMITMENTS. Each
/// field is a digest of externally-retained evidence, never the evidence itself.
///
/// # The two producers, both named
///
/// The census (EX-004 question 11) found all seven fields `pub`, so a `complete` label
/// could be paired with handles from an unrelated call — a record asserting a whole chain
/// while naming digests that were never folded together. The representation is now private
/// and there are exactly two ways to obtain one:
///
/// 1. [`from_reconstruction`](Self::from_reconstruction) — DERIVED. Every field comes from
///    one `ChainReconstruction`, so the label and the handles cannot disagree, because
///    nothing chooses them separately.
/// 2. `Deserialize` — RECEIVED. A statement read off the wire is a CLAIM by its issuer, and
///    it is trusted only after the issuer's `COSE_Sign1` verifies over it. That is not a
///    hole in the seal; it is what a received record is, and naming it here is the point.
///
/// What is gone is the third way: assembling one field by field in this process. The
/// comparison that used to destructure seven fields at the call site is now
/// [`corresponds_to`](Self::corresponds_to), so the rule for *when two commitments describe
/// the same call* belongs to the value rather than to whoever remembered to write it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCommitment {
    /// Digest over the request signature base (the request evidence handle).
    request_evidence: String,
    /// Digest over the response signature base (the response evidence handle).
    response_evidence: String,
    /// Digest over the canonical bytes of the artifact bindings, or `None` when
    /// the call carried none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bindings_commitment: Option<String>,
    /// Digest over the verified-context the PEP produced, or `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_context_commitment: Option<String>,
    /// The chain-reconstruction label this record commits to — complete, or
    /// incomplete naming the failing hop. Serialized as a string so a receipt
    /// distinguishes the two without re-running reconstruction.
    chain_label: String,
    /// Digest over the ordered per-hop evidence handles the reconstruction
    /// produced — the commitment to the SHAPE of the retained chain.
    chain_commitment: String,
    /// Digest over the SUBMITTED hop bytes, verified or not.
    ///
    /// The three fields above are all derived from the VERIFIED prefix, so a chain that
    /// broke at hop 0 left every record with the same two empty handles and the same
    /// fold over zero bytes: byte-identical statements about unrelated calls. This field
    /// gives such a record an identity — of the submission, not of a verified call. Read
    /// it with [`commits_to_verified_evidence`](Self::commits_to_verified_evidence),
    /// which still says whether anything in it verified.
    ///
    /// Defaulted for reading, because a v1 statement genuinely has no submission
    /// identity and refusing to parse one would make every pre-revision record
    /// unreadable rather than merely weaker. That default is safe HERE and would not be
    /// safe in a receipt header: this field lives inside the payload the issuer's
    /// COSE_Sign1 covers, so removing it from a v2 statement breaks the signature.
    /// Nothing an attacker can do turns a v2 record into a v1 one.
    /// [`identifies_a_submission`](Self::identifies_a_submission) is how a reader tells
    /// the two apart.
    #[serde(default)]
    submitted_commitment: String,
}

impl EvidenceCommitment {
    /// Build the commitment from a chain reconstruction plus the optional
    /// binding/context digests the caller retains.
    pub fn from_reconstruction(
        reconstruction: &ChainReconstruction,
        bindings_commitment: Option<String>,
        verified_context_commitment: Option<String>,
    ) -> Self {
        // The record commits to the FIRST hop's request/response handles as the
        // call's identity, and to a digest over every hop's handles as its shape.
        //
        // A reconstruction that broke at hop 0 — and the empty chain — has no verified
        // prefix, so there is nothing here to take an identity from: the handles are
        // empty and the shape digest folds over nothing. `submitted_commitment` is what
        // distinguishes two such records; it is an identity for the SUBMISSION and
        // asserts nothing about it, so
        // [`commits_to_verified_evidence`](Self::commits_to_verified_evidence) remains
        // how a reader tells whether anything verified. [`verify_retained_evidence`]
        // still refuses to compare retained bytes against such a record rather than
        // reporting a match that holds for every unrelated record that failed the same
        // way.
        let (request_evidence, response_evidence) = match reconstruction.hop_evidence().first() {
            Some(h) => (
                h.request_evidence.digest_value.clone(),
                h.response_evidence.digest_value.clone(),
            ),
            None => (String::new(), String::new()),
        };
        let mut shape = Sha256::new();
        for h in reconstruction.hop_evidence() {
            shape.update(h.request_evidence.digest_value.as_bytes());
            shape.update([0x00]);
            shape.update(h.response_evidence.digest_value.as_bytes());
            shape.update([0x00]);
        }
        EvidenceCommitment {
            request_evidence,
            response_evidence,
            bindings_commitment,
            verified_context_commitment,
            chain_label: label_token(reconstruction.label()),
            chain_commitment: b64url_encode(&shape.finalize()),
            submitted_commitment: reconstruction.submitted_commitment().to_owned(),
        }
    }

    /// Whether this record is a COMPLETE call record. An incomplete one is not a
    /// weaker complete record — it is a distinct, explicitly-labeled record, and a
    /// receipt over it can never read as whole.
    pub fn is_complete_record(&self) -> bool {
        self.chain_label == "complete"
    }

    /// Whether this commitment names any verified evidence at all.
    ///
    /// False for a reconstruction with no verified prefix — a chain that broke at hop
    /// 0, and the empty chain. Every such record produces the SAME three identity
    /// fields: two empty handles and SHA-256 over zero bytes. The label still says
    /// which hop broke and why, so the statement is a truthful record of "I was handed
    /// evidence and none of it verified", but it identifies no particular call, and
    /// recomputing the handles from some other archivist's bytes would reproduce it
    /// exactly. Anything that treats a commitment as naming specific bytes — above all
    /// [`verify_retained_evidence`] — must consult this first.
    pub fn commits_to_verified_evidence(&self) -> bool {
        !self.request_evidence.is_empty() || !self.response_evidence.is_empty()
    }

    /// The chain-reconstruction label this record commits to, as its receipt-embeddable
    /// token. Read it through [`is_complete_record`](Self::is_complete_record) unless the
    /// exact token is what is wanted — an auditor reading `incomplete:<hop>:<reason>`.
    pub fn chain_label(&self) -> &str {
        &self.chain_label
    }

    /// Whether this record identifies the SUBMISSION it was made about.
    ///
    /// False only for a statement issued before the evidence profile carried
    /// [`submitted_commitment`](Self::submitted_commitment). Such a record that also
    /// fails [`commits_to_verified_evidence`](Self::commits_to_verified_evidence) names
    /// nothing at all: it is a truthful account of "I was handed evidence and none of it
    /// verified" that could equally be an account of any other call that failed the same
    /// way. Anything reasoning about WHICH call a record concerns must consult this.
    pub fn identifies_a_submission(&self) -> bool {
        !self.submitted_commitment.is_empty()
    }

    /// The three identity fields the VERIFIED PREFIX derives, plus the label, for a test
    /// that needs to say "the prefix is untouched" about two commitments.
    ///
    /// `#[cfg(test)]` and `pub(super)`: not production surface, compiles to nothing outside
    /// the test build, and the assertion it serves belongs to the correspondence rule next
    /// door rather than to this module. Production consumers get
    /// [`corresponds_to`](Self::corresponds_to), which answers the whole question.
    #[cfg(test)]
    pub(super) fn verified_prefix_fields(&self) -> (&str, &str, &str, &str) {
        (
            &self.request_evidence,
            &self.response_evidence,
            &self.chain_commitment,
            &self.chain_label,
        )
    }

    /// This commitment with its submission identity erased — a PRE-REVISION record, which a
    /// v1 statement genuinely is.
    ///
    /// `#[cfg(test)]`: there is no production path that produces one and there must not be.
    /// It exists so a test can build the record a v1 issuer would have signed, without
    /// keeping a v1 issuer around to sign it.
    #[cfg(test)]
    pub(super) fn without_submission_identity(&self) -> Self {
        EvidenceCommitment {
            submitted_commitment: String::new(),
            ..self.clone()
        }
    }
}

/// The chain label as a receipt-embeddable token. `incomplete:<hop>:<reason>`
/// preserves WHICH hop broke the chain, so an auditor reading the receipt learns
/// the failing hop without the retained evidence.
fn label_token(label: &ChainLabel) -> String {
    match label {
        ChainLabel::Complete => "complete".to_owned(),
        ChainLabel::Incomplete { hop, reason } => format!("incomplete:{hop}:{reason:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::HopEvidence;
    use crate::chain::IncompleteReason;
    use crate::evidence::RequestEvidence;
    use crate::scitt::fixtures::*;
    use crate::scitt::retained::verify_retained_evidence;

    /// A chain that broke at hop 0 has no verified prefix, so all three identity
    /// fields degenerate to constants: two empty handles and SHA-256 over zero bytes.
    /// Every such record — of every unrelated call, whatever the retained bytes were —
    /// produces the same three values.
    ///
    /// This is stated as a test rather than left implicit because it is the reason the
    /// check below has to refuse: the comparison `verify_retained_evidence` makes
    /// simply has no discriminating power here.
    #[test]
    fn a_record_with_no_verified_hop_has_no_identity() {
        let broke_at_hop_zero = recon(
            ChainLabel::Incomplete {
                hop: 0,
                reason: IncompleteReason::ContinuationDoesNotLink,
            },
            0,
        );
        let empty = recon(
            ChainLabel::Incomplete {
                hop: 0,
                reason: IncompleteReason::ContinuationDoesNotLink,
            },
            0,
        );
        let a = EvidenceCommitment::from_reconstruction(&broke_at_hop_zero, None, None);
        let b = EvidenceCommitment::from_reconstruction(&empty, None, None);
        assert_eq!(a, b, "the identity fields carry nothing to tell them apart");
        assert!(a.request_evidence.is_empty());
        assert!(a.response_evidence.is_empty());
        assert_eq!(
            a.chain_commitment,
            b64url_encode(&Sha256::digest(b"")),
            "the shape digest folds over nothing"
        );
        assert!(!a.commits_to_verified_evidence());
        assert!(
            EvidenceCommitment::from_reconstruction(&recon(ChainLabel::Complete, 1), None, None)
                .commits_to_verified_evidence(),
            "a record with a verified hop DOES name evidence"
        );
    }

    /// The two roles are distinct values over the same bytes. Presenting the response
    /// base as the request base must fail — that is what the domain separation buys,
    /// and without this test the labelling could be dropped and everything else would
    /// still pass.
    #[test]
    fn the_two_evidence_roles_are_not_interchangeable() {
        let same = b"identical-signature-base".as_slice();
        let retained = ChainReconstruction::with_authored_submission_identity(
            ChainLabel::Complete,
            vec![HopEvidence {
                request_evidence: RequestEvidence::from_signature_base(same),
                response_evidence: RequestEvidence::from_response_signature_base(same),
            }],
            "test-submitted".to_owned(),
        );
        let commitment = EvidenceCommitment::from_reconstruction(&retained, None, None);
        assert_ne!(
            commitment.request_evidence, commitment.response_evidence,
            "the same bytes in two roles are two different handles"
        );
        verify_retained_evidence(&commitment, &retained, None, None)
            .expect("each role in its own place");
    }
}
