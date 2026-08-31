// SPDX-License-Identifier: Apache-2.0
//! The reconstruction a chain verification produces, and what may be said about one.
//!
//! Its own module because it owns an invariant its neighbours only read. The record's
//! `submitted_commitment` is an IDENTITY for the submission — the one field that reaches
//! the hops after the verified prefix — and the only way to obtain a real one is
//! [`super::reconstruct_chain`], which digests the submitted bytes. The representation is
//! private so that a record which cannot reproduce that digest has to say so through
//! [`ChainReconstruction::from_retained_handles`], rather than by leaving a field empty in
//! passing where nothing names the limitation.

use super::ChainLabel;
use super::HopEvidence;

/// The reconstruction output. Shaped so a Layer 5 receipt can commit to it: the
/// label is part of the record, so an incomplete chain is representable and
/// distinguishable rather than being an absence of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReconstruction {
    label: ChainLabel,
    /// The per-hop (request handle, response handle) pairs, in order, for every
    /// hop that verified before the chain was labeled. On a `Complete` chain this
    /// is every hop; on an `Incomplete` one it is the verified prefix — the part
    /// of the record that IS accounted for.
    hop_evidence: Vec<HopEvidence>,
    /// A digest over the SUBMITTED hop bytes, whether or not any of them verified.
    ///
    /// [`hop_evidence`](Self::hop_evidence) is the verified prefix, so a chain that
    /// broke at hop 0 contributes nothing to it and every such record collapsed to the
    /// same three identity fields: two empty handles and a fold over zero bytes. A
    /// Signed Statement about one could not be told from a statement about any other
    /// call that failed the same way, which makes "this record is about that call" an
    /// unanswerable question exactly where an auditor most needs it answered.
    ///
    /// This is the answer, and it is deliberately taken from what was SUBMITTED rather
    /// than from what verified: unverified bytes are still specific bytes. It is an
    /// identity, never an endorsement — nothing here asserts the submission was
    /// well-formed, authentic, or served.
    submitted_commitment: String,
}

impl ChainReconstruction {
    /// How the chain was labeled — `Complete`, or which hop broke it and why.
    pub fn label(&self) -> &ChainLabel {
        &self.label
    }

    /// The per-hop handles of the VERIFIED PREFIX, in order.
    pub fn hop_evidence(&self) -> &[HopEvidence] {
        &self.hop_evidence
    }

    /// The digest identifying the SUBMISSION this record was made over, or an empty string
    /// for a record that identifies none.
    pub fn submitted_commitment(&self) -> &str {
        &self.submitted_commitment
    }

    /// The record [`super::reconstruct_chain`] produces, carrying the identity it computed
    /// over the submitted hops.
    ///
    /// `pub(super)`: visible to the `chain` module and nothing else, because that is where
    /// the only code that can compute a real submission identity lives. It is the narrowest
    /// level the legitimate producer can work at — the producer is this type's PARENT, not
    /// a sibling, so a `pub(crate)` here would hand the same unchecked construction to
    /// every module in the crate for no gain.
    pub(super) fn from_verified_chain(
        label: ChainLabel,
        hop_evidence: Vec<HopEvidence>,
        submitted_commitment: String,
    ) -> Self {
        ChainReconstruction {
            label,
            hop_evidence,
            submitted_commitment,
        }
    }

    /// The record an auditor holds when the retained artifact carries HANDLES rather than
    /// the submitted messages.
    ///
    /// It identifies no submission and cannot be made to: the digest is over the submitted
    /// bytes, and an artifact that did not keep them cannot reproduce it. Saying so is the
    /// whole purpose — [`crate::scitt::verify_retained_evidence`] refuses a record that
    /// binds no submission rather than reporting the verified-prefix match as though it
    /// reached the tail.
    ///
    /// This is the ONLY producer outside [`reconstruct_chain`], and it deliberately takes
    /// no submission identity. A caller that could supply one would be authoring an
    /// identity nothing computed, which is the fabrication the private field exists to make
    /// unconstructible — and the interop corpus, whose artifact carries `req-0`/`rsp-0`
    /// handles, was doing exactly that through a struct literal.
    pub fn from_retained_handles(label: ChainLabel, hop_evidence: Vec<HopEvidence>) -> Self {
        ChainReconstruction {
            label,
            hop_evidence,
            submitted_commitment: String::new(),
        }
    }

    /// The verified prefix, mutably, for the controls that alter or truncate it.
    ///
    /// `#[cfg(test)]` and `pub(crate)`: production never edits a reconstruction after it is
    /// built, and a public mutable projection would be the seal in name only.
    #[cfg(test)]
    pub(crate) fn hop_evidence_mut(&mut self) -> &mut Vec<HopEvidence> {
        &mut self.hop_evidence
    }

    /// A reconstruction carrying an AUTHORED submission identity — a corpus fixture, and
    /// nothing a production path produces.
    ///
    /// Public because conformance vectors in other crates pin the ENCODING of a commitment
    /// and need one that identifies a submission; there is no production caller and there
    /// must not be, since a real identity is [`reconstruct_chain`]'s digest over the
    /// submitted hops.
    ///
    /// **What the seal on this field does and does not buy.** It is not that a string is
    /// hard to author: an authored identity can only ever match a statement whose identity
    /// was authored the same way, and a real statement carries the real digest, so a
    /// fabricated record cannot be made to bind a real one — [`Self::submitted_commitment`]
    /// is compared, not trusted. What the private field buys is that a record with NO
    /// identity has one named producer, [`Self::from_retained_handles`], so an artifact
    /// that cannot reproduce the digest says so rather than filling the field in silently.
    pub fn with_authored_submission_identity(
        label: ChainLabel,
        hop_evidence: Vec<HopEvidence>,
        submitted_commitment: String,
    ) -> Self {
        ChainReconstruction {
            label,
            hop_evidence,
            submitted_commitment,
        }
    }
}