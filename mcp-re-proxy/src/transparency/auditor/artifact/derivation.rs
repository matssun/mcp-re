// SPDX-License-Identifier: Apache-2.0
//! Deriving the artifact from one completed attestation.
//!
//! One fact: **what one attestation looks like as a file, and the refusal when its two
//! views of the record disagree.**
//!
//! A CHILD of [`super`] rather than a sibling: this is the artifact's SOLE producer and it
//! fills the private representation directly. A sibling would need a constructor taking
//! every field, which is the seal undone in order to move a function — and the field this
//! type most needs sealed is `receipt`, whose whole meaning is that nothing but a verified
//! registration can set it.
//!
//! # One fact, one derivation
//!
//! The completeness verdict is read from the SIGNED commitment, never recomputed beside it.
//! The label the statement carries is the one a receipt will commit to, so a summary derived
//! from anything else could describe a different record than the one that gets registered.
//! The reconstruction supplies only what the commitment does not spell out — which hop broke,
//! and why — and this function REFUSES if the two disagree.

use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::RetainedCorrespondence;

use crate::transparency::Attestation;

use super::AttestationArtifact;
use super::AttestedService;
use super::ChainVerdict;
use super::CorrespondenceVerdict;
use super::ATTESTATION_SCHEMA;

impl AttestationArtifact {
    /// Build the artifact for one completed attestation.
    ///
    /// Refuses when the SIGNED commitment and the reconstruction disagree about whether
    /// the record is complete. They are derived from the same reconstruction in the same
    /// run, so a disagreement is not an operator error — it is the label inside the
    /// statement having drifted from the label the auditor read, and an artifact that
    /// summarized one while carrying the other would misdescribe exactly the records this
    /// distinction exists for.
    pub(in crate::transparency::auditor) fn of(
        attestation: &Attestation,
        hops: &[EvidenceDigest],
        service: AttestedService,
    ) -> Result<Self, String> {
        let chain = ChainVerdict::of(attestation.reconstruction.label());
        if chain.is_complete() != attestation.statement.commitment().is_complete_record() {
            return Err(
                "the signed commitment and the reconstruction disagree about whether this \
                 record is complete; refusing to write an artifact that describes one and \
                 carries the other"
                    .to_owned(),
            );
        }
        Ok(AttestationArtifact {
            schema: ATTESTATION_SCHEMA.to_owned(),
            issuer_kid: attestation.statement.issuer_kid().to_owned(),
            issued_at: attestation.statement.issued_at(),
            signed_statement: mcp_re_core::b64url_encode(attestation.statement.to_cose()),
            hops: hops.iter().map(|d| d.as_str().to_owned()).collect(),
            chain,
            correspondence: match attestation.correspondence {
                RetainedCorrespondence::BoundToVerifiedCall => {
                    CorrespondenceVerdict::BoundToVerifiedCall
                }
                RetainedCorrespondence::BoundToSubmissionOnly => {
                    CorrespondenceVerdict::BoundToSubmissionOnly
                }
            },
            transparency_service: service,
            receipt: None,
            registration_protocol: None,
        })
    }
}
