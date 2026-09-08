// SPDX-License-Identifier: Apache-2.0
//! The ATTESTATION ARTIFACT — authority D.
//!
//! One fact: **the portable product of one audit**, and the interface a later registration
//! step consumes.
//!
//! It carries the exact Signed Statement bytes, and beside them the two verdicts a reader
//! must not have to decode COSE to see: whether the record is a COMPLETE one, and WHICH
//! binding the issuer's self-check established between the statement and the retained
//! bytes. Both are the reasons [`crate::transparency::Attestation`] hands back more than a
//! statement, and dropping them at the file boundary would undo that: an operator holding
//! the artifact would be back to acting on an INCOMPLETE record without knowing it.
//!
//! # One fact, one derivation
//!
//! The completeness verdict is read from the SIGNED commitment, not recomputed beside it.
//! The label the statement carries is the one a receipt will commit to, so a summary
//! derived from anything else could describe a different record than the one that gets
//! registered. The reconstruction supplies only what the commitment does not spell out —
//! which hop broke, and why — and construction REFUSES if the two disagree.

use serde::Deserialize;
use serde::Serialize;

use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::RetainedCorrespondence;

/// The chain verdict as the artifact spells it.
mod verdict;

pub use verdict::ChainVerdict;
pub use verdict::CorrespondenceVerdict;
pub use verdict::IncompleteAt;

use crate::transparency::Attestation;

/// The schema token an artifact carries.
pub(super) const ATTESTATION_SCHEMA: &str = "mcp-re-attestation/v1";

/// The transparency service this attestation was cut for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedService {
    /// How the operator's pin names the service.
    pub service_identifier: String,
    /// The `kid` that pin answers for.
    pub kid: String,
}

/// The portable product of one audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationArtifact {
    /// The schema token, so a reader knows what it is holding.
    schema: String,
    /// The `kid` the Signed Statement is attributed to.
    issuer_kid: String,
    /// The instant the statement was issued at, which is the audit instant.
    issued_at: i64,
    /// The exact Signed Statement, base64url. Registration submits these bytes verbatim.
    signed_statement: String,
    /// The hops that were reconstructed, in the order they were given.
    hops: Vec<String>,
    /// Whether the record is whole.
    chain: ChainVerdict,
    /// Which binding the issuer's self-check established.
    correspondence: CorrespondenceVerdict,
    /// The service this attestation is for.
    transparency_service: AttestedService,
    /// The transparency-service Receipt, base64url — present only when registration
    /// happened AND the receipt verified offline against the statement above and the
    /// operator's pin.
    ///
    /// That is the field's whole meaning, and it is why nothing can set it but
    /// [`AttestationArtifact::with_verified_receipt`], which takes a `RegisteredStatement`
    /// — a value that exists only on the far side of the verification. An artifact
    /// carrying a receipt is one whose receipt verified; an artifact without one says
    /// nothing about whether the statement reached a log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<String>,
}

impl AttestationArtifact {
    /// Build the artifact for one completed attestation.
    ///
    /// Refuses when the SIGNED commitment and the reconstruction disagree about whether
    /// the record is complete. They are derived from the same reconstruction in the same
    /// run, so a disagreement is not an operator error — it is the label inside the
    /// statement having drifted from the label the auditor read, and an artifact that
    /// summarized one while carrying the other would misdescribe exactly the records this
    /// distinction exists for.
    pub(super) fn of(
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
        })
    }

    /// The same artifact, now carrying the receipt of a VERIFIED registration.
    ///
    /// The argument is the proof: a `RegisteredStatement` is constructible only by the
    /// function that put the service's answer through the offline verifier against the
    /// exact statement submitted and the operator's pin. There is no way to attach a
    /// receipt that merely arrived.
    pub fn with_verified_receipt(
        mut self,
        registered: &crate::transparency::auditor::registration::RegisteredStatement,
    ) -> Self {
        self.receipt = Some(mcp_re_core::b64url_encode(registered.receipt_bytes()));
        self
    }

    /// The verified receipt, if this attestation was registered.
    pub fn receipt(&self) -> Option<Result<Vec<u8>, String>> {
        self.receipt.as_ref().map(|encoded| {
            mcp_re_core::b64url_decode(encoded)
                .map_err(|_| "attestation artifact: receipt is not base64url".to_owned())
        })
    }

    /// Read an artifact back, refusing anything this reader cannot use.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let artifact: AttestationArtifact =
            serde_json::from_slice(bytes).map_err(|e| format!("attestation artifact: {e}"))?;
        if artifact.schema != ATTESTATION_SCHEMA {
            return Err(format!(
                "attestation artifact: schema is {:?}, expected {ATTESTATION_SCHEMA:?}",
                artifact.schema,
            ));
        }
        // Decoded on the way in, so holding an artifact means its statement — and its
        // receipt, when it has one — are recoverable rather than recoverable-if-asked.
        artifact.signed_statement()?;
        if let Some(receipt) = artifact.receipt() {
            receipt?;
        }
        Ok(artifact)
    }

    /// The artifact as bytes an operator can keep beside the archive.
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| format!("attestation artifact: {e}"))
    }

    /// The EXACT Signed Statement bytes, for a registration step to submit.
    pub fn signed_statement(&self) -> Result<Vec<u8>, String> {
        mcp_re_core::b64url_decode(&self.signed_statement)
            .map_err(|_| "attestation artifact: signed_statement is not base64url".to_owned())
    }

    /// The service this attestation was cut for.
    pub fn transparency_service(&self) -> &AttestedService {
        &self.transparency_service
    }

    /// Whether the record is whole.
    pub fn chain(&self) -> &ChainVerdict {
        &self.chain
    }

    /// Which binding the issuer's self-check established.
    pub fn correspondence(&self) -> CorrespondenceVerdict {
        self.correspondence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> AttestedService {
        AttestedService {
            service_identifier: "example-ts".to_owned(),
            kid: "ts-1".to_owned(),
        }
    }

    fn artifact(chain: ChainVerdict) -> AttestationArtifact {
        AttestationArtifact {
            schema: ATTESTATION_SCHEMA.to_owned(),
            issuer_kid: "auditor-1".to_owned(),
            issued_at: 1_700_000_100,
            signed_statement: mcp_re_core::b64url_encode(b"not a real statement"),
            hops: vec![EvidenceDigest::of(b"hop-0").as_str().to_owned()],
            chain,
            correspondence: CorrespondenceVerdict::BoundToVerifiedCall,
            transparency_service: service(),
            receipt: None,
        }
    }

    /// The two verdicts survive the file boundary — which is the whole reason the artifact
    /// carries more than the statement.
    #[test]
    fn an_artifact_round_trips_its_verdicts() {
        let written = artifact(ChainVerdict::Incomplete {
            hop: 2,
            reason: IncompleteAt::ResponseUnverifiable,
            wire_code: Some("mcp-re.signature_invalid".to_owned()),
        });
        let bytes = written.to_json().expect("json");
        let read = AttestationArtifact::parse(&bytes).expect("parses");

        assert_eq!(read.chain(), written.chain());
        assert!(!read.chain().is_complete());
        assert_eq!(
            read.correspondence(),
            CorrespondenceVerdict::BoundToVerifiedCall
        );
        assert_eq!(read.transparency_service(), &service());
        assert_eq!(
            read.signed_statement().expect("recoverable"),
            b"not a real statement",
            "registration submits the exact bytes, so they must survive verbatim",
        );
    }

    #[test]
    fn a_foreign_schema_is_refused() {
        let mut written = artifact(ChainVerdict::Complete);
        written.schema = "something-else/v1".to_owned();
        let bytes = written.to_json().expect("json");
        assert!(AttestationArtifact::parse(&bytes).is_err());
    }

    #[test]
    fn a_statement_that_is_not_base64url_is_refused_on_the_way_in() {
        let mut written = artifact(ChainVerdict::Complete);
        written.signed_statement = "!!!".to_owned();
        let bytes = written.to_json().expect("json");
        assert!(AttestationArtifact::parse(&bytes).is_err());
    }
}
