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

/// The chain verdict as the artifact spells it.
mod verdict;

/// Deriving the artifact from one completed attestation.
mod derivation;

/// The artifact read back.
mod document;

pub use document::AttestationDocument;
pub use document::ClaimedRegistration;
pub use verdict::ChainVerdict;
pub use verdict::CorrespondenceVerdict;
pub use verdict::IncompleteAt;

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
#[derive(Debug, Clone, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<String>,
    /// WHICH contract established the registration, present exactly when `receipt` is.
    ///
    /// Written because the two mechanisms do not earn the same sentence: a run against a
    /// SCRAPI peer is SCRAPI interoperability, a run against `capsule-anchor` is external
    /// Transparency Service interoperability, and a reader of this file has no other way to
    /// tell which one produced the receipt beside it. Set by the same method, from the same
    /// `RegisteredStatement`, so the two facts cannot disagree.
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_protocol: Option<String>,
}

impl AttestationArtifact {
    /// The same artifact, now carrying the receipt of a VERIFIED registration.
    ///
    /// The argument is the proof: a `RegisteredStatement` is constructible only by the
    /// function that put the service's answer through the offline verifier against the
    /// exact statement submitted and the operator's pin. There is no way to attach a
    /// receipt that merely arrived. It is refused unless this artifact carries the very
    /// statement the receipt verified against.
    pub fn with_verified_receipt(
        mut self,
        registered: &crate::transparency::auditor::registration::RegisteredStatement,
    ) -> Result<Self, String> {
        if self.signed_statement()? != registered.statement_bytes() {
            return Err(
                "attestation artifact: the receipt is about a different statement".to_owned(),
            );
        }
        self.receipt = Some(mcp_re_core::b64url_encode(registered.receipt_bytes()));
        // Set HERE, from the same value, so a receipt and the contract that produced it
        // arrive together or not at all.
        self.registration_protocol = Some(registered.protocol().to_owned());
        Ok(self)
    }

    /// The contract that established the registration, if this attestation was registered.
    pub fn registration_protocol(&self) -> Option<&str> {
        self.registration_protocol.as_deref()
    }

    /// The verified receipt, if this attestation was registered.
    pub fn receipt(&self) -> Option<Result<Vec<u8>, String>> {
        self.receipt.as_ref().map(|encoded| {
            mcp_re_core::b64url_decode(encoded)
                .map_err(|_| "attestation artifact: receipt is not base64url".to_owned())
        })
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
impl AttestationArtifact {
    /// An artifact around `signed_statement`, as a reader would hold it.
    pub(in crate::transparency::auditor) fn carrying_statement(signed_statement: &[u8]) -> Self {
        AttestationArtifact {
            schema: ATTESTATION_SCHEMA.to_owned(),
            issuer_kid: "auditor-1".to_owned(),
            issued_at: 1_700_000_100,
            signed_statement: mcp_re_core::b64url_encode(signed_statement),
            hops: Vec::new(),
            chain: ChainVerdict::Complete,
            correspondence: CorrespondenceVerdict::BoundToVerifiedCall,
            transparency_service: AttestedService {
                service_identifier: "example-ts".to_owned(),
                kid: "ts-1".to_owned(),
            },
            receipt: None,
            registration_protocol: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_http_profile::scitt::EvidenceDigest;

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
            registration_protocol: None,
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
        let read = AttestationDocument::parse(&bytes).expect("parses");

        assert_eq!(read.claimed_chain(), written.chain());
        assert!(!read.claimed_chain().is_complete());
        assert_eq!(
            read.claimed_correspondence(),
            CorrespondenceVerdict::BoundToVerifiedCall
        );
        assert_eq!(read.transparency_service(), &service());
        assert_eq!(
            read.signed_statement(),
            b"not a real statement",
            "registration submits the exact bytes, so they must survive verbatim",
        );
    }

    #[test]
    fn a_foreign_schema_is_refused() {
        let mut written = artifact(ChainVerdict::Complete);
        written.schema = "something-else/v1".to_owned();
        let bytes = written.to_json().expect("json");
        assert!(AttestationDocument::parse(&bytes).is_err());
    }

    #[test]
    fn a_statement_that_is_not_base64url_is_refused_on_the_way_in() {
        let mut written = artifact(ChainVerdict::Complete);
        written.signed_statement = "!!!".to_owned();
        let bytes = written.to_json().expect("json");
        assert!(AttestationDocument::parse(&bytes).is_err());
    }
}
