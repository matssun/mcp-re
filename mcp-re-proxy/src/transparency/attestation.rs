// SPDX-License-Identifier: Apache-2.0
//! Turning retained evidence into a portable SCITT record — the AUDITOR's half.
//!
//! Deliberately not on the request path, and for three separate reasons stated in [`super`]:
//! a chain is not whole until its last hop, the audit posture is the auditor's to choose,
//! and registering against a transparency service would make an audit dependency an
//! availability dependency.
//!
//! What comes back is BOTH the statement and the reconstruction it commits to. A
//! `SignedStatement` alone does not say whether the record it describes is whole — the
//! `ChainLabel` inside it does — so handing back only the statement would leave a caller
//! acting on an INCOMPLETE verdict, or discovering it by decoding what it had just
//! published.

use mcp_re_http_profile::scitt::EvidenceDigest;

use super::durability::EvidenceRetention;
use super::RetentionError;

/// What an attestation produced: the portable statement, and the chain verdict it
/// commits to.
///
/// Both, never just the statement. A `SignedStatement` alone does not say whether the
/// record it describes is whole — the `ChainLabel` inside it does, and handing back the
/// reconstruction means a caller can act on an INCOMPLETE verdict rather than discover
/// it by decoding the statement it just published.
pub struct Attestation {
    /// The RFC 9943 Signed Statement, ready to submit to a transparency service.
    pub statement: mcp_re_http_profile::scitt::SignedStatement,
    /// The reconstruction the statement commits to.
    pub reconstruction: mcp_re_http_profile::ChainReconstruction,
    /// WHICH binding the self-check established between the statement and the retained
    /// bytes it was issued over.
    ///
    /// Carried rather than discarded because the two are not interchangeable to a reader:
    /// a record with no verified hop binds its SUBMISSION and nothing else, and an
    /// attestation that reported only success would leave that distinction to be recovered
    /// from the chain label by a consumer who might not.
    pub correspondence: mcp_re_http_profile::scitt::RetainedCorrespondence,
}

/// An attestation that could not be produced.
#[derive(Debug)]
pub enum AttestError {
    /// The retained evidence could not be read.
    Retention(RetentionError),
    /// The statement could not be issued, or did not describe the retained bytes.
    Statement(mcp_re_http_profile::HttpProfileError),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestError::Retention(e) => write!(f, "{e}"),
            AttestError::Statement(e) => write!(f, "scitt statement: {}", e.wire_code()),
        }
    }
}

impl std::error::Error for AttestError {}

/// Reconstruct a retained chain and issue a Signed Statement committing to it.
///
/// This is the auditor step, off the request path by design (see the module note). It
/// runs the FULL delegated verification over every retained hop — that is what
/// `reconstruct_chain` is for, and the label it produces is embedded in the statement,
/// so a receipt could otherwise commit to a COMPLETE call record established without
/// any delegation chain ever being checked.
///
/// `audit` carries the two full-profile inputs the retained bytes cannot supply — the
/// verifier's own audience tuple and the artifact credential surface — so a `Complete`
/// label asserts what an admission asserts rather than the minimal proof path.
///
/// An INCOMPLETE chain is attested, not refused. That is the point of the §9 seam: a
/// truncated or broken record is representable and distinguishable, and refusing to
/// issue a statement about one would leave the most interesting records — the ones with
/// a hop missing — with no portable evidence at all.
///
/// The statement is verified against the retained bytes before it is returned. Issuing
/// is a signature over a commitment this function just computed, so checking it is
/// checking our own arithmetic — but the check is the one an auditor will later run
/// with the same call, and a statement that fails it must never leave this process.
#[allow(clippy::too_many_arguments)]
pub fn attest_chain<R: Into<mcp_re_http_profile::ResolverOutcome>>(
    retention: &EvidenceRetention,
    hops: &[EvidenceDigest],
    verifier: &mcp_re_http_profile::Verifier<'_, R>,
    expect: &mcp_re_http_profile::DelegationExpectations<'_>,
    audit: &mcp_re_http_profile::ChainAudit<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
    issuer_kid: &str,
    bindings_commitment: Option<String>,
    verified_context_commitment: Option<String>,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, mcp_re_http_profile::HttpProfileError>,
) -> Result<Attestation, AttestError> {
    let retained = retention.load_chain(hops).map_err(AttestError::Retention)?;
    let reconstruction =
        mcp_re_http_profile::reconstruct_chain(&retained, verifier, expect, audit, is_revoked, now);
    let commitment = mcp_re_http_profile::scitt::EvidenceCommitment::from_reconstruction(
        &reconstruction,
        bindings_commitment.clone(),
        verified_context_commitment.clone(),
    );
    let statement =
        mcp_re_http_profile::scitt::issue_signed_statement(issuer_kid, commitment, now, sign)
            .map_err(AttestError::Statement)?;
    // The self-check runs on EVERY record, including the ones with no verified hop. It
    // used to be skipped for those, on the reasoning that a reconstruction which broke at
    // hop 0 names no call — two empty handles and a fold over nothing, the same three
    // values for every unrelated submission that failed the same way. That reasoning is
    // right about the identity fields and wrong about the submission: `submitted_commitment`
    // is call-specific there too, and skipping left it unexercised on exactly the records
    // an auditor investigates (R9-C103, R9-C128).
    //
    // The verdict says which binding was established, and this seam does not weaken it:
    // `BoundToSubmissionOnly` means these are the bytes the issuer saw and no hop verified,
    // which is what the label already reports and what a reader must not read as more.
    let correspondence = mcp_re_http_profile::scitt::verify_retained_evidence(
        statement.commitment(),
        &reconstruction,
        bindings_commitment,
        verified_context_commitment,
    )
    .map_err(AttestError::Statement)?;
    Ok(Attestation {
        statement,
        reconstruction,
        correspondence,
    })
}
