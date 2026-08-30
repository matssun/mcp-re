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
    // The self-check compares a record against the bytes it names, and a reconstruction
    // with no verified prefix — a chain that broke at hop 0, and the empty chain — names
    // none: two empty handles and a fold over nothing. `verify_retained_evidence` refuses
    // such a record rather than reporting a match that would equally hold for every
    // unrelated submission that failed the same way, so running it here would refuse to
    // attest exactly the records this seam exists for. The statement is still issued: its
    // label says which hop broke, and `commits_to_verified_evidence` is how any reader
    // tells that it identifies no particular call.
    if statement.commitment().commits_to_verified_evidence() {
        mcp_re_http_profile::scitt::verify_retained_evidence(
            statement.commitment(),
            &reconstruction,
            bindings_commitment,
            verified_context_commitment,
        )
        .map_err(AttestError::Statement)?;
    }
    Ok(Attestation {
        statement,
        reconstruction,
    })
}
