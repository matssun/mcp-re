// SPDX-License-Identifier: Apache-2.0
//! The audit RUN — the composition.
//!
//! It decides nothing of its own. It opens the archive, loads the three documents an
//! audit is asserted by, builds the posture from them, drives
//! [`crate::transparency::attest_chain`], and writes the artifact — in the one order that
//! makes the result mean what it says.
//!
//! # Fail closed, and where
//!
//! Everything an audit rests on is established BEFORE a statement is issued: an
//! unreadable archive, an incoherent profile, a trust document that will not parse, an
//! illegal service pin and a missing signing seed are all refusals, and none of them can
//! happen after bytes have been signed. What is deliberately NOT a refusal is an
//! INCOMPLETE record: that is a verdict, it is labelled, and it is exactly the record an
//! auditor most needs portable evidence about.
//!
//! # The service pin, and what it does here
//!
//! The pin is loaded and is not verified against anything in this half — there is no
//! receipt yet. It is not decoration:
//!
//! * as a CONTROL it decides whether the run proceeds at all. A statement cut for a
//!   service whose pin is unreadable or illegal can never be shown to have been registered
//!   with that service, so producing one would be producing an artifact with no possible
//!   future;
//! * as a WITNESS it goes into the artifact, naming which service this attestation is
//!   for, so a registration step cannot submit it to a different one by accident.
//!
//! Verifying a receipt against it is the registration step's job, and keeping the two
//! apart is why a produced attestation cannot be read as a registered one.
//!
//! # One limitation, stated rather than discovered
//!
//! [`crate::transparency::EvidenceRetention::open`] proves the archive WRITABLE — it
//! writes and removes a probe object, and starts the writer thread the serving path hands
//! jobs to. So this auditor needs write access to the directory it reads, and cannot run
//! against a read-only mount or a snapshot. That is a property of the retention
//! authority's only constructor, not of auditing, and splitting a read-only projection out
//! of it is that owner's decision rather than this one's.

use std::path::Path;

use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ChainAudit;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use crate::key_source::signing_key_from_seed_b64url;
use crate::transparency::attest_chain;
use crate::transparency::AttestError;
use crate::transparency::EvidenceRetention;
use crate::trust_document::TrustDocument;

use super::artifact::AttestationArtifact;
use super::artifact::AttestedService;
use super::invocation::AuditInvocation;
use super::profile::AuditProfile;
use super::trust_view::AuditorTrustView;

/// An audit that could not be performed. Every variant refuses the run.
#[derive(Debug)]
pub enum AuditError {
    /// An input document could not be read or could not be used.
    Input(String),
    /// The archive could not be opened.
    Archive(std::io::Error),
    /// The attestation could not be established over what was read.
    Attest(AttestError),
    /// The artifact could not be written.
    Output(std::io::Error),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Input(what) => write!(f, "{what}"),
            AuditError::Archive(e) => write!(f, "retained-evidence archive: {e}"),
            AuditError::Attest(e) => write!(f, "attestation: {e}"),
            AuditError::Output(e) => write!(f, "writing the attestation artifact: {e}"),
        }
    }
}

impl std::error::Error for AuditError {}

/// Read a file, naming what was being read when it failed.
fn read(what: &str, path: &Path) -> Result<Vec<u8>, AuditError> {
    std::fs::read(path).map_err(|e| AuditError::Input(format!("{what} {}: {e}", path.display())))
}

/// Perform one audit: reconstruct the named record, attest to it, and write the artifact.
pub fn attest(invocation: &AuditInvocation) -> Result<AttestationArtifact, AuditError> {
    let profile = AuditProfile::parse(&read("--audit-profile", &invocation.audit_profile)?)
        .map_err(AuditError::Input)?;
    let trust = TrustDocument::parse(&read("--trust-document", &invocation.trust_document)?)
        .map_err(AuditError::Input)?;
    let pin: ScittServiceTrustPin =
        serde_json::from_slice(&read("--service-trust-pin", &invocation.service_trust_pin)?)
            .map_err(|e| AuditError::Input(format!("--service-trust-pin: {e}")))?;
    let seed = read("--issuer-key-seed", &invocation.issuer_key_seed)?;
    let seed = std::str::from_utf8(&seed)
        .map_err(|_| AuditError::Input("--issuer-key-seed: not UTF-8".to_owned()))?;
    let issuer =
        signing_key_from_seed_b64url(seed).map_err(|e| AuditError::Input(format!("{e:?}")))?;

    let retention =
        EvidenceRetention::open(&invocation.retained_evidence_dir).map_err(AuditError::Archive)?;

    let attestation = reconstruct_and_issue(invocation, &profile, &trust, &retention, &issuer)
        .map_err(AuditError::Attest)?;

    let artifact = AttestationArtifact::of(
        &attestation,
        &invocation.hops,
        AttestedService {
            service_identifier: pin.service_identifier().to_owned(),
            kid: pin.kid().to_owned(),
        },
    )
    .map_err(AuditError::Input)?;

    let bytes = artifact.to_json().map_err(AuditError::Input)?;
    std::fs::write(&invocation.out, &bytes).map_err(AuditError::Output)?;
    Ok(artifact)
}

/// The posture, assembled and spent in one place.
///
/// Separate from [`attest`] because the borrows demand it: the verifier, the audit inputs
/// and the delegation expectations all borrow values that must outlive the call and none
/// of them can be returned. Keeping the assembly here also means there is exactly one
/// place where a posture is built, so there is no second combination for a caller to
/// construct.
fn reconstruct_and_issue(
    invocation: &AuditInvocation,
    profile: &AuditProfile,
    trust: &TrustDocument,
    retention: &EvidenceRetention,
    issuer: &mcp_re_core::SigningKey,
) -> Result<crate::transparency::Attestation, AttestError> {
    let view = AuditorTrustView::new(trust, profile);
    let resolve = |kid: &str, slot: SignerSlot| -> ResolverOutcome { view.resolve(kid, slot) };
    let policy = VerifierPolicy::default();
    let verifier = Verifier::new(&policy, &resolve);

    // The auditor supplies NO out-of-band credential material. A DPoP binding resolves
    // from the covered `authorization` header the archive keeps verbatim; anything else is
    // not derivable from the archive, and a hop that needs it is reported unverifiable
    // rather than verified against material an operator typed in.
    let no_material = |_: &ArtifactBinding| -> Option<Vec<u8>> { None };
    let audit = ChainAudit {
        expected_audience: profile.expected_audience(),
        artifact_material: &no_material,
    };

    let revoked = |kid: &str| -> bool { profile.is_revoked(kid) };
    profile.with_delegation(|expect| {
        attest_chain(
            retention,
            &invocation.hops,
            &verifier,
            expect,
            &audit,
            &revoked,
            invocation.at,
            &invocation.issuer_kid,
            // The auditor holds no PEP-side binding or verified-context digest — a
            // retained record is messages. `attest_chain` runs its own self-check with the
            // same absence, so the statement and the check are about the same thing.
            None,
            None,
            |preimage: &[u8]| {
                mcp_re_core::b64url_decode(&issuer.sign(preimage))
                    .map_err(|_| mcp_re_http_profile::HttpProfileError::InvalidSignature)
            },
        )
    })
}
