// SPDX-License-Identifier: Apache-2.0
//! The audit RUN — the composition.
//!
//! It decides nothing of its own. It loads the documents an audit is asserted by, opens
//! the archive, builds the posture, drives [`crate::transparency::attest_chain`], writes
//! the artifact, and — when this run was asked to — registers it. In the one order that
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
//! Verifying a receipt against it is [`super::registration`]'s job, and keeping the two
//! apart is why a produced attestation cannot be read as a registered one.
//!
//! # Registration is the second outcome, never the first
//!
//! It runs after the artifact is on disk. A submission that does not succeed therefore
//! costs the receipt and nothing else: the attestation is durable, offline-verifiable, and
//! reproducible byte for byte by re-running with the same `--at`. That is why
//! [`AuditError::Registration`] is its own variant. [`AuditError::ReceiptNotRecorded`] is
//! the second surviving outcome: the statement IS registered and the artifact on disk is
//! the attestation without its receipt. Every other variant means no artifact exists, and
//! collapsing them would have an operator discard a portable record because a network was
//! down.
//!
//! # It opens the archive for READING, and holds no more than that
//!
//! [`crate::transparency::RetainedArchive::open_read_only`] takes no write authority,
//! creates nothing and starts no thread, so an audit runs against a read-only mount or a
//! filesystem snapshot — the ordinary way an archive is handed to somebody meant to audit
//! it and not to add to it. This process never constructs an
//! [`crate::transparency::EvidenceRetention`]: the serving authority still proves its
//! directory writable at startup, and that is a claim only a replica that will write needs
//! to make (MCPRE-179).

use std::path::Path;

use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ChainAudit;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::Verifier;
use mcp_re_http_profile::VerifierPolicy;

use crate::transparency::attest_chain;
use crate::transparency::AttestError;
use crate::transparency::RetainedArchive;
use crate::trust_document::TrustDocument;

use super::artifact::AttestationArtifact;
use super::durable_file::replace_atomically;
use super::inputs::AuditInputs;
use super::invocation::AuditInvocation;
use super::profile::AuditProfile;
use super::refusal::AuditError;
use super::trust_view::AuditorTrustView;

/// Perform one audit: reconstruct the named record, attest to it, write the artifact, and
/// — if this run was asked to — register it.
pub fn attest(invocation: &AuditInvocation) -> Result<AttestationArtifact, AuditError> {
    // Every document first, and the archive after. An input that will not do must refuse
    // before a statement exists, not after one has been signed and possibly submitted.
    let inputs = AuditInputs::load(invocation).map_err(AuditError::Input)?;

    let archive = RetainedArchive::open_read_only(invocation.retained_evidence_dir())
        .map_err(AuditError::Archive)?;

    let attestation = reconstruct_and_issue(
        invocation,
        &inputs.profile,
        &inputs.trust,
        &archive,
        &inputs.issuer,
    )
    .map_err(AuditError::Attest)?;

    let artifact =
        AttestationArtifact::of(&attestation, invocation.hops(), inputs.attested_service())
            .map_err(AuditError::Input)?;

    write(invocation.output_path(), &artifact)?;

    // Registration is a SEPARATE outcome, and it runs after the attestation is durable.
    // A failed submission must not cost the attestation: an operator who cannot reach a
    // transparency service still holds a portable, offline-verifiable record, and
    // re-running this audit with the same `--at` reproduces the same statement byte for
    // byte, so nothing is lost by trying again later.
    let Some(target) = invocation.registration() else {
        return Ok(artifact);
    };
    // The receipt's service key is judged at the host's current time, never at `--at`:
    // that instant dates the statement, and a key revoked since must not be honoured.
    let ts_key = |kid: &str| inputs.profile.transparency_key_lifecycle(kid).copied();
    let registered = target
        .register(
            &attestation.statement,
            &inputs.issuer.public_key(),
            &inputs.pin,
            &ts_key,
            crate::clock::now_unix(),
        )
        .map_err(AuditError::Registration)?;
    let artifact = artifact
        .with_verified_receipt(&registered)
        .map_err(AuditError::ReceiptNotRecorded)?;
    record_receipt(invocation.output_path(), &artifact)?;
    Ok(artifact)
}

/// Write the artifact, replacing whatever is there.
fn write(path: &Path, artifact: &AttestationArtifact) -> Result<(), AuditError> {
    let bytes = artifact.to_json().map_err(AuditError::Input)?;
    replace_atomically(path, &bytes).map_err(AuditError::Output)
}

/// Replace the artifact with its receipt-bearing form after the statement is registered.
fn record_receipt(path: &Path, artifact: &AttestationArtifact) -> Result<(), AuditError> {
    let bytes = artifact.to_json().map_err(AuditError::ReceiptNotRecorded)?;
    replace_atomically(path, &bytes).map_err(|e| AuditError::ReceiptNotRecorded(e.to_string()))
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
    archive: &RetainedArchive,
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
            archive,
            invocation.hops(),
            &verifier,
            expect,
            &audit,
            &revoked,
            invocation.at(),
            invocation.issuer_kid(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Once the statement is registered, a failure to record its receipt is not an
    /// `Output` refusal: it names the registration and says not to re-submit.
    #[test]
    fn a_receipt_that_cannot_be_recorded_reports_the_registration() {
        let artifact = AttestationArtifact::carrying_statement(b"x");
        let dir = std::env::temp_dir().join(format!("auditor-run-receipt-{}", std::process::id()));
        let out = dir.join("missing-parent").join("artifact.json");

        let err = record_receipt(&out, &artifact).expect_err("parent is absent");
        assert!(matches!(err, AuditError::ReceiptNotRecorded(_)));
        let shown = err.to_string();
        assert!(shown.contains("IS registered"));
        assert!(!shown.contains("writing the attestation artifact"));
    }

    /// An unwritable artifact path before registration is still `Output`: no artifact
    /// exists.
    #[test]
    fn a_write_that_fails_before_registration_is_an_output_refusal() {
        let artifact = AttestationArtifact::carrying_statement(b"x");
        let out = std::env::temp_dir()
            .join(format!("auditor-run-output-{}", std::process::id()))
            .join("missing-parent")
            .join("artifact.json");

        let err = write(&out, &artifact).expect_err("parent is absent");
        assert!(matches!(err, AuditError::Output(_)));
    }
}
