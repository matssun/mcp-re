// SPDX-License-Identifier: Apache-2.0
//! The auditor's RUNNABLE half — retained evidence in, a portable attestation out.
//!
//! [`super::attest_chain`] has been the auditor authority since ADR-MCPRE-054, and until
//! this module its only callers were an integration test's five call sites. A deployment
//! could therefore turn `--retained-evidence-dir` on and accumulate evidence it had no
//! shipped way to attest: the serving half was a product and the auditing half was a
//! library driven from a harness. That is what
//! `docs/architecture/components/scitt-externalization-census.md` recorded as G-2, and
//! this module is its answer.
//!
//! ## Off the request path, and structurally so
//!
//! It is a SEPARATE EXECUTABLE (`mcp-re-auditor`), not a mode of the serving proxy. The
//! three reasons [`super`] gives for keeping attestation off the request path are reasons
//! about *when* it runs; a mode flag would honour all three and still put the auditor's
//! trust inputs, signing key and audit posture inside the process that answers requests.
//! A deployment that runs one does not have to run the other, and an auditor may run on
//! an archive long after the proxy that produced it is gone.
//!
//! It is an additional binary in THIS crate rather than a new one because the authority it
//! composes — `attest_chain`, [`super::RetainedArchive`], the deployment's trust
//! document — lives here. A separate crate would depend on this one for all of it and buy
//! nothing but a directory.
//!
//! ## The authorities
//!
//! ```text
//! auditor                the facade — this file re-exports, and owns nothing
//!   ├─ invocation    A   WHICH record this run attests, and where its inputs are
//!   ├─ profile       B   WHAT this auditor asserts about the deployment it audits
//!   ├─ trust_view    C   WHICH keys were legitimate signers, frozen for this run
//!   ├─ artifact      D   the portable product, and the registration interface
//!   ├─ inputs        E   every document this run is asserted by, in hand before signing
//!   ├─ refusal           WHICH stage did not complete, and what survived it
//!   ├─ registration      submitting the attestation, and verifying what comes back
//!   └─ run               the composition: load, open, reconstruct, attest, write, submit
//! ```
//!
//! ## It reads the archive, and holds nothing that could write to it
//!
//! The archive is opened through [`super::RetainedArchive`], the retention owner's READ
//! projection: no writability probe, no writer thread, no create. An audit therefore runs
//! against a read-only mount or a snapshot, and an auditor never holds write access to the
//! evidence it attests (MCPRE-179).
//!
//! ## Two outcomes, in that order
//!
//! Producing the Signed Statement and submitting it are separate authorities with separate
//! failures, so they are separate steps and the attestation is durable before anything is
//! submitted. An auditor with no transparency service still gets everything up to the
//! submission; one whose service is down loses the receipt and nothing else, because
//! re-running with the same audit instant reproduces the statement byte for byte.
//!
//! Registration is opt-in and lives in [`registration`], where the certainty of a failure
//! is decided: *definitely not registered* and *may be registered* are different answers,
//! and only an explicit refusal from the service is the first.
//!
//! ## What this half deliberately does NOT do
//!
//! **No out-of-band credential material.** [`mcp_re_http_profile::ChainAudit`] takes an
//! `artifact_material` seam for credentials a retained request cannot supply; this auditor
//! answers `None` to every binding. A DPoP binding resolves from the covered
//! `authorization` header, which retention keeps verbatim, so the common case needs
//! nothing. Anything else is not derivable from the archive, and a hop that needs it is
//! reported as unverifiable rather than verified against material an operator typed in.
//! That is the fail-closed direction and it removes a credential-injection surface with no
//! operator story behind it.
//!
//! **No refusal of an INCOMPLETE record.** A truncated or broken chain is attested and
//! labelled, because refusing would leave the most interesting records with no portable
//! evidence at all. What fails closed is not being able to READ the archive, or not being
//! able to establish the attestation over what was read.

/// WHICH record this run attests, and where its inputs are.
mod invocation;

/// WHAT this auditor asserts about the deployment it audits.
mod profile;

/// WHICH keys were legitimate signers, frozen for the duration of one audit.
mod trust_view;

/// The portable product of one audit — and the interface the registration step consumes.
mod artifact;

/// The documents one run is asserted by, loaded before anything is signed.
mod inputs;

/// WHAT a run refuses in, and which refusal still leaves an attestation behind.
mod refusal;

/// The composition: open the archive, load the posture, reconstruct, attest, write.
mod run;

/// Registering an attestation with an external Transparency Service.
mod registration;

pub use artifact::AttestationArtifact;
pub use artifact::AttestedService;
pub use artifact::ChainVerdict;
pub use artifact::CorrespondenceVerdict;
pub use artifact::IncompleteAt;
pub use invocation::AuditInvocation;
pub use profile::AuditProfile;
pub use refusal::AuditError;
pub use registration::RegisteredStatement;
pub use registration::RegistrationError;
pub use run::attest;
