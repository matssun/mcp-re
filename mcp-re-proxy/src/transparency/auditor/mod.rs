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
//! composes — `attest_chain`, [`super::EvidenceRetention`], the deployment's trust
//! document — lives here. A separate crate would depend on this one for all of it and buy
//! nothing but a directory.
//!
//! ## The four authorities
//!
//! ```text
//! auditor                the facade — this file re-exports, and owns nothing
//!   ├─ invocation    A   WHICH record this run attests, and where its inputs are
//!   ├─ profile       B   WHAT this auditor asserts about the deployment it audits
//!   ├─ trust_view    C   WHICH keys were legitimate signers, frozen for this run
//!   ├─ artifact      D   the portable product, and the C2 registration interface
//!   └─ run               the composition: open, load, reconstruct, attest, write
//! ```
//!
//! ## What this half deliberately does NOT do
//!
//! **No transparency-service network registration.** Producing the Signed Statement and
//! submitting it are separate authorities with separate failures, and the artifact written
//! here is the exact input the registration step consumes. An auditor with no external
//! service still gets everything up to the submission.
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

/// The composition: open the archive, load the posture, reconstruct, attest, write.
mod run;

pub use artifact::AttestationArtifact;
pub use artifact::AttestedService;
pub use artifact::ChainVerdict;
pub use artifact::CorrespondenceVerdict;
pub use artifact::IncompleteAt;
pub use invocation::AuditInvocation;
pub use profile::AuditProfile;
pub use run::attest;
pub use run::AuditError;
