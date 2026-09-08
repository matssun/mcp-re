// SPDX-License-Identifier: Apache-2.0
//! WHAT an audit run refuses in — and, for one variant, what survived it.
//!
//! One fact: **which stage of an audit did not complete, and whether an attestation
//! exists anyway.**
//!
//! Its own owner because that second clause is not decoration. Four of these variants mean
//! no artifact was written and the operator has nothing; the fifth means the attestation
//! is on disk and durable, and only the submission failed. Collapsing the two into "the
//! audit failed" would have an operator discard a portable, offline-verifiable record
//! because a network was down.

use crate::transparency::auditor::registration::RegistrationError;
use crate::transparency::AttestError;

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
    /// The attestation was produced and written; registering it did not succeed.
    ///
    /// Separate from every variant above because the attestation SURVIVED. The others
    /// mean no artifact exists; this one means one does, and the question it leaves open
    /// is whether a transparency service holds it — which the error itself answers with
    /// its own certainty.
    Registration(RegistrationError),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Input(what) => write!(f, "{what}"),
            AuditError::Archive(e) => write!(f, "retained-evidence archive: {e}"),
            AuditError::Attest(e) => write!(f, "attestation: {e}"),
            AuditError::Output(e) => write!(f, "writing the attestation artifact: {e}"),
            AuditError::Registration(e) => write!(
                f,
                "the attestation was written; registering it did not succeed — {e}"
            ),
        }
    }
}

impl std::error::Error for AuditError {}
