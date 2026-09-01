// SPDX-License-Identifier: Apache-2.0
//! Evidence retention on the serving path, and the auditor step that turns retained
//! evidence into a portable SCITT record (ADR-MCPRE-054).
//!
//! The SCITT surface — `issue_signed_statement`, `reconstruct_chain`,
//! `verify_retained_evidence`, `FsRetainedEvidenceStore` — was reachable only from
//! tests, conformance vectors and interop harnesses. Nothing on the serving path
//! produced a statement, reconstructed a chain, or retained anything, so
//! `retained_evidence.rs` was dead code inside the serving crate and any claim of
//! transparency coverage was unbacked.
//!
//! ## The split: the PEP retains, an auditor attests
//!
//! Retention is the only half that MUST happen while the call is being served — nobody
//! can reconstruct later what was not kept. So the PEP writes each exchange into the
//! content-addressed store and nothing more.
//!
//! Everything else is deliberately NOT on the request path:
//!
//! * `reconstruct_chain` needs the WHOLE chain, and a chain is not whole until its last
//!   hop. A PEP attesting per hop could only ever commit to a one-hop record, which for
//!   a continuation is a truncated one — precisely what the `ChainLabel` exists to make
//!   impossible to launder.
//! * It needs an audit posture — a resolver, delegation expectations, an audit instant —
//!   which is the auditor's to choose, not the serving deployment's.
//! * Registering against a transparency service is network I/O, and putting it in front
//!   of a response would make an audit dependency an availability dependency.
//!
//! ## Retention fails CLOSED
//!
//! When a deployment turns retention on it is asserting it can account for what it
//! served. Serving a call whose evidence could not be kept breaks that assertion
//! silently, and the deployment would find out only when an auditor asked for a record
//! that was never written. So a retention failure refuses the exchange with a signed
//! `mcp-re.evidence_retention_unavailable` rejection, the same posture the replay tier
//! takes for the same reason.
//!
//! This is the opposite of the audit SINK's posture, and deliberately: the sink must not
//! fail a request, because a lost log line does not change what the deployment can
//! prove about the call. Lost retained evidence does.
//!
//! **The cost of that choice, stated rather than discovered.** Failing closed on a store
//! failure means a FULL VOLUME is a total outage: every request is refused until space
//! is freed. The store grows without bound by construction — one object per accepted
//! call, each holding a request and response body up to `--max-body-bytes` (16 MiB by
//! default), with no expiry, no lifecycle and no quota. So an authenticated client can
//! drive disk exhaustion, and the fail-closed posture turns that into a refusal of
//! everything.
//!
//! A cap here would not fix it, it would only move it: at the cap the choice is refuse
//! (the same outage) or stop retaining (breaking the assertion retention exists to make).
//! The real control is an external retention policy — a dedicated volume, rotation or
//! archival off the node, and free-space alerting — which is a deployment concern this
//! module deliberately does not try to be. Turning retention on without one is choosing
//! an outage on a timer.
//!
//! ## What is retained: ACCEPTED exchanges only
//!
//! Retention runs at the one exit where a request was verified, dispatched and answered.
//! A REJECTED request is not retained: it produced no hop a chain can be reconstructed
//! from, and a signed rejection receipt is already an audit-sink record carrying the
//! frozen wire code. "We can account for what we served" is therefore the honest reading
//! of a full store — not "we can account for everything that was attempted."
//!
//! ## What a retained record contains: the covered headers, credentials included
//!
//! A record keeps each message's body and the headers that message's own signature
//! covers — no more, because reconstruction reads nothing else, and no less, because the
//! signature base cannot be recomputed from a subset. This profile REQUIRES
//! `authorization` and `dpop` to be covered when present, so a retained request holds the
//! call's live bearer token and DPoP proof verbatim.
//!
//! That is a real cost, stated rather than discovered. It cannot be avoided by digesting
//! them — the signature is over the raw header line, so a digest makes the hop
//! unverifiable, which is the one thing retention exists to enable. What it does buy is a
//! boundary that can be stated: the store holds what the evidence carrier covers, never
//! whatever else the client happened to send. Uncovered credentials — `cookie`,
//! `proxy-authorization`, bespoke API-key headers — are dropped, because no auditor can
//! use them.
//!
//! The consequence for a deployment: this directory is credential material for every
//! call since it was created, with no expiry. It is created `0700` and its objects
//! `0600`, and an existing directory that is looser is warned about at startup. Handing
//! it to an auditor hands over replayable tokens.
//!
//! ## First exposure
//!
//! Nothing under here had met hostile input before this wiring. Every value that
//! arrives from the wire — a body, a header, a digest read back from disk — is treated
//! as such: the store re-addresses what it returns, the retained record carries a schema
//! token, and the loader refuses a record it cannot read rather than reconstructing a
//! chain from a partial one.

/// WHAT is retained: the record's schema and its encoding.
mod retained_record;

/// WHICH headers a retained hop keeps: exactly the ones the signature base names.
mod covered_set;

/// WHEN responsibility for retaining an exchange has been durably established.
mod durability;
mod durability_bounds;
/// WHAT a durable job asks for, and what its failure means.
mod durable_job;
/// HOW a durable job is executed.
mod durable_writer;

/// The execution threshold CROSSED, and durably recorded.
mod dispatch_committed;
/// WHAT a marker persists, and what it deliberately does not.
mod reservation_marker;
/// The obligation ACCEPTED, before anything has run.
mod reserved_before_dispatch;

/// Turning retained evidence into a portable SCITT record — the auditor's half.
mod attestation;

pub use attestation::attest_chain;
pub use attestation::AttestError;
pub use attestation::Attestation;
pub use dispatch_committed::DispatchCommitted;
pub use durability::EvidenceRetention;
pub use reserved_before_dispatch::ReservedBeforeDispatch;

/// The schema token every retained record carries.
///
/// A content-addressed blob has no type of its own — the store returns bytes that hash
/// to the name asked for and nothing more. Without a token in the record, a future
/// change to the encoding would be read by an old reader as a valid record of a
/// different shape, and the chain it reconstructed would be about something else.
pub const RETAINED_HOP_SCHEMA: &str = "mcp-re-retained-hop/v1";

/// A retention failure. Every variant refuses the exchange.
#[derive(Debug)]
pub enum RetentionError {
    /// The store could not write or read.
    Store(std::io::Error),
    /// A record came back that this reader cannot use.
    Malformed(&'static str),
    /// The commitment offered has already had its completion taken.
    AlreadyCompleted,
    /// A pre-dispatch retention state could not be established AND could not be
    /// withdrawn.
    ///
    /// Separate from [`Store`](Self::Store) because the two demand different answers. A
    /// store failure that published nothing leaves the exchange exactly where it was:
    /// nothing dispatched, nothing on disk, an ordinary retry is correct. This one leaves
    /// something on disk that may read as a crossed execution threshold for an exchange
    /// that never dispatched — so answering it as an ordinary retry-safe outage would be
    /// the deployment telling a client to retry freely while holding a record it cannot
    /// account for (R9-C099).
    Unresolved(std::io::Error),
}

impl std::fmt::Display for RetentionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetentionError::Store(e) => write!(f, "retained-evidence store: {e}"),
            RetentionError::Malformed(what) => write!(f, "retained evidence: {what}"),
            RetentionError::AlreadyCompleted => {
                write!(f, "retained evidence: the commitment is already completed")
            }
            RetentionError::Unresolved(e) => write!(
                f,
                "retained evidence: a pre-dispatch retention state could not be \
                 established or withdrawn ({e}); the exchange did not dispatch and the \
                 store's record of it cannot be stated"
            ),
        }
    }
}

impl std::error::Error for RetentionError {}
