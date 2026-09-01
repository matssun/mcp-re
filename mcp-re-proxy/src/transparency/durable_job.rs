// SPDX-License-Identifier: Apache-2.0
//! WHAT a durable job asks for, and what its failure MEANS.
//!
//! The vocabulary the retention obligation and the writer thread share, and deliberately
//! neither's. [`super::durability`] decides when a job is owed; [`super::durable_writer`]
//! decides what the filesystem did about it. What is here is the part both must agree on
//! and neither may reinterpret: which disposition a job carries toward a durability barrier
//! that did not hold, and which of two facts its failure established.

use std::path::PathBuf;

/// The admission permit a retention obligation holds from `reserve` to `complete`.
///
/// Named because two products share one — see
/// [`super::ReservedBeforeDispatch::permit`] — and `OwnedSemaphorePermit` at those seams
/// says only *a semaphore*, not *this exchange's slot in the write queue's bound*.
pub(super) type AdmissionPermit = tokio::sync::OwnedSemaphorePermit;

/// One durable job, and the acknowledgement the awaiting request is owed.
pub(super) struct WriteJob {
    /// What the store is asked to do. Read by the writer, which is the only executor.
    pub(super) kind: JobKind,
    /// Sent ONLY after the durability boundary for this job has been crossed. Never on
    /// enqueue: a queued write that is acknowledged early is fire-and-forget with extra
    /// steps, and the serving path would emit a success for an exchange it cannot
    /// account for.
    pub(super) ack: tokio::sync::oneshot::Sender<Result<(), JobFault>>,
}

impl WriteJob {
    /// A job and the channel its outcome is owed to.
    pub(super) fn new(
        kind: JobKind,
        ack: tokio::sync::oneshot::Sender<Result<(), JobFault>>,
    ) -> Self {
        WriteJob { kind, ack }
    }
}

/// What a job asks the store to do, split by WHAT SURVIVES ITS OWN FAILURE.
///
/// Not four verbs — four dispositions toward a failed durability barrier, and the split is
/// the security content. A publication taken BEFORE the exchange may dispatch must not
/// survive its own failure: the artefact would assert a crossing that has not happened, and
/// the caller would be told a retry is free while execution-signifying state stayed behind
/// (R9-C099). One taken AFTER the backend acted must survive: losing it would under-report
/// an exchange the deployment cannot account for.
pub(super) enum JobKind {
    /// Publish, and WITHDRAW if durability cannot be established.
    ///
    /// The pre-dispatch disposition. Its failure is reported as what the store could
    /// establish about the withdrawal, never as a bare error.
    PublishOrWithdraw { path: PathBuf, bytes: Vec<u8> },
    /// Advance a marker from the reserved stage to the committed one — the dispatch
    /// commitment, as a rename, which is the only way a marker changes what it asserts.
    ///
    /// Rolled back if the barrier does not hold, for the same reason as above: until this
    /// is durable, nothing has committed, and a surviving committed-stage marker would say
    /// otherwise.
    Commit {
        reserved: PathBuf,
        committed: PathBuf,
    },
    /// Publish, then unlink `clear_marker` once the publication is durable. Whatever
    /// survives a failure STAYS.
    ///
    /// The post-dispatch disposition, and the one with no execution boundary at all
    /// ([`EvidenceRetention::retain`]). The marker's own removal is deliberately not made
    /// durable: a lost unlink leaves a stale marker, which over-reports indeterminacy —
    /// the safe direction, here.
    Publish {
        path: PathBuf,
        bytes: Vec<u8>,
        clear_marker: Option<PathBuf>,
    },
    /// Unlink a reserved-stage marker for an exchange that never committed. Publishes
    /// nothing, so there is no object to make durable and no barrier to take.
    Rescind { marker: PathBuf },
}

/// Why a durable job did not land, and — for a pre-dispatch one — what it left behind.
///
/// Two cases, because a caller must answer two different questions with them. Both say the
/// obligation was not established; only one says the store may now hold something that
/// reads as a crossed execution threshold for an exchange that never dispatched.
#[derive(Debug)]
pub(super) enum JobFault {
    /// Nothing this job would have published is on disk. The store is where it was.
    NotPublished(std::io::Error),
    /// A pre-dispatch publication could not be made durable AND could not be withdrawn.
    ///
    /// The exchange did not dispatch — but what the store holds about it cannot be stated,
    /// so the refusal it produces must not read as an ordinary retry-safe outage.
    Unwithdrawn(std::io::Error),
}
