// SPDX-License-Identifier: Apache-2.0
//! WHAT a durable job asks for, and what its failure MEANS.
//!
//! The vocabulary the retention obligation and the writer thread share, and deliberately
//! neither's. [`super::durability`] decides when a job is owed; [`super::durable_writer`]
//! decides what the filesystem did about it. What is here is the part both must agree on
//! and neither may reinterpret: which disposition a job carries toward a durability barrier
//! that did not hold, and which of two facts its failure established.

use std::path::PathBuf;
use std::sync::Arc;

/// The admission permit a retention obligation holds from `reserve` to `complete`.
///
/// Named because two products share one — see
/// [`super::ReservedBeforeDispatch::permit`] — and `OwnedSemaphorePermit` at those seams
/// says only *a semaphore*, not *this exchange's slot in the write queue's bound*.
pub(super) type AdmissionPermit = tokio::sync::OwnedSemaphorePermit;

/// One durable job, the acknowledgement the awaiting request is owed, and the slot it is
/// accounted against.
///
/// # Two ownership classes, and the constructor is which one
///
/// A **security-bearing** job — the ones the awaited durable transitions submit — carries
/// the [`AdmissionPermit`] it was admitted against, so the slot is held until the writer
/// has finished with the job rather than until its caller's future happens to survive. A
/// request future dropped at the `await` is exactly the case that distinguishes them: the
/// job stays queued either way, and only a job that holds its own slot keeps the queue
/// bounded by the reservation ceiling while it does.
///
/// **Best-effort cleanup** — the rescind a reservation queues as it goes out of scope —
/// carries none. Nobody awaits it, nothing downstream reads its outcome, and its only
/// residue is a stale reserved-stage marker. Giving it a slot would tie an admission
/// decision to when an unwitnessed job happened to be drained;
/// [`super::durability_bounds::write_queue_capacity`] accounts for it as overlap instead.
pub(super) struct WriteJob {
    /// What the store is asked to do. Read by the writer, which is the only executor.
    pub(super) kind: JobKind,
    /// Sent ONLY after the durability boundary for this job has been crossed. Never on
    /// enqueue: a queued write that is acknowledged early is fire-and-forget with extra
    /// steps, and the serving path would emit a success for an exchange it cannot
    /// account for.
    pub(super) ack: tokio::sync::oneshot::Sender<Result<(), JobFault>>,
    /// The slot this job is accounted against, for as long as the job exists.
    ///
    /// `None` is cleanup, and it is the only thing `None` may mean here.
    pub(super) slot: Option<Arc<AdmissionPermit>>,
}

impl WriteJob {
    /// A security-bearing job, holding the slot it was admitted against.
    ///
    /// Shared rather than moved: the exchange's own durable stages hold the same permit,
    /// and it returns when the last of them is gone. Requiring the permit HERE is what
    /// makes the accounting total — a caller cannot submit an awaited job without naming
    /// the slot it was admitted against.
    pub(super) fn accounted(
        kind: JobKind,
        ack: tokio::sync::oneshot::Sender<Result<(), JobFault>>,
        slot: Arc<AdmissionPermit>,
    ) -> Self {
        WriteJob {
            kind,
            ack,
            slot: Some(slot),
        }
    }

    /// A best-effort cleanup job, which owns no slot and is owed no answer.
    pub(super) fn cleanup(
        kind: JobKind,
        ack: tokio::sync::oneshot::Sender<Result<(), JobFault>>,
    ) -> Self {
        WriteJob {
            kind,
            ack,
            slot: None,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    fn slot(permits: &Arc<Semaphore>) -> Arc<AdmissionPermit> {
        Arc::new(
            Arc::clone(permits)
                .try_acquire_owned()
                .expect("a free slot"),
        )
    }

    fn rescind() -> JobKind {
        JobKind::Rescind {
            marker: PathBuf::from("/store/abc.reserved"),
        }
    }

    /// A security-bearing job outlives its caller's interest in it, and holds the slot.
    ///
    /// The cancellation case, stated where it is decidable: dropping every holder OUTSIDE
    /// the queue must not free the slot while the job is still in it. A request future
    /// dropped at its `await` is exactly that — the job it enqueued is already the
    /// writer's, and a slot returned there would admit a successor whose own job joins an
    /// orphan the ceiling has stopped counting.
    #[test]
    fn an_accounted_job_holds_its_slot_after_its_caller_is_gone() {
        let permits = Arc::new(Semaphore::new(1));
        let held = slot(&permits);
        let (ack, _acked) = tokio::sync::oneshot::channel();
        let job = WriteJob::accounted(rescind(), ack, Arc::clone(&held));

        drop(held);
        assert_eq!(
            permits.available_permits(),
            0,
            "the queued job is still accounted for"
        );

        drop(job);
        assert_eq!(
            permits.available_permits(),
            1,
            "and the slot comes back once nothing holds the job either"
        );
    }

    /// Cleanup owns no slot, which is what lets it be dropped, lost or drained late.
    ///
    /// Its mirror above is what makes this a decision rather than an omission: the type
    /// can carry a slot, and this class deliberately does not. A cleanup job holding one
    /// would make an admission depend on when an unwitnessed unlink was drained.
    #[test]
    fn a_cleanup_job_owns_no_slot() {
        let permits = Arc::new(Semaphore::new(1));
        let held = slot(&permits);
        let (ack, _acked) = tokio::sync::oneshot::channel();
        let job = WriteJob::cleanup(rescind(), ack);

        assert!(job.slot.is_none(), "cleanup is accounted against nothing");
        drop(held);
        assert_eq!(
            permits.available_permits(),
            1,
            "so the slot returns with the exchange, never with the cleanup job"
        );
        drop(job);
        assert_eq!(permits.available_permits(), 1);
    }
}
