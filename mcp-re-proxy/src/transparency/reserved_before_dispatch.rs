// SPDX-License-Identifier: Apache-2.0
//! A retention obligation ACCEPTED, and an execution threshold NOT crossed.

use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use mcp_re_http_profile::scitt::EvidenceDigest;

use super::durable_job::AdmissionPermit;
use super::durable_job::JobKind;
use super::durable_job::WriteJob;

/// The extension a marker carries while its exchange has not committed to dispatching.
///
/// A separate NAME from [`super::PENDING_EXTENSION`] is the whole repair. One artefact was
/// asked to mean two contradictory things — *responsibility is accepted, nothing has run*
/// at `reserve`, and *this call crossed the execution threshold and its outcome was never
/// retained* at reconciliation — so no byte on disk distinguished a refused call from one
/// whose backend may have acted. Two names, and the commitment is the rename between them.
pub(super) const RESERVED_EXTENSION: &str = "reserved";

/// Durable acceptance of responsibility for one exchange, taken BEFORE the backend runs.
///
/// **It is not evidence that anything ran, and its durable form says so.** Holding one
/// means a `<request-digest>.reserved` marker is on disk, carrying the exchange's digest
/// commitment and nothing else — no bearer token, no DPoP proof, no request body. Those
/// belong to the completed hop; a marker for a call that has not dispatched has no
/// business holding a live credential ([`super::reservation_marker`]).
///
/// # Two things can happen to it, and only two
///
/// [`super::EvidenceRetention::commit_to_dispatch`] advances it to a
/// [`super::DispatchCommitted`], renaming the marker — that rename IS the durable record
/// that the threshold was crossed. Anything else drops it, and dropping RESCINDS: the
/// marker is queued for removal and the admission permit goes back.
///
/// There is no release call, and deleting one would not be how this goes wrong. The
/// predecessor had `release_before_dispatch`, reachable only from tests, and the operative
/// test for whether a value owns its invariant is *can the check be deleted and still
/// leave the forbidden state unconstructible?* — for a call site, no. Rescinding on drop
/// is not a discipline a path can skip: a refusal, an early return, a panic and a
/// cancelled request future all drop, and dropping is the rescind.
///
/// # What a rescind is allowed to fail to do
///
/// The queue send is best-effort and the unlink is not made durable. A lost rescind leaves
/// a stale `.reserved` marker — cleanup debt, and readable as exactly that: it says an
/// obligation was accepted and says nothing about execution. That the residue is honest
/// rather than merely rare is the reason the pre-dispatch stage has its own name on disk.
pub struct ReservedBeforeDispatch {
    digest: EvidenceDigest,
    marker: PathBuf,
    /// Cloned from the store, because [`Drop`] cannot await. A rescind is therefore
    /// queued, never awaited — the caller is already leaving, and nothing downstream reads
    /// the outcome.
    jobs: SyncSender<WriteJob>,
    /// SHARED with the committed state rather than moved into it.
    ///
    /// This value has a `Drop`, so nothing can be moved out of it — and the alternative,
    /// an `Option` the commitment empties, would put a state in the type that means
    /// *committed* and would have to be read wherever the permit is. One permit exists per
    /// reservation either way, so the queue bound is unchanged: it is released when the
    /// last of the two products is gone.
    permit: Arc<AdmissionPermit>,
}

impl ReservedBeforeDispatch {
    /// Take the value that stands for an accepted, uncommitted obligation.
    ///
    /// Called only by the store, once its marker is durable. Constructing one before that
    /// would make possession mean *a write was attempted*, which is what the exchange
    /// machine goes on to treat as *a refusal here is still free and still honest*.
    pub(super) fn over(
        digest: EvidenceDigest,
        marker: PathBuf,
        jobs: SyncSender<WriteJob>,
        permit: Arc<AdmissionPermit>,
    ) -> Self {
        ReservedBeforeDispatch {
            digest,
            marker,
            jobs,
            permit,
        }
    }

    /// The request digest this reservation is keyed by.
    pub fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }

    /// Where its reserved-stage marker is, so the commitment knows what to advance.
    pub(super) fn marker(&self) -> &Path {
        &self.marker
    }

    /// The admission permit, shared onward to the committed state.
    pub(super) fn permit(&self) -> Arc<AdmissionPermit> {
        Arc::clone(&self.permit)
    }
}

impl Drop for ReservedBeforeDispatch {
    /// Rescind: this exchange is leaving without having committed to a dispatch.
    ///
    /// Unconditional, and correct after a commitment too. The commitment RENAMES the
    /// reserved marker, so this unlink finds nothing and is a no-op — while the
    /// alternative, a flag saying *already committed*, would be a second statement of a
    /// fact the filesystem already carries, and one a future path could set wrongly.
    /// Unlinking a reserved-stage marker is safe in every direction it can be wrong in:
    /// the artefact asserts no execution, so removing one that should have stayed loses
    /// cleanup debt, not evidence.
    fn drop(&mut self) {
        let (ack, _) = tokio::sync::oneshot::channel();
        let _ = self.jobs.try_send(WriteJob::new(
            JobKind::Rescind {
                marker: self.marker.clone(),
            },
            ack,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    fn permit() -> Arc<AdmissionPermit> {
        Arc::new(
            Arc::new(Semaphore::new(1))
                .try_acquire_owned()
                .expect("a fresh semaphore has its permit"),
        )
    }

    /// Dropping queues the rescind. No call, and no path that can forget one.
    ///
    /// The store-level control is in [`super::super::durability`], where the marker is a
    /// real file. What is asserted here is the property the type owns: going out of scope
    /// EMITS the withdrawal, and it names the reserved-stage marker rather than the
    /// committed one.
    #[test]
    fn dropping_a_reservation_queues_the_rescind_for_its_own_marker() {
        let (jobs, queued) = std::sync::mpsc::sync_channel(4);
        let marker = PathBuf::from("/store/abc.reserved");
        let reserved = ReservedBeforeDispatch::over(
            EvidenceDigest::of(b"request"),
            marker.clone(),
            jobs,
            permit(),
        );
        assert!(
            queued.try_recv().is_err(),
            "holding a reservation withdraws nothing"
        );

        drop(reserved);
        let job = queued.try_recv().expect("a dropped reservation rescinds");
        let JobKind::Rescind { marker: rescinded } = &job.kind else {
            panic!("a reservation must withdraw, never publish");
        };
        assert_eq!(rescinded, &marker);
    }

    /// The permit is given back with the reservation, and only when the last holder goes.
    ///
    /// It is shared with the committed state rather than moved, so this asserts the half
    /// that could go wrong quietly: a reservation that dropped without releasing would
    /// shrink the write queue's bound by one for the life of the process.
    #[test]
    fn dropping_a_reservation_gives_its_admission_permit_back() {
        let permits = Arc::new(Semaphore::new(1));
        let held = Arc::new(
            Arc::clone(&permits)
                .try_acquire_owned()
                .expect("the permit"),
        );
        let (jobs, _queued) = std::sync::mpsc::sync_channel(4);
        let reserved = ReservedBeforeDispatch::over(
            EvidenceDigest::of(b"request"),
            PathBuf::from("/store/abc.reserved"),
            jobs,
            held,
        );
        assert_eq!(permits.available_permits(), 0);
        drop(reserved);
        assert_eq!(permits.available_permits(), 1);
    }

    /// A rescind that cannot be queued is dropped, not blocked.
    ///
    /// `Drop` runs on the request future's own task and cannot await, so a full queue must
    /// not stall it. The cost is a stale reserved-stage marker, which is cleanup debt and
    /// says nothing about execution — the residue this stage was named for.
    #[test]
    fn a_full_queue_costs_a_stale_marker_and_never_a_stall() {
        let (jobs, queued) = std::sync::mpsc::sync_channel(1);
        // Fill it.
        let (ack, _) = tokio::sync::oneshot::channel();
        jobs.try_send(WriteJob::new(
            JobKind::Rescind {
                marker: PathBuf::from("/store/other.reserved"),
            },
            ack,
        ))
        .expect("the first job fits");

        let reserved = ReservedBeforeDispatch::over(
            EvidenceDigest::of(b"request"),
            PathBuf::from("/store/abc.reserved"),
            jobs,
            permit(),
        );
        drop(reserved); // must not block, and must not panic
        let first = queued.try_recv().expect("the job that fitted");
        assert!(matches!(first.kind, JobKind::Rescind { .. }));
        assert!(
            queued.try_recv().is_err(),
            "the rescind that did not fit was dropped, and the debt is the marker"
        );
    }
}
