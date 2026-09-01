// SPDX-License-Identifier: Apache-2.0
//! HOW a durable job is executed, and what its failure established.
//!
//! Three authorities, not one. [`super::durability`] decides WHEN an exchange owes the
//! store something and what the obligation's states are; [`super::durable_job`] names WHAT
//! a job asks for and what its failure means; this one owns the filesystem mechanics that
//! decide it — the dedicated writer thread, the batch, the single directory barrier, and
//! the withdrawal a barrier that did not hold obliges.
//!
//! The split follows the invalidation boundary: changing how a batch is barriered cannot
//! alter what a reservation means, and changing what a reservation means cannot alter how a
//! rename is made durable.

use std::sync::mpsc::Receiver;

use crate::retained_evidence::FsRetainedEvidenceStore;

use super::durability_bounds::MAX_WRITE_BATCH;
use super::durable_job::JobFault;
use super::durable_job::JobKind;
use super::durable_job::WriteJob;

/// Copy an `io::Error`: it is not `Clone`, and a batch shares one barrier failure.
fn shared(e: &std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), e.to_string())
}

/// Drain, act, take ONE directory barrier for the batch, then acknowledge.
///
/// The order is the whole contract: no job is acknowledged until the `fsync` covering its
/// rename has returned, so a batch is a durability optimisation over jobs that were each
/// admitted individually — never a transaction over them, and never an early success.
///
/// When the barrier does not hold, the batch splits by disposition. Every job that
/// published before its exchange could dispatch is withdrawn and ONE further barrier is
/// taken over the withdrawals; a job whose withdrawal and that barrier both succeed left
/// nothing behind and says so, and one whose did not says THAT instead of pretending to be
/// an ordinary store outage.
pub(super) fn write_loop(store: FsRetainedEvidenceStore, jobs: Receiver<WriteJob>) {
    loop {
        let Ok(first) = jobs.recv() else { return };
        let mut batch = vec![first];
        while batch.len() < MAX_WRITE_BATCH {
            match jobs.try_recv() {
                Ok(job) => batch.push(job),
                Err(_) => break,
            }
        }
        run_batch(&store, batch);
    }
}

/// Act on one batch, barrier it, and acknowledge every job in it.
fn run_batch(store: &FsRetainedEvidenceStore, batch: Vec<WriteJob>) {
    let acted: Vec<std::io::Result<bool>> = batch.iter().map(|job| act(store, &job.kind)).collect();
    let published = acted.iter().any(|a| matches!(a, Ok(true)));
    let barrier = if published { store.sync_root() } else { Ok(()) };

    // Withdraw first, then take ONE barrier over every withdrawal, so a failed batch costs
    // one extra fsync rather than one per job.
    let withdrawn: Vec<Option<std::io::Result<()>>> = batch
        .iter()
        .zip(&acted)
        .map(|(job, acted)| match (&barrier, acted) {
            (Err(_), Ok(true)) => withdraw(&job.kind),
            _ => None,
        })
        .collect();
    let any_withdrawal = withdrawn.iter().any(Option::is_some);
    let withdrawal_barrier = if any_withdrawal {
        store.sync_root()
    } else {
        Ok(())
    };

    for ((job, acted), withdrawn) in batch.into_iter().zip(acted).zip(withdrawn) {
        let outcome = resolve(
            &job.kind,
            acted,
            &barrier,
            withdrawn,
            &withdrawal_barrier,
            store,
        );
        let _ = job.ack.send(outcome);
    }
}

/// Perform a job's filesystem action, reporting whether it changed the directory in a way
/// the barrier must cover.
fn act(store: &FsRetainedEvidenceStore, kind: &JobKind) -> std::io::Result<bool> {
    match kind {
        JobKind::PublishOrWithdraw { path, bytes } | JobKind::Publish { path, bytes, .. } => {
            store.stage_at(path, bytes).map(|()| true)
        }
        JobKind::Commit {
            reserved,
            committed,
        } => std::fs::rename(reserved, committed).map(|()| true),
        // A rescind publishes nothing, so it needs no barrier — and its unlink is
        // deliberately not made durable: a lost one leaves a reserved-stage marker, which
        // asserts no execution and is cleanup debt.
        JobKind::Rescind { marker } => {
            let removed = std::fs::remove_file(marker);
            match removed {
                Ok(()) => Ok(false),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e),
            }
        }
    }
}

/// Undo a pre-dispatch action whose durability could not be established.
///
/// `None` for a job that has nothing to withdraw: a post-dispatch publication must survive
/// its own failure, and a rescind published nothing to begin with.
fn withdraw(kind: &JobKind) -> Option<std::io::Result<()>> {
    match kind {
        JobKind::PublishOrWithdraw { path, .. } => Some(std::fs::remove_file(path)),
        JobKind::Commit {
            reserved,
            committed,
        } => Some(std::fs::rename(committed, reserved)),
        JobKind::Publish { .. } | JobKind::Rescind { .. } => None,
    }
}

/// What one job established, given what it did and what the barriers said.
fn resolve(
    kind: &JobKind,
    acted: std::io::Result<bool>,
    barrier: &std::io::Result<()>,
    withdrawn: Option<std::io::Result<()>>,
    withdrawal_barrier: &std::io::Result<()>,
    store: &FsRetainedEvidenceStore,
) -> Result<(), JobFault> {
    let changed = acted.map_err(JobFault::NotPublished)?;
    if let Err(e) = barrier {
        if !changed {
            return Err(JobFault::NotPublished(shared(e)));
        }
        return match withdrawn {
            // Withdrawn and the withdrawal is durable: the store is where it was.
            Some(Ok(())) if withdrawal_barrier.is_ok() => Err(JobFault::NotPublished(shared(e))),
            // A pre-dispatch publication that could not be taken back. The caller is owed
            // the difference: this is not an outage a retry walks away from cleanly.
            Some(_) => Err(JobFault::Unwithdrawn(shared(e))),
            // Nothing to withdraw — a post-dispatch publication, which survives its own
            // failure on purpose.
            None => Err(JobFault::NotPublished(shared(e))),
        };
    }
    clear_marker_of(kind, store);
    Ok(())
}

/// Unlink the marker a durable publication discharges, if it has one.
fn clear_marker_of(kind: &JobKind, store: &FsRetainedEvidenceStore) {
    let JobKind::Publish {
        path,
        clear_marker: Some(marker),
        ..
    } = kind
    else {
        return;
    };
    let Err(e) = std::fs::remove_file(marker) else {
        return;
    };
    if e.kind() == std::io::ErrorKind::NotFound {
        return;
    }
    let _ = store;
    eprintln!(
        "retained evidence: hop {} is stored but its reservation marker {} could not be \
         cleared ({e}); an auditor will see it as indeterminate",
        path.display(),
        marker.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mcp-re-durable-writer-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn store(dir: &TempDir) -> FsRetainedEvidenceStore {
        FsRetainedEvidenceStore::open(&dir.0).expect("open")
    }

    fn barrier_failed() -> std::io::Result<()> {
        Err(std::io::Error::other("directory barrier did not hold"))
    }

    /// A pre-dispatch publication whose barrier fails is WITHDRAWN, and the caller is told
    /// nothing was published.
    ///
    /// R9-C099's first half. The predecessor staged the marker, renamed it into place, hit
    /// a failing `sync_root`, and returned `Err` — leaving the artefact on disk with no
    /// value in existence for any release path to consume.
    #[test]
    fn a_pre_dispatch_publication_that_cannot_be_made_durable_is_withdrawn() {
        let dir = TempDir::new("withdraw");
        let store = store(&dir);
        let path = dir.0.join("abc.reserved");
        let kind = JobKind::PublishOrWithdraw {
            path: path.clone(),
            bytes: b"{}".to_vec(),
        };

        assert!(act(&store, &kind).expect("staged"));
        assert!(path.exists(), "the publication landed");

        let withdrawn = withdraw(&kind).expect("a pre-dispatch publication withdraws");
        assert!(withdrawn.is_ok());
        assert!(!path.exists(), "and the withdrawal removed it");

        let outcome = resolve(
            &kind,
            Ok(true),
            &barrier_failed(),
            Some(Ok(())),
            &Ok(()),
            &store,
        );
        assert!(
            matches!(outcome, Err(JobFault::NotPublished(_))),
            "a withdrawal that held leaves the store where it was"
        );
    }

    /// A withdrawal that itself fails is reported as UNWITHDRAWN, never as an ordinary
    /// store outage.
    ///
    /// R9-C099's sharp end. This is the only case in which something that reads as a
    /// crossed execution threshold can survive for an exchange that never dispatched, and
    /// the caller must be able to tell it from the case where nothing survived — because
    /// the two differ in whether a retry is free.
    #[test]
    fn a_withdrawal_that_fails_is_not_reported_as_an_ordinary_outage() {
        let dir = TempDir::new("unwithdrawn");
        let store = store(&dir);
        let kind = JobKind::Commit {
            reserved: dir.0.join("abc.reserved"),
            committed: dir.0.join("abc.pending"),
        };
        let rollback_failed = Some(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "rollback rename refused",
        )));
        let outcome = resolve(
            &kind,
            Ok(true),
            &barrier_failed(),
            rollback_failed,
            &Ok(()),
            &store,
        );
        assert!(
            matches!(outcome, Err(JobFault::Unwithdrawn(_))),
            "a marker that could not be taken back must not read as retry-safe"
        );
    }

    /// A withdrawal whose own barrier fails is equally unwithdrawn.
    ///
    /// The unlink or rename succeeding is not the property — its DURABILITY is. Reporting
    /// `NotPublished` on the strength of a syscall that returned while the directory entry
    /// is still only in cache would be the same false green the barrier exists to prevent.
    #[test]
    fn a_withdrawal_whose_barrier_does_not_hold_is_unwithdrawn() {
        let dir = TempDir::new("unwithdrawn-barrier");
        let store = store(&dir);
        let kind = JobKind::PublishOrWithdraw {
            path: dir.0.join("abc.reserved"),
            bytes: b"{}".to_vec(),
        };
        let outcome = resolve(
            &kind,
            Ok(true),
            &barrier_failed(),
            Some(Ok(())),
            &barrier_failed(),
            &store,
        );
        assert!(matches!(outcome, Err(JobFault::Unwithdrawn(_))));
    }

    /// A POST-dispatch publication survives its own failure, and is never withdrawn.
    ///
    /// The opposite disposition, and the reason the split is by disposition rather than by
    /// verb. Withdrawing here would erase the record of an exchange whose backend may have
    /// acted — under-reporting, which is the direction that loses evidence.
    #[test]
    fn a_post_dispatch_publication_is_never_withdrawn() {
        let dir = TempDir::new("post-dispatch");
        let store = store(&dir);
        let path = dir.0.join("hop");
        let kind = JobKind::Publish {
            path: path.clone(),
            bytes: b"{}".to_vec(),
            clear_marker: None,
        };
        assert!(act(&store, &kind).expect("staged"));
        assert!(
            withdraw(&kind).is_none(),
            "a post-dispatch publication has nothing to take back"
        );
        let outcome = resolve(&kind, Ok(true), &barrier_failed(), None, &Ok(()), &store);
        assert!(matches!(outcome, Err(JobFault::NotPublished(_))));
        assert!(path.exists(), "and whatever survived stays");
    }

    /// A staging failure is reported as nothing published, with no withdrawal attempted.
    #[test]
    fn a_publication_that_never_staged_publishes_nothing() {
        let dir = TempDir::new("unstaged");
        let store = store(&dir);
        let kind = JobKind::PublishOrWithdraw {
            // A path under a directory that does not exist: the staging write fails.
            path: dir.0.join("missing").join("abc.reserved"),
            bytes: b"{}".to_vec(),
        };
        let acted = act(&store, &kind);
        assert!(acted.is_err(), "staging into a missing directory fails");
        let outcome = resolve(&kind, acted, &Ok(()), None, &Ok(()), &store);
        assert!(matches!(outcome, Err(JobFault::NotPublished(_))));
    }

    /// A commitment whose rename cannot happen at all publishes nothing.
    #[test]
    fn a_commitment_with_nothing_to_advance_publishes_nothing() {
        let dir = TempDir::new("no-source");
        let store = store(&dir);
        let kind = JobKind::Commit {
            reserved: dir.0.join("absent.reserved"),
            committed: dir.0.join("absent.pending"),
        };
        let acted = act(&store, &kind);
        assert!(acted.is_err());
        let outcome = resolve(&kind, acted, &Ok(()), None, &Ok(()), &store);
        assert!(matches!(outcome, Err(JobFault::NotPublished(_))));
        assert!(!dir.0.join("absent.pending").exists());
    }

    /// A rescind publishes nothing, so it takes no barrier — and a marker that is already
    /// gone is a success, not an error.
    ///
    /// The second half is what lets the reservation's `Drop` be unconditional: after a
    /// commitment has renamed the marker away, the rescind that follows finds nothing, and
    /// that must be ordinary rather than an error to report.
    #[test]
    fn a_rescind_publishes_nothing_and_tolerates_an_absent_marker() {
        let dir = TempDir::new("rescind");
        let store = store(&dir);
        let marker = dir.0.join("abc.reserved");
        std::fs::write(&marker, b"{}").expect("write");

        let kind = JobKind::Rescind {
            marker: marker.clone(),
        };
        assert!(!act(&store, &kind).expect("removed"), "no barrier is owed");
        assert!(!marker.exists());
        assert!(
            !act(&store, &kind).expect("an absent marker is not a failure"),
            "no barrier is owed"
        );
    }

    /// A durable publication clears the marker it discharges, and a marker that is already
    /// gone is not an error for the caller.
    #[test]
    fn a_durable_publication_clears_the_marker_it_discharges() {
        let dir = TempDir::new("clear");
        let store = store(&dir);
        let marker = dir.0.join("abc.pending");
        std::fs::write(&marker, b"{}").expect("write");
        let kind = JobKind::Publish {
            path: dir.0.join("hop"),
            bytes: b"{}".to_vec(),
            clear_marker: Some(marker.clone()),
        };
        assert!(act(&store, &kind).expect("staged"));
        assert!(resolve(&kind, Ok(true), &Ok(()), None, &Ok(()), &store).is_ok());
        assert!(!marker.exists(), "the crossing is discharged by the hop");
        // And again, with the marker already gone: an auditor pays one reconciliation,
        // the exchange is not refused.
        assert!(resolve(&kind, Ok(true), &Ok(()), None, &Ok(()), &store).is_ok());
    }
}
