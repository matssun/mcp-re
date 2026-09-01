// SPDX-License-Identifier: Apache-2.0
//! The execution threshold, CROSSED and durably recorded.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use mcp_re_http_profile::scitt::EvidenceDigest;

use super::durable_job::AdmissionPermit;

/// The extension a marker carries once its exchange has committed to dispatching.
///
/// The one an auditor reads as *this exact request crossed the execution threshold and its
/// outcome was never retained*. Distinct from
/// [`super::RESERVED_EXTENSION`](super::reserved_before_dispatch::RESERVED_EXTENSION)
/// because those are different facts, and a reconciliation that could not tell them apart
/// counted refused calls as calls that may have run.
pub(super) const PENDING_EXTENSION: &str = "pending";

/// The exchange has committed to dispatching, and the commitment is durable.
///
/// Holding one means a `<request-digest>.pending` marker is on disk. It is consumed by
/// [`super::EvidenceRetention::complete`] once the exchange is retained; a marker that
/// outlives the process is the record that this exact request crossed the execution
/// threshold and its outcome was never retained — the one fact an auditor otherwise cannot
/// recover, because the completed hop is precisely what failed to be written.
///
/// # It has no `Drop`, and that is the asymmetry
///
/// [`super::ReservedBeforeDispatch`] rescinds when it is dropped; this does not. The two
/// dispositions are opposite because the facts are: a pre-dispatch reservation that dies
/// leaves nothing, because nothing ran, and a crossed threshold that dies leaves its
/// record, because something may have. Over-reporting indeterminacy is the safe direction
/// HERE and only here — inventing it for a call that never dispatched is what the split
/// exists to stop.
///
/// # One completion
///
/// A reservation is worth exactly one completion, taken by the first
/// [`super::EvidenceRetention::complete`] that asks. One crossing of the execution
/// threshold produces one hop: a value that could be completed repeatedly would let one
/// execution write N hop objects, so an auditor counting hops would count calls that never
/// happened — and it would put N jobs behind the one permit that bounds the write queue,
/// which is what makes a completion never refusable for capacity after the backend has
/// already run.
#[derive(Debug)]
pub struct DispatchCommitted {
    digest: EvidenceDigest,
    /// Held for the whole span from `reserve` to `complete`, which is what guarantees the
    /// completion job always has somewhere to go. Shared with the reservation this was
    /// advanced from, which drops immediately afterwards.
    _permit: Arc<AdmissionPermit>,
    completion: AtomicBool,
}

impl DispatchCommitted {
    /// Take the value that stands for a durably recorded crossing.
    ///
    /// Called only by the store, once the marker has been advanced to the committed stage
    /// and that advance is durable. Constructing one earlier would make possession mean
    /// *a dispatch is intended*, and every exit from here is answerable as though the
    /// backend may already have acted.
    pub(super) fn over(digest: EvidenceDigest, permit: Arc<AdmissionPermit>) -> Self {
        DispatchCommitted {
            digest,
            _permit: permit,
            completion: AtomicBool::new(true),
        }
    }

    /// The request digest this commitment is keyed by.
    pub fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }

    /// Take this commitment's single completion, reporting whether it was still there.
    ///
    /// The swap is what makes the second taker lose even when both race. A completion that
    /// could be taken from the same handle twice would put two jobs behind one permit, so
    /// the count that bounds the queue would stop counting jobs.
    pub(super) fn take_completion(&self) -> bool {
        self.completion.swap(false, Ordering::AcqRel)
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

    /// One crossing is worth one completion, and the second taker loses.
    #[test]
    fn a_commitment_is_worth_exactly_one_completion() {
        let committed = DispatchCommitted::over(EvidenceDigest::of(b"request"), permit());
        assert!(committed.take_completion(), "the first taker gets it");
        assert!(!committed.take_completion(), "the second does not");
        assert!(!committed.take_completion());
    }

    /// Dropping a commitment releases the admission permit and NOTHING else.
    ///
    /// The permit is a capacity fact and goes back; the marker is an evidence fact and
    /// stays. A `Drop` that also cleared the marker — the disposition its pre-dispatch
    /// sibling has — would erase the one record an auditor cannot recover, for an exchange
    /// whose backend may have acted.
    #[test]
    fn dropping_a_commitment_gives_the_permit_back_and_keeps_its_record() {
        let permits = Arc::new(Semaphore::new(1));
        let held = Arc::new(
            Arc::clone(&permits)
                .try_acquire_owned()
                .expect("the permit"),
        );
        let committed = DispatchCommitted::over(EvidenceDigest::of(b"request"), held);
        assert_eq!(permits.available_permits(), 0);
        drop(committed);
        assert_eq!(
            permits.available_permits(),
            1,
            "a dropped commitment must not hold the queue bound forever"
        );
    }
}
