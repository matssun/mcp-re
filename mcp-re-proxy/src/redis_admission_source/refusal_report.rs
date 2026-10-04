// SPDX-License-Identifier: Apache-2.0
//! Telling an operator WHICH refusal class fired, without letting a caller pace the writing.
//!
//! The frozen wire taxonomy gives a revoked workload, an unknown one and a store outage the
//! same code, so `actor_binding_failed` alone is not something an operator can act on. The
//! refusal CLASS is the missing fact, and this is where it is said.
//!
//! # Why once per class, and not per request
//!
//! The path that produces a refusal is reachable on every request: a caller that presents a
//! workload id with no record drives it forever. An unconditional line is therefore an
//! attacker-paced write to a shared file descriptor. The write here is non-panicking: a failed
//! write is dropped, so the diagnostic cannot turn a designed refusal into a fault.
//!
//! Pacing by CLASS rather than by request bounds the writing by the size of a closed
//! taxonomy. The operator still learns every class that has fired; what they stop getting is
//! one line per attempt.

use mcp_re_http_profile::authoritative_admission::record::AdmissionRecordRefusal;

use std::sync::atomic::{AtomicBool, Ordering};

/// One latch per refusal class.
///
/// An array rather than a map: the taxonomy is closed and small, so there is nothing to
/// allocate, nothing to lock, and no key a caller chooses — a caller-chosen key was the
/// shape of the defect this replaces.
#[derive(Default)]
pub(super) struct ReportedClasses {
    seen: [AtomicBool; AdmissionRecordRefusal::COUNT],
}

impl ReportedClasses {
    /// Report `refusal` if this source has not reported its class before.
    ///
    /// Neither the workload id nor the stored bytes appear: both are attacker-influenced,
    /// and this is a line-oriented record.
    pub(super) fn report_once(&self, refusal: AdmissionRecordRefusal) {
        self.report_once_into(refusal, &mut std::io::stderr());
    }

    fn report_once_into(&self, refusal: AdmissionRecordRefusal, sink: &mut impl std::io::Write) {
        // Class C: `discriminant_index` is `0..COUNT` by construction — a match over the
        // closed enum with one arm per variant and no catch-all, pinned by
        // `every_class_has_a_distinct_index_inside_the_published_count`.
        #[allow(clippy::indexing_slicing)]
        let slot = &self.seen[refusal.discriminant_index()];
        if slot.swap(true, Ordering::Relaxed) {
            return;
        }
        // A failed diagnostic write is dropped: the diagnostic must not be able to fail the
        // refusal it describes.
        let _ = writeln!(
            sink,
            "mcp-re-proxy: an admission record in the shared store is not the configured \
             authority's current statement ({refusal}); the workload is treated as NOT \
             ADMITTED. A reachable store that answered is not an outage. Reported once per \
             class; workload id and stored bytes withheld."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The latch is per CLASS: the first of each is written, every repeat is suppressed.
    #[test]
    fn a_class_is_reported_once_and_then_suppressed() {
        let reported = ReportedClasses::default();
        let mut buf = Vec::new();
        for _ in 0..3 {
            reported.report_once_into(AdmissionRecordRefusal::SignatureInvalid, &mut buf);
        }
        assert_eq!(buf.iter().filter(|b| **b == b'\n').count(), 1);
    }

    /// Classes do not share a latch, so one noisy class cannot silence another — which is
    /// the failure an operator would never notice.
    #[test]
    fn one_class_being_reported_does_not_suppress_another() {
        let reported = ReportedClasses::default();
        let mut buf = Vec::new();
        reported.report_once_into(AdmissionRecordRefusal::SignatureInvalid, &mut buf);
        reported.report_once_into(AdmissionRecordRefusal::SignatureInvalid, &mut buf);
        reported.report_once_into(AdmissionRecordRefusal::SubjectMismatch, &mut buf);
        assert_eq!(buf.iter().filter(|b| **b == b'\n').count(), 2);
    }

    /// Every class has its own latch, so the array `COUNT` sizes is exactly covered.
    #[test]
    fn every_class_has_its_own_latch() {
        let reported = ReportedClasses::default();
        for refusal in [
            AdmissionRecordRefusal::Malformed,
            AdmissionRecordRefusal::IssuerUntrusted,
            AdmissionRecordRefusal::SignatureInvalid,
            AdmissionRecordRefusal::ProfileMismatch,
            AdmissionRecordRefusal::SubjectMismatch,
            AdmissionRecordRefusal::Expired,
            AdmissionRecordRefusal::WindowExceedsBudget,
            AdmissionRecordRefusal::RevisionRewound,
        ] {
            assert!(
                !reported.seen[refusal.discriminant_index()].swap(true, Ordering::Relaxed),
                "{refusal} must have an unset latch of its own"
            );
        }
        assert!(
            reported.seen.iter().all(|s| s.load(Ordering::Relaxed)),
            "every latch is now set, so none was shared"
        );
    }
}
