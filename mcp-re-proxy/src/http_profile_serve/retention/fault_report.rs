// SPDX-License-Identifier: Apache-2.0
//! Saying that an evidence-retention or continuation-store fault happened, without letting the fault set the rate.
//!
//! Each fault class owns the operator sentence that names it, so the serving code decides
//! the answer and this module decides only how it is said.
//!
//! # Two rules
//!
//! **Non-panicking.** `eprintln!` panics when the write fails — a closed pipe, a full
//! buffer with a dead reader. A diagnostic on a refusal path must not be able to unwind
//! it, so the write result is discarded: losing the line is the correct outcome.
//!
//! **Paced by the process, per class.** A full retention queue is drivable by any peer and
//! refuses on every request; one line per refusal would hand that peer the write rate of
//! this process's stderr. The first fault of a class is reported, then at most one line per
//! `LINE_INTERVAL_MS` for that class, each carrying the running total. The slots are per
//! class so a backpressure flood cannot suppress the post-dispatch line.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use crate::transparency::RetentionError;

/// The shortest gap between two lines of one class.
const LINE_INTERVAL_MS: u64 = 10_000;

/// Which retention fault this is, and therefore which sentence says it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::http_profile_serve) enum Fault {
    /// The store's queue is full; nothing was published and a retry is safe.
    Backpressure,
    /// The store's writer is gone; this replica will accept no further write.
    Retired,
    /// A record this exchange cannot form, or a completion already taken.
    Unusable,
    /// The crossing could be neither made durable nor withdrawn.
    Unresolved,
    /// The call executed and the retention write then failed.
    AfterDispatch,
    /// The continuation store could not be read for the approval an answer leg names.
    ContinuationPeek,
    /// The continuation store could not retire the approval an exchange answered.
    ContinuationRetire,
    /// The continuation store could not record an open leg.
    ContinuationRecord,
}

/// The number of [`Fault`] classes, one pacing slot each.
const FAULT_CLASSES: usize = 8;

/// One class's pacing state.
struct Slot {
    count: AtomicU64,
    last_line_ms: AtomicU64,
}

impl Slot {
    const fn new() -> Self {
        Slot {
            count: AtomicU64::new(0),
            last_line_ms: AtomicU64::new(0),
        }
    }

    /// Count this fault; `Some(running total)` when a line is due at `now_ms`.
    ///
    /// The first fault is always due; after that one line per `LINE_INTERVAL_MS`, and under
    /// concurrency only the caller that wins the window's swap gets it.
    fn admit(&self, now_ms: u64) -> Option<u64> {
        let seen = self.count.fetch_add(1, Ordering::Relaxed);
        let total = seen.saturating_add(1);
        if seen == 0 {
            self.last_line_ms.store(now_ms, Ordering::Relaxed);
            return Some(total);
        }
        let last = self.last_line_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < LINE_INTERVAL_MS {
            return None;
        }
        self.last_line_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .ok()
            .map(|_| total)
    }
}

/// One slot per [`Fault`], indexed by its discriminant.
struct Pacer {
    slots: [Slot; FAULT_CLASSES],
}

impl Pacer {
    const fn new() -> Self {
        Pacer {
            slots: [const { Slot::new() }; FAULT_CLASSES],
        }
    }

    fn admit(&self, fault: Fault, now_ms: u64) -> Option<u64> {
        self.slots.get(fault as usize)?.admit(now_ms)
    }
}

static PACER: Pacer = Pacer::new();
static ORIGIN: OnceLock<Instant> = OnceLock::new();

fn elapsed_ms() -> u64 {
    let origin = ORIGIN.get_or_init(Instant::now);
    u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Report a pre-dispatch fault at the paced rate.
pub(in crate::http_profile_serve) fn report(
    fault: Fault,
    attempted: &str,
    error: &dyn std::fmt::Display,
) {
    if let Some(total) = PACER.admit(fault, elapsed_ms()) {
        write_line(
            &mut std::io::stderr().lock(),
            fault,
            attempted,
            error,
            total,
        );
    }
}

/// Report a fault after the call executed, at the paced rate.
pub(super) fn report_after_dispatch(error: &RetentionError) {
    report(Fault::AfterDispatch, "complete", error);
}

/// The write result is discarded: a failed diagnostic write is lost, never unwound.
fn write_line(
    sink: &mut impl std::io::Write,
    fault: Fault,
    attempted: &str,
    error: &dyn std::fmt::Display,
    total: u64,
) {
    let _ = match fault {
        Fault::Backpressure => writeln!(
            sink,
            "evidence retention could not {attempted}, refusing before dispatch: {error} \
             ({total} such faults so far on this replica)"
        ),
        Fault::Retired => writeln!(
            sink,
            "evidence retention could not {attempted}, and this replica will not accept the \
             next one either: {error} ({total} such faults so far on this replica)"
        ),
        Fault::Unusable => writeln!(
            sink,
            "evidence retention could not {attempted}: the record of this exchange cannot be \
             formed, refusing before dispatch: {error} ({total} such faults so far on this \
             replica)"
        ),
        Fault::Unresolved => writeln!(
            sink,
            "evidence retention could not {attempted}: the exchange did NOT dispatch and the \
             store's record of it cannot be stated: {error} ({total} such faults so far on \
             this replica)"
        ),
        Fault::AfterDispatch => writeln!(
            sink,
            "evidence retention failed AFTER the call executed; the exchange is \
             indeterminate and MUST NOT be blindly retried: {error} ({total} such faults so \
             far on this replica)"
        ),
        Fault::ContinuationPeek | Fault::ContinuationRetire | Fault::ContinuationRecord => {
            writeln!(
                sink,
                "continuation store could not {attempted}: {error} ({total} such faults so far \
                 on this replica)"
            )
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingSink;

    impl std::io::Write for FailingSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed pipe"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("closed pipe"))
        }
    }

    #[test]
    fn the_first_fault_is_reported_and_the_next_is_paced() {
        let slot = Slot::new();
        assert_eq!(slot.admit(0), Some(1));
        assert_eq!(slot.admit(LINE_INTERVAL_MS - 1), None);
        assert_eq!(slot.admit(LINE_INTERVAL_MS), Some(3));
        assert_eq!(slot.admit(LINE_INTERVAL_MS + 1), None);
    }

    #[test]
    fn a_flood_of_one_fault_class_does_not_pace_another() {
        let pacer = Pacer::new();
        for _ in 0..1_000 {
            let _ = pacer.admit(Fault::Backpressure, 0);
        }
        assert_eq!(pacer.admit(Fault::Backpressure, 1), None);
        assert_eq!(pacer.admit(Fault::AfterDispatch, 1), Some(1));
        assert_eq!(pacer.admit(Fault::ContinuationPeek, 1), Some(1));
    }

    #[test]
    fn a_failing_sink_is_discarded_not_unwound() {
        let error = RetentionError::AlreadyCompleted;
        for fault in [
            Fault::Backpressure,
            Fault::Retired,
            Fault::Unusable,
            Fault::Unresolved,
            Fault::AfterDispatch,
            Fault::ContinuationPeek,
            Fault::ContinuationRetire,
            Fault::ContinuationRecord,
        ] {
            write_line(&mut FailingSink, fault, "accept the exchange", &error, 1);
        }
    }
}
