// SPDX-License-Identifier: Apache-2.0
//! The thread that owns stderr, and what it can honestly say about what it wrote.
//!
//! Separate from the sink because two different things are being decided. The sink decides
//! WHICH records are admitted to the hand-off queue and at what depth; this decides what
//! happens to a line once it is on the queue — and, the part that was missing, whether the
//! process is entitled to report a clean drain afterwards.
//!
//! # `Drained` has to mean arrived, not attempted
//!
//! The writer swallows write errors, and it must: a sink that cannot write must not fail a
//! request, and on the hot path there is nowhere to report them. What does not follow is
//! that the SHUTDOWN report may ignore them too. The `Flush` acknowledgement says the lines
//! ahead of it were dequeued and written AT; a shutdown in which every `write_all` returned
//! `EPIPE` acknowledged exactly as fast as one in which they all arrived.
//!
//! [`AuditDrain`](super::drain::AuditDrain) exists because `Drained` and `OutcomeUnknown`
//! must never read as the same fact, and a failed write collapsed them in the worse
//! direction: unknown-or-lost read as clean. So a failed write is LATCHED here, and the
//! drain consults the latch after the acknowledgement orders it behind every prior write.
//!
//! # A writer that never started is a fact the process has to be able to state
//!
//! The spawn result was discarded and the sender installed regardless. That does not wedge
//! the queue — a dropped receiver disconnects the channel, `try_send` fails, and `offer`
//! releases the slot it reserved — so records are dropped rather than accumulating. What it
//! does is lose them SILENTLY: `report_drops` is reached only from the writer loop, so with
//! no writer the drop counter grows and nobody ever reads it. The latch is what lets the
//! drain say so.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::{STDERR_AUDIT_DROP_REPORT_INTERVAL, STDERR_AUDIT_QUEUE_DEPTH};

/// One item on the hand-off queue.
pub(crate) enum AuditMessage {
    /// A formatted record to write.
    Line(String),
    /// Write everything queued ahead of this, then acknowledge. The acknowledgement is
    /// what makes a shutdown drain observable rather than a hope about timing.
    Flush(std::sync::mpsc::SyncSender<()>),
}

/// The writer's channel, started on first use.
///
/// Process-global because the sink is a unit type installed once and shared by every
/// core: one stderr, one thread that owns it, one queue in front of it.
pub(crate) static STDERR_AUDIT_WRITER: std::sync::OnceLock<
    std::sync::mpsc::SyncSender<AuditMessage>,
> = std::sync::OnceLock::new();

/// Records that never reached the writer because the queue was full.
pub(super) static STDERR_AUDIT_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Lines handed over and not yet written, so admission can reserve headroom. A
/// `sync_channel` does not expose its occupancy, and the reservation needs it.
pub(super) static STDERR_AUDIT_QUEUED: AtomicUsize = AtomicUsize::new(0);

/// Set the first time a write to stderr fails, or the writer thread fails to start.
///
/// Monotonic and never cleared. A drain that happened after a failed write cannot report
/// "every record reached stderr" merely because the writes after it succeeded — the
/// records lost to the failure are lost whatever happened later, and the whole point of
/// the two-case outcome is that "some are unaccounted for" is not the same fact as "all
/// arrived".
static STDERR_AUDIT_WRITES_FAILED: AtomicBool = AtomicBool::new(false);

/// Whether any write has failed, or the writer never started.
///
/// Read by the drain AFTER the flush acknowledgement, which is what orders it behind every
/// write the drain is reporting on.
pub(super) fn writes_have_failed() -> bool {
    STDERR_AUDIT_WRITES_FAILED.load(Ordering::Relaxed)
}

pub(super) fn stderr_audit_writer() -> &'static std::sync::mpsc::SyncSender<AuditMessage> {
    STDERR_AUDIT_WRITER.get_or_init(|| {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<AuditMessage>(STDERR_AUDIT_QUEUE_DEPTH);
        // A detached thread: it lives as long as the process, and the sink it drains for
        // is a `static`. Errors from an individual write are swallowed — a sink that
        // cannot write must not fail a request — but they are LATCHED, because the
        // shutdown report is a different question from the request path's.
        let started = std::thread::Builder::new()
            .name("mcp-re-audit".to_owned())
            .spawn(move || write_until_disconnected(&receiver));
        if started.is_err() {
            // The sender is still installed: the channel is disconnected, so `try_send`
            // fails, `offer` releases its reservation and every record is counted as
            // dropped. What would otherwise be lost is the FACT — `report_drops` runs only
            // on the writer thread, so with no writer nobody reads that counter. The latch
            // is the one thing that survives to be reported at shutdown.
            STDERR_AUDIT_WRITES_FAILED.store(true, Ordering::Relaxed);
            eprintln!(
                "mcp-re-proxy: WARNING: the audit writer thread did not start. No audit \
                 record will reach stderr for the life of this process, and the shutdown \
                 drain will report its outcome as UNKNOWN rather than clean."
            );
        }
        sender
    })
}

/// Drain the queue until the sender side is gone.
fn write_until_disconnected(receiver: &std::sync::mpsc::Receiver<AuditMessage>) {
    use std::io::Write;
    loop {
        let message = match receiver.recv_timeout(STDERR_AUDIT_DROP_REPORT_INTERVAL) {
            Ok(message) => Some(message),
            // Nothing arrived. A burst that stopped must still report the records it
            // cost, or the stream ends in a silence that reads exactly like no traffic
            // at all.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let line = match message {
            Some(AuditMessage::Line(line)) => {
                STDERR_AUDIT_QUEUED.fetch_sub(1, Ordering::Relaxed);
                Some(line)
            }
            Some(AuditMessage::Flush(ack)) => {
                report_drops(
                    &mut std::io::stderr().lock(),
                    &STDERR_AUDIT_DROPPED,
                    &STDERR_AUDIT_WRITES_FAILED,
                );
                let _ = ack.try_send(());
                continue;
            }
            None => None,
        };
        let mut stderr = std::io::stderr().lock();
        report_drops(
            &mut stderr,
            &STDERR_AUDIT_DROPPED,
            &STDERR_AUDIT_WRITES_FAILED,
        );
        if let Some(line) = line {
            if stderr.write_all(line.as_bytes()).is_err() || stderr.write_all(b"\n").is_err() {
                STDERR_AUDIT_WRITES_FAILED.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// Emit the outstanding drop count, if any, latching `failed` when the write does not land.
///
/// `failed` is a parameter rather than a reach for the global, because the global is
/// process-wide and monotonic: a battery that set it would make every later drain in the
/// same process report `OutcomeUnknown`, and the tests below would then be measuring each
/// other's order rather than this function.
///
/// The count is taken out of the counter atomically, so it can never be reported twice —
/// and PUT BACK when the write fails, so it can never be reported zero times either. The
/// earlier form took the count and discarded the write result, which erased exactly the
/// gaps the condition it names (a full volume, a closed stderr, a stalled collector) is
/// most likely to produce. "Never twice" and "at least once" are both halves of the
/// property; only the first was held.
fn report_drops(stderr: &mut impl std::io::Write, counter: &AtomicU64, failed: &AtomicBool) {
    let dropped = counter.swap(0, Ordering::Relaxed);
    if dropped == 0 {
        return;
    }
    let reported = writeln!(
        stderr,
        "mcp-re-proxy: audit dropped={dropped} (the audit hand-off queue was full; \
         that many decisions are missing from this stream, and their seq numbers are \
         the gaps in it)"
    );
    if reported.is_err() {
        // Saturating: the counter is a report of how many records were lost, and a
        // saturated one still says "at least this many". Wrapping would say a number
        // smaller than the truth, which is the direction that matters.
        counter.fetch_add(dropped, Ordering::Relaxed);
        failed.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A write that fails does not consume the drop count: the next successful report
    /// still names those records. Without the put-back the gap is erased silently, and
    /// erasure is indistinguishable from there having been no drops at all.
    #[test]
    fn a_drop_count_survives_a_failed_report_and_is_reported_later() {
        struct Failing;
        impl std::io::Write for Failing {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("EPIPE"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let counter = AtomicU64::new(7);
        let failed = AtomicBool::new(false);
        report_drops(&mut Failing, &counter, &failed);
        assert_eq!(
            counter.load(Ordering::Relaxed),
            7,
            "a failed report must leave the count to be reported later"
        );

        let mut ok: Vec<u8> = Vec::new();
        report_drops(&mut ok, &counter, &failed);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert!(String::from_utf8_lossy(&ok).contains("dropped=7"));
    }

    /// R8-C123: the drop count is reported without a later record to carry it.
    ///
    /// A burst that ends in quiescence used to report nothing at all — the count was read
    /// only when the NEXT line was dequeued — so the stream's last state was
    /// indistinguishable from no traffic. The writer's own timeout is what makes the gap
    /// visible.
    #[test]
    fn the_drop_count_is_reported_without_a_following_record() {
        let mut sink: Vec<u8> = Vec::new();
        let dropped = std::sync::atomic::AtomicU64::new(7);
        report_drops(&mut sink, &dropped, &AtomicBool::new(false));
        assert!(
            String::from_utf8_lossy(&sink).contains("audit dropped=7"),
            "the tail of a burst reports itself: {:?}",
            String::from_utf8_lossy(&sink)
        );
        assert_eq!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a reported drop must not be reported twice"
        );
    }

    /// The other half, unchanged: a count that WAS reported is not reported again.
    #[test]
    fn a_reported_drop_count_is_not_reported_twice() {
        let counter = AtomicU64::new(3);
        let failed = AtomicBool::new(false);
        let mut first: Vec<u8> = Vec::new();
        report_drops(&mut first, &counter, &failed);
        assert!(String::from_utf8_lossy(&first).contains("dropped=3"));

        let mut second: Vec<u8> = Vec::new();
        report_drops(&mut second, &counter, &failed);
        assert!(
            second.is_empty(),
            "a count already reported must not be reported again"
        );
    }

    /// A failed write latches, so the shutdown drain can refuse to call itself clean.
    #[test]
    fn a_failed_report_latches_the_write_failure() {
        struct Failing;
        impl std::io::Write for Failing {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("ENOSPC"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let counter = AtomicU64::new(1);
        let failed = AtomicBool::new(false);
        report_drops(&mut Failing, &counter, &failed);
        assert!(
            failed.load(Ordering::Relaxed),
            "a failed write must be observable by the drain"
        );
    }
}
