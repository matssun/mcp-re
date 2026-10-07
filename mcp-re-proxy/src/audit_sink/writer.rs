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
pub(super) enum AuditMessage {
    /// A formatted record to write.
    Line(String),
    /// Write everything queued ahead of this, then acknowledge. The acknowledgement is
    /// what makes a shutdown drain observable rather than a hope about timing.
    Flush(std::sync::mpsc::SyncSender<()>),
}

/// The writer's channel, started on first use.
///
/// Process-global because the process has one audit stream shared by every core: one
/// stderr, one thread that owns it, one queue in front of it.
pub(super) static STDERR_AUDIT_WRITER: std::sync::OnceLock<
    std::sync::mpsc::SyncSender<AuditMessage>,
> = std::sync::OnceLock::new();

/// Records that never reached the writer: the queue was full, or past their class's ceiling.
pub(super) static STDERR_AUDIT_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Lines on the queue and not yet dequeued by the writer: the channel's line occupancy,
/// which the admission reservation needs and a `sync_channel` does not expose. `Flush`
/// messages are not counted.
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
            .spawn(move || {
                write_until_disconnected(
                    &receiver,
                    STDERR_AUDIT_DROP_REPORT_INTERVAL,
                    &STDERR_AUDIT_DROPPED,
                    &STDERR_AUDIT_QUEUED,
                    &STDERR_AUDIT_WRITES_FAILED,
                    || std::io::stderr().lock(),
                );
            });
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
///
/// The cadence, the three counters and the output are PARAMETERS for the reason [`report_drops`]
/// already gives about its own: the globals are process-wide and monotonic, so a battery
/// that drove this loop over them would make every later drain in the same process report
/// `OutcomeUnknown`. Passing them is also what makes the loop's own decisions measurable —
/// the timeout arm below is the whole reason the drop report is ever emitted for a burst
/// that stopped, and calling `report_drops` directly cannot establish that it is reached.
fn write_until_disconnected<W: std::io::Write>(
    receiver: &std::sync::mpsc::Receiver<AuditMessage>,
    report_interval: std::time::Duration,
    dropped: &AtomicU64,
    queued: &AtomicUsize,
    failed: &AtomicBool,
    mut out: impl FnMut() -> W,
) {
    loop {
        let message = match receiver.recv_timeout(report_interval) {
            Ok(message) => Some(message),
            // Nothing arrived. A burst that stopped must still report the records it
            // cost, or the stream ends in a silence that reads exactly like no traffic
            // at all.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let line = match message {
            Some(AuditMessage::Line(line)) => {
                let _ =
                    queued.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
                Some(line)
            }
            Some(AuditMessage::Flush(ack)) => {
                report_drops(&mut out(), dropped, failed);
                let _ = ack.try_send(());
                continue;
            }
            None => None,
        };
        let mut stderr = out();
        report_drops(&mut stderr, dropped, failed);
        if line.is_some_and(|line| !write_record(&mut stderr, &line)) {
            failed.store(true, Ordering::Relaxed);
        }
    }
}

/// One terminated physical record in ONE write, so a pipe receives it whole or not at all.
fn write_record(out: &mut impl std::io::Write, record: &str) -> bool {
    out.write_all(format!("{record}\n").as_bytes()).is_ok()
}

/// Emit the outstanding drop count, if any, latching `failed` when the write does not land.
///
/// `failed` is a parameter rather than a reach for the global, because the global is
/// process-wide and monotonic: a battery that set it would make every later drain in the
/// same process report `OutcomeUnknown`, and the tests below would then be measuring each
/// other's order rather than this function.
///
/// The count is swapped out atomically and the report is ONE write, so a failure on a pipe
/// means nothing was emitted; a short write to a regular file can still leave a fragment,
/// the put-back then errs toward reporting again, and over-stating a loss count is the safe
/// direction (the latch already makes the drain `OutcomeUnknown`). The count is PUT BACK
/// when the write fails, so it can never be reported zero times: that erases exactly the
/// gaps a full volume, a closed stderr or a stalled collector is most likely to produce.
fn report_drops(stderr: &mut impl std::io::Write, counter: &AtomicU64, failed: &AtomicBool) {
    let dropped = counter.swap(0, Ordering::Relaxed);
    if dropped == 0 {
        return;
    }
    let report = format!(
        "mcp-re-proxy: audit dropped={dropped}{run} (the hand-off queue was full, or past \
         the share unattributed records may take; that many decisions are missing from \
         this stream, and their seq numbers are the gaps in it)",
        run = super::stream::run_suffix()
    );
    if !write_record(stderr, &report) {
        // A wrapping add that cannot wrap: the counter never exceeds the records ever
        // offered, one per position allocated, and 2^64 offers outlast any process.
        // It exists so the report never understates the loss.
        counter.fetch_add(dropped, Ordering::Relaxed);
        failed.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A burst that STOPS still reports the records it cost.
    ///
    /// The loop's timeout arm is the only thing that makes that true: with nothing arriving
    /// there is no Flush and no line, so the drop count would sit in the counter until the
    /// process ended and the stream would end in a silence that reads exactly like no
    /// traffic at all. `the_drop_count_is_reported_without_a_following_record` next door
    /// calls `report_drops` DIRECTLY — it establishes that the function reports, and stays
    /// green if the timeout arm stops reaching it. This drives the loop.
    #[test]
    fn a_burst_that_stops_still_reports_what_it_cost() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<AuditMessage>(4);
        let dropped = AtomicU64::new(5);
        let queued = AtomicUsize::new(0);
        let failed = AtomicBool::new(false);
        let interval = std::time::Duration::from_millis(20);

        // `Receiver` is `Send` and not `Sync`, so it is MOVED into the writer thread — the
        // shape production uses. The three counters cross as shared references.
        let (d, q, f) = (&dropped, &queued, &failed);
        std::thread::scope(|scope| {
            scope.spawn(move || write_until_disconnected(&rx, interval, d, q, f, std::io::sink));
            // Nothing is sent, so only the timeout arm can run. Ten intervals is far more
            // than the one turn the property needs and keeps the control off the scheduler's
            // exact timing.
            std::thread::sleep(interval * 10);
            assert_eq!(
                dropped.load(Ordering::Relaxed),
                0,
                "a stopped burst must still have its drop count reported"
            );
            assert!(
                !failed.load(Ordering::Relaxed),
                "the report itself succeeded"
            );
            drop(tx);
        });
    }

    /// Output shared with the test: every `write` call is recorded, and calls past
    /// `accept` fail.
    struct Shared<'a> {
        bytes: &'a std::sync::Mutex<Vec<u8>>,
        calls: &'a AtomicUsize,
        accept: usize,
    }
    impl std::io::Write for Shared<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.calls.fetch_add(1, Ordering::Relaxed) >= self.accept {
                return Err(std::io::Error::other("EPIPE"));
            }
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Drive the loop over `Shared` output with the given messages, then disconnect.
    fn drive(
        accept: usize,
        queued: &AtomicUsize,
        failed: &AtomicBool,
        send: impl FnOnce(&std::sync::mpsc::SyncSender<AuditMessage>, &std::sync::Mutex<Vec<u8>>),
    ) -> Vec<u8> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<AuditMessage>(4);
        let bytes = std::sync::Mutex::new(Vec::new());
        let calls = AtomicUsize::new(0);
        let dropped = AtomicU64::new(0);
        std::thread::scope(|scope| {
            let (b, c, d) = (&bytes, &calls, &dropped);
            scope.spawn(move || {
                write_until_disconnected(
                    &rx,
                    std::time::Duration::from_secs(60),
                    d,
                    queued,
                    failed,
                    || Shared {
                        bytes: b,
                        calls: c,
                        accept,
                    },
                );
            });
            send(&tx, &bytes);
            drop(tx);
        });
        bytes.into_inner().unwrap()
    }

    #[test]
    fn a_failed_line_write_latches_the_failure() {
        let (queued, failed) = (AtomicUsize::new(1), AtomicBool::new(false));
        drive(0, &queued, &failed, |tx, _| {
            tx.send(AuditMessage::Line("x".to_owned())).unwrap();
        });
        assert!(failed.load(Ordering::Relaxed));
        assert_eq!(queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_flush_is_acknowledged_behind_the_lines_ahead_of_it() {
        let (queued, failed) = (AtomicUsize::new(1), AtomicBool::new(false));
        let (ack, acked) = std::sync::mpsc::sync_channel::<()>(1);
        let bytes = drive(usize::MAX, &queued, &failed, |tx, captured| {
            tx.send(AuditMessage::Line("x".to_owned())).unwrap();
            tx.send(AuditMessage::Flush(ack)).unwrap();
            acked
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the flush is acknowledged");
            assert_eq!(*captured.lock().unwrap(), b"x\n");
        });
        assert_eq!(bytes, b"x\n");
    }

    #[test]
    fn a_record_is_one_write_call() {
        let (queued, failed) = (AtomicUsize::new(1), AtomicBool::new(false));
        let bytes = drive(1, &queued, &failed, |tx, _| {
            tx.send(AuditMessage::Line("x".to_owned())).unwrap();
        });
        assert_eq!(bytes, b"x\n");
        assert!(!failed.load(Ordering::Relaxed));
    }

    /// One counter carries both refusals `offer` makes — a full queue, and an unattributed
    /// record past its ceiling while the queue still has room — so the report names both
    /// rather than blaming a full queue for a drop made at three-quarters depth.
    #[test]
    fn a_drop_report_names_both_causes_the_counter_carries() {
        let mut out = Vec::new();
        report_drops(&mut out, &AtomicU64::new(1), &AtomicBool::new(false));
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("queue was full") && text.contains("unattributed records"),
            "{text:?}"
        );
    }

    #[test]
    fn a_drop_report_is_one_write_call() {
        let bytes = std::sync::Mutex::new(Vec::new());
        let calls = AtomicUsize::new(0);
        let counter = AtomicU64::new(5);
        let failed = AtomicBool::new(false);
        let mut out = Shared {
            bytes: &bytes,
            calls: &calls,
            accept: 1,
        };
        report_drops(&mut out, &counter, &failed);
        let text = String::from_utf8(bytes.into_inner().unwrap()).unwrap();
        assert!(
            text.contains("dropped=5") && text.ends_with('\n'),
            "{text:?}"
        );
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert!(!failed.load(Ordering::Relaxed));
    }

    #[test]
    fn an_unpaired_line_does_not_wrap_the_occupancy_counter() {
        let (queued, failed) = (AtomicUsize::new(0), AtomicBool::new(false));
        drive(usize::MAX, &queued, &failed, |tx, _| {
            tx.send(AuditMessage::Line("x".to_owned())).unwrap();
        });
        assert_eq!(queued.load(Ordering::Relaxed), 0);
    }

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
