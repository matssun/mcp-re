// SPDX-License-Identifier: Apache-2.0
//! Discharging the audit writer's teardown obligation, and saying which of two things
//! happened.
//!
//! The writer thread is detached and cannot be joined, so a process that exits with records
//! still queued loses them silently — a shutdown under load drops precisely the decisions
//! taken last. The wait is therefore bounded: the writer owns a file descriptor the proxy
//! does not control, and a log collector applying backpressure, a full volume or a stalled
//! pipe reader must cost a bounded shutdown delay and a stated uncertainty, never a process
//! that will not exit.
//!
//! The bound, the wait and the meaning of the result are one authority and live together.
//! A composition root that held the timeout, or that decided what a missing acknowledgement
//! meant, would be re-deciding what this owns.

use std::time::Duration;

use super::writer::writes_have_failed;
use super::AuditMessage;
use super::STDERR_AUDIT_WRITER;

/// How long shutdown waits for the audit writer to write out what it was already handed.
const AUDIT_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// What became of the records already handed to the writer.
///
/// Two cases and not a `bool`, because the second is not the negation of the first. A
/// timeout does NOT report that records were lost — it reports that nobody can say either
/// way, since the acknowledgement that would have settled it never came. `false` invites a
/// reader to treat the unknown case as the failure case, and collapsing those destroys
/// exactly the distinction an audit stream exists to preserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditDrain {
    /// Every record handed to the writer reached stderr.
    Drained,
    /// Whether the records handed to the writer reached stderr is unknown, and stays
    /// unknown. Two ways to get here, and they are the same fact: the drain was not
    /// acknowledged inside the bound, or a write failed at some point and the records it
    /// carried are unaccounted for however cleanly the later ones landed.
    OutcomeUnknown,
}

/// Discharge the teardown obligation, and report the outcome when this deployment writes
/// its audit stream to stderr.
///
/// `report` decides only whether the outcome is spoken: the drain itself is unconditional,
/// because a sink installed past the composition seam would still have left records in the
/// same global queue.
///
/// A timeout is deliberately NOT turned into a non-zero result. The serving outcome is what
/// the caller asked about, and reporting a clean shutdown as failed because a log collector
/// was slow would make an observability fault look like a serving fault — the inversion the
/// sink's own "audit must never fail a request" rule rejects on the hot path.
pub(crate) fn at_shutdown(report: bool) {
    if let Some(line) = drain_line(flush(AUDIT_FLUSH_TIMEOUT), report) {
        eprintln!("{line}");
    }
}

/// Write out everything already handed to the stderr audit writer, then return.
///
/// Gives up after `timeout` rather than letting a stalled log collector hold the process
/// open.
fn flush(timeout: Duration) -> AuditDrain {
    let Some(queue) = STDERR_AUDIT_WRITER.get() else {
        // Nothing ever recorded, so there is nothing to drain.
        return AuditDrain::Drained;
    };
    drain_queue(queue, timeout, writes_have_failed)
}

/// The drain DECISION, over a queue and a latch it is handed.
///
/// Split from [`flush`] because `flush` reaches two process globals, and a function that
/// looks a decision's inputs up cannot be driven to its own arms: every one of these three
/// was asserted by the contract and measured by nothing (r11 `R11-167`, `R11-169`). Flipping
/// the full-queue arm from `OutcomeUnknown` to `Drained` left the whole battery green.
///
/// ```text
/// ensures  the Flush cannot be queued       => OutcomeUnknown
///          no acknowledgement inside bound  => OutcomeUnknown
///          acknowledged, a write had failed => OutcomeUnknown
///          acknowledged, no write failed    => Drained
/// ```
///
/// `writes_failed` is read AFTER the acknowledgement and not before, and the ordering is the
/// claim: the ack says the lines ahead of it were DEQUEUED and written AT, never that they
/// arrived — the writer swallows individual write errors by design, so a shutdown in which
/// every `write_all` returned EPIPE acknowledges exactly as fast as one in which they all
/// landed. Reading the latch behind the ack is what keeps `Drained` meaning ARRIVED rather
/// than attempted.
fn drain_queue(
    queue: &std::sync::mpsc::SyncSender<AuditMessage>,
    timeout: Duration,
    writes_failed: impl Fn() -> bool,
) -> AuditDrain {
    let (ack, acked) = std::sync::mpsc::sync_channel(1);
    if queue.try_send(AuditMessage::Flush(ack)).is_err() {
        return AuditDrain::OutcomeUnknown;
    }
    if acked.recv_timeout(timeout).is_err() {
        return AuditDrain::OutcomeUnknown;
    }
    if writes_failed() {
        return AuditDrain::OutcomeUnknown;
    }
    AuditDrain::Drained
}

/// What shutdown says about the drain, or `None` when this deployment does not write its
/// audit stream to stderr and so has nothing to say about it.
///
/// Separated from the wait so the one property that matters — that the two outcomes never
/// read as the same fact — is assertable without stalling a log collector.
fn drain_line(outcome: AuditDrain, report: bool) -> Option<String> {
    if !report {
        return None;
    }
    Some(match outcome {
        // BEFORE this drain, and the qualification is load-bearing: `Drained` means every
        // record queued ahead of the Flush reached stderr, and at shutdown in-flight
        // exchanges are still recording. A record offered during or after the flush is
        // outside the claim, so a line that said "every record" would be claiming an
        // ordering nothing establishes.
        AuditDrain::Drained => "mcp-re-proxy: audit stream drained at shutdown: every record \
                                handed to the audit writer before this drain reached stderr"
            .to_string(),
        AuditDrain::OutcomeUnknown => format!(
            "mcp-re-proxy: WARNING: the audit stream did not complete a clean drain — it either \
             failed to acknowledge within {}s or reported a failed write. This is NOT a report \
             that records were lost and NOT a clean shutdown of the audit stream: whether the \
             decisions recorded last reached stderr is UNKNOWN. Their seq numbers are the gap \
             to look for, and the writer's backing channel (a stalled log collector, a full \
             volume, a closed stderr) is what to check.",
            AUDIT_FLUSH_TIMEOUT.as_secs()
        ),
    })
}

/// The bounded wait, for the sink's own queue tests. Not a production entry point: the
/// shutdown path goes through [`at_shutdown`], which owns the bound.
#[cfg(test)]
pub(super) fn flush_for_test(timeout: Duration) -> AuditDrain {
    flush(timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R8-C123, second half: a drain that TIMED OUT must never read as a drain that
    /// completed.
    ///
    /// The bounded wait exists so a stalled log collector cannot hold the process open,
    /// which means the timeout is a reachable outcome in production and not an error path.
    /// What it must not become is a quiet one: "the queue was drained" and "nobody can say
    /// whether the queue was drained" are different facts about the audit stream, and an
    /// operator reading the shutdown transcript has to be able to tell which they got.
    ///
    /// The broken implementation this catches: reporting both as one shutdown-complete
    /// line, or reporting only the success and leaving the timeout silent.
    #[test]
    fn a_timed_out_audit_drain_never_reads_as_a_completed_one() {
        let drained = drain_line(AuditDrain::Drained, true).expect("stderr audit states its drain");
        let timed_out = drain_line(AuditDrain::OutcomeUnknown, true)
            .expect("a timeout is stated, not swallowed");

        assert_ne!(drained, timed_out);
        assert!(
            !drained.contains("WARNING") && drained.contains("drained"),
            "a completed drain must read as one: {drained}"
        );
        assert!(
            timed_out.contains("WARNING") && timed_out.contains("UNKNOWN"),
            "a timeout must state the uncertainty AS uncertainty — not as loss, and not as \
             a clean shutdown: {timed_out}"
        );
        assert!(
            !timed_out.contains("drained at shutdown"),
            "the timeout line must not carry the completed line's claim: {timed_out}"
        );
        // A deployment whose audit goes nowhere says nothing about a stream it does not
        // write; without this control the two assertions above would also hold for a
        // function that always spoke.
        assert!(drain_line(AuditDrain::Drained, false).is_none());
        assert!(drain_line(AuditDrain::OutcomeUnknown, false).is_none());
    }

    /// **R11-167 / R11-169.** A queue that cannot accept the Flush is `OutcomeUnknown`.
    ///
    /// G15 asserted this and nothing measured it: flipping the arm to `Drained` left the
    /// whole battery green. A full queue at drain time is the shutdown-under-load case the
    /// bound exists for — the records already handed over are exactly the decisions taken
    /// last, and reporting a clean drain there would state that they reached stderr when
    /// nobody can say whether they did.
    ///
    /// The receiver is dropped rather than the queue filled: `try_send` fails either way,
    /// and a disconnected channel is the one a test can stage deterministically.
    #[test]
    fn a_queue_that_cannot_accept_the_flush_is_unknown_not_drained() {
        let (queue, receiver) = std::sync::mpsc::sync_channel::<AuditMessage>(1);
        drop(receiver);
        assert_eq!(
            drain_queue(&queue, Duration::from_millis(50), || false),
            AuditDrain::OutcomeUnknown,
        );
    }

    /// **G14.** The wait RETURNS under a writer that never acknowledges, and says unknown.
    ///
    /// Two properties in one control, and the first is why the bound exists: a stalled log
    /// collector must cost a bounded shutdown delay, never a process that will not exit. A
    /// control that only asserted the verdict would pass against a wait that never returned
    /// — it would simply hang, which reads as a slow suite rather than as a failure.
    #[test]
    fn a_writer_that_never_acknowledges_returns_bounded_and_unknown() {
        let (queue, _receiver) = std::sync::mpsc::sync_channel::<AuditMessage>(1);
        let started = std::time::Instant::now();
        let outcome = drain_queue(&queue, Duration::from_millis(50), || false);
        assert_eq!(outcome, AuditDrain::OutcomeUnknown);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the wait must be BOUNDED; it took {:?}",
            started.elapsed()
        );
    }

    /// An acknowledged drain over which a write had already failed is `OutcomeUnknown`.
    ///
    /// The ack says the lines ahead of it were dequeued and written AT, never that they
    /// arrived — the writer swallows individual write errors by design, so a shutdown in
    /// which every `write_all` returned EPIPE acknowledges exactly as fast as one in which
    /// they all landed. Reading the latch BEHIND the ack is what keeps `Drained` meaning
    /// arrived; reading it before would report a clean drain for records that went nowhere.
    #[test]
    fn an_acknowledged_drain_with_a_failed_write_behind_it_is_unknown() {
        assert_eq!(acknowledging_drain(|| true), AuditDrain::OutcomeUnknown);
    }

    /// **The mirror, and it is not optional.** An acknowledged drain with no failed write is
    /// `Drained` — otherwise every control above passes against a function that never
    /// reports success, which would make every clean shutdown state an uncertainty it does
    /// not have.
    #[test]
    fn an_acknowledged_drain_with_no_failed_write_is_drained() {
        assert_eq!(acknowledging_drain(|| false), AuditDrain::Drained);
    }

    /// Drive `drain_queue` against a writer that answers the Flush, with `writes_failed`
    /// under the test's control.
    fn acknowledging_drain(writes_failed: impl Fn() -> bool) -> AuditDrain {
        let (queue, receiver) = std::sync::mpsc::sync_channel::<AuditMessage>(1);
        let writer = std::thread::spawn(move || {
            if let Ok(AuditMessage::Flush(ack)) = receiver.recv() {
                let _ = ack.send(());
            }
        });
        let outcome = drain_queue(&queue, Duration::from_secs(5), writes_failed);
        writer.join().expect("the fixture writer must not panic");
        outcome
    }

    /// The unknown case is not the failure case, and the type is what keeps them apart:
    /// a `bool` would let a reader write `if !drained { /* records lost */ }`.
    #[test]
    fn the_unknown_outcome_is_its_own_case() {
        assert_ne!(AuditDrain::Drained, AuditDrain::OutcomeUnknown);
    }
}
