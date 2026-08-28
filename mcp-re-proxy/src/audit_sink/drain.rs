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
    /// The drain was not acknowledged inside the bound. Whether those records reached
    /// stderr is unknown, and stays unknown.
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
    let (ack, acked) = std::sync::mpsc::sync_channel(1);
    if queue.try_send(AuditMessage::Flush(ack)).is_err() {
        return AuditDrain::OutcomeUnknown;
    }
    if acked.recv_timeout(timeout).is_ok() {
        AuditDrain::Drained
    } else {
        AuditDrain::OutcomeUnknown
    }
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
        AuditDrain::Drained => "mcp-re-proxy: audit stream drained at shutdown: every record \
                                handed to the audit writer reached stderr"
            .to_string(),
        AuditDrain::OutcomeUnknown => format!(
            "mcp-re-proxy: WARNING: the audit stream did NOT acknowledge its drain within {}s. \
             This is NOT a report that records were lost and NOT a clean shutdown of the audit \
             stream: whether the decisions recorded last reached stderr is UNKNOWN. Their seq \
             numbers are the gap to look for, and the writer's backing channel (a stalled log \
             collector, a full volume) is what to check.",
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

    /// The unknown case is not the failure case, and the type is what keeps them apart:
    /// a `bool` would let a reader write `if !drained { /* records lost */ }`.
    #[test]
    fn the_unknown_outcome_is_its_own_case() {
        assert_ne!(AuditDrain::Drained, AuditDrain::OutcomeUnknown);
    }
}
