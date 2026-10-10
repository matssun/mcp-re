// SPDX-License-Identifier: Apache-2.0
//! The stderr audit sink: a handle on this process's audit stream.

use super::stream::{self, AuditPosition};
use super::writer::{stderr_audit_writer, AuditMessage, STDERR_AUDIT_DROPPED, STDERR_AUDIT_QUEUED};
use super::{admission_ceiling, offer, AuditSink, STDERR_AUDIT_QUEUE_DEPTH};
use crate::audit_record::text::{render_record, AuditField};
use crate::audit_record::AuditRecord;

/// The default sink: one structured line per decision on stderr, the proxy's
/// diagnostic channel.
///
/// Deliberately plain text with stable `key=value` fields rather than JSON — the
/// startup lines and rotation warnings on this channel already use this shape, and a
/// deployment that wants structured audit ships its own [`AuditSink`].
///
/// The line is formatted on the request path and then HANDED OFF: a dedicated thread
/// owns stderr, so the trait's "MUST NOT block the request path" is a property of the
/// implementation rather than a hope about the writer. It matters because `record` is
/// reached from the preflight rejection path — before any signature verifies — so an
/// unauthenticated peer decides how often it is called. Writing inline meant a log
/// collector applying backpressure, a rotation, or a full volume stalled the serving
/// core inside the request future, and a closed stderr PANICKED the connection task.
/// Neither degrades to "audit lost, request served", which is the documented intent.
///
/// The hand-off queue is bounded and DROPS when full, which is the same intent from the
/// other side: audit must never fail or delay a request. Three things keep that from
/// becoming an attacker-chosen blind spot:
///
/// * **Every line carries its position `seq=N run=<hex>`**, assigned before the hand-off.
///   `seq` is monotonic within one run of the process, and `run` names the run. A dropped
///   record is then a numbered hole in its run's stream, so which decisions are missing is
///   readable from the surviving records rather than inferred from an aggregate.
/// * **An unattributed record cannot consume the whole queue.** The flood an
///   unauthenticated peer can produce is by construction unattributed — no actor was
///   resolved — so those records are admitted only while the queue is below
///   [`STDERR_AUDIT_UNATTRIBUTED_CEILING`](super::STDERR_AUDIT_UNATTRIBUTED_CEILING). The remaining depth is reachable only by a
///   record naming a verifier-resolved actor, which is what stops a preflight flood from
///   evicting the decisions an attacker wants unrecorded.
/// * **The drop count is reported on a timer**, not only by the next record. A burst that
///   ends in silence still says so.
///
/// What none of that changes: records still in the queue at process exit are lost unless
/// the shutdown path calls [`drain::at_shutdown`](super::drain::at_shutdown). A run that died that way has a start
/// line and no shutdown line.
#[derive(Debug, Clone, Copy)]
pub struct StderrAuditSink {
    positions: &'static stream::AuditPositions,
}

impl StderrAuditSink {
    /// The sink of this process's audit stream. The first call draws the run and writes the
    /// stream's start line; later calls return a sink on the same run. `None` when the OS
    /// CSPRNG fails, which refuses startup.
    pub fn open() -> Option<Self> {
        Self::open_on(
            &stream::STREAM,
            stderr_audit_writer(),
            &STDERR_AUDIT_DROPPED,
            &STDERR_AUDIT_QUEUED,
        )
    }

    /// [`Self::open`] over a given stream cell and writer queue.
    fn open_on(
        cell: &'static std::sync::OnceLock<stream::AuditPositions>,
        queue: &std::sync::mpsc::SyncSender<AuditMessage>,
        dropped: &std::sync::atomic::AtomicU64,
        queued: &std::sync::atomic::AtomicUsize,
    ) -> Option<Self> {
        let (positions, opened) = stream::open(cell)?;
        if opened {
            let line = stream::start_line(&positions.run());
            offer(queue, dropped, queued, line, STDERR_AUDIT_QUEUE_DEPTH);
        }
        Some(StderrAuditSink { positions })
    }
}

impl AuditSink for StderrAuditSink {
    fn record(&self, record: &AuditRecord) {
        let line = audit_line(&self.positions.next(), record);
        offer(
            stderr_audit_writer(),
            &STDERR_AUDIT_DROPPED,
            &STDERR_AUDIT_QUEUED,
            line,
            admission_ceiling(record),
        );
    }
}

/// One record's line at `position`.
///
/// The position is this sink's own coordinate — it is what makes a drop a visible hole in
/// THIS run's stream — so the sink contributes it and the record contributes everything
/// else. The sink interprets nothing it was handed: a field slice carries no vocabulary, and
/// `render_record` owns every question of spelling.
fn audit_line(position: &AuditPosition, record: &AuditRecord) -> String {
    let run = position.run();
    let seq = position.seq_within(&run).unwrap_or_default();
    let mut fields = vec![
        AuditField::number("seq", i64::try_from(seq).unwrap_or(i64::MAX)),
        AuditField::text("run", run.to_string()),
    ];
    fields.extend(record.audit_fields());
    format!("mcp-re-proxy: audit {}", render_record(&fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_enforcer::AdmissionFacet;
    use crate::audit_record::AuditSubject;
    use crate::authorization::AuthorizationFacet;
    use crate::authorization::AuthorizationRefusalFacet;

    fn accepted(actor: &str) -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                AdmissionFacet::NotConfigured,
            ),
            actor_id: Some(actor.into()),
            status: 200,
            at_unix: 10,
        }
    }

    /// A record's line names its position — its number AND the run that number belongs to —
    /// so a dropped one is a numbered hole in a named run rather than an aggregate nobody can
    /// attribute, and an equal number from another run of the process cannot stand in for it.
    #[test]
    fn every_line_names_its_run_and_its_number_in_that_run() {
        let sink = StderrAuditSink::open().expect("the OS CSPRNG yields an incarnation");
        let run = sink.positions.run();
        let position = sink.positions.next();
        let seq = position
            .seq_within(&run)
            .expect("the sink's position is in its own run");
        let line = audit_line(&position, &accepted("actor-a"));
        assert!(
            line.starts_with(&format!("mcp-re-proxy: audit seq={seq} run={run} ")),
            "{line}"
        );
    }

    /// A run's stream states its start exactly once, naming the run its records carry, so a
    /// run with a start and no shutdown line is one whose tail is unknown.
    #[test]
    fn a_stream_states_its_start_once_naming_its_run() {
        let cell = Box::leak(Box::new(std::sync::OnceLock::new()));
        let (queue, lines) = std::sync::mpsc::sync_channel(4);
        let (dropped, queued) = Default::default();
        let open = || StderrAuditSink::open_on(cell, &queue, &dropped, &queued);
        let sink = open().expect("the OS CSPRNG yields an incarnation");
        let again = open().expect("an opened stream is returned");
        let run = sink.positions.run();
        assert_eq!(again.positions.run(), run, "one stream, one run");
        let offered: Vec<String> = lines
            .try_iter()
            .map(|message| match message {
                AuditMessage::Line(line) => line,
                AuditMessage::Flush(_) => panic!("opening a stream flushes nothing"),
            })
            .collect();
        assert_eq!(
            offered,
            [format!("mcp-re-proxy: audit stream started run={run}")]
        );
    }

    /// Records handed to the sink are drainable at shutdown rather than lost with the
    /// detached writer.
    #[test]
    fn recorded_lines_are_drainable_at_shutdown() {
        let sink = StderrAuditSink::open().expect("the OS CSPRNG yields an incarnation");
        sink.record(&accepted("actor-a"));
        sink.record(&AuditRecord {
            subject: AuditSubject::request_rejected(
                Some(&mcp_re_core::McpReError::ReplayDetected),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
                AdmissionFacet::NotConfigured,
            ),
            actor_id: None,
            status: 403,
            at_unix: 11,
        });
        assert_eq!(
            super::super::drain::flush_for_test(std::time::Duration::from_secs(5)),
            super::super::drain::AuditDrain::Drained,
            "a queued record must be drainable at shutdown rather than lost with the \
             detached writer"
        );
    }
}
