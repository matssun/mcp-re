// SPDX-License-Identifier: Apache-2.0
//! The security-audit emission seam for the RFC 9421 serving path (ADR-MCPS-035).
//!
//! `mcp-re-core` freezes the audit VOCABULARY ([`mcp_re_core::audit::AuditEvent`]) and a CI
//! guard pins it, but the vocabulary is a pure value type with no transport — by
//! design, since `mcp-re-core` does no I/O. This module is the missing half: the sink
//! the serving PEP writes those events to.
//!
//! What an event may carry is deliberately narrow. An audit record names the DECISION
//! and, for a rejection, the exact frozen `mcp-re.*` wire code — never a parallel
//! sub-name, never key material, and never the nonce or correlation state (the
//! ADR-MCPS-020 startup-line discipline applies here too: a forensic record that leaks
//! the replay-cache key is a new attack surface, not a control). The actor identity is
//! carried because attribution is the whole point of the surface; it is an identity the
//! verifier already RESOLVED, not a claim from the wire.
//!
//! Emissions go to the proxy's own diagnostic channel, never onto an inner server's
//! protocol stream and never as MCP content — the same boundary
//! [`crate::log_sink`] observes for inner-server lifecycle events. The two are distinct
//! surfaces: this one is the normative security record documented in
//! `docs/spec/security-boundary.md` S9; `log_sink` is the proxy's inner-plane
//! diagnostic channel.

use std::sync::Arc;

use crate::audit_record::AuditRecord;

/// A sink for [`AuditRecord`]s.
///
/// `Send + Sync` because one `HttpProfileProxy` serves every connection on a core
/// (MCPRE-111) and the per-core fleet shares it. Implementations MUST NOT block the
/// request path for long: this is called on the hot path, so a sink that does
/// synchronous network I/O would put that latency in front of every response.
pub trait AuditSink: Send + Sync {
    /// Record one decision. Failures are the sink's own problem: a sink that cannot
    /// write MUST NOT fail the request, because refusing to serve a verified request
    /// over a logging fault would convert an observability outage into a
    /// availability outage.
    fn record(&self, record: &AuditRecord);
}

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
/// * **Every line carries a monotonic `seq`**, assigned before the hand-off. A dropped
///   record is then a numbered hole in the stream, so which decisions are missing is
///   readable from the surviving records rather than inferred from an aggregate.
/// * **An unattributed record cannot consume the whole queue.** The flood an
///   unauthenticated peer can produce is by construction unattributed — no actor was
///   resolved — so those records are admitted only while the queue is below
///   [`STDERR_AUDIT_UNATTRIBUTED_CEILING`]. The remaining depth is reachable only by a
///   record naming a verifier-resolved actor, which is what stops a preflight flood from
///   evicting the decisions an attacker wants unrecorded.
/// * **The drop count is reported on a timer**, not only by the next record. A burst that
///   ends in silence still says so.
///
/// What none of that changes: records still in the queue at process exit are lost unless
/// the shutdown path calls [`flush_stderr_audit`].
#[derive(Debug, Default)]
pub struct StderrAuditSink;

/// Bounded hand-off depth. Deep enough to absorb a burst while the writer is inside one
/// `write` syscall, shallow enough that a stalled writer costs bounded memory.
const STDERR_AUDIT_QUEUE_DEPTH: usize = 4096;

/// How much of the queue a record with no verifier-resolved actor may occupy.
///
/// `record` is reached from the preflight rejection path, so an unauthenticated peer sets
/// the rate of unattributed records and nothing else. Letting them fill the queue would
/// hand that peer the choice of which OTHER decision is dropped — it floods, then does the
/// thing it wants unrecorded. Above this mark an unattributed record is dropped in favour
/// of headroom that only an attributed one can use.
const STDERR_AUDIT_UNATTRIBUTED_CEILING: usize = 3 * STDERR_AUDIT_QUEUE_DEPTH / 4;

/// How long the writer waits for a record before reporting drops it already knows about.
const STDERR_AUDIT_DROP_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// One item on the hand-off queue.
enum AuditMessage {
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
static STDERR_AUDIT_WRITER: std::sync::OnceLock<std::sync::mpsc::SyncSender<AuditMessage>> =
    std::sync::OnceLock::new();

/// Records that never reached the writer because the queue was full.
static STDERR_AUDIT_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Lines handed over and not yet written, so admission can reserve headroom. A
/// `sync_channel` does not expose its occupancy, and the reservation needs it.
static STDERR_AUDIT_QUEUED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The sequence number of the next record, so a drop is a visible hole.
static STDERR_AUDIT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn stderr_audit_writer() -> &'static std::sync::mpsc::SyncSender<AuditMessage> {
    STDERR_AUDIT_WRITER.get_or_init(|| {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<AuditMessage>(STDERR_AUDIT_QUEUE_DEPTH);
        // A detached thread: it lives as long as the process, and the sink it drains for
        // is a `static`. Errors from the write are swallowed — a sink that cannot write
        // must not fail a request, and there is nowhere else to report them.
        let _ = std::thread::Builder::new()
            .name("mcp-re-audit".to_owned())
            .spawn(move || {
                use std::io::Write;
                loop {
                    let message = match receiver.recv_timeout(STDERR_AUDIT_DROP_REPORT_INTERVAL) {
                        Ok(message) => Some(message),
                        // Nothing arrived. A burst that stopped must still report the
                        // records it cost, or the stream ends in a silence that reads
                        // exactly like no traffic at all.
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                    };
                    let line = match message {
                        Some(AuditMessage::Line(line)) => {
                            STDERR_AUDIT_QUEUED.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                            Some(line)
                        }
                        Some(AuditMessage::Flush(ack)) => {
                            report_drops(&mut std::io::stderr().lock(), &STDERR_AUDIT_DROPPED);
                            let _ = ack.try_send(());
                            continue;
                        }
                        None => None,
                    };
                    let mut stderr = std::io::stderr().lock();
                    report_drops(&mut stderr, &STDERR_AUDIT_DROPPED);
                    if let Some(line) = line {
                        let _ = stderr.write_all(line.as_bytes());
                        let _ = stderr.write_all(b"\n");
                    }
                }
            });
        sender
    })
}

/// Emit the outstanding drop count, if any.
fn report_drops(stderr: &mut impl std::io::Write, counter: &std::sync::atomic::AtomicU64) {
    let dropped = counter.swap(0, std::sync::atomic::Ordering::Relaxed);
    if dropped > 0 {
        let _ = writeln!(
            stderr,
            "mcp-re-proxy: audit dropped={dropped} (the audit hand-off queue was full; \
             that many decisions are missing from this stream, and their seq numbers are \
             the gaps in it)"
        );
    }
}

/// Write out everything already handed to the stderr audit writer, then return.
///
/// The writer thread is detached and cannot be joined, so a process that exits with
/// records still queued loses them silently — a shutdown under load drops precisely the
/// decisions taken last. A shutdown path calls this to make the drain happen; it gives up
/// after `timeout` rather than letting a stalled log collector hold the process open,
/// returning whether the drain was acknowledged.
pub fn flush_stderr_audit(timeout: std::time::Duration) -> bool {
    let Some(queue) = STDERR_AUDIT_WRITER.get() else {
        // Nothing ever recorded, so there is nothing to drain.
        return true;
    };
    let (ack, acked) = std::sync::mpsc::sync_channel(1);
    if queue.try_send(AuditMessage::Flush(ack)).is_err() {
        return false;
    }
    acked.recv_timeout(timeout).is_ok()
}

impl AuditSink for StderrAuditSink {
    fn record(&self, record: &AuditRecord) {
        let seq = STDERR_AUDIT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Each authority renders its own fields (`AuditSubject::audit_fields`); this sink
        // formats only the ones every record shares. A sink that interpreted the
        // authorization coordinate would be a third place the two vocabularies could merge.
        let line = format!(
            "mcp-re-proxy: audit seq={} event={} decision={:?} reason={} actor={} \
             status={} at={} {}",
            seq,
            record.event().event_type,
            record.event().decision,
            record.event().reason.unwrap_or("-"),
            record.actor_id.as_deref().unwrap_or("-"),
            record.status,
            record.at_unix,
            record.subject.audit_fields(),
        );
        offer(
            stderr_audit_writer(),
            &STDERR_AUDIT_DROPPED,
            &STDERR_AUDIT_QUEUED,
            line,
            admission_ceiling(record.actor_id.is_some()),
        );
    }
}

/// The queue depth a record of this attribution may be admitted at.
fn admission_ceiling(attributed: bool) -> usize {
    if attributed {
        STDERR_AUDIT_QUEUE_DEPTH
    } else {
        STDERR_AUDIT_UNATTRIBUTED_CEILING
    }
}

/// Claim one slot below `ceiling`, reporting whether the claim succeeded.
///
/// The test and the claim are ONE atomic step. Every core of the fleet offers into these
/// same statics concurrently, and the rate of unattributed offers is set by an
/// unauthenticated peer; a separate test-then-increment would let any number of those
/// offers observe the same sub-ceiling depth and all proceed, so the ceiling would bound
/// nothing but a single-threaded run.
fn reserve_slot(queued: &std::sync::atomic::AtomicUsize, ceiling: usize) -> bool {
    queued
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |current| (current < ceiling).then_some(current + 1),
        )
        .is_ok()
}

/// Hand one line to a writer, counting it as dropped rather than waiting for room.
///
/// Never blocks and never fails the caller: this is called on the request path, and a
/// full queue means the audit stream has a gap — not that the request must stall or be
/// refused. `ceiling` is how much of the queue this line's attribution class may take;
/// past it the line is dropped even though the channel would still accept it, which is
/// what keeps an unauthenticated flood from choosing whose record is lost. The slot is
/// reserved before the send and released if the send fails, so the reservation counts
/// exactly what is on the queue.
fn offer(
    queue: &std::sync::mpsc::SyncSender<AuditMessage>,
    dropped: &std::sync::atomic::AtomicU64,
    queued: &std::sync::atomic::AtomicUsize,
    line: String,
    ceiling: usize,
) {
    if !reserve_slot(queued, ceiling) {
        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    }
    if queue.try_send(AuditMessage::Line(line)).is_err() {
        queued.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A sink that records nothing. The explicit no-audit posture, so a deployment states
/// it rather than getting it by omission.
#[derive(Debug, Default)]
pub struct NoAuditSink;

impl AuditSink for NoAuditSink {
    fn record(&self, _record: &AuditRecord) {}
}

/// A test/embedding sink that retains every record in memory.
#[derive(Debug, Default)]
pub struct CollectingAuditSink {
    records: std::sync::Mutex<Vec<AuditRecord>>,
}

impl CollectingAuditSink {
    /// A fresh, empty collector.
    pub fn new() -> Self {
        CollectingAuditSink::default()
    }

    /// Every record observed so far, in emission order.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

impl AuditSink for CollectingAuditSink {
    fn record(&self, record: &AuditRecord) {
        if let Ok(mut records) = self.records.lock() {
            records.push(record.clone());
        }
    }
}

/// The installed audit sink, or `None` for no emission.
pub type MaybeAuditSink = Option<Arc<dyn AuditSink>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_record::AuditSubject;
    use crate::authorization::AuthorizationFacet;
    use crate::authorization::AuthorizationRefusalFacet;
    use mcp_re_core::audit::AuditEvent;

    #[test]
    fn the_collector_preserves_emission_order() {
        let sink = CollectingAuditSink::new();
        sink.record(&AuditRecord {
            subject: AuditSubject::request(
                AuditEvent::request_accepted(),
                AuthorizationFacet::NotConfigured,
            ),
            actor_id: Some("actor-a".into()),
            status: 200,
            at_unix: 10,
        });
        sink.record(&AuditRecord {
            subject: AuditSubject::request(
                AuditEvent::request_rejected_code("mcp-re.replay_detected"),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
            ),
            actor_id: None,
            status: 403,
            at_unix: 11,
        });
        let records = sink.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].event().event_type, "mcp-re.request.accepted");
        assert_eq!(records[1].event().reason, Some("mcp-re.replay_detected"));
    }

    /// R7-C145: the emission must never wait on the reader. `record` is reached from
    /// the preflight rejection path, so an unauthenticated peer sets its rate; a
    /// stalled log collector would otherwise stall the serving core inside the request
    /// future.
    #[test]
    fn a_full_audit_queue_drops_rather_than_blocking_the_caller() {
        let (queue, held) = std::sync::mpsc::sync_channel::<AuditMessage>(1);
        let dropped = std::sync::atomic::AtomicU64::new(0);
        let queued = std::sync::atomic::AtomicUsize::new(0);

        // Nothing ever receives from `held`, so after one line the queue is full.
        for i in 0..1000 {
            offer(&queue, &dropped, &queued, format!("line {i}"), 1024);
        }

        assert_eq!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            999,
            "every line past the queue's capacity is dropped and counted, not queued"
        );
        drop(held);
    }

    /// R8-C100: an unattributed flood must not be able to evict an attributed decision.
    ///
    /// `record` is reached before any signature verifies, so an unauthenticated peer sets
    /// the rate of records carrying no resolved actor — and if those could fill the
    /// queue, the peer would choose which OTHER decision goes unrecorded: flood, then do
    /// the thing you want missing from the stream. The headroom above the unattributed
    /// ceiling is reachable only by a record naming a verifier-resolved actor.
    #[test]
    fn an_unattributed_flood_cannot_consume_the_headroom_an_attributed_record_needs() {
        let depth = 64;
        let ceiling = 3 * depth / 4;
        let (queue, held) = std::sync::mpsc::sync_channel::<AuditMessage>(depth);
        let dropped = std::sync::atomic::AtomicU64::new(0);
        let queued = std::sync::atomic::AtomicUsize::new(0);

        // The flood: nothing drains, so it runs the queue up to its own ceiling.
        for i in 0..10_000 {
            offer(
                &queue,
                &dropped,
                &queued,
                format!("unattributed {i}"),
                ceiling,
            );
        }
        assert_eq!(
            queued.load(std::sync::atomic::Ordering::SeqCst),
            ceiling,
            "an unattributed record must stop at its ceiling, not at the channel's"
        );

        // The decision the attacker wants unrecorded still has somewhere to go.
        let before = dropped.load(std::sync::atomic::Ordering::SeqCst);
        for i in 0..(depth - ceiling) {
            offer(&queue, &dropped, &queued, format!("attributed {i}"), depth);
        }
        assert_eq!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "a flood of unauthenticated records dropped an attributed decision"
        );
        drop(held);
    }

    /// Concurrent offers may not carry the depth past the ceiling.
    ///
    /// Every core of the fleet offers into one set of statics, and an unauthenticated peer
    /// sets the rate of the unattributed ones. If admission tested the depth and then
    /// increased it as two steps, all the offers racing at the mark would observe the same
    /// sub-ceiling value and all proceed, so the headroom the ceiling reserves for an
    /// attributed decision would shrink by however many callers an attacker can run at
    /// once.
    #[test]
    fn concurrent_offers_at_the_ceiling_admit_only_the_remaining_slots() {
        const CONTENDERS: usize = 16;
        let ceiling = 8;

        for _ in 0..300 {
            // Nothing drains, and the channel is wide enough to accept every contender —
            // so the ceiling is the only thing that can bound the depth.
            let (queue, held) = std::sync::mpsc::sync_channel::<AuditMessage>(1024);
            let dropped = std::sync::atomic::AtomicU64::new(0);
            let queued = std::sync::atomic::AtomicUsize::new(ceiling - 1);
            let start = std::sync::Barrier::new(CONTENDERS);

            std::thread::scope(|scope| {
                for _ in 0..CONTENDERS {
                    scope.spawn(|| {
                        start.wait();
                        offer(
                            &queue,
                            &dropped,
                            &queued,
                            "unattributed".to_owned(),
                            ceiling,
                        );
                    });
                }
            });

            assert_eq!(
                queued.load(std::sync::atomic::Ordering::SeqCst),
                ceiling,
                "one free slot admitted more than one concurrent offer"
            );
            assert_eq!(
                dropped.load(std::sync::atomic::Ordering::SeqCst),
                (CONTENDERS - 1) as u64,
                "every offer that found no slot must be counted as dropped"
            );
            drop(held);
        }
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
        report_drops(&mut sink, &dropped);
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

    /// A record carries a sequence number, so a dropped one is a numbered hole rather
    /// than an aggregate nobody can attribute.
    #[test]
    fn every_record_carries_a_sequence_number() {
        let first = STDERR_AUDIT_SEQ.load(std::sync::atomic::Ordering::SeqCst);
        StderrAuditSink.record(&AuditRecord {
            subject: AuditSubject::request(
                AuditEvent::request_accepted(),
                AuthorizationFacet::NotConfigured,
            ),
            actor_id: Some("actor-a".into()),
            status: 200,
            at_unix: 10,
        });
        StderrAuditSink.record(&AuditRecord {
            subject: AuditSubject::request(
                AuditEvent::request_rejected_code("mcp-re.replay_detected"),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
            ),
            actor_id: None,
            status: 403,
            at_unix: 11,
        });
        assert_eq!(
            STDERR_AUDIT_SEQ.load(std::sync::atomic::Ordering::SeqCst),
            first + 2,
            "each record takes the next number, whether or not it survives the queue"
        );
        assert!(
            flush_stderr_audit(std::time::Duration::from_secs(5)),
            "a queued record must be drainable at shutdown rather than lost with the \
             detached writer"
        );
    }

    #[test]
    fn the_no_audit_sink_records_nothing_and_does_not_panic() {
        NoAuditSink.record(&AuditRecord {
            subject: AuditSubject::response(AuditEvent::response_signed()),
            actor_id: None,
            status: 200,
            at_unix: 1,
        });
    }
}
