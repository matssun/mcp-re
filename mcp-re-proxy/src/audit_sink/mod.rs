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
//! protocol stream and never as MCP content. This is the normative security record
//! documented in `docs/spec/security-boundary.md` S9.

/// Discharging the writer's teardown obligation at shutdown, and saying which of the two
/// things happened. Holds the bound, the wait, and the outcome — they are one authority.
pub(crate) mod drain;

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

/// The default sink: one line per decision on stderr.
mod stderr;

pub use stderr::StderrAuditSink;

/// This process's run and the position of each record within it.
mod stream;

/// What the writer thread does with a line, and what it can truthfully say afterwards.
mod writer;

use writer::{AuditMessage, STDERR_AUDIT_WRITER};

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

/// The queue depth a record may be admitted at, decided from the record's OWN attribution
/// — so the mapping is a fact a control can drive, not one a call site supplies.
fn admission_ceiling(record: &AuditRecord) -> usize {
    if record.actor_id.is_some() {
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
            |current| (current < ceiling).then(|| current.saturating_add(1)),
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

/// A harness sink, not a deployment one: it retains every record in memory, unbounded and
/// sized by request rate (including rejections an unauthenticated peer drives), with each
/// resolved `actor_id` unredacted for the sink's life. Nothing is evicted.
#[derive(Debug, Default)]
pub struct CollectingAuditSink {
    records: std::sync::Mutex<Vec<AuditRecord>>,
}

impl CollectingAuditSink {
    /// A fresh, empty collector.
    pub fn new() -> Self {
        CollectingAuditSink::default()
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, Vec<AuditRecord>> {
        let locked = self.records.lock();
        locked.unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every record observed so far, in emission order.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.guard().clone()
    }
}

impl AuditSink for CollectingAuditSink {
    fn record(&self, record: &AuditRecord) {
        self.guard().push(record.clone());
    }
}

/// The installed audit sink, or `None` for no emission: the one representation of audit
/// off, which a deployment states as an OFF posture line rather than as a sink.
pub type MaybeAuditSink = Option<Arc<dyn AuditSink>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_enforcer::AdmissionFacet;
    use crate::audit_record::text::{render_record, AuditField};
    use crate::audit_record::AuditSubject;
    use crate::authorization::AuthorizationFacet;
    use crate::authorization::AuthorizationRefusalFacet;

    /// One record is one line, whatever the resolved actor's identity contains.
    ///
    /// Asserted on the line handed to `offer` rather than on captured stderr, because
    /// `record` hands off to a detached process-global writer: capturing the other end would
    /// measure the writer's scheduling, not this claim.
    #[test]
    fn one_record_writes_exactly_one_line_for_any_actor_id() {
        let record = AuditRecord {
            subject: AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                AdmissionFacet::NotConfigured,
            ),
            actor_id: Some("client:example.com:a\nmcp-re-proxy: audit seq=8 status=200".into()),
            status: 200,
            at_unix: 10,
        };
        let mut fields = vec![AuditField::number("seq", 7)];
        fields.extend(record.audit_fields());
        let line = render_record(&fields);

        assert!(!line.contains('\n'), "{line}");
        assert!(!line.contains('\r'), "{line}");
        // `write_all(line)` + `write_all(b"\n")` therefore emits exactly one record, and the
        // forged `status=200` is inside the actor's value rather than beside it.
        assert_eq!(line.matches("status=").count(), 1, "{line}");
    }

    #[test]
    fn a_poisoned_collector_still_records_and_reports_what_it_holds() {
        let sink = CollectingAuditSink::new();
        let record = AuditRecord {
            subject: AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                AdmissionFacet::NotConfigured,
            ),
            actor_id: None,
            status: 200,
            at_unix: 1,
        };
        sink.record(&record);
        let joined = std::thread::scope(|s| {
            s.spawn(|| {
                let _guard = sink.records.lock();
                panic!("poison the collector");
            })
            .join()
        });
        assert!(joined.is_err());
        assert!(sink.records.is_poisoned());
        sink.record(&record);
        assert_eq!(sink.records().len(), 2);
    }

    #[test]
    fn the_collector_preserves_emission_order() {
        let sink = CollectingAuditSink::new();
        sink.record(&AuditRecord {
            subject: AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                AdmissionFacet::NotConfigured,
            ),
            actor_id: Some("actor-a".into()),
            status: 200,
            at_unix: 10,
        });
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
        let records = sink.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].event().event_type(), "mcp-re.request.accepted");
        assert_eq!(records[1].event().reason(), Some("mcp-re.replay_detected"));
    }

    /// A record's ATTRIBUTION is what chooses its ceiling, and the unattributed one is
    /// strictly lower.
    ///
    /// The property `STDERR_AUDIT_UNATTRIBUTED_CEILING` exists for, measured where it is
    /// decided. The neighbouring flood control builds its own channel, its own counters and
    /// passes `ceiling` by hand, so it establishes that `offer` respects a ceiling it was
    /// GIVEN — and stays green under an implementation that hands every record the full
    /// depth. This drives the mapping from the record instead, which is the fact the
    /// unattributed reservation actually rests on.
    ///
    /// Both halves matter. Lower is the reservation; equal-to-the-depth for an attributed
    /// record is what makes the reserved headroom reachable by exactly the class it is held
    /// for, rather than the two simply being different numbers.
    #[test]
    fn the_ceiling_a_record_is_admitted_at_is_chosen_by_its_attribution() {
        let attributed = AuditRecord {
            subject: AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                AdmissionFacet::NotConfigured,
            ),
            actor_id: Some("client:example.com:a".into()),
            status: 200,
            at_unix: 10,
        };
        let unattributed = AuditRecord {
            subject: AuditSubject::request_rejected(
                Some(&mcp_re_core::McpReError::ReplayDetected),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
                AdmissionFacet::NotConfigured,
            ),
            actor_id: None,
            status: 403,
            at_unix: 11,
        };
        assert_eq!(admission_ceiling(&attributed), STDERR_AUDIT_QUEUE_DEPTH);
        assert!(
            admission_ceiling(&unattributed) < admission_ceiling(&attributed),
            "an unattributed record must not be admitted at the attributed ceiling"
        );
        assert_eq!(
            admission_ceiling(&unattributed),
            STDERR_AUDIT_UNATTRIBUTED_CEILING
        );
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
}
