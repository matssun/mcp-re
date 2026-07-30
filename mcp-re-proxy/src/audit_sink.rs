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

use mcp_re_core::audit::AuditEvent;

/// One audit record: the frozen event plus the attribution context the serving path
/// knows at that exit.
///
/// `actor_id` is the VERIFIER-RESOLVED actor for an accepted request (the same value
/// the continuation key is domain-separated by), and `None` when the request was
/// rejected before an actor could be resolved — which is itself the useful signal, so
/// it is represented rather than defaulted to a placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The frozen event (type + decision + `mcp-re.*` reason for a rejection).
    pub event: AuditEvent,
    /// The verifier-resolved actor id, when one was established before this exit.
    pub actor_id: Option<String>,
    /// The HTTP status the PEP returned alongside this decision.
    pub status: u16,
    /// Unix seconds at the decision, taken from the serving path's clock (never a
    /// second, independently-read clock — two clocks would let the record disagree
    /// with the freshness decision it describes).
    pub at_unix: i64,
}

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
#[derive(Debug, Default)]
pub struct StderrAuditSink;

impl AuditSink for StderrAuditSink {
    fn record(&self, record: &AuditRecord) {
        eprintln!(
            "mcp-re-proxy: audit event={} decision={:?} reason={} actor={} status={} at={}",
            record.event.event_type,
            record.event.decision,
            record.event.reason.unwrap_or("-"),
            record.actor_id.as_deref().unwrap_or("-"),
            record.status,
            record.at_unix,
        );
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

    #[test]
    fn the_collector_preserves_emission_order() {
        let sink = CollectingAuditSink::new();
        sink.record(&AuditRecord {
            event: AuditEvent::request_accepted(),
            actor_id: Some("actor-a".into()),
            status: 200,
            at_unix: 10,
        });
        sink.record(&AuditRecord {
            event: AuditEvent::request_rejected_code("mcp-re.replay_detected"),
            actor_id: None,
            status: 403,
            at_unix: 11,
        });
        let records = sink.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].event.event_type, "mcp-re.request.accepted");
        assert_eq!(records[1].event.reason, Some("mcp-re.replay_detected"));
    }

    #[test]
    fn the_no_audit_sink_records_nothing_and_does_not_panic() {
        NoAuditSink.record(&AuditRecord {
            event: AuditEvent::response_signed(),
            actor_id: None,
            status: 200,
            at_unix: 1,
        });
    }
}
