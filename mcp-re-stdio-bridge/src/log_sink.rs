//! Inner-server lifecycle logging seam (MCPS-036) — the proxy's OWN diagnostic
//! channel for inner-server events.
//!
//! These types are transport-agnostic and belong to the PEP, not to any
//! particular inner transport. The async serving path (ADR-MCPRE-051) emits
//! [`InnerLogEvent::RequestForwarded`] / [`InnerLogEvent::ResponseSigned`] through
//! an [`InnerLogSink`] on every dispatch, so the sink seam stays in `mcp-re-proxy`
//! even though the stdio subprocess machinery (which also logged spawn/exit/stderr
//! events) has been relocated OUT of the PEP's trust boundary to
//! `mcp-re-stdio-bridge`. Emissions go to the proxy's diagnostic channel only —
//! never onto an inner server's stdout protocol stream and never as MCP content.

/// A structured inner-server lifecycle / hygiene event (MCPS-036).
///
/// The proxy emits these to its OWN diagnostic channel (never onto the inner
/// server's stdout protocol stream and never as MCP content). Each event is
/// tagged with the inner process / session identity so emissions from concurrent
/// or successive inner launches stay attributable. Captured stderr is BOUNDED
/// and structured, not safe-from-secrets: an inner server can write a secret to
/// its own stderr, so the capture is bounded blast-radius, not redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerLogEvent {
    /// The inner subprocess was spawned successfully (`pid` of the child).
    Spawned { pid: u32 },
    /// Spawning the inner subprocess failed (reason names no secret value).
    SpawnFailed { reason: String },
    /// The inner subprocess exited; `code` is the OS exit status code if known.
    Exited { code: Option<i32> },
    /// The proxy actively killed the inner subprocess.
    Killed { reason: String },
    /// Captured inner stderr hit the configured byte/line bound and was
    /// truncated; the dropped tail is NOT retained.
    StderrTruncated { captured_bytes: usize, cap_bytes: usize },
    /// The inner server's stdout could not be parsed as a JSON-RPC frame the
    /// proxy expects (the protocol stream was dirty).
    ProtocolError { detail: String },
    /// A verified request was forwarded to the inner server.
    RequestForwarded,
    /// A signed response was produced for the caller from an inner result.
    ResponseSigned,
}

impl InnerLogEvent {
    /// The stable event tag (the `inner_*` names from the issue / brief §13).
    pub fn tag(&self) -> &'static str {
        match self {
            InnerLogEvent::Spawned { .. } => "inner_spawned",
            InnerLogEvent::SpawnFailed { .. } => "inner_spawn_failed",
            InnerLogEvent::Exited { .. } => "inner_exited",
            InnerLogEvent::Killed { .. } => "inner_killed",
            InnerLogEvent::StderrTruncated { .. } => "inner_stderr_truncated",
            InnerLogEvent::ProtocolError { .. } => "inner_protocol_error",
            InnerLogEvent::RequestForwarded => "inner_request_forwarded",
            InnerLogEvent::ResponseSigned => "inner_response_signed",
        }
    }
}

/// A sink for [`InnerLogEvent`]s, tagged with the inner identity.
///
/// Injected so the lifecycle emissions are deterministically testable without
/// scraping the proxy's real stderr. The proxy's production sink writes a single
/// structured line per event to the proxy's OWN stderr (see
/// [`StderrLogSink`]) — this is the proxy's diagnostic channel, entirely
/// separate from the inner server's stdout protocol stream.
pub trait InnerLogSink {
    /// Record one lifecycle event for the inner identified by `inner_identity`.
    fn log(&self, inner_identity: &str, event: &InnerLogEvent);

    /// Record the BOUNDED captured stderr of one inner invocation. This is the
    /// destination for the inner server's stderr — it goes ONLY here (the proxy's
    /// structured log), never onto stdout (the protocol stream) and never into
    /// MCP content. The default writes one line to the proxy's stderr. Bounded is
    /// not secrets-safe: an inner server may write a secret here.
    fn log_stderr(&self, inner_identity: &str, captured: &[u8]) {
        eprintln!(
            "mcp-re-proxy: inner-stderr inner={inner_identity} {:?}",
            String::from_utf8_lossy(captured)
        );
    }
}

/// The production sink: one structured line per event on the PROXY's stderr.
///
/// This is the proxy's own diagnostic channel. It is intentionally distinct from
/// the inner server's stdout (the MCP protocol stream) and from the inner
/// server's captured stderr (the bounded log), so a lifecycle event can never be
/// mistaken for MCP content.
#[derive(Debug, Clone, Default)]
pub struct StderrLogSink;

impl InnerLogSink for StderrLogSink {
    fn log(&self, inner_identity: &str, event: &InnerLogEvent) {
        eprintln!("mcp-re-proxy: inner-event {} inner={inner_identity} {:?}", event.tag(), event);
    }
}

#[cfg(test)]
mod tests {
    use super::InnerLogEvent;

    #[test]
    fn log_event_tags_match_the_brief() {
        assert_eq!(InnerLogEvent::Spawned { pid: 1 }.tag(), "inner_spawned");
        assert_eq!(
            InnerLogEvent::SpawnFailed { reason: "x".into() }.tag(),
            "inner_spawn_failed"
        );
        assert_eq!(InnerLogEvent::Exited { code: Some(0) }.tag(), "inner_exited");
        assert_eq!(InnerLogEvent::Killed { reason: "x".into() }.tag(), "inner_killed");
        assert_eq!(
            InnerLogEvent::StderrTruncated { captured_bytes: 4, cap_bytes: 4 }.tag(),
            "inner_stderr_truncated"
        );
        assert_eq!(
            InnerLogEvent::ProtocolError { detail: "x".into() }.tag(),
            "inner_protocol_error"
        );
        assert_eq!(InnerLogEvent::RequestForwarded.tag(), "inner_request_forwarded");
        assert_eq!(InnerLogEvent::ResponseSigned.tag(), "inner_response_signed");
    }
}
