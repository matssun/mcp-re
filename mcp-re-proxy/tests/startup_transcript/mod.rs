// SPDX-License-Identifier: Apache-2.0
//! An ORDERED, NORMALIZED view of what the proxy reports while it starts up.
//!
//! ADR-MCPRE-056 restructures the composition root. To show that restructuring preserved
//! behaviour, the tests need something to compare — and today the only things `app::run`
//! makes observable are its `Result` and 35 `eprintln!` posture statements. Snapshotting
//! that prose would be self-defeating: the same ADR (§11) then moves those statements
//! into structured records and explicitly permits the wording to change.
//!
//! So this harness reads the real binary's stderr and normalizes it into
//! [`StartupEvent`]s. Tests assert on the events and their ORDER, never on the text.
//! Startup order carries meaning — trust is resolved before the replay tier is opened,
//! and a posture line that moved across that boundary would be a real change — so this
//! is a `Vec`, not a set, and duplicates are preserved.
//!
//! **The marker strings here are a test synchronization dependency, not a logging
//! contract.** They are recognized because they are today's observable behaviour. Once
//! the refactor produces structured decision/evidence records, tests move to those and
//! this normalization layer is deleted.
//!
//! **Observed from outside.** The harness spawns the shipped binary rather than calling
//! `app::run` in-process, so it witnesses the system across the restructuring without
//! being coupled to any internal seam the restructuring introduces.

#![allow(dead_code)] // each test binary uses a subset

use std::io::BufRead;
use std::io::BufReader;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

/// One normalized startup fact.
///
/// Deliberately LOSSY about anything unstable — bound ports, timestamps, temp paths,
/// generated ids, elapsed times — because none of those are the behaviour under test. A
/// value appears only where it is itself part of the claim (a declared tier, an
/// enforced mode, a configured bound).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupEvent {
    /// Host clock reads at/near the Unix epoch; freshness will fail closed.
    ClockFaultWarning,
    /// The dev/CI-only environment key source is in use.
    DevKeySourceWarning,
    /// Reverse-proxy identity ingress is enabled.
    ReverseProxyIdentityWarning,
    /// The declared revocation tier, and whether the trust store itself can change.
    RevocationTier {
        tier: String,
        store_change_bounded: bool,
    },
    /// Push tier configured with no networked event source; running at its fallback.
    PushTierNoEventSource,
    /// Whether `--trust` is re-read on a cadence.
    TrustReload { active: bool },
    /// The authoritative replay tier that was opened.
    ReplayTier { backend: String },
    /// Offline client-cert revocation: how many CRL files were loaded.
    CrlLoaded { files: usize },
    /// A loaded CRL is near its `nextUpdate`.
    CrlNearExpiryWarning,
    /// The structured `mcp-re.revocation.posture` line and its declared mode.
    RevocationPosture { mode: String },
    /// Fleet-wide cross-replica revocation-lag bounds were computed.
    FleetLagBounds,
    /// TLS handshake key custody.
    TlsCustody { delegated: bool },
    /// In-process CRL hot-reload, and whether it was actually scheduled.
    CrlReload { scheduled: bool },
    /// Online OCSP client-cert revocation is enabled.
    OcspEnabled,
    /// The inner-plane in-flight bound was raised to match the fleet ceiling.
    InFlightCeilingRaised,
    /// The shared trust-epoch watch is active for delegated minting.
    DelegatedEpochWatch,
    /// Response signing is delegated and the first key has been issued.
    ResponseSigningDelegated,
    /// The MCP transport contract is enforced.
    McpTransportContract,
    /// The RFC 9421 freshness gate's configured skew, in seconds.
    FreshnessGate { skew_secs: u64 },
    /// Where the per-request security record goes.
    AuditSink { mode: String },
    /// Whether accepted exchanges are retained.
    EvidenceRetention { enabled: bool },
    /// The PEP writes its own verified context into the forwarded body.
    VerifiedContextTrusted,
    /// Whether MRTR continuations are shared across replicas.
    ContinuationStore { shared: bool },
    /// The admission-currency gate's enforcement level.
    AdmissionCurrency { enforcement: String },
    /// The fleet bound its listener and is serving. Startup finished.
    FleetServing,
    /// The fleet drained cleanly after a stop signal.
    FleetDrained,
}

/// How a captured run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The process exited on its own. `refused` carries the final diagnostic line for a
    /// non-zero exit — the operator-visible reason startup was refused.
    Exited {
        success: bool,
        refused: Option<String>,
    },
    /// The proxy reached its serving state and was stopped by the harness.
    ServedThenStopped,
    /// Neither happened within the deadline.
    TimedOut,
}

/// One startup, as observed from outside the process.
#[derive(Debug, Clone)]
pub struct Transcript {
    /// Normalized events in emission order.
    pub events: Vec<StartupEvent>,
    pub outcome: Outcome,
    /// Every stderr line, kept for diagnosing an assertion failure. Never asserted on.
    pub raw: Vec<String>,
}

impl Transcript {
    /// Whether `event` appears at all.
    pub fn has(&self, event: &StartupEvent) -> bool {
        self.events.contains(event)
    }

    /// The index of the first occurrence of `event`.
    pub fn position_of(&self, event: &StartupEvent) -> Option<usize> {
        self.events.iter().position(|e| e == event)
    }

    /// Whether `first` is emitted before `second`. Both must be present.
    ///
    /// Order is the property most at risk in a restructuring that moves phases into
    /// separate materializers, so it gets a first-class assertion rather than being
    /// spelled out at every call site.
    pub fn emits_in_order(&self, first: &StartupEvent, second: &StartupEvent) -> bool {
        match (self.position_of(first), self.position_of(second)) {
            (Some(a), Some(b)) => a < b,
            _ => false,
        }
    }

    /// The raw transcript, for an assertion message.
    pub fn dump(&self) -> String {
        self.raw.join("\n")
    }
}

/// Deadline for one capture. Generous: a startup that binds and serves is quick, but a
/// freshly linked binary can spend seconds in the loader on a loaded machine.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(90);

/// Run the real `mcp-re-proxy` with `args` and normalize what it reports.
///
/// Handles both shapes of startup uniformly:
///
/// * a config that is REFUSED — the process exits by itself and the transcript ends
///   with [`Outcome::Exited`] carrying the refusal line;
/// * a config that SERVES — the process would run forever, so reaching the serving
///   marker triggers a `SIGTERM` and the drain is captured too.
///
/// `SIGTERM`, not `kill`: the drain path is part of the behaviour being characterized,
/// and `Child::kill` sends `SIGKILL`, which would skip it.
pub fn capture(args: &[String]) -> Transcript {
    let binary = mcp_re_test_paths::resolve_runfile("MCP_RE_PROXY_CLI");
    let mut child = Command::new(&binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", binary.display()));

    let stderr = child.stderr.take().expect("stderr is piped");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    // A reader thread: `read_line` on the child's pipe blocks, and the main thread has
    // to stay responsive enough to stop a proxy that has started serving.
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });

    let mut raw = Vec::new();
    let mut events = Vec::new();
    let mut stopped = false;
    let deadline = Instant::now() + CAPTURE_TIMEOUT;
    let outcome = loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break Outcome::TimedOut;
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if let Some(event) = normalize(&line) {
                    let serving = event == StartupEvent::FleetServing;
                    events.push(event);
                    // Startup is over; stop it so the drain is observed rather than the
                    // harness hanging on a process that will never exit.
                    if serving && !stopped {
                        stopped = true;
                        send_sigterm(&child);
                    }
                }
                raw.push(line);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            // The pipe closed: the child is done writing, so reap it.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let status = child.wait().expect("wait for the proxy");
                break if stopped {
                    Outcome::ServedThenStopped
                } else {
                    Outcome::Exited {
                        success: status.success(),
                        refused: raw.last().cloned(),
                    }
                };
            }
        }
    };

    Transcript {
        events,
        outcome,
        raw,
    }
}

/// Ask the proxy to shut down the way an orchestrator does.
fn send_sigterm(child: &std::process::Child) {
    // SAFETY: `kill(2)` with a pid this process owns and a valid signal number. The
    // child is still alive here — its stderr pipe has not closed — and the worst case
    // for a race is `ESRCH`, which is ignored.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

/// Map one stderr line to a normalized event, or `None` if it carries no startup fact.
///
/// Unknown lines are dropped rather than failing: the proxy also emits per-request audit
/// records and operational diagnostics on this channel, and a characterization harness
/// that broke whenever an unrelated line appeared would be worse than useless.
fn normalize(line: &str) -> Option<StartupEvent> {
    // The source wraps these strings across source lines, which leaves runs of spaces in
    // the output. Collapse first so the matching below is about content, not layout.
    let l = line.split_whitespace().collect::<Vec<_>>().join(" ");

    if l.contains("the system clock reads at/near the Unix epoch") {
        return Some(StartupEvent::ClockFaultWarning);
    }
    if l.contains("--key-source env is a dev/CI-only build") {
        return Some(StartupEvent::DevKeySourceWarning);
    }
    if l.contains("reverse-proxy identity mode is ENABLED") {
        return Some(StartupEvent::ReverseProxyIdentityWarning);
    }
    if l.contains("revocation-tier=") {
        return Some(StartupEvent::RevocationTier {
            tier: after(&l, "revocation-tier=")?
                .split_whitespace()
                .next()?
                .to_string(),
            // "NONE:" means the store itself never changes while the process runs.
            store_change_bounded: !l.contains("store-change-cadence=NONE"),
        });
    }
    if l.contains("revocation-tier PUSH has no networked event source") {
        return Some(StartupEvent::PushTierNoEventSource);
    }
    if l.contains("trust store reload ACTIVE") {
        return Some(StartupEvent::TrustReload { active: true });
    }
    if l.contains("trust store reload OFF") {
        return Some(StartupEvent::TrustReload { active: false });
    }
    if l.contains("replay tier = shared") {
        let backend = if l.contains("etcd") { "etcd" } else { "redis" };
        return Some(StartupEvent::ReplayTier {
            backend: backend.to_string(),
        });
    }
    if l.contains("offline client-cert revocation enabled") {
        return Some(StartupEvent::CrlLoaded {
            files: after(&l, "enabled — ")
                .and_then(|r| r.split_whitespace().next()?.parse().ok())
                .unwrap_or(0),
        });
    }
    if l.contains("is near expiry") {
        return Some(StartupEvent::CrlNearExpiryWarning);
    }
    if l.contains("mcp-re.revocation.posture") {
        return Some(StartupEvent::RevocationPosture {
            mode: after(&l, "revocation_mode=")
                .and_then(|r| r.split_whitespace().next())
                .unwrap_or("connection")
                .to_string(),
        });
    }
    if l.contains("cross-replica revocation-lag bounds") {
        return Some(StartupEvent::FleetLagBounds);
    }
    if l.contains("TLS custody = DELEGATED") {
        return Some(StartupEvent::TlsCustody { delegated: true });
    }
    if l.contains("in-process CRL hot-reload enabled") {
        return Some(StartupEvent::CrlReload { scheduled: true });
    }
    if l.contains("no --client-crl configured; no CRL reload scheduled") {
        return Some(StartupEvent::CrlReload { scheduled: false });
    }
    if l.contains("ONLINE OCSP client-cert revocation enabled") {
        return Some(StartupEvent::OcspEnabled);
    }
    if l.contains("inner-plane in-flight bound raised") {
        return Some(StartupEvent::InFlightCeilingRaised);
    }
    if l.contains("delegated trust-epoch watch ACTIVE") {
        return Some(StartupEvent::DelegatedEpochWatch);
    }
    if l.contains("response signing = DELEGATED") {
        return Some(StartupEvent::ResponseSigningDelegated);
    }
    if l.contains("MCP transport contract ENFORCED") {
        return Some(StartupEvent::McpTransportContract);
    }
    if l.contains("freshness gate = created-") {
        return Some(StartupEvent::FreshnessGate {
            skew_secs: after(&l, "created-")
                .and_then(|r| r.split('s').next()?.parse().ok())
                .unwrap_or(0),
        });
    }
    if l.contains("security audit record = ") {
        let mode = if l.contains("record = NONE") {
            "none"
        } else {
            "stderr"
        };
        return Some(StartupEvent::AuditSink {
            mode: mode.to_string(),
        });
    }
    if l.contains("evidence retention = ") {
        return Some(StartupEvent::EvidenceRetention {
            enabled: !l.contains("evidence retention = OFF"),
        });
    }
    if l.contains("verified-context carrier = TRUSTED") {
        return Some(StartupEvent::VerifiedContextTrusted);
    }
    if l.contains("MRTR continuation store = shared") {
        return Some(StartupEvent::ContinuationStore { shared: true });
    }
    if l.contains("MRTR continuation") && l.contains("OFF") {
        return Some(StartupEvent::ContinuationStore { shared: false });
    }
    if l.contains("admission currency = ") {
        let enforcement = if l.contains("= REQUIRED") {
            "required"
        } else {
            "optional"
        };
        return Some(StartupEvent::AdmissionCurrency {
            enforcement: enforcement.to_string(),
        });
    }
    if l.contains("async fleet serving on") {
        return Some(StartupEvent::FleetServing);
    }
    if l.contains("async fleet drained, exiting cleanly") {
        return Some(StartupEvent::FleetDrained);
    }
    None
}

/// The remainder of `haystack` after the first occurrence of `needle`.
fn after<'a>(haystack: &'a str, needle: &str) -> Option<&'a str> {
    haystack.find(needle).map(|i| &haystack[i + needle.len()..])
}
