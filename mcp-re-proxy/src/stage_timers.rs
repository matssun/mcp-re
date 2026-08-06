// SPDX-License-Identifier: Apache-2.0
//! Per-stage timers for the async serving path.
//!
//! A CPU profiler answers "which code burns cycles". The serving path's problem is the
//! opposite: at saturation it uses ~1.3 of 8 cores while requests take tens of
//! milliseconds, so the time is spent WAITING and a sampling profiler shows almost
//! nothing at the wait sites. Worse, running one under load collapses throughput to a
//! third, which measures a different system than the one in question.
//!
//! These timers measure elapsed wall time around each stage instead, which is what a
//! wait actually is. They are off unless `MCP_RE_STAGE_TIMERS` names an output path, and
//! when off the cost is one relaxed atomic load per stage.
//!
//! Sums and counts only — no histogram. The question is where tens of milliseconds go,
//! and a mean over tens of thousands of requests answers that; percentiles would cost
//! per-request allocation on the path being measured.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;
use std::time::Instant;

/// The stages a request passes through, in order.
#[derive(Clone, Copy, Debug)]
pub enum Stage {
    /// Waiting for the per-core in-flight permit.
    Admission = 0,
    /// Reading the request body off the connection.
    BodyRead = 1,
    /// The whole handler: verify, replay admit, inner dispatch, sign.
    Handler = 2,
    /// The shared replay store round trip (inside `Handler`).
    ReplayInsert = 3,
    /// The HTTP call to the inner backend (inside `Handler`).
    InnerDispatch = 4,
    /// Everything from entry to response, including the stages above.
    Total = 5,
}

const STAGES: usize = 6;
const NAMES: [&str; STAGES] = [
    "admission",
    "body_read",
    "handler",
    "replay_insert",
    "inner_dispatch",
    "total",
];

/// How often the snapshot is rewritten, in completed requests.
const REPORT_EVERY_N_REQUESTS: u64 = 5000;

struct Acc {
    nanos: [AtomicU64; STAGES],
    count: [AtomicU64; STAGES],
    reported: AtomicU64,
}

fn acc() -> &'static Acc {
    static ACC: OnceLock<Acc> = OnceLock::new();
    ACC.get_or_init(|| Acc {
        nanos: std::array::from_fn(|_| AtomicU64::new(0)),
        count: std::array::from_fn(|_| AtomicU64::new(0)),
        reported: AtomicU64::new(0),
    })
}

/// `Some(path)` when timing is on. Read once; the hot path only sees an `AtomicBool`.
fn output_path() -> Option<&'static str> {
    static PATH: OnceLock<Option<String>> = OnceLock::new();
    PATH.get_or_init(|| {
        std::env::var("MCP_RE_STAGE_TIMERS")
            .ok()
            .filter(|p| !p.is_empty())
    })
    .as_deref()
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static INIT: OnceLock<()> = OnceLock::new();

/// Whether timing is on. Cheap enough to call per stage.
pub fn enabled() -> bool {
    INIT.get_or_init(|| {
        ENABLED.store(output_path().is_some(), Ordering::Relaxed);
    });
    ENABLED.load(Ordering::Relaxed)
}

/// A running stage timer. Dropping it records the elapsed time.
pub struct Timed {
    stage: Stage,
    started: Option<Instant>,
}

impl Timed {
    pub fn start(stage: Stage) -> Self {
        Self {
            stage,
            started: enabled().then(Instant::now),
        }
    }
}

impl Drop for Timed {
    fn drop(&mut self) {
        if let Some(t0) = self.started {
            let i = self.stage as usize;
            let a = acc();
            a.nanos[i].fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            a.count[i].fetch_add(1, Ordering::Relaxed);
            // Rewrite the report periodically. The proxy is killed by
            // the harness rather than shut down, so a report written only at exit would
            // never survive; rewriting the same path keeps the last snapshot readable.
            if matches!(self.stage, Stage::Total)
                && a.count[Stage::Total as usize]
                    .load(Ordering::Relaxed)
                    .is_multiple_of(REPORT_EVERY_N_REQUESTS)
            {
                write_report();
            }
        }
    }
}

fn write_report() {
    let Some(path) = output_path() else { return };
    let a = acc();
    a.reported.fetch_add(1, Ordering::Relaxed);
    let mut out = String::from("stage,count,total_ms,mean_us\n");
    for (i, name) in NAMES.iter().enumerate() {
        let n = a.count[i].load(Ordering::Relaxed);
        let ns = a.nanos[i].load(Ordering::Relaxed);
        let mean_us = if n > 0 {
            ns as f64 / n as f64 / 1000.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "{},{},{:.1},{:.1}\n",
            name,
            n,
            ns as f64 / 1e6,
            mean_us
        ));
    }
    let _ = std::fs::write(path, out);
}
