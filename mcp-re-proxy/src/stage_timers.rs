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
    /// Scheduler latency: how long a freshly spawned task waited before it was first
    /// polled. See [`probe_scheduler`].
    SchedulerLatency = 6,
    /// RFC 9421 request verification (inside `Handler`). Contains no `await`, so its
    /// wall time IS CPU time — which is the point: it measures what the per-core thread
    /// is actually spending, rather than what it is waiting for.
    Verify = 7,
    /// Signing the response (inside `Handler`). No `await` either, same reasoning.
    Sign = 8,
    /// Our own work before the store is touched: composite key, skew fold, connection
    /// checkout. No I/O, so this isolates the caller-side cost from the round trip.
    ReplayPrep = 9,
    /// The `SET NX PX` round trip alone (inside `ReplayInsert`).
    ReplaySet = 10,
    /// The `WAIT <quorum> <timeout>` round trip alone (inside `ReplayInsert`).
    ReplayWait = 11,
}

const STAGES: usize = 12;
const NAMES: [&str; STAGES] = [
    "admission",
    "body_read",
    "handler",
    "replay_insert",
    "inner_dispatch",
    "total",
    "scheduler_latency",
    "verify",
    "sign",
    "replay_prep",
    "replay_set",
    "replay_wait",
];

/// How often the snapshot is rewritten, in completed requests.
const REPORT_EVERY_N_REQUESTS: u64 = 5000;

struct Acc {
    nanos: [AtomicU64; STAGES],
    count: [AtomicU64; STAGES],
    reported: AtomicU64,
    /// Replay calls currently between entry and exit.
    inflight: AtomicU64,
    /// Sum of the occupancy observed on entry, and how many entries — their ratio is
    /// the mean concurrency actually reaching the store.
    inflight_sum: AtomicU64,
    inflight_samples: AtomicU64,
    inflight_max: AtomicU64,
}

/// Counts replay calls in flight, so the store's OFFERED concurrency is measured rather
/// than inferred.
///
/// Reading throughput back through the store's own latency curve suggested the proxy has
/// only ~8-10 requests at the store while holding 768 connections. That is an inference
/// from two separate measurements and it deserves a direct one: either the requests are
/// held up before they reach the store, or they are all there and the store behaves
/// differently inside the proxy than in the bench. This distinguishes those.
pub struct InFlight(bool);

impl InFlight {
    pub fn enter() -> Self {
        if !enabled() {
            return InFlight(false);
        }
        let a = acc();
        let now = a.inflight.fetch_add(1, Ordering::Relaxed) + 1;
        a.inflight_sum.fetch_add(now, Ordering::Relaxed);
        a.inflight_samples.fetch_add(1, Ordering::Relaxed);
        a.inflight_max.fetch_max(now, Ordering::Relaxed);
        InFlight(true)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.0 {
            acc().inflight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn acc() -> &'static Acc {
    static ACC: OnceLock<Acc> = OnceLock::new();
    ACC.get_or_init(|| Acc {
        nanos: std::array::from_fn(|_| AtomicU64::new(0)),
        count: std::array::from_fn(|_| AtomicU64::new(0)),
        reported: AtomicU64::new(0),
        inflight: AtomicU64::new(0),
        inflight_sum: AtomicU64::new(0),
        inflight_samples: AtomicU64::new(0),
        inflight_max: AtomicU64::new(0),
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

/// Measure how long this runtime takes to first poll a freshly spawned task, and record
/// it under [`Stage::SchedulerLatency`].
///
/// The other stages bracket spans, and one of those spans —
/// [`Stage::ReplayInsert`] — contains the only awaited I/O a request performs. So every
/// scheduling delay in the process lands there and is indistinguishable from store work.
/// Measuring the store separately showed it sustains more than 30x the proxy's
/// throughput, which means most of that span is a task waiting to be polled rather than
/// a store waiting to answer.
///
/// This probe measures the wait directly. Spawned from the serving path itself, so it
/// queues behind exactly the work a request queues behind: a large value here means the
/// runtime's workers are not getting to their tasks, and a small one means the time is
/// being spent somewhere the timers do not yet bracket.
///
/// One probe per `every` requests — the probe is itself a task, so probing every request
/// would measure a runtime perturbed by the measurement.
pub fn probe_scheduler(every: u64) {
    if !enabled() {
        return;
    }
    let a = acc();
    if !a.count[Stage::Total as usize]
        .load(Ordering::Relaxed)
        .is_multiple_of(every.max(1))
    {
        return;
    }
    let spawned_at = Instant::now();
    tokio::spawn(async move {
        let waited = spawned_at.elapsed();
        let a = acc();
        let i = Stage::SchedulerLatency as usize;
        a.nanos[i].fetch_add(waited.as_nanos() as u64, Ordering::Relaxed);
        a.count[i].fetch_add(1, Ordering::Relaxed);
    });
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

/// Write the snapshot now. The periodic rewrite is driven by [`Stage::Total`], which only
/// the serving path records — a caller that exercises the store directly (the store bench)
/// has no `Total` and would otherwise never emit a report.
pub fn report() {
    if enabled() {
        write_report();
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
    // Occupancy, not a duration: the mean_us column carries the MEAN concurrency and the
    // total_ms column the MAX, so the row fits the same CSV without a second format.
    let samples = a.inflight_samples.load(Ordering::Relaxed);
    let mean_inflight = if samples > 0 {
        a.inflight_sum.load(Ordering::Relaxed) as f64 / samples as f64
    } else {
        0.0
    };
    out.push_str(&format!(
        "replay_inflight,{},{},{:.1}\n",
        samples,
        a.inflight_max.load(Ordering::Relaxed),
        mean_inflight
    ));
    let _ = std::fs::write(path, out);
}
#[cfg(test)]
mod tests {
    // This module is the file's test region: `scripts/module_size_gate.py` opens it at the
    // `#[cfg(test)]` above and stops counting production lines here. The note lives INSIDE
    // the region rather than above it, because a comment above the marker is a production
    // line, and this file is registered in `config/module-size-debt.toml` — where the
    // ratchet only turns one way.
    use super::*;

    /// Every [`Stage`]. Declared INSIDE the test module on purpose: a `#[cfg(test)]` item
    /// at file scope opens a region `scripts/module_size_gate.py` reads to the end of the
    /// file, which silently removed 24 production lines from this file's measurement.
    const ALL_STAGES: [Stage; STAGES] = [
        Stage::Admission,
        Stage::BodyRead,
        Stage::Handler,
        Stage::ReplayInsert,
        Stage::InnerDispatch,
        Stage::Total,
        Stage::SchedulerLatency,
        Stage::Verify,
        Stage::Sign,
        Stage::ReplayPrep,
        Stage::ReplaySet,
        Stage::ReplayWait,
    ];

    /// Every [`Stage`] is a valid index into the parallel arrays.
    ///
    /// The discriminants are written by hand and used directly as subscripts into
    /// `nanos`, `count` and `NAMES`. A variant added without widening `STAGES` would
    /// index out of bounds on the serving path; one added with a duplicate discriminant
    /// would silently add its time to another stage's total.
    #[test]
    fn every_stage_indexes_within_the_accumulator() {
        for stage in ALL_STAGES {
            assert!(
                (stage as usize) < STAGES,
                "{stage:?} indexes past the accumulator"
            );
        }
    }

    /// The discriminants are dense and distinct: each stage owns exactly one slot.
    ///
    /// Two stages sharing a slot would fold two measurements into one column, and the
    /// report would read as a plausible number rather than as an error.
    #[test]
    fn stage_discriminants_are_distinct_and_cover_every_slot() {
        let mut seen = [false; STAGES];
        for stage in ALL_STAGES {
            let i = stage as usize;
            assert!(!seen[i], "{stage:?} shares slot {i} with another stage");
            seen[i] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "a report column has no stage writing to it"
        );
    }

    /// The name table is exactly as wide as the slot count it labels.
    ///
    /// `write_report` walks `NAMES` and subscripts the accumulators with the same index,
    /// so a short table would silently drop the last stages from every report.
    #[test]
    fn the_name_table_covers_every_slot() {
        assert_eq!(NAMES.len(), STAGES);
    }

    /// Each stage's slot carries that stage's name. The mapping is positional, so a
    /// reordering of either list mis-attributes every row after it.
    #[test]
    fn each_stage_slot_carries_its_own_name() {
        assert_eq!(NAMES[Stage::Admission as usize], "admission");
        assert_eq!(NAMES[Stage::BodyRead as usize], "body_read");
        assert_eq!(NAMES[Stage::Handler as usize], "handler");
        assert_eq!(NAMES[Stage::ReplayInsert as usize], "replay_insert");
        assert_eq!(NAMES[Stage::InnerDispatch as usize], "inner_dispatch");
        assert_eq!(NAMES[Stage::Total as usize], "total");
        assert_eq!(NAMES[Stage::SchedulerLatency as usize], "scheduler_latency");
        assert_eq!(NAMES[Stage::Verify as usize], "verify");
        assert_eq!(NAMES[Stage::Sign as usize], "sign");
        assert_eq!(NAMES[Stage::ReplayPrep as usize], "replay_prep");
        assert_eq!(NAMES[Stage::ReplaySet as usize], "replay_set");
        assert_eq!(NAMES[Stage::ReplayWait as usize], "replay_wait");
    }

    /// With timing off, a timer takes no clock reading at all.
    ///
    /// The module's whole claim is that the off path costs one relaxed atomic load per
    /// stage. `started` staying `None` is what makes that true, and it is also what keeps
    /// `Drop` from recording into a report nobody asked for. This asserts the state, not
    /// a duration, because a duration would measure the machine.
    #[test]
    fn a_timer_started_while_disabled_reads_no_clock() {
        if enabled() {
            return; // MCP_RE_STAGE_TIMERS is set in this process; the off path is not under test.
        }
        assert!(Timed::start(Stage::Total).started.is_none());
    }

    /// With timing off, the in-flight counter is never entered — so `Drop` has nothing to
    /// decrement, and the occupancy gauge cannot be driven negative by an unbalanced
    /// pair. The guard carries the flag that makes its own drop a no-op.
    #[test]
    fn an_inflight_guard_taken_while_disabled_is_inert() {
        if enabled() {
            return;
        }
        assert!(!InFlight::enter().0);
    }

    /// The rewrite period is non-zero, checked at COMPILE time.
    ///
    /// `Drop` calls `is_multiple_of(REPORT_EVERY_N_REQUESTS)` on every completed request,
    /// and zero would make that a division by zero on the serving path — a panic in a
    /// diagnostic that is supposed to be free when off and harmless when on. A `const`
    /// block states it where a runtime assert could only observe it: the build fails
    /// rather than the test.
    #[test]
    fn the_rewrite_period_cannot_divide_by_zero() {
        const { assert!(REPORT_EVERY_N_REQUESTS > 0) }
    }
}
