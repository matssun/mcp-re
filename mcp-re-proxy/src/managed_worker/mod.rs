// SPDX-License-Identifier: Apache-2.0
//! Owned background workers (ADR-MCPRE-056 §9).
//!
//! No startup phase may spawn a long-lived thread whose lifetime is not represented by
//! an owned value returned from that phase. A bare `std::thread::spawn(..)` whose
//! `JoinHandle` is dropped is not acceptable for runtime-owned work: the thread outlives
//! every value it was conceptually part of, and nothing can stop it or observe that it
//! stopped.
//!
//! That is not hypothetical here. The trust reloader, the CRL reloader and the delegated
//! rotor were each spawned detached and each loop on the CALLER's shutdown flag — the one
//! wired to SIGTERM. Startup sets that flag on no error path, so a `run` that failed
//! after the first spawn returned `Err` while its workers kept reading files and minting
//! keys. In-process callers (tests, harnesses, embedders) accumulated them for the
//! lifetime of the process.
//!
//! # What [`WorkerSet`] guarantees
//!
//! Precisely, and no more than this:
//!
//! 1. **Structural halt is raised for every owned worker.** Unconditional.
//! 2. **Reclamation is bounded**, not guaranteed. Workers that stop within
//!    [`JOIN_DEADLINE`] are joined; the deadline itself always terminates.
//! 3. **A worker that does not stop in time is surfaced by name**, not silently detached.
//!
//! (2) and (3) cannot both be absolute for an ordinary blocking OS thread: once entered,
//! `join` cannot be abandoned, so either shutdown is unbounded or some worker was not
//! joined. This type chooses bounded shutdown and says which worker it left. A named
//! straggler after a real attempt is a different thing from the silent detachment this
//! type replaces, but it is not the same as "all workers are joined", and the docs and
//! tests here must not claim that it is.
//!
//! # Two halt sources, deliberately
//!
//! `deployment` is the operator's — SIGTERM/SIGINT, a flag in tests. `owner` is
//! structural: the set raises it when it is dropped. They are separate because they mean
//! different things, and collapsing them into one `Arc<AtomicBool>` would make a
//! partially-built runtime tearing itself down indistinguishable from the operator asking
//! the deployment to stop. Discarding an evidence plane because an authority plane failed
//! to materialize must not tell the rest of the process that SIGTERM arrived.
//!
//! # The late-straggler property
//!
//! The risk a straggler poses is not that it runs for a few more seconds. It is that it
//! finishes a call started under one runtime and publishes the result into state that
//! belongs to a runtime already replaced.
//!
//! Today that is prevented structurally rather than by machinery: a worker body owns
//! `Arc`s to the objects its own runtime built, so a late write lands in state only the
//! dead runtime ever referenced, and a successor's state is a different allocation the
//! straggler has no handle on. The halt it observes also stays raised for as long as it
//! holds its [`Halt`], so a straggler that wakes after the set is gone exits rather than
//! resuming its loop.
//!
//! That property is a consequence of ownership, so it must be re-checked, not assumed,
//! whenever a worker is given a handle to anything shared BETWEEN runtimes rather than
//! owned by one. It is the invariant to watch as planes are extracted.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

mod halt;
pub use halt::Halt;

/// How long [`WorkerSet::halt_and_reclaim`] waits for a worker to notice the halt.
///
/// Every loop in the crate polls its halt in 50ms increments, so a healthy worker exits
/// well inside this. The deadline exists for the one that cannot: a worker parked in a
/// blocking KMS or network call it did not choose the timeout for.
pub(crate) const JOIN_DEADLINE: Duration = Duration::from_secs(5);

/// Poll interval while waiting for a worker to finish.
const JOIN_POLL: Duration = Duration::from_millis(10);

/// One owned background thread.
struct ManagedWorker {
    /// Names the worker in the diagnostic emitted when it outlives the join deadline.
    name: &'static str,
    handle: JoinHandle<()>,
}

/// The owned set of background workers belonging to one runtime.
///
/// Dropping it raises the structural halt and reclaims what it can within
/// [`JOIN_DEADLINE`]. Correctness on the failure path does not depend on anyone having
/// remembered to write the cleanup.
pub struct WorkerSet {
    deployment: Arc<AtomicBool>,
    owner: Arc<AtomicBool>,
    latched: Arc<AtomicBool>,
    workers: Vec<ManagedWorker>,
}

impl WorkerSet {
    /// An empty set whose workers also stop when `deployment` is flipped.
    pub fn new(deployment: Arc<AtomicBool>) -> WorkerSet {
        WorkerSet {
            deployment,
            owner: Arc::new(AtomicBool::new(false)),
            latched: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
        }
    }

    /// The halt to hand to a worker body. Cheap to clone.
    ///
    /// All halts from one set share a latch, so a raise observed by any worker is
    /// permanent for all of them.
    pub fn halt(&self) -> Halt {
        Halt::over(
            Arc::clone(&self.deployment),
            Arc::clone(&self.owner),
            Arc::clone(&self.latched),
        )
    }

    /// Start `body` on a named thread this set owns.
    ///
    /// Returns nothing, deliberately. There is no way to obtain a `JoinHandle` from this
    /// type, so the shape that caused the original defect —
    ///
    /// ```text
    /// spawn  ─►  something fallible  ─►  register the handle
    /// ```
    ///
    /// — cannot be written: a worker is owned from the instant it can execute, and no
    /// intervening failure can strand it. Registration here is unconditional and has no
    /// fallible step between the thread starting and the set owning it.
    ///
    /// `body` is expected to be the supervised wrapper (`catch_unwind` plus whatever
    /// fail-closed action the domain requires); this type deliberately takes no view on
    /// what a panic MEANS, because the answer differs per worker — retiring a signing
    /// snapshot is right for the rotor and wrong for the CRL reloader.
    pub fn spawn<F>(&mut self, name: &'static str, body: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(body)
            .unwrap_or_else(|e| panic!("spawn {name} worker: {e}"));
        self.workers.push(ManagedWorker { name, handle });
    }

    /// Number of workers still owned. Drops to zero once reclamation has been attempted.
    ///
    /// Nothing in the runtime asks — a set is dropped, not inspected — so this exists for
    /// the tests that assert registration happened.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.workers.len()
    }

    /// Whether this set owns no workers.
    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    /// Raise the structural halt and reclaim every worker, within a bounded budget.
    ///
    /// Idempotent. Returns the names of workers still running when the budget expired;
    /// each is also reported on stderr. An empty slice means everything was joined.
    ///
    /// The budget is spent in total, not per worker, so a set with many workers cannot
    /// multiply the shutdown time by its size.
    pub fn halt_and_reclaim(&mut self) -> Vec<&'static str> {
        if self.is_empty() {
            return Vec::new();
        }
        self.owner.store(true, Ordering::SeqCst);
        // Class R: this budget bounds how long shutdown may wait, so a deadline that
        // cannot be represented is treated as already reached.
        let now = Instant::now();
        let deadline = now.checked_add(JOIN_DEADLINE).unwrap_or(now);
        let mut stragglers = Vec::new();
        for worker in self.workers.drain(..) {
            while !worker.handle.is_finished() && Instant::now() < deadline {
                std::thread::sleep(JOIN_POLL);
            }
            let ManagedWorker { name, handle } = worker;
            if handle.is_finished() {
                // RECLAIMED. Already finished, so this returns immediately. A panic
                // inside the body was the body's to handle; nothing is re-raised here.
                let _ = handle.join();
            } else {
                // RELINQUISHED. The budget expired, so the handle is dropped and the OS
                // thread becomes detached from here on. The `drop` is written out
                // because that transition is the one decision in this type that gives up
                // a guarantee — it should be legible as a choice, not happen because a
                // binding fell out of scope.
                eprintln!(
                    "mcp-re-proxy: the {name} worker did not stop within {}s of being asked; it \
                     is left running rather than blocking shutdown on it. It holds only state \
                     this runtime owned, so a late result cannot reach a successor.",
                    JOIN_DEADLINE.as_secs()
                );
                stragglers.push(name);
                drop(handle);
            }
        }
        stragglers
    }
}

impl Drop for WorkerSet {
    fn drop(&mut self) {
        let _ = self.halt_and_reclaim();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    /// A worker that polls its halt and then records that it stopped.
    fn cooperative(halt: Halt, stopped: Arc<AtomicBool>) -> impl FnOnce() + Send + 'static {
        move || {
            while !halt.requested() {
                std::thread::sleep(Duration::from_millis(5));
            }
            stopped.store(true, Ordering::SeqCst);
        }
    }

    /// The defect this type exists to remove: a worker must stop when the thing that
    /// owns it goes away, on a path nobody wrote by hand.
    ///
    /// The deployment flag is never set here — the same situation as a startup that
    /// fails after spawning, which is exactly when the old detached workers kept running.
    #[test]
    fn dropping_the_set_stops_a_worker_the_deployment_flag_never_stopped() {
        let deployment = flag();
        let stopped = Arc::new(AtomicBool::new(false));

        {
            let mut set = WorkerSet::new(Arc::clone(&deployment));
            set.spawn("test", cooperative(set.halt(), Arc::clone(&stopped)));
            assert_eq!(set.len(), 1);
        }

        assert!(
            stopped.load(Ordering::SeqCst),
            "a cooperative worker must have stopped and been reclaimed before drop returned"
        );
        assert!(
            !deployment.load(Ordering::SeqCst),
            "tearing down a runtime must not look like the deployment being asked to stop"
        );
    }

    #[test]
    fn a_worker_also_stops_when_the_deployment_stops() {
        let deployment = flag();
        let mut set = WorkerSet::new(Arc::clone(&deployment));
        let stopped = Arc::new(AtomicBool::new(false));
        set.spawn("test", cooperative(set.halt(), Arc::clone(&stopped)));

        deployment.store(true, Ordering::SeqCst);
        assert!(set.halt_and_reclaim().is_empty(), "no stragglers expected");

        assert!(stopped.load(Ordering::SeqCst));
        assert!(set.is_empty());
    }

    #[test]
    fn reclaiming_twice_is_harmless() {
        let mut set = WorkerSet::new(flag());
        let stopped = Arc::new(AtomicBool::new(false));
        set.spawn("test", cooperative(set.halt(), stopped));
        assert!(set.halt_and_reclaim().is_empty());
        assert!(set.halt_and_reclaim().is_empty());
        assert!(set.is_empty());
    }

    /// The bounded-reclamation half of the contract, asserted as what it IS rather than
    /// as an unconditional join: shutdown terminates, and the worker it could not
    /// reclaim is returned by name.
    #[test]
    fn a_worker_that_ignores_the_halt_is_bounded_and_named() {
        let release = Arc::new(AtomicBool::new(false));
        let mut set = WorkerSet::new(flag());
        let release_in_worker = Arc::clone(&release);
        // Deliberately ignores the halt, the way a thread parked in a blocking network
        // call cannot see it.
        set.spawn("stuck", move || {
            while !release_in_worker.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let started = Instant::now();
        let stragglers = set.halt_and_reclaim();
        let waited = started.elapsed();

        assert_eq!(stragglers, vec!["stuck"], "the straggler must be named");
        // Bounds, not a stopwatch. The claim is "does not give up immediately" and "does
        // not wait on it forever"; asserting the budget to any precision would make a
        // lifecycle test fail on a loaded runner, which measures the CI box rather than
        // this type. The worker here never stops, so elapsed time can only exceed the
        // budget, never undershoot it — the lower bound carries slack for a coarse
        // monotonic clock, and the upper bound is deliberately far away.
        assert!(
            waited >= JOIN_DEADLINE.mul_f64(0.8),
            "reclamation must not give up on a worker immediately, waited {waited:?}"
        );
        assert!(
            waited < JOIN_DEADLINE * 4,
            "reclamation must not wait on a worker indefinitely, waited {waited:?}"
        );
        release.store(true, Ordering::SeqCst);
    }

    /// The late-straggler property, in the form this type is responsible for: a worker
    /// outliving its set still observes the halt, so it exits instead of resuming work
    /// against a runtime that no longer exists.
    ///
    /// Containment of what a straggler could WRITE is structural — it holds only handles
    /// its own runtime gave it — and belongs to whoever builds the worker body. What
    /// belongs here is that the stop signal survives its owner.
    #[test]
    fn the_halt_stays_raised_after_the_set_is_gone() {
        // `answered` separates "the worker has not looked yet" from "it looked and saw
        // false", so a slow thread cannot be mistaken for a raised-then-cleared halt.
        let answered = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));

        let answered_in_worker = Arc::clone(&answered);
        let halt_seen = Arc::clone(&observed);
        let release_in_worker = Arc::clone(&released);
        let mut set = WorkerSet::new(flag());
        let halt = set.halt();
        set.spawn("late", move || {
            // Blind to the halt until released, so it cannot be reclaimed...
            while !release_in_worker.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            // ...and only then asks whether it should still be running.
            halt_seen.store(halt.requested(), Ordering::SeqCst);
            answered_in_worker.store(true, Ordering::SeqCst);
        });

        let stragglers = set.halt_and_reclaim();
        assert_eq!(stragglers, vec!["late"]);
        drop(set);

        released.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !answered.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(JOIN_POLL);
        }
        assert!(answered.load(Ordering::SeqCst), "the worker never answered");
        assert!(
            observed.load(Ordering::SeqCst),
            "a worker waking after its set was dropped must still see the halt raised"
        );
    }

    #[test]
    fn an_interrupted_sleep_reports_that_it_was_cut_short() {
        let deployment = flag();
        let halt = Halt::detached(Arc::clone(&deployment));
        assert!(!halt.sleep(Duration::from_millis(10)), "ran to completion");

        deployment.store(true, Ordering::SeqCst);
        let started = Instant::now();
        assert!(halt.sleep(Duration::from_secs(30)), "cut short");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "an already-raised halt must be observed immediately"
        );
    }
}
