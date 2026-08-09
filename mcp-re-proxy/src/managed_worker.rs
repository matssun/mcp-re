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

/// How long [`WorkerSet::halt_and_reclaim`] waits for a worker to notice the halt.
///
/// Every loop in the crate polls its halt in 50ms increments, so a healthy worker exits
/// well inside this. The deadline exists for the one that cannot: a worker parked in a
/// blocking KMS or network call it did not choose the timeout for.
pub(crate) const JOIN_DEADLINE: Duration = Duration::from_secs(5);

/// Poll interval while waiting for a worker to finish.
const JOIN_POLL: Duration = Duration::from_millis(10);

/// A stop signal with two independent sources.
///
/// A worker asks only whether it should stop, never why. That is the point of the type:
/// a reload loop has no business distinguishing "SIGTERM arrived" from "the plane I
/// belong to failed to finish materializing" — both mean stop, and coupling worker bodies
/// to deployment-global state is what made the original threads impossible to own.
///
/// The signal is MONOTONIC. Once [`Halt::requested`] has observed either source raised,
/// it stays raised for the life of that `Halt` and every clone of it, even if the
/// underlying flag is later cleared. A worker that has begun winding down must not be
/// able to see the world become healthy again half way through.
#[derive(Clone)]
pub struct Halt {
    deployment: Arc<AtomicBool>,
    owner: Arc<AtomicBool>,
    latched: Arc<AtomicBool>,
}

impl Halt {
    /// Whether this worker should stop now.
    ///
    /// Stays true once raised, including after the owning set is gone — the worker's own
    /// clone keeps the flags alive — so a straggler that wakes late exits rather than
    /// resuming its loop.
    pub fn requested(&self) -> bool {
        if self.latched.load(Ordering::SeqCst) {
            return true;
        }
        if self.deployment.load(Ordering::SeqCst) || self.owner.load(Ordering::SeqCst) {
            // Latch, so the answer cannot revert. `deployment` is owned by the CALLER of
            // `run`, which makes "raised" something this type observes rather than
            // controls; without the latch a caller that reset its flag could restart a
            // worker that had already decided to stop.
            self.latched.store(true, Ordering::SeqCst);
            return true;
        }
        false
    }

    /// Sleep up to `total`, waking early if a halt is requested. Returns `true` if it
    /// was cut short, so a caller can `return` without re-reading the flag.
    ///
    /// Naps in small increments rather than sleeping the whole interval, so a stop is
    /// observed within one increment instead of after a full reload or rotation cadence.
    pub fn sleep(&self, total: Duration) -> bool {
        const TICK: Duration = Duration::from_millis(50);
        let deadline = Instant::now() + total;
        loop {
            if self.requested() {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            std::thread::sleep(TICK.min(deadline - now));
        }
    }

    /// A halt over caller-supplied sources, so each can be raised independently.
    #[cfg(test)]
    fn from_parts(deployment: Arc<AtomicBool>, owner: Arc<AtomicBool>) -> Halt {
        Halt {
            deployment,
            owner,
            latched: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A halt with no owning set, raised only by the deployment flag.
    #[cfg(test)]
    fn detached(deployment: Arc<AtomicBool>) -> Halt {
        Halt::from_parts(deployment, Arc::new(AtomicBool::new(false)))
    }
}

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
        Halt {
            deployment: Arc::clone(&self.deployment),
            owner: Arc::clone(&self.owner),
            latched: Arc::clone(&self.latched),
        }
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
        let deadline = Instant::now() + JOIN_DEADLINE;
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

    /// Each source raises the halt on its own. Asserted directly, with the other source
    /// held down, so neither case can pass by accident of the other being set.
    #[test]
    fn either_source_alone_raises_the_halt() {
        // Deployment stopping, owner intact.
        let deployment = flag();
        let owner = flag();
        let halt = Halt::from_parts(Arc::clone(&deployment), Arc::clone(&owner));
        assert!(!halt.requested());
        deployment.store(true, Ordering::SeqCst);
        assert!(halt.requested(), "the deployment halt must raise it");
        assert!(
            !owner.load(Ordering::SeqCst),
            "the owner source is untouched"
        );

        // Owner disappearing, deployment intact — the case a single shared flag could
        // not express without telling the process that SIGTERM had arrived.
        let deployment = flag();
        let owner = flag();
        let halt = Halt::from_parts(Arc::clone(&deployment), Arc::clone(&owner));
        assert!(!halt.requested());
        owner.store(true, Ordering::SeqCst);
        assert!(halt.requested(), "the structural halt must raise it");
        assert!(
            !deployment.load(Ordering::SeqCst),
            "the deployment source is untouched"
        );
    }

    /// The halt is a monotonic lifecycle signal, not a boolean convenience: a worker
    /// that has begun winding down must never see the world become healthy again.
    ///
    /// `deployment` belongs to the caller of `run`, so "raised" is something this type
    /// observes rather than controls; the latch is what makes the observation stick.
    #[test]
    fn a_raised_halt_never_becomes_unraised() {
        for clear_source in [true, false] {
            let deployment = flag();
            let owner = flag();
            let halt = Halt::from_parts(Arc::clone(&deployment), Arc::clone(&owner));
            let source = if clear_source { &deployment } else { &owner };

            source.store(true, Ordering::SeqCst);
            assert!(halt.requested());
            source.store(false, Ordering::SeqCst);

            assert!(
                halt.requested(),
                "a halt observed as raised must stay raised"
            );
            assert!(
                halt.clone().requested(),
                "and must stay raised for every clone, including ones taken afterwards"
            );
            assert!(
                halt.sleep(Duration::from_secs(30)),
                "and must keep cutting sleeps short"
            );
        }
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
