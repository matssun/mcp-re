// SPDX-License-Identifier: Apache-2.0
//! The shared control runtime (ADR-MCPRE-056 §8): execution substrate, not a plane.
//!
//! Every networked control-plane client runs its background work here — the Redis replay
//! store's `ConnectionManager` reconnect task, the MRTR continuation store, the admission
//! source — on one process-lifetime runtime distinct from the per-core serving runtimes.
//!
//! # It does not know why it exists
//!
//! This module never inspects configuration. Whether a runtime is needed is decided by
//! the pure plans that know what they intend to build, and arrives here as a
//! [`ControlRuntimeRequirement`]. Domain plans declare requirements; infrastructure
//! satisfies them.
//!
//! That boundary is not decoration. The requirement used to be inferred from whichever
//! seam happened to reach a runtime first, which was the replay tier — and admission,
//! whose Redis endpoint has nothing to do with replay, was thereby made unimplementable
//! on the CP/linearizable tier. An operator who supplied `--admission-redis-url` was told
//! the flag was missing, and the natural resolution was to turn a security control off.
//!
//! So: control-runtime availability is derived independently from EVERY capability that
//! requires it. It must never be inferred from the replay tier or from replay having been
//! selected, because continuation and admission have their own requirements.
//!
//! # PRECONDITION
//!
//! **[`ControlRuntimeRequirement`] is not a feature-availability validator.** Its
//! correctness assumes that unsupported requested capabilities have ALREADY been
//! rejected, by validation or by a materialization guard.
//!
//! It answers one question: does this VALID configuration require control execution. In
//! a build without `redis_replay`, shared replay, `--trust-epoch-redis-url` and
//! `--admission` each refuse rather than serve with the control silently disabled, and
//! reporting `NotRequired` there is sound only BECAUSE they do.
//!
//! Remove one of those refusals and this becomes the place an unsupported configuration
//! passes through — which is the opposite of where that decision belongs. It is stated
//! as a precondition so nobody expects the aggregation to catch it.
//!
//! # Ownership vs. access
//!
//! [`ControlRuntime`] owns the runtime. Consumers get a `tokio::runtime::Handle`, which
//! conveys execution ACCESS and no ownership: a cloned handle does not keep the runtime
//! alive, which is exactly the lifetime property wanted here. A handle conveys no usable
//! execution guarantee once its owner is gone — after shutdown, I/O-dependent work on it
//! can fail or panic. It is access while the owner lives, not a way to resurrect it.
//!
//! # Shutdown order, for whoever owns this next
//!
//! An owner holding BOTH this runtime and resources bound to it must drain or drop those
//! resources BEFORE reclaiming the runtime. The Redis clients' reconnect machinery is
//! asynchronous and lives here; tearing the substrate down under a live consumer is a
//! lifecycle relationship nobody wrote down, which is the class of defect this refactor
//! exists to remove. Do not leave that to field-declaration order.

/// Whether this deployment needs the shared control runtime.
///
/// Produced by aggregating what the plans declare (see `startup_plan`), never by asking
/// any single consumer — no consumer owns the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRuntimeRequirement {
    Required,
    NotRequired,
}

impl ControlRuntimeRequirement {
    /// `Required` if any contributor needs it.
    pub fn any(contributors: impl IntoIterator<Item = bool>) -> ControlRuntimeRequirement {
        if contributors.into_iter().any(|needed| needed) {
            ControlRuntimeRequirement::Required
        } else {
            ControlRuntimeRequirement::NotRequired
        }
    }

    pub fn is_required(self) -> bool {
        self == ControlRuntimeRequirement::Required
    }
}

/// The owned process-lifetime control runtime.
pub struct ControlRuntime {
    /// Read only by [`ControlRuntime::handle`]. Every consumer that would call it is
    /// gated on `redis_replay`, so in a build without that backend this substrate has
    /// no callers at all — and correctly, since nothing then requires it either.
    #[cfg_attr(not(feature = "redis_replay"), allow(dead_code))]
    runtime: tokio::runtime::Runtime,
}

impl ControlRuntime {
    /// Start the runtime if the plans require one.
    ///
    /// Returns `None` for `NotRequired`, so a deployment that needs no networked
    /// control-plane client starts no threads for one.
    pub fn start(requirement: ControlRuntimeRequirement) -> Result<Option<ControlRuntime>, String> {
        if !requirement.is_required() {
            return Ok(None);
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("mcp-re-control")
            .build()
            .map_err(|e| format!("build control runtime: {e}"))?;
        Ok(Some(ControlRuntime { runtime }))
    }

    /// Execution access for a consumer. Conveys no ownership: this handle will not keep
    /// the runtime alive, and is not usable once the owner is gone.
    #[cfg_attr(not(feature = "redis_replay"), allow(dead_code))]
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn a_deployment_that_needs_no_control_plane_client_starts_no_runtime() {
        let none = ControlRuntime::start(ControlRuntimeRequirement::NotRequired)
            .expect("no runtime is not an error");
        assert!(none.is_none(), "nothing required it, so nothing was built");
    }

    #[test]
    fn a_single_contributor_is_enough_and_no_contributor_is_not() {
        assert_eq!(
            ControlRuntimeRequirement::any([false, true, false]),
            ControlRuntimeRequirement::Required
        );
        assert_eq!(
            ControlRuntimeRequirement::any([false, false, false]),
            ControlRuntimeRequirement::NotRequired
        );
        assert_eq!(
            ControlRuntimeRequirement::any([]),
            ControlRuntimeRequirement::NotRequired
        );
    }

    /// Several consumers share ONE substrate rather than each building its own.
    #[test]
    fn every_consumer_receives_a_handle_to_the_same_runtime() {
        let rt = ControlRuntime::start(ControlRuntimeRequirement::Required)
            .expect("build")
            .expect("required");
        let (replay, continuation, admission) = (rt.handle(), rt.handle(), rt.handle());
        assert_eq!(replay.id(), continuation.id());
        assert_eq!(continuation.id(), admission.id());
    }

    /// A handle conveys access, not ownership.
    ///
    /// The task is COOPERATIVE — it yields — because that is what the contract is about:
    /// dropping the runtime stops tasks at a yield point and drops their futures. A
    /// non-yielding or `spawn_blocking` task would instead be testing tokio's handling of
    /// uncooperative work, and could hang shutdown rather than assert anything.
    #[test]
    fn dropping_the_owner_stops_work_a_surviving_handle_had_started() {
        let started = Arc::new(AtomicBool::new(false));
        let still_running = Arc::new(AtomicBool::new(false));

        let rt = ControlRuntime::start(ControlRuntimeRequirement::Required)
            .expect("build")
            .expect("required");
        let handle = rt.handle();

        let started_in_task = Arc::clone(&started);
        let running_in_task = Arc::clone(&still_running);
        handle.spawn(async move {
            started_in_task.store(true, Ordering::SeqCst);
            loop {
                // A yield point, so shutdown can reclaim this task.
                tokio::time::sleep(Duration::from_millis(5)).await;
                running_in_task.store(true, Ordering::SeqCst);
            }
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        while !started.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(started.load(Ordering::SeqCst), "the task never ran");

        drop(rt);

        // The handle outlived the runtime; it did not keep it alive.
        still_running.store(false, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !still_running.load(Ordering::SeqCst),
            "work continued after its execution substrate was reclaimed"
        );
        drop(handle);
    }

    /// Property 4, and NOT what the test above proves.
    ///
    /// That one shows a handle does not own the runtime. This one shows the OWNER does
    /// not escape a later failure: an implementation could kill tasks correctly on drop
    /// and still leak the runtime by stashing it somewhere that outlives the `?`.
    ///
    /// This is the third instance of one family — detached workers surviving a failed
    /// startup, a resolver surviving its refresh producer, a runtime surviving a later
    /// materialization failure. The law is that successful construction of an
    /// intermediate resource must not let its lifetime escape a later startup failure.
    #[test]
    fn a_runtime_built_before_a_later_failure_does_not_escape_it() {
        let alive = Arc::new(AtomicBool::new(false));

        // A materialization that gets the substrate up, starts control-plane work on
        // it, and then fails at a later phase — the shape of every `?` between the
        // first networked client and `serve_fleet`.
        fn materialize(alive: Arc<AtomicBool>) -> Result<(), String> {
            let control =
                ControlRuntime::start(ControlRuntimeRequirement::Required)?.expect("required");
            control.handle().spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    alive.store(true, Ordering::SeqCst);
                }
            });
            std::thread::sleep(Duration::from_millis(50));
            Err("a later materialization phase failed".to_string())
        }

        assert!(materialize(Arc::clone(&alive)).is_err());
        assert!(
            alive.load(Ordering::SeqCst),
            "the control-plane work never started, so this proves nothing"
        );

        // Nothing holds the runtime now. If it had escaped, the task would still tick.
        alive.store(false, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !alive.load(Ordering::SeqCst),
            "control-plane activity survived the failed materialization that created it"
        );
    }
}
