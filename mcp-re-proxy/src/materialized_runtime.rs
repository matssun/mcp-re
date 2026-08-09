// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-056 §10 — the assembled runtime, and the order it comes apart in.
//!
//! This is the first type that owns the whole resource graph rather than a slice of it.
//! Its job is NOT to be a container: it is to make the teardown dependency graph
//! inspectable, and to make successful shutdown and failed materialization obey the same
//! rules.
//!
//! # The order, and why each step is where it is
//!
//! ```text
//! 1. drain      fleet.shutdown_and_join() returns — no request is in flight
//! 2. transition the security planes drop, each performing its OWN post-owner
//!               transition (stale / retire / nothing)
//! 3. reclaim    the proxy, then the control runtime it bound clients to
//! ```
//!
//! **Drain before transition.** The proxy holds the trust plane's resolver and the
//! signing plane's signer, and both planes perform a security transition on drop —
//! `mark_stale()` and `retire()`. Dropping either while the fleet still serves would make
//! in-flight requests fail closed mid-drain: safe, but wrong, because a graceful shutdown
//! would start refusing traffic it had already accepted. This edge is invisible at the
//! call site — the planes and the proxy are simply separate values — which is why it is
//! written here rather than inferred.
//!
//! **Reclaim the substrate last.** The replay tier, the continuation store and the
//! admission source each hold a redis client bound to `ControlRuntime` by
//! `Runtime::locate()` for its whole life, so the runtime must outlive every USE, not just
//! the connect. Dropping the proxy first releases them; the runtime then goes.
//!
//! **Order among the planes is free.** They share no resource: each owns its own OS
//! threads and, for the epoch watches, its own synchronous redis socket. That was checked,
//! not assumed — an assumed dependency here would have been encoded as a field order and
//! then quietly relied upon.
//!
//! # Phases 2 and 3 are IN-PROCESS ONLY
//!
//! Every plane's post-owner work is a local state change and a thread join: `mark_stale`,
//! `retire`, `halt_and_reclaim`. No lease is released, no audit is flushed, no replica
//! deregisters. Two things rest on that.
//!
//! Each plane's reclamation is bounded by its own [`JOIN_DEADLINE`], so the worst case is
//! that budget times the number of planes, spent AFTER the drain the deployment's grace
//! period was sized around. The chart's drain invariant
//! (`deploy/helm/mcp-re-proxy/templates/_helpers.tpl`) does not include it, and is right
//! not to — only because nothing here needs to reach the outside world before the process
//! dies. A `SIGKILL` landing mid-teardown loses no observable state.
//!
//! Adding externally-visible work to a plane's `Drop` therefore breaks a contract that is
//! enforced nowhere: it would silently shorten the effective grace period and start losing
//! whatever that work was for. Such work belongs in the drain, before phase 2, where the
//! grace period accounts for it.
//!
//! [`JOIN_DEADLINE`]: crate::managed_worker::JOIN_DEADLINE
//!
//! # Why `Option` fields and an explicit `shutdown`
//!
//! A struct that implements `Drop` cannot be destructured, so "drop these in this order"
//! cannot be written as a sequence of `drop(field)` calls. The alternative — relying on
//! declaration order — is exactly what this type exists to eliminate: it is correct today
//! in `run_validated` purely because `serve_fleet` blocks and the locals then unwind in
//! reverse, which no one wrote down and nothing checks.
//!
//! So each owned resource is an `Option`, [`shutdown`](MaterializedRuntime::shutdown)
//! takes them in the documented order, and [`Drop`] defers to it. Both the normal path and
//! an accidental drop get the same sequence, and re-ordering the fields changes nothing.
//!
//! # No `trait Plane`
//!
//! Deliberately absent. The four post-owner contracts differ — the trust resolver fails
//! closed, the signer is retired, the signer directory keeps answering, the TLS snapshot
//! stays usable to its own validity bound — and a common lifecycle vocabulary would have
//! to be either vacuous or wrong about at least one of them. A shared ownership MECHANISM
//! is right; a shared semantic OUTCOME is not.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::cli;
use crate::config_snapshot;
use crate::control_runtime::ControlRuntime;
use crate::signing_plane::SigningPlane;
use crate::tls_plane::TlsPlane;
use crate::trust_plane::TrustPlane;
use crate::HttpProfileProxy;
use crate::ServerOptions;

/// Everything startup established, owned together so that teardown can be ordered.
///
/// Each field is `Option` only so [`shutdown`](Self::shutdown) can take it at the right
/// moment; every one is `Some` from construction until teardown begins.
///
/// **Ordered teardown is provided by [`shutdown`](Self::shutdown), not by field
/// declaration order.** The two currently coincide, and that coincidence must not be
/// relied upon or "simplified" into: it is why removing the `Drop` impl leaves every test
/// in this module green, so nothing here would catch the removal. The declaration order is
/// a readability choice; the protocol is the guarantee.
pub(crate) struct MaterializedRuntime {
    /// Owns the swappable trust store and its refresh workers. Its `Drop` marks the store
    /// stale BEFORE halting, so a resolver that outlives it fails closed.
    trust: Option<TrustPlane>,
    /// Owns the delegated snapshot and its rotation worker. Its `Drop` retires the signer
    /// BEFORE halting, so a signer that outlives it stops signing immediately.
    signing: Option<SigningPlane>,
    /// Owns the CRL reload worker. No security transition on drop: an unrefreshed CRL
    /// converges on refusing, because unknown revocation state is never admissible.
    tls: Option<TlsPlane>,
    /// The serving assembly. Holds the two plane handles above, plus the replay tier,
    /// continuation store and admission source that are bound to `control`.
    ///
    /// `Arc` because the fleet shares one proxy across every core. After
    /// `shutdown_and_join` returns, the handler clones are gone and this is the last
    /// reference, so taking it here is what actually drops the assembly.
    proxy: Option<Arc<HttpProfileProxy>>,
    /// The shared control-plane substrate. Reclaimed last, after the proxy has released
    /// the clients bound to it.
    control: Option<ControlRuntime>,
}

impl MaterializedRuntime {
    /// Assemble what startup established. Takes every owned resource by value, so a
    /// caller cannot retain one and outlive the ordering this type enforces.
    pub(crate) fn new(
        trust: TrustPlane,
        signing: SigningPlane,
        tls: TlsPlane,
        proxy: HttpProfileProxy,
        control: Option<ControlRuntime>,
    ) -> Self {
        Self {
            trust: Some(trust),
            signing: Some(signing),
            tls: Some(tls),
            proxy: Some(Arc::new(proxy)),
            control,
        }
    }

    /// Serve until `shutdown` is raised, then tear down in the documented order.
    ///
    /// Consumes `self`: the ordering guarantee is only worth having if the runtime cannot
    /// be used again afterwards.
    pub(crate) fn serve(
        mut self,
        config_snapshot: Arc<config_snapshot::ServerConfigSnapshot>,
        serve_options: Arc<ServerOptions>,
        config: &cli::Config,
        shutdown: Arc<AtomicBool>,
    ) -> Result<(), String> {
        // PHASE 1 — drain. Returns only once every per-core worker has stopped, so no
        // request can be using anything below when phase 2 begins.
        let proxy = Arc::clone(
            self.proxy
                .as_ref()
                .expect("the runtime serves before it is torn down"),
        );
        let served =
            crate::app::serve_fleet(proxy, config_snapshot, serve_options, config, shutdown);
        // Phases 2 and 3 run whether serving succeeded or failed: a fleet that could not
        // bind still leaves every plane's workers running, and a failure path that skipped
        // teardown would be the §I leak this ADR exists to close.
        self.shutdown();
        served
    }

    /// Phases 2 and 3. Idempotent — a second call finds every `Option` already taken.
    ///
    /// Separate from `serve` so the same sequence runs on the `Drop` path, and so a test
    /// can drive teardown without standing up a listener.
    pub(crate) fn shutdown(&mut self) {
        self.transition();
        self.reclaim();
    }

    /// PHASE 2 — each plane performs its own post-owner transition.
    ///
    /// Order among the three is free: they share no resource, each owning its own OS
    /// threads and (for the epoch watches) its own synchronous redis socket.
    ///
    /// This phase MUST NOT touch the substrate. A plane's transition is a security
    /// statement about its own artifact — stale, retired, or nothing — and none of them
    /// needs the control runtime to make it. Taking the substrate here would couple a
    /// security transition to a networked dependency that can be slow or wedged.
    fn transition(&mut self) {
        drop(self.trust.take());
        drop(self.signing.take());
        drop(self.tls.take());
    }

    /// PHASE 3 — reclaim, substrate last.
    ///
    /// The proxy first: it holds the replay tier, the continuation store and the admission
    /// source, each carrying a redis client bound to the control runtime by
    /// `Runtime::locate()` for its whole life. Only once those are released is the runtime
    /// itself reclaimed.
    fn reclaim(&mut self) {
        drop(self.proxy.take());
        drop(self.control.take());
    }
}

impl Drop for MaterializedRuntime {
    /// Defers to [`shutdown`](Self::shutdown) so a runtime dropped without serving — a
    /// later materialization step failing, a test, a panic unwinding through startup —
    /// comes apart in the same order as one that served.
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::managed_worker::Halt;
    use crate::managed_worker::JOIN_DEADLINE;
    use crate::trust_plane::TEST_KID as TRUST_KID;
    use crate::trust_plane::TEST_SIGNER as TRUST_SIGNER;
    use std::time::Duration;
    use std::time::Instant;

    /// A worker that notices its halt and stops. The shape every production worker has.
    fn cooperative(halt: Halt) {
        while !halt.requested() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A worker that never notices its halt — the one `JOIN_DEADLINE` exists for. Bounded
    /// well above the deadline so the test proves the deadline terminated the wait, and
    /// still finite so the process does not carry it for the rest of the run.
    fn ignores_the_halt(_halt: Halt) {
        std::thread::sleep(JOIN_DEADLINE * 3);
    }

    /// A worker that dies. The panic message it prints is expected output, not a failure.
    fn panics(_halt: Halt) {
        panic!("the test worker died on purpose");
    }

    /// A control runtime, the substrate phase 3 reclaims.
    fn substrate() -> ControlRuntime {
        ControlRuntime::start(crate::control_runtime::ControlRuntimeRequirement::Required)
            .expect("a control runtime builds")
            .expect("Required yields one")
    }

    /// A fully populated runtime whose three planes are real, each running `body`.
    ///
    /// `proxy` stays `None`: it needs a resolver, an audience, a replay tier and an inner
    /// pool, and none of those bear on which phase takes which field or on what a plane
    /// does to its own artifact on the way out.
    fn populated(
        trust_body: fn(Halt),
        signing_body: fn(Halt),
        tls_body: fn(Halt),
    ) -> MaterializedRuntime {
        MaterializedRuntime {
            trust: Some(TrustPlane::for_teardown_test(trust_body)),
            signing: Some(SigningPlane::for_teardown_test(signing_body)),
            tls: Some(TlsPlane::for_teardown_test(tls_body)),
            proxy: None,
            control: Some(substrate()),
        }
    }

    /// The whole teardown, with REAL planes — the case every other test in this module
    /// approximates with `None`.
    ///
    /// Three claims at once, because they are one sequence and asserting them apart would
    /// not show that they hold together:
    ///
    /// 1. each plane performs its OWN post-owner transition (§I.5) — the resolver fails
    ///    closed, the signer is retired, and those are DIFFERENT outcomes reached by one
    ///    call;
    /// 2. phase 2 leaves the substrate alone, so no security transition waits on a
    ///    networked dependency;
    /// 3. cooperative workers are JOINED, not waited out — a teardown that silently
    ///    burned the deadline on every plane would still pass 1 and 2.
    #[test]
    fn a_populated_runtime_transitions_every_plane_and_then_reclaims_the_substrate() {
        let mut runtime = populated(cooperative, cooperative, cooperative);
        let resolver = runtime.trust.as_ref().expect("trust").resolver();
        let signer = runtime.signing.as_ref().expect("signing").signer();

        // Alive: the resolver answers on its own terms (an unenrolled kid is NotFound, not
        // an outage) and the signer holds a key an hour from expiry.
        assert!(
            matches!(
                resolver.resolve(TRUST_SIGNER, TRUST_KID),
                Ok(_) | Err(mcp_re_core::TrustResolverError::NotFound)
            ),
            "a live plane's resolver must answer rather than report an outage"
        );
        assert!(
            signer.current(crate::app::now_unix()).is_some(),
            "a live plane must publish a usable delegated key"
        );

        let started = Instant::now();
        runtime.transition();
        let elapsed = started.elapsed();

        assert!(
            matches!(
                resolver.resolve(TRUST_SIGNER, TRUST_KID),
                Err(mcp_re_core::TrustResolverError::Unavailable { .. })
            ),
            "a resolver that outlived its plane must fail CLOSED, not answer from a \
             snapshot nothing is re-reading"
        );
        assert!(
            signer.current(crate::app::now_unix()).is_none(),
            "a signer that outlived its plane must stop signing: nothing is rotating that \
             key and no trust-epoch advance can revoke it"
        );
        assert!(
            runtime.control.is_some(),
            "phase 2 took the substrate: a security transition must not depend on a \
             networked dependency that can be slow or wedged"
        );
        assert!(
            elapsed < JOIN_DEADLINE,
            "three cooperative workers took {elapsed:?}, at or past the {JOIN_DEADLINE:?} \
             straggler deadline — they were waited out rather than joined"
        );

        runtime.reclaim();
        assert!(
            runtime.control.is_none(),
            "phase 3 must reclaim the substrate"
        );
    }

    /// One worker that never stops must not cost the OTHER planes their transitions.
    ///
    /// This is the case the whole `WorkerSet` deadline exists for, raised to the system
    /// level: `halt_and_reclaim` is bounded per plane, but nothing until now asserted that
    /// a plane which spends its whole budget still lets the ones after it run. A
    /// `transition` that joined without a deadline, or that abandoned the sequence on the
    /// first straggler, would leave a live signer behind on a process that believes it has
    /// shut down.
    ///
    /// The budget is per plane and therefore ADDITIVE across them; the upper bound below
    /// states that, and would catch a change that made every plane wait for every other.
    #[test]
    fn a_worker_that_never_stops_bounds_teardown_without_skipping_the_other_planes() {
        let mut runtime = populated(ignores_the_halt, cooperative, cooperative);
        let signer = runtime.signing.as_ref().expect("signing").signer();

        let started = Instant::now();
        runtime.transition();
        let elapsed = started.elapsed();

        assert!(
            elapsed >= JOIN_DEADLINE,
            "teardown returned in {elapsed:?}, before the {JOIN_DEADLINE:?} deadline — the \
             straggler was abandoned without being given its budget"
        );
        assert!(
            elapsed < JOIN_DEADLINE * 3,
            "teardown took {elapsed:?}: one straggler must cost ONE budget, not one per \
             plane"
        );
        assert!(
            signer.current(crate::app::now_unix()).is_none(),
            "the signing plane's retirement was skipped because an earlier plane stalled"
        );
        assert!(
            runtime.control.is_some(),
            "phase 2 took the substrate while waiting out a straggler"
        );

        runtime.reclaim();
        assert!(
            runtime.control.is_none(),
            "a stalled transition must not prevent the substrate being reclaimed"
        );
    }

    /// A worker that PANICKED must not take the teardown with it.
    ///
    /// What this can catch: `halt_and_reclaim` discarding the `join` result. A
    /// `join().unwrap()` — the reflexive spelling — would re-raise the worker's panic
    /// inside `transition`, unwinding through a partially torn-down runtime and never
    /// reaching phase 3, so the substrate would be reclaimed by `Drop` in whatever order
    /// unwinding produced rather than by the documented sequence.
    ///
    /// What it does NOT catch, stated because the assertion looks like it does: the
    /// stale-before-halt ORDER inside `TrustPlane::drop`. Both statements run either way,
    /// so the resolver ends up failing closed under either order. That order matters
    /// against a live request during a graceful drain, not here; it is
    /// `trust_plane`'s own tests that hold it. The resolver assertion here says only that
    /// the plane was transitioned at all on a path where a worker died.
    #[test]
    fn a_panicked_worker_still_leaves_its_plane_transitioned_and_the_substrate_reclaimable() {
        let mut runtime = populated(panics, cooperative, cooperative);
        let resolver = runtime.trust.as_ref().expect("trust").resolver();

        runtime.transition();

        assert!(
            matches!(
                resolver.resolve(TRUST_SIGNER, TRUST_KID),
                Err(mcp_re_core::TrustResolverError::Unavailable { .. })
            ),
            "a plane whose worker panicked must still fail its resolver closed"
        );
        assert!(runtime.control.is_some(), "phase 2 took the substrate");

        runtime.reclaim();
        assert!(
            runtime.control.is_none(),
            "a panicked worker must not prevent the substrate being reclaimed"
        );
    }

    /// `shutdown` must be safe to call twice: `serve` calls it, and then `Drop` calls it
    /// again on the way out. A second pass that re-entered teardown would double-drop.
    /// Every owned resource is `None` — the state teardown leaves behind. Constructing it
    /// directly keeps the test free of TLS material, a key source and a listener, none of
    /// which the ordering property depends on.
    fn already_torn_down() -> MaterializedRuntime {
        MaterializedRuntime {
            trust: None,
            signing: None,
            tls: None,
            proxy: None,
            control: None,
        }
    }

    /// `shutdown` must be safe to call twice: `serve` calls it, and `Drop` calls it again
    /// on the way out. A second pass that re-entered teardown would double-drop.
    #[test]
    fn shutdown_is_idempotent() {
        let mut runtime = already_torn_down();
        runtime.shutdown();
        runtime.shutdown();
    }

    /// A runtime dropped WITHOUT serving still reclaims its substrate.
    ///
    /// Covers the path a later startup failure or an unwinding panic takes: constructed,
    /// never served, dropped. It runs `Drop` with a populated field and asserts the
    /// control runtime is genuinely gone afterwards — work a surviving handle had started
    /// stops, which is `control_runtime`'s own contract.
    ///
    /// **What it does not prove, and cannot today.** That `Drop`'s delegation to
    /// `shutdown` is what ORDERED the teardown. The fields are declared in the same order
    /// teardown requires, so plain field-order dropping would produce an identical
    /// sequence; no test can separate the two while they agree. The delegation is
    /// insurance against a future field reordering, not a behaviour observable now.
    /// Ordering itself is covered by `the_transition_phase_leaves_the_substrate_intact`,
    /// which drives `shutdown` directly.
    #[test]
    fn a_runtime_dropped_without_serving_reclaims_its_substrate() {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        use std::time::Instant;

        let started = Arc::new(AtomicBool::new(false));
        let still_running = Arc::new(AtomicBool::new(false));

        let control =
            ControlRuntime::start(crate::control_runtime::ControlRuntimeRequirement::Required)
                .expect("a control runtime builds")
                .expect("Required yields one");
        let handle = control.handle();

        let started_in_task = Arc::clone(&started);
        let running_in_task = Arc::clone(&still_running);
        handle.spawn(async move {
            started_in_task.store(true, Ordering::SeqCst);
            loop {
                // A yield point, so reclamation can stop this task.
                tokio::time::sleep(Duration::from_millis(5)).await;
                running_in_task.store(true, Ordering::SeqCst);
            }
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        while !started.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(started.load(Ordering::SeqCst), "the task never ran");

        // Never served. This is the only teardown this runtime gets.
        drop(MaterializedRuntime {
            trust: None,
            signing: None,
            tls: None,
            proxy: None,
            control: Some(control),
        });

        still_running.store(false, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !still_running.load(Ordering::SeqCst),
            "the substrate outlived a runtime that was dropped without serving"
        );
        drop(handle);
    }

    /// The transition phase does not touch the substrate.
    ///
    /// Falsifiable, which the first version of this test was not: it populates `control`
    /// with a real runtime and asserts it SURVIVES phase 2. Moving `control` (or `proxy`)
    /// into `transition` — the reordering the phase split exists to prevent — makes this
    /// fail. An earlier draft set every field to `None` first and asserted they were
    /// `None` afterwards, which is true of any implementation whatsoever.
    ///
    /// It matters beyond tidiness: a plane's transition is a security statement about its
    /// own artifact, and every one of them is computable without the network. Reclaiming
    /// the control runtime alongside them would put a possibly-wedged redis connection
    /// between the process and `retire()`.
    #[test]
    fn the_transition_phase_leaves_the_substrate_intact() {
        let control =
            ControlRuntime::start(crate::control_runtime::ControlRuntimeRequirement::Required)
                .expect("a control runtime builds")
                .expect("Required yields one");
        let mut runtime = MaterializedRuntime {
            // The planes need TLS material, a key source and a trust store to build, and
            // none of that bears on WHICH FIELDS each phase takes. `None` here costs the
            // test nothing: the assertion below is about the substrate.
            trust: None,
            signing: None,
            tls: None,
            proxy: None,
            control: Some(control),
        };

        runtime.transition();
        assert!(
            runtime.control.is_some(),
            "phase 2 took the control runtime: a security transition must not depend on \
             the networked substrate, and reclaiming it here couples the two"
        );

        runtime.reclaim();
        assert!(
            runtime.control.is_none(),
            "phase 3 must reclaim the substrate"
        );
    }
}
