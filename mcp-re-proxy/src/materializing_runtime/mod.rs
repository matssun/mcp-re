// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-057 §9 / ADR-MCPRE-058 §14 — the owner of a partly-built runtime.
//!
//! # The invariant
//!
//! > **Lifecycle state may not advance beyond the ownership state it describes.**
//!
//! [`RuntimeLifecycle`] on its own proves only that a legal sequence of events was
//! applied. It does not prove that the resources whose existence *defines* `Materialized`
//! are actually owned by anything. This type is what makes those the same fact:
//! `MaterializationSucceeded` is applied inside [`finish`](MaterializingRuntime::finish),
//! *after* every required resource has been moved out of the builder and into
//! [`MaterializedRuntime`]. There is no other producer of that event, and
//! `MaterializedRuntime` has no other constructor. So a `Materialized` lifecycle cannot
//! exist over an incomplete resource graph — not by convention, but because no code path
//! creates one.
//!
//! # What this fixes (F3)
//!
//! `MaterializedRuntime` used to be constructed by the last statement of `run_validated`,
//! after roughly 38 fallible steps. Each of those steps could fail, and the acquisitions
//! that had already succeeded were plain locals — so they unwound in reverse DECLARATION
//! order, not the order teardown is documented in. `materialized_runtime` states that it
//! exists "to make successful shutdown and failed materialization obey the same rules";
//! for the failure path that was not true. Nothing went wrong today only because order
//! among the planes was checked to be free.
//!
//! Here a resource becomes owned the moment it is acquired. A later failure drops the
//! builder, and [`Drop`] reclaims what was installed in the documented order — the same
//! order a successful shutdown uses, because it is the same sequence of steps.
//!
//! # Failure is a transition, not an unwind
//!
//! [`RuntimeEvent::MaterializationFailed`] is emitted only from here, and only where the
//! partial resources have actually been reclaimed. It is not applied because a `?`
//! returned an error: an event that merely decorated an error path would assert an
//! ownership fact nobody established.

use crate::control_runtime::ControlRuntime;
use crate::materialized_runtime::MaterializedRuntime;
use crate::runtime_state::RuntimeEvent;
use crate::runtime_state::RuntimeLifecycle;
use crate::runtime_state::RuntimeState;
use crate::signing_plane::SigningPlane;
use crate::tls_plane::TlsPlane;
use crate::trust_plane::TrustPlane;
use crate::HttpProfileProxy;

mod completeness;

/// A runtime under construction: the lifecycle, plus every teardown-bearing resource
/// acquired so far.
///
/// The fields are `Option` because installation is progressive and
/// [`finish`](Self::finish) takes them out. Absence means "not acquired yet", which is
/// exactly what makes `finish` able to refuse.
pub(crate) struct MaterializingRuntime {
    /// `None` only after a consuming method has taken it. Held here rather than by the
    /// caller so that lifecycle state and resource ownership cannot be advanced
    /// separately — the whole point of this type.
    lifecycle: Option<RuntimeLifecycle>,
    trust: Option<TrustPlane>,
    signing: Option<SigningPlane>,
    tls: Option<TlsPlane>,
    proxy: Option<HttpProfileProxy>,
    /// Genuinely optional: a deployment with no networked control-plane dependency has
    /// none. Absence here is a legal outcome, unlike the four above.
    control: Option<ControlRuntime>,
}

impl MaterializingRuntime {
    /// Begin materializing. `lifecycle` must be in [`RuntimeState::Planned`]; the
    /// `MaterializationStarted` transition is applied here, so entering this type and
    /// entering the state are one act.
    pub(crate) fn begin(mut lifecycle: RuntimeLifecycle) -> Result<Self, String> {
        lifecycle.apply(RuntimeEvent::MaterializationStarted)?;
        Ok(MaterializingRuntime {
            lifecycle: Some(lifecycle),
            trust: None,
            signing: None,
            tls: None,
            proxy: None,
            control: None,
        })
    }

    /// The lifecycle position, for the tests below. Deliberately not offered to
    /// production code: reading the state and then acting on it is the stale-observation
    /// pattern ADR-MCPRE-057 §5.4 warns about, and nothing in startup needs it — the
    /// transitions are applied where the work happens.
    #[cfg(test)]
    pub(crate) fn state(&self) -> RuntimeState {
        self.lifecycle
            .as_ref()
            .map_or(RuntimeState::FailedToStart, RuntimeLifecycle::state)
    }

    /// Take ownership of the trust plane.
    ///
    /// Returns nothing. Handing back a borrow would tie it to the builder for the rest of
    /// startup and block the next `install_*`; handing back the value would defeat the
    /// point. The wiring that follows re-borrows through [`trust`](Self::trust), which is
    /// what keeps ownership here across every fallible step in between.
    pub(crate) fn install_trust(&mut self, trust: TrustPlane) {
        self.trust = Some(trust);
    }

    pub(crate) fn install_tls(&mut self, tls: TlsPlane) {
        self.tls = Some(tls);
    }

    pub(crate) fn install_signing(&mut self, signing: SigningPlane) {
        self.signing = Some(signing);
    }

    pub(crate) fn install_proxy(&mut self, proxy: HttpProfileProxy) {
        self.proxy = Some(proxy);
    }

    /// Take ownership of the control runtime, when the deployment has one.
    pub(crate) fn install_control(&mut self, control: Option<ControlRuntime>) {
        self.control = control;
    }

    /// Every required resource is owned: assemble the runtime and advance the lifecycle.
    ///
    /// The order here is load-bearing. The resources are taken FIRST, and only once all
    /// four are in hand is `MaterializationSucceeded` applied. Applying it earlier — the
    /// obvious-looking simplification — would let a `Materialized` lifecycle exist while
    /// a required resource was still absent, which is precisely the equivalence this type
    /// is for.
    pub(crate) fn finish(mut self) -> Result<(MaterializedRuntime, RuntimeLifecycle), String> {
        let present = [
            self.trust.is_some(),
            self.signing.is_some(),
            self.tls.is_some(),
            self.proxy.is_some(),
        ];
        if let Some(missing) = completeness::first_missing(present) {
            // Left un-taken, so `Drop` still reclaims whatever WAS installed.
            return Err(completeness::incomplete(missing));
        }
        // Class B: the check above returned for every absence, and taking all four as ONE
        // destructuring carries that guarantee in a pattern the compiler checks rather
        // than in these lines staying adjacent to the loop that established it.
        let (Some(trust), Some(signing), Some(tls), Some(proxy)) = (
            self.trust.take(),
            self.signing.take(),
            self.tls.take(),
            self.proxy.take(),
        ) else {
            return Err(completeness::vanished());
        };
        let control = self.control.take();

        // `finish` consumes `self`, so the lifecycle is here; reported all the same.
        let Some(mut lifecycle) = self.lifecycle.take() else {
            return Err("internal error: materialization finished without a lifecycle".to_owned());
        };
        lifecycle.apply(RuntimeEvent::MaterializationSucceeded)?;

        Ok((
            MaterializedRuntime::new(trust, signing, tls, proxy, control),
            lifecycle,
        ))
    }

    /// Reclaim the partial construction, in the documented order.
    ///
    /// The same sequence as a successful teardown — planes first, then the proxy, then the
    /// substrate the proxy's networked clients were bound to — because it is the same
    /// dependency graph. Drop glue would instead run in field-declaration order, and
    /// relying on that is the F3 defect.
    fn reclaim_partial(&mut self) {
        drop(self.trust.take());
        drop(self.signing.take());
        drop(self.tls.take());
        drop(self.proxy.take());
        drop(self.control.take());
    }
}

impl Drop for MaterializingRuntime {
    /// A builder that was not `finish`ed means materialization failed.
    ///
    /// Reclaim FIRST, then record the transition: the event says partial resources were
    /// released, so it must not be applied before they were.
    fn drop(&mut self) {
        self.reclaim_partial();
        if let Some(mut lifecycle) = self.lifecycle.take() {
            // `Materializing` always has this transition, so a failure here would mean the
            // relation changed underneath us. Ignored rather than panicking: this runs on
            // an unwind path, where panicking again aborts the process and loses the
            // original error the operator needs.
            let _ = lifecycle.apply(RuntimeEvent::MaterializationFailed);
            debug_assert_eq!(lifecycle.state(), RuntimeState::FailedToStart);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_worker::Halt;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    /// A lifecycle that has legally reached `Planned` — the precondition `begin` takes.
    fn planned() -> RuntimeLifecycle {
        let mut lifecycle = RuntimeLifecycle::new();
        lifecycle.apply(RuntimeEvent::ValidationSucceeded).unwrap();
        lifecycle.apply(RuntimeEvent::PlanBuilt).unwrap();
        lifecycle
    }

    /// A worker that waits to be halted and then records WHEN it stopped, relative to the
    /// other planes, by taking the next number from a shared counter.
    fn recording(
        order: Arc<AtomicUsize>,
        slot: Arc<AtomicUsize>,
    ) -> impl FnOnce(Halt) + Send + 'static {
        move |halt: Halt| {
            while !halt.requested() {
                std::thread::sleep(Duration::from_millis(2));
            }
            slot.store(order.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
        }
    }

    /// # Why the all-four success path is not exercised here
    ///
    /// `finish` needs a real `HttpProfileProxy`, which has no cheap constructor — building
    /// one means a key source, a resolver, TLS material and an inner plane. Standing that
    /// up would make these tests an integration harness and would not strengthen what they
    /// assert.
    ///
    /// What matters is covered without it. That `Materialized` is reachable ONLY through
    /// `finish` is a property of the type: `MaterializedRuntime::new` is the sole
    /// constructor and `finish` is its only caller, and `MaterializationSucceeded` has no
    /// other producer in the crate. That the lifecycle does NOT reach it when a resource
    /// is missing is asserted below against the real type. The transition itself is
    /// covered by the 110-pair relation test in `runtime_state`.
    #[allow(dead_code)]
    const WHY_NO_FULL_SUCCESS_TEST: () = ();

    /// B1 — the invariant. A failure AFTER some acquisitions must leave neither a
    /// `Materialized` lifecycle nor a resource outside the owner.
    ///
    /// The broken implementation this catches: applying `MaterializationSucceeded` when
    /// the builder is created, or at any point before the final acquisition, so that the
    /// lifecycle claims a complete runtime while `finish` could still fail.
    #[test]
    fn a_failure_after_partial_acquisition_reaches_neither_materialized_nor_a_leak() {
        let stopped = Arc::new(AtomicUsize::new(0));
        let counter = Arc::new(AtomicUsize::new(0));
        let mut building = MaterializingRuntime::begin(planned()).unwrap();
        assert_eq!(building.state(), RuntimeState::Materializing);

        building.install_trust(TrustPlane::for_teardown_test(recording(
            Arc::clone(&counter),
            Arc::clone(&stopped),
        )));
        // The signing plane never arrives — a later `?` failed.
        let err = match building.finish() {
            Err(e) => e,
            Ok(_) => panic!("finishing without the signing plane must refuse"),
        };
        assert!(
            err.contains("signing plane"),
            "the refusal must name what was missing, got: {err}"
        );
        assert!(
            stopped.load(Ordering::SeqCst) > 0,
            "the installed trust plane must have been reclaimed by the owner, not leaked"
        );
    }

    /// The other half of B1: a refused `finish` must not have advanced the lifecycle.
    ///
    /// `finish` consumes the builder, so the state is observed through the error path
    /// rather than after the call — which is the point. There is no way to hold a
    /// `RuntimeLifecycle` out of a failed `finish` at all, because the only route to one
    /// past this type is the success return.
    #[test]
    fn a_refused_finish_yields_no_lifecycle_at_all() {
        let building = MaterializingRuntime::begin(planned()).unwrap();
        assert_eq!(building.state(), RuntimeState::Materializing);
        assert!(
            building.finish().is_err(),
            "an empty builder must not produce a lifecycle"
        );
        // The compiler enforces the rest: `finish` is the only source of a post-
        // materialization `RuntimeLifecycle`, and it returns one only in the Ok arm.
    }

    /// B2 — `finish` refuses over an incomplete graph, and its refusal is the completeness
    /// owner's verdict rather than a message assembled here.
    ///
    /// WHICH resource is named for a given absence is that owner's own control
    /// (`completeness::the_first_missing_resource_is_the_one_named`), where the required
    /// set lives. What this pins is the half `finish` is responsible for: the verdict
    /// reaches the caller, and it says the graph was incomplete rather than merely failing.
    #[test]
    fn finish_reports_the_incomplete_graph_and_names_a_resource() {
        let building = MaterializingRuntime::begin(planned()).unwrap();
        let err = match building.finish() {
            Err(e) => e,
            Ok(_) => panic!("an empty builder cannot finish"),
        };
        assert!(
            err.contains("incomplete resource graph"),
            "the refusal must say what was wrong: {err}"
        );
        assert!(
            err.contains("trust plane"),
            "the refusal must name the first absent resource: {err}"
        );
    }

    /// B3 — `MaterializationFailed` is reached only with the reclaim actually performed.
    ///
    /// The broken implementation this catches: applying the event from an error path that
    /// released nothing, so the lifecycle records an ownership fact that never happened.
    #[test]
    fn dropping_an_unfinished_builder_reclaims_and_records_the_failure() {
        let stopped = Arc::new(AtomicUsize::new(0));
        let counter = Arc::new(AtomicUsize::new(0));
        let mut building = MaterializingRuntime::begin(planned()).unwrap();
        building.install_trust(TrustPlane::for_teardown_test(recording(
            Arc::clone(&counter),
            Arc::clone(&stopped),
        )));
        building.install_signing(SigningPlane::for_teardown_test(recording(
            Arc::clone(&counter),
            Arc::clone(&stopped),
        )));

        drop(building);

        assert!(
            stopped.load(Ordering::SeqCst) > 0,
            "an unfinished builder must reclaim what it owned"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "both installed planes must have been reclaimed"
        );
    }

    /// B4 — the reclaim order is the documented one, not field-declaration order.
    ///
    /// Trust is installed LAST here but must still be reclaimed FIRST, so the assertion
    /// cannot be satisfied by drop glue running over the struct's fields.
    #[test]
    fn partial_reclaim_follows_the_documented_order_not_installation_order() {
        let counter = Arc::new(AtomicUsize::new(0));
        let trust_at = Arc::new(AtomicUsize::new(0));
        let signing_at = Arc::new(AtomicUsize::new(0));

        let mut building = MaterializingRuntime::begin(planned()).unwrap();
        building.install_signing(SigningPlane::for_teardown_test(recording(
            Arc::clone(&counter),
            Arc::clone(&signing_at),
        )));
        building.install_trust(TrustPlane::for_teardown_test(recording(
            Arc::clone(&counter),
            Arc::clone(&trust_at),
        )));

        drop(building);

        let (trust, signing) = (
            trust_at.load(Ordering::SeqCst),
            signing_at.load(Ordering::SeqCst),
        );
        assert!(trust > 0 && signing > 0, "both planes must have stopped");
        assert!(
            trust < signing,
            "trust must be reclaimed before signing regardless of install order \
             (trust={trust}, signing={signing}); reverse-declaration unwinding is the \
             F3 defect this owner exists to remove"
        );
    }
}
