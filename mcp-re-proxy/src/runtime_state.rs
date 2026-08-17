// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-057 §3 — the global runtime lifecycle, as a value.
//!
//! # Why this exists
//!
//! The lifecycle below is not new. MCP-RE has always moved through these states; until now
//! no value held which one it was in. States 1-5 were positions of the program counter
//! inside [`run_validated`](crate::app), and 6-9 were `MaterializedRuntime`'s fields being
//! progressively taken.
//!
//! That absence had a consequence. The trust and signing planes each needed to tell "my
//! owner is terminating" from "I failed and may recover", and neither could observe the
//! runtime, so each duplicated the distinction locally — and in both cases the duplicate
//! collapsed into the child's own recoverable state. A reload landing after
//! `TrustPlane::drop` could report the store fresh again; a mint landing after
//! `SigningPlane::drop` could republish a delegated key. Both are fixed at their own
//! transition points; this type is what makes the distinction they encode expressible.
//!
//! # What this is NOT
//!
//! **Not synchronization** (ADR-MCPRE-057 §5.4). Reading a state from here is a read: by
//! the time the caller acts on it, the answer may be stale. A worker that observes
//! `Serving` and then completes a slow operation has learned nothing about whether its
//! eventual mutation is still legal. Terminal transitions reachable from more than one
//! thread must ALSO be enforced atomically where they are committed — the latches in
//! `TrustStoreFreshness` and `DelegatedServerSigner` are not redundant with this type and
//! must not be replaced by consulting it.
//!
//! ```text
//! this type                = source of truth about which transitions are legal
//! local guarded transition = enforcement against races
//! ```
//!
//! **Not a framework.** A closed enum and one exhaustive match, per ADR-MCPRE-058 §12.
//! **Not public.** Runtime state is not a protocol surface (ADR-MCPRE-057 §18).

/// Where the process is in its own lifecycle.
///
/// One authority: the thread running startup and shutdown. Every transition is committed
/// there, which is why this type carries no interior mutability — sharing it across
/// threads would create the ambiguous transition authority ADR-MCPRE-057 §6 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeState {
    /// Raw arguments parsed; nothing validated.
    Configured,
    /// Past the unbypassable configuration boundary (`ValidatedDeployment`).
    Validated,
    /// Pure planning done; no effect has been performed yet.
    Planned,
    /// Resources are being acquired. Partial ownership exists from here.
    Materializing,
    /// Every required resource is owned.
    Materialized,
    /// The fleet is accepting requests.
    Serving,
    /// No new requests are admitted; those in flight may finish.
    Draining,
    /// Drain is proven complete; the planes perform their post-owner transitions.
    Transitioning,
    /// Security transitions are done; owned resources are released.
    Reclaiming,
    /// Terminal.
    Stopped,
    /// Terminal. Materialization failed and partial resources were reclaimed.
    ///
    /// Distinct from [`Stopped`](Self::Stopped) because nothing ever served: no drain was
    /// required and no request could have been in flight. Collapsing the two would let a
    /// test assert the drain-ordering law against a path that never had to satisfy it.
    FailedToStart,
}

/// What happened. Events are facts already established, never intentions — a state is
/// entered because the work that justifies it succeeded, not to announce that it is about
/// to be attempted (ADR-MCPRE-057 §18: planned != established).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeEvent {
    ValidationSucceeded,
    PlanBuilt,
    MaterializationStarted,
    MaterializationSucceeded,
    /// Acquisition failed after `MaterializationStarted`, and the partial resources have
    /// been reclaimed.
    ///
    /// Emitted only by `MaterializingRuntime`'s `Drop`, after the reclaim it performs —
    /// never merely to decorate an error path. The event asserts an ownership fact, so a
    /// producer that released nothing would make the lifecycle record something untrue.
    MaterializationFailed,
    ServingStarted,
    ShutdownRequested,
    /// The fleet's drain/join has returned, which is what proves no non-terminal request
    /// lifecycle remains (ADR-MCPRE-057 §8.1). Deliberately not an in-flight counter: the
    /// predicate is discharged by the existing join semantics, not by new request-path
    /// accounting.
    FleetDrained,
    SecurityTransitionCompleted,
    ResourceReclaimCompleted,
}

/// An event that the current state has no transition for.
///
/// Carries both halves because the pair is the diagnosis: neither alone says what was
/// attempted. A caller must not recover by picking a nearby legal transition
/// (ADR-MCPRE-057 §12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidTransition {
    pub(crate) state: RuntimeState,
    pub(crate) event: RuntimeEvent,
}

impl std::fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "illegal runtime transition: {:?} has no transition for {:?}",
            self.state, self.event
        )
    }
}

/// So a startup path returning `Result<_, String>` can propagate an illegal transition
/// with `?` rather than flattening it into a bare message at each call site.
impl From<InvalidTransition> for String {
    fn from(e: InvalidTransition) -> String {
        format!("internal error: {e}")
    }
}

impl RuntimeState {
    /// Whether this state admits new request lifecycles (ADR-MCPRE-057 §8.2).
    ///
    /// No production consumer yet: the request lifecycle it gates is ADR-MCPRE-058 §17A
    /// step 7. Stated and tested here because it is the parent half of the hierarchy —
    /// §8.2 is a property of the RUNTIME state, and defining it beside the states it
    /// classifies is what keeps it from being re-derived, differently, at the request
    /// seam later.
    #[allow(dead_code)]
    pub(crate) fn admits_requests(self) -> bool {
        matches!(self, RuntimeState::Serving)
    }

    /// Whether the process has finished, by either terminal route. Used by the transition
    /// tests; the production teardown asserts the exact terminal state instead.
    #[allow(dead_code)]
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, RuntimeState::Stopped | RuntimeState::FailedToStart)
    }
}

/// The whole legal transition relation. Anything absent is illegal, by construction:
/// the fallthrough arm cannot be reached by a pair listed above it, and a pair listed
/// nowhere has no other way to be accepted.
///
/// Written as one match rather than a table of tuples so that the compiler, not a
/// reviewer, is what proves the relation is total over the input pairs.
pub(crate) fn transition(
    state: RuntimeState,
    event: RuntimeEvent,
) -> Result<RuntimeState, InvalidTransition> {
    use RuntimeEvent as E;
    use RuntimeState as S;
    let next = match (state, event) {
        (S::Configured, E::ValidationSucceeded) => S::Validated,
        (S::Validated, E::PlanBuilt) => S::Planned,
        (S::Planned, E::MaterializationStarted) => S::Materializing,
        (S::Materializing, E::MaterializationSucceeded) => S::Materialized,
        // The failure route is a first-class transition, not an unwind. F3: today a
        // failure between the first acquisition and `MaterializedRuntime::new` unwinds
        // locals in reverse DECLARATION order, which is the "correct by accident" property
        // that type exists to eliminate. Naming the transition is what lets an owner take
        // responsibility for the reclaim.
        (S::Materializing, E::MaterializationFailed) => S::FailedToStart,
        (S::Materialized, E::ServingStarted) => S::Serving,
        (S::Serving, E::ShutdownRequested) => S::Draining,
        (S::Draining, E::FleetDrained) => S::Transitioning,
        (S::Transitioning, E::SecurityTransitionCompleted) => S::Reclaiming,
        (S::Reclaiming, E::ResourceReclaimCompleted) => S::Stopped,
        (state, event) => return Err(InvalidTransition { state, event }),
    };
    Ok(next)
}

/// The runtime's lifecycle position, advanced only through [`transition`].
///
/// Owned by the startup/shutdown thread. An illegal event leaves the state UNCHANGED and
/// reports — it never advances, never falls back to a nearby legal state, and never
/// grants authority (ADR-MCPRE-057 §12).
#[derive(Debug)]
pub(crate) struct RuntimeLifecycle {
    state: RuntimeState,
}

impl RuntimeLifecycle {
    /// A lifecycle at the beginning: arguments in hand, nothing validated.
    pub(crate) fn new() -> Self {
        RuntimeLifecycle {
            state: RuntimeState::Configured,
        }
    }

    pub(crate) fn state(&self) -> RuntimeState {
        self.state
    }

    /// Apply `event`. On success the new state is returned and stored; on failure the
    /// state is untouched.
    pub(crate) fn apply(&mut self, event: RuntimeEvent) -> Result<RuntimeState, InvalidTransition> {
        let next = transition(self.state, event)?;
        self.state = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RuntimeEvent as E;
    use RuntimeState as S;

    const STATES: [RuntimeState; 11] = [
        S::Configured,
        S::Validated,
        S::Planned,
        S::Materializing,
        S::Materialized,
        S::Serving,
        S::Draining,
        S::Transitioning,
        S::Reclaiming,
        S::Stopped,
        S::FailedToStart,
    ];
    const EVENTS: [RuntimeEvent; 10] = [
        E::ValidationSucceeded,
        E::PlanBuilt,
        E::MaterializationStarted,
        E::MaterializationSucceeded,
        E::MaterializationFailed,
        E::ServingStarted,
        E::ShutdownRequested,
        E::FleetDrained,
        E::SecurityTransitionCompleted,
        E::ResourceReclaimCompleted,
    ];

    /// The relation, restated here as data so the test compares two independent
    /// expressions of it. Restating the match arms in the same shape would only assert
    /// that the file equals itself.
    const LEGAL: [(RuntimeState, RuntimeEvent, RuntimeState); 10] = [
        (S::Configured, E::ValidationSucceeded, S::Validated),
        (S::Validated, E::PlanBuilt, S::Planned),
        (S::Planned, E::MaterializationStarted, S::Materializing),
        (
            S::Materializing,
            E::MaterializationSucceeded,
            S::Materialized,
        ),
        (S::Materializing, E::MaterializationFailed, S::FailedToStart),
        (S::Materialized, E::ServingStarted, S::Serving),
        (S::Serving, E::ShutdownRequested, S::Draining),
        (S::Draining, E::FleetDrained, S::Transitioning),
        (
            S::Transitioning,
            E::SecurityTransitionCompleted,
            S::Reclaiming,
        ),
        (S::Reclaiming, E::ResourceReclaimCompleted, S::Stopped),
    ];

    /// Every one of the 110 (state, event) pairs is either in `LEGAL` with exactly that
    /// successor, or rejected. There is no third outcome.
    ///
    /// The broken implementation this catches: a fallthrough arm that returns
    /// `Ok(current)` for an unlisted pair, silently ignoring an illegal event instead of
    /// reporting it. That reads as harmless — the state did not change — and it is exactly
    /// how an out-of-order or duplicated event stops being visible.
    #[test]
    fn every_state_event_pair_is_either_explicitly_legal_or_rejected() {
        for state in STATES {
            for event in EVENTS {
                let expected = LEGAL
                    .iter()
                    .find(|(s, e, _)| *s == state && *e == event)
                    .map(|(_, _, next)| *next);
                match (transition(state, event), expected) {
                    (Ok(got), Some(want)) => assert_eq!(
                        got, want,
                        "{state:?} + {event:?} must reach {want:?}, reached {got:?}"
                    ),
                    (Err(e), None) => {
                        assert_eq!(e.state, state);
                        assert_eq!(e.event, event);
                    }
                    (Ok(got), None) => panic!(
                        "{state:?} + {event:?} is not a legal transition but was accepted, \
                         reaching {got:?}"
                    ),
                    (Err(_), Some(want)) => {
                        panic!("{state:?} + {event:?} must reach {want:?} but was rejected")
                    }
                }
            }
        }
    }

    /// Count the legal pairs, so shrinking the relation cannot pass by making both sides
    /// of the test above agree on less.
    #[test]
    fn the_relation_has_exactly_ten_legal_transitions() {
        let legal = STATES
            .iter()
            .flat_map(|s| EVENTS.iter().map(move |e| (*s, *e)))
            .filter(|(s, e)| transition(*s, *e).is_ok())
            .count();
        assert_eq!(legal, LEGAL.len(), "the transition relation changed size");
    }

    /// Terminal means terminal. No event revives a finished process.
    ///
    /// The broken implementation this catches: a `Stopped -> Serving` or
    /// `FailedToStart -> Materializing` arm added to support a restart-in-place feature,
    /// which would make every post-owner guarantee in the planes conditional on nobody
    /// using it.
    #[test]
    fn no_event_moves_a_terminal_state() {
        for state in [S::Stopped, S::FailedToStart] {
            for event in EVENTS {
                assert!(
                    transition(state, event).is_err(),
                    "{state:?} is terminal but {event:?} moved it"
                );
            }
        }
    }

    /// The drain law: reaching `Transitioning` is possible only through `Draining`, and
    /// only via the event that proves the fleet joined.
    ///
    /// The broken implementation this catches: a `Serving -> Transitioning` shortcut added
    /// so shutdown "goes faster", which would start retiring signers and staling trust
    /// while requests were still being served — the ordering `MaterializedRuntime`
    /// documents and nothing else enforces.
    #[test]
    fn transitioning_is_reachable_only_from_draining_on_fleet_drained() {
        for state in STATES {
            for event in EVENTS {
                if transition(state, event) == Ok(S::Transitioning) {
                    assert_eq!(
                        (state, event),
                        (S::Draining, E::FleetDrained),
                        "the security transition must follow a proven drain"
                    );
                }
            }
        }
    }

    /// Only `Serving` admits requests — in particular `Draining` does not
    /// (ADR-MCPRE-057 §8.2).
    #[test]
    fn only_serving_admits_new_requests() {
        for state in STATES {
            assert_eq!(
                state.admits_requests(),
                state == S::Serving,
                "{state:?} disagreed about admitting requests"
            );
        }
    }

    /// A rejected event leaves the lifecycle exactly where it was.
    ///
    /// The broken implementation this catches: `apply` writing the state before checking
    /// the transition, or committing a partially-computed successor on the error path.
    #[test]
    fn a_rejected_event_does_not_advance_the_lifecycle() {
        let mut lifecycle = RuntimeLifecycle::new();
        lifecycle.apply(E::ValidationSucceeded).unwrap();
        let before = lifecycle.state();

        let err = lifecycle
            .apply(E::ServingStarted)
            .expect_err("Validated has no transition for ServingStarted");
        assert_eq!(err.state, S::Validated);
        assert_eq!(err.event, E::ServingStarted);
        assert_eq!(
            lifecycle.state(),
            before,
            "the state moved on a rejected event"
        );

        // And the lifecycle is still usable: the rejection was not a poisoning.
        assert_eq!(lifecycle.apply(E::PlanBuilt).unwrap(), S::Planned);
    }

    /// The whole successful path, in order, ending Stopped.
    #[test]
    fn the_ordinary_lifecycle_runs_from_configured_to_stopped() {
        let mut lifecycle = RuntimeLifecycle::new();
        assert_eq!(lifecycle.state(), S::Configured);
        for (event, expected) in [
            (E::ValidationSucceeded, S::Validated),
            (E::PlanBuilt, S::Planned),
            (E::MaterializationStarted, S::Materializing),
            (E::MaterializationSucceeded, S::Materialized),
            (E::ServingStarted, S::Serving),
            (E::ShutdownRequested, S::Draining),
            (E::FleetDrained, S::Transitioning),
            (E::SecurityTransitionCompleted, S::Reclaiming),
            (E::ResourceReclaimCompleted, S::Stopped),
        ] {
            assert_eq!(lifecycle.apply(event).unwrap(), expected);
        }
        assert!(lifecycle.state().is_terminal());
    }

    /// The failure path is terminal and distinct: a failed startup never served, so it
    /// must not be reachable into the drain sequence.
    #[test]
    fn a_failed_materialization_ends_distinctly_from_a_served_shutdown() {
        let mut lifecycle = RuntimeLifecycle::new();
        lifecycle.apply(E::ValidationSucceeded).unwrap();
        lifecycle.apply(E::PlanBuilt).unwrap();
        lifecycle.apply(E::MaterializationStarted).unwrap();
        assert_eq!(
            lifecycle.apply(E::MaterializationFailed).unwrap(),
            S::FailedToStart
        );
        assert!(lifecycle.state().is_terminal());
        assert_ne!(
            lifecycle.state(),
            S::Stopped,
            "a startup that never served must not be indistinguishable from a clean \
             shutdown; the drain-ordering law does not apply to it"
        );
    }
}
