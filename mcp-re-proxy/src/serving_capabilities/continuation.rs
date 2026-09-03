// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPS-047 — the shared store that carries a multi-round-trip continuation across a
//! replica switch, established as the deployment selected it.
//!
//! # The capability is OPTIONAL, and selecting it is not the same as omitting it
//!
//! `--continuation-control-redis-url` is an explicit operator selection, so this seam has
//! two legitimate outcomes and one illegitimate one:
//!
//! | plan | outcome |
//! |---|---|
//! | no locator | the capability was not selected; OFF, and nothing is installed |
//! | a locator, and it establishes | ON, with exactly the selected store |
//! | a locator, and it cannot establish | startup REFUSES |
//!
//! The third row includes a build that lacks the backend. An operator who named a store
//! asked for cross-replica continuation, and a binary that cannot provide it must say so
//! rather than serve a deployment that silently holds a weaker posture than the one it was
//! configured with — the same rule admission follows, and for the same reason.
//!
//! # OFF installs nothing, and never a local substitute
//!
//! OFF is not a downgrade to a node-local tier. The composition root installs no store at
//! all, and the legs know it: the open leg refuses instead of returning an elicitation
//! nothing was kept for, and an answer leg needing correlation is refused as a fact about
//! this deployment. Installing an in-memory tier here to widen what OFF can do would be a
//! second capability with a different scope, and nobody selected it.

use std::sync::Arc;

use super::Established;

/// The OFF line, in every build that was not given a continuation locator.
///
/// It says what this deployment CANNOT do, and does not promise a weaker tier in place of
/// the one that is absent. It is NOT "single-replica MRTR": no node-local tier is
/// installed, and installing one to make that sentence true would be a second,
/// differently-scoped capability nobody selected.
///
/// One line for both build profiles, because the operator's next step is the same in each:
/// a build without the backend REFUSES this flag rather than serving a weaker posture, so
/// at the OFF branch there is no build-specific advice to give — the flag is simply absent.
const CONTINUATION_STORE_OFF: &str =
    "MRTR continuation correlation = OFF (no --continuation-control-redis-url): no \
     correlation store is installed, so a continuation-dependent leg cannot complete. An \
     `input_required` reply is refused at the point it would be opened rather than \
     returned unanswerable. Set --continuation-control-redis-url to select the shared \
     store.";

/// The refusal for a build asked for a capability it does not carry.
///
/// A missing backend is a fact about the BUILD, so the diagnostic names the build rather
/// than the flag: the flag is already set, and telling an operator to set it again sends
/// them nowhere.
#[cfg(not(feature = "redis_replay"))]
const CONTINUATION_STORE_NO_BACKEND: &str =
    "--continuation-control-redis-url selects the shared MRTR continuation store, and \
     this build lacks the `redis_replay` feature that implements it. A selected security \
     capability is never silently downgraded to OFF: use a binary built with \
     `redis_replay`, or omit the flag to run with continuation correlation OFF.";

/// Establish the capability the plan selected — the arm that CAN establish one.
#[cfg(feature = "redis_replay")]
pub(crate) fn mrtr_continuation_store(
    plan: &crate::startup_plan::ContinuationControlPlan,
    control: Option<&crate::control_runtime::ControlRuntime>,
) -> Result<Established<Arc<dyn crate::continuation_store::AsyncContinuationStore>>, String> {
    let Some(url) = plan.shared_store() else {
        return Ok(Established::off(CONTINUATION_STORE_OFF));
    };
    let handle = control
        .ok_or(
            "internal error: the plan declared the continuation store needs the control runtime",
        )?
        .handle();
    let store = handle
        .block_on(crate::redis_continuation_store::RedisContinuationStore::connect(url))
        .map_err(|e| format!("connect redis continuation store: {e}"))?;
    Ok(Established::on(
        Arc::new(store) as Arc<dyn crate::continuation_store::AsyncContinuationStore>,
        format!(
            "MRTR continuation correlation = ON (shared async Redis backend, TTL {}s)",
            crate::http_profile_serve::DEFAULT_CONTINUATION_TTL_SECS
        ),
    ))
}

/// The same seam in a build without the backend.
///
/// The two arms differ only in what they can do with a SELECTED store, and that difference
/// is a refusal rather than a posture: a plan naming a store this build cannot establish is
/// refused by name. Deliberately not `Established::off` — an ignored selection is the
/// silent weakening this seam exists to prevent, and in the transcript it would be
/// indistinguishable from an operator who never set the flag.
#[cfg(not(feature = "redis_replay"))]
pub(crate) fn mrtr_continuation_store(
    plan: &crate::startup_plan::ContinuationControlPlan,
    _control: Option<&crate::control_runtime::ControlRuntime>,
) -> Result<Established<Arc<dyn crate::continuation_store::AsyncContinuationStore>>, String> {
    if plan.shared_store().is_some() {
        return Err(CONTINUATION_STORE_NO_BACKEND.to_string());
    }
    Ok(Established::off(CONTINUATION_STORE_OFF))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;
    use crate::deployment_request::{DeploymentRequest, SharedStoreRequest};

    /// The plan for a request, reached the only way a plan can be reached: through the
    /// owning machine's own classification. A plan built by hand would let this measure a
    /// selection the configuration boundary never accepted.
    fn plan_for(
        mutate: impl FnOnce(&mut DeploymentRequest),
    ) -> crate::startup_plan::ContinuationControlPlan {
        let mut config = legal_config();
        mutate(&mut config);
        let (state, violations) =
            crate::config_state::continuation_control::classify_and_validate(&config);
        assert!(violations.is_empty(), "{violations:?}");
        state.continuation_plan()
    }

    fn no_locator() -> crate::startup_plan::ContinuationControlPlan {
        plan_for(|c| c.continuation_control.shared = None)
    }

    fn selected() -> crate::startup_plan::ContinuationControlPlan {
        plan_for(|c| {
            c.continuation_control.shared =
                Some(SharedStoreRequest::redis("redis://127.0.0.1:6379"))
        })
    }

    /// CONTROL 1 — an unselected capability is OFF, and OFF installs NOTHING.
    ///
    /// The second half is the one that matters and the one no type enforces: `Established`
    /// makes an ON posture over nothing unrepresentable, and says nothing at all about an
    /// OFF posture quietly carrying a node-local artifact. That is the substitution the
    /// 2026-09-03 ruling forbids, so it is asserted here rather than assumed.
    #[test]
    fn an_unselected_capability_is_off_and_installs_no_store() {
        let (artifact, posture) = mrtr_continuation_store(&no_locator(), None)
            .expect("omitting the flag is a legitimate posture, not a refusal")
            .into_parts();
        assert!(
            artifact.is_none(),
            "OFF installed a store: a deployment that selected nothing now holds a \
             capability nobody asked for"
        );
        assert!(matches!(posture, crate::startup_posture::SeamState::Off(_)));
    }

    /// CONTROL 5 — the OFF line does not describe a tier this deployment does not have.
    ///
    /// A posture line is the operator-facing half of the same claim, and it drifted before:
    /// it promised "single-replica MRTR" while the composition root installed no store at
    /// all. A line that names a fallback is evidence someone reintroduced one.
    #[test]
    fn the_off_line_promises_no_local_fallback() {
        let (_, posture) = mrtr_continuation_store(&no_locator(), None)
            .expect("OFF is not a refusal")
            .into_parts();
        let crate::startup_posture::SeamState::Off(line) = posture else {
            panic!("an unselected capability must be OFF");
        };
        let lowered = line.to_lowercase();
        for forbidden in ["single-replica", "in-memory", "in memory", "node-local"] {
            assert!(
                !lowered.contains(forbidden),
                "the OFF line claims {forbidden:?}, which this deployment does not have: {line}"
            );
        }
        assert!(
            lowered.contains("--continuation-control-redis-url"),
            "an OFF line must name what turns the capability on: {line}"
        );
    }

    /// CONTROL 3 — a SELECTED capability this build cannot carry refuses startup.
    ///
    /// The defect this replaces returned `Established::off` here, so a binary without the
    /// backend served a deployment whose operator had asked for cross-replica continuation
    /// and whose transcript was byte-identical to one that never asked. Compiled only in
    /// the arm that has the defect to make.
    #[cfg(not(feature = "redis_replay"))]
    #[test]
    fn a_selected_capability_this_build_cannot_carry_refuses_startup() {
        let refusal = mrtr_continuation_store(&selected(), None)
            .err()
            .expect("a selected capability this build lacks must refuse, never announce OFF");
        assert!(
            refusal.contains("redis_replay"),
            "the refusal must name the missing build capability: {refusal}"
        );
    }

    /// CONTROL 4 — a SELECTED capability that cannot be established refuses startup.
    ///
    /// Reached without a store to connect to: the plan says the establishment needs the
    /// control runtime and none is offered, so the seam cannot produce the artifact it was
    /// asked for. What is under test is the DIRECTION — an establishment that does not
    /// happen is an error, never an OFF posture.
    #[cfg(feature = "redis_replay")]
    #[test]
    fn a_selected_capability_that_cannot_be_established_refuses_startup() {
        assert!(
            mrtr_continuation_store(&selected(), None).is_err(),
            "a selected store that cannot be established must refuse, never announce OFF"
        );
    }

    /// The plan is the OWNER's projection, and both arms read the same one.
    ///
    /// Without this the controls above could be satisfied by a seam reading some other
    /// value: what makes them claims about the deployment's SELECTION is that the input
    /// came from the continuation-control machine's own classification.
    #[test]
    fn the_seam_reads_the_owners_projection_and_not_a_locator_of_its_own() {
        assert_eq!(no_locator().shared_store(), None);
        assert_eq!(selected().shared_store(), Some("redis://127.0.0.1:6379"));
    }
}
