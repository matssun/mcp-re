// SPDX-License-Identifier: Apache-2.0
//! The `ContinuationControl` configuration machine — `work/CONFIG-STATE-ATLAS.md` §C.7.
//!
//! Whether multi-round-trip flows resolve across replicas (ADR-MCPS-047). Two states:
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `Disabled` | — | the continuation locator | — |
//! | `Redis` | the continuation locator | — | scheme-bearing URL |
//!
//! **`Disabled` is a state, not missing configuration.** MRTR continuation correlation is
//! an OPTIONAL capability an operator selects with `--continuation-control-redis-url`, so
//! `Disabled` says the capability was not selected — not that it is unavailable this time.
//! Absence is announced at startup and installs NO correlation store: there is no
//! node-local fallback tier, so a deployment in this state cannot complete a
//! continuation-dependent leg at all, and the legs say so rather than guessing.
//!
//! What this state does NOT permit is the reverse. A `Shared` state names a store the
//! deployment asked for, and a runtime that cannot establish it refuses startup rather
//! than serving `Disabled` — a selected security capability is never silently downgraded.
//! In that respect this machine behaves exactly like `Admission`; only the meaning of the
//! omitted flag differs.
//!
//! **This machine has no relation to `Replay` (CF-12).** The apparent dependency was an
//! alias: one field, `replay_redis_url`, carried two different facts — where admitted
//! nonces live, and where a retained continuation base lives. Sharing a backend technology
//! and a cargo feature with `Replay` is not a semantic edge. The endpoints may name the
//! same Redis, and when they do that is an operator's deployment choice.

use crate::deployment_request::{DeploymentRequest, SharedStoreRequest};

/// Which continuation-control state a configuration requests.
///
/// The representation is private to this module. [`classify_and_validate`] is the only
/// producer, so possessing this state IS the statement that the locator it carries was
/// checked for shape. As with the CRL machine, presence IS the classification — the
/// locator's presence is what makes the state shared — so the state cannot exist without
/// the value that selected it and no fallible build step is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationControlState {
    kind: ContinuationKind,
}

/// The two states, as the owner's own representation.
///
/// Private to this module: every consumer of this state lives in this crate, so a `pub`
/// variant would be constructible by all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ContinuationKind {
    /// No shared store was selected, so no correlation store is installed and a
    /// continuation-dependent leg cannot complete.
    Disabled,
    /// A shared store, so a flow opened on one replica can be answered on another.
    Shared {
        /// Where retained continuation bases live.
        endpoint: String,
    },
}

impl ContinuationControlState {
    /// Whether a shared continuation store is requested.
    pub fn is_shared(&self) -> bool {
        matches!(self.kind, ContinuationKind::Shared { .. })
    }

    /// What establishing continuation control requires, as this owner states it.
    ///
    /// The projection replaces a match on the representation performed in planning.
    /// Whether a deployment resolves flows across replicas, and which store it does that
    /// with, is this machine's semantics; a planner that re-read the locator would be a
    /// second authority over the same question.
    pub fn continuation_plan(&self) -> ContinuationControlPlan {
        match &self.kind {
            ContinuationKind::Disabled => ContinuationControlPlan { store: None },
            ContinuationKind::Shared { endpoint } => ContinuationControlPlan {
                store: Some(endpoint.clone()),
            },
        }
    }
}

/// Whether multi-round-trip flows resolve across replicas, and at which store.
///
/// Produced only by [`ContinuationControlState::continuation_plan`]. The endpoint is
/// private, so no consumer can name a continuation store the configuration did not.
///
/// The endpoint is the continuation store's OWN. It is not the replay store's, even when
/// an operator points both at the same Redis (CF-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationControlPlan {
    store: Option<String>,
}

impl ContinuationControlPlan {
    /// The shared store to establish, or `None` when flows resolve on the replica that
    /// opened them.
    pub fn shared_store(&self) -> Option<&str> {
        self.store.as_deref()
    }

    /// Whether establishing this plan needs the shared control runtime.
    ///
    /// One contributor to the aggregate — never the decision itself.
    pub fn needs_control_runtime(&self) -> bool {
        cfg!(feature = "redis_replay") && self.store.is_some()
    }
}

/// Recognise the requested state. Total: presence of the locator IS the request.
fn classify(config: &DeploymentRequest) -> ContinuationControlState {
    ContinuationControlState {
        kind: match &config.continuation_control.shared {
            Some(store) => ContinuationKind::Shared {
                endpoint: store.locator().to_string(),
            },
            None => ContinuationKind::Disabled,
        },
    }
}

/// Classify the requested continuation-control state and check its columns.
///
/// Only the build-independent shape of the URL is checked. Whether this binary has a Redis
/// client is layer B, and whether the store answers is layer C.
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (ContinuationControlState, Vec<String>) {
    let state = classify(config);
    let mut violations = Vec::new();
    if let Some(url) = config
        .continuation_control
        .shared
        .as_ref()
        .map(SharedStoreRequest::locator)
    {
        if !url.contains("://") {
            violations.push(format!(
                "--continuation-control-redis-url {url:?} is not a URL: give a \
                 scheme-bearing URL such as redis://host:6379, or omit the flag to run \
                 with MRTR continuation correlation OFF"
            ));
        }
    }
    (state, violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn run(mutate: impl FnOnce(&mut DeploymentRequest)) -> (ContinuationControlState, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let (state, violations) = run(|_| {});
        assert!(!state.is_shared());
        assert_eq!(state.continuation_plan().shared_store(), None);
        assert!(violations.is_empty(), "{violations:?}");

        let (state, violations) = run(|c| {
            c.continuation_control.shared =
                Some(SharedStoreRequest::redis("redis://127.0.0.1:6379"));
        });
        assert_eq!(
            state.continuation_plan().shared_store(),
            Some("redis://127.0.0.1:6379")
        );
        assert!(violations.is_empty(), "{violations:?}");
        assert!(state.is_shared());
    }

    /// The negative control for CF-12: absence is a posture the model names, so the
    /// classifier must produce a state rather than treat it as an under-specified one.
    #[test]
    fn disabled_is_a_state_and_not_a_missing_value() {
        let (state, violations) = run(|c| c.continuation_control.shared = None);
        assert!(!state.is_shared());
        assert_eq!(state.continuation_plan().shared_store(), None);
        assert!(
            violations.is_empty(),
            "absence must not be reported as a defect: {violations:?}"
        );
        assert!(!state.is_shared());
    }

    #[test]
    fn a_locator_that_cannot_name_a_store_is_refused() {
        let (_, violations) = run(|c| {
            c.continuation_control.shared = Some(SharedStoreRequest::redis("127.0.0.1:6379"));
        });
        assert!(
            violations.iter().any(|v| v.contains("is not a URL")),
            "{violations:?}"
        );
    }

    /// The independence CF-12 exists to establish, at this machine's own level: the
    /// replay tier does not reach the continuation state.
    #[test]
    fn the_replay_tier_does_not_reach_this_machine() {
        let shared = |c: &mut DeploymentRequest| {
            c.continuation_control.shared =
                Some(SharedStoreRequest::redis("redis://127.0.0.1:6379"));
        };
        assert_eq!(
            run(|c| {
                c.replay.durability = Some(crate::ReplayDurabilityTier::Linearizable);
                shared(c);
            })
            .0
            .continuation_plan()
            .shared_store(),
            Some("redis://127.0.0.1:6379")
        );
        assert_eq!(
            run(|c| {
                c.replay.store = Some(crate::deployment_request::ReplayStoreRequest::redis(
                    "redis://127.0.0.1:6379",
                ));
            })
            .0
            .continuation_plan()
            .shared_store(),
            None,
            "the replay store's URL must no longer switch this machine on"
        );
    }
}
