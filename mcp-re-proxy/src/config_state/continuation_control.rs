// SPDX-License-Identifier: Apache-2.0
//! The `ContinuationControl` configuration machine — `work/CONFIG-STATE-ATLAS.md` §C.7.
//!
//! Whether multi-round-trip flows resolve across replicas (ADR-MCPS-047). Two states:
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `Disabled` | — | the continuation locator, a live-entry bound | — |
//! | `Redis` | the continuation locator | — | scheme-bearing URL; bound within range |
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
//! omitted flag differs. Where §C.7's "opportunistic" / `continuation_binding_failed`
//! paragraph disagrees, the governing rule is THM-0093 (`verification/policy/theorems.toml`):
//! a deployment holding no correlation store refuses a dependent leg before admission as a
//! fact about the deployment, and a selected store that cannot establish refuses startup
//! (`proxy.continuation_materialization`).
//!
//! **This machine has no relation to `Replay` (CF-12).** The apparent dependency was an
//! alias: one field, `replay_redis_url`, carried two different facts — where admitted
//! nonces live, and where a retained continuation base lives. Sharing a backend technology
//! and a crate feature with `Replay` is not a semantic edge. The endpoints may name the
//! same Redis, and when they do that is an operator's deployment choice.

use crate::continuation_store::ContinuationCapacity;
use crate::deployment_request::{DeploymentRequest, RedactedLocator, SharedStoreRequest};

/// Which continuation-control state a configuration requests.
///
/// The representation is private to this module. [`classify_and_validate`] is the only
/// producer, so possessing this state IS the statement that the locator it carries was
/// checked for shape. Presence of the locator is what selects the shared state, and the
/// classifier names no state at all for a locator that fails the shape guard.
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
        endpoint: SharedStoreRequest,
        /// How many live entries that store may hold.
        capacity: ContinuationCapacity,
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
            ContinuationKind::Shared { endpoint, capacity } => ContinuationControlPlan {
                store: Some((endpoint.clone(), *capacity)),
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
    store: Option<(SharedStoreRequest, ContinuationCapacity)>,
}

impl ContinuationControlPlan {
    /// The shared store to establish, or `None` when none was selected — no correlation
    /// store is installed and a continuation-dependent leg is refused as a fact about the
    /// deployment (THM-0093).
    pub fn shared_store(&self) -> Option<&str> {
        self.store.as_ref().map(|(endpoint, _)| endpoint.locator())
    }

    /// The shared store to establish and the live-entry bound it is established with, or
    /// `None` when none was selected.
    pub fn shared(&self) -> Option<(&str, ContinuationCapacity)> {
        self.store
            .as_ref()
            .map(|(endpoint, capacity)| (endpoint.locator(), *capacity))
    }

    /// Whether establishing this plan needs the shared control runtime.
    ///
    /// One contributor to the aggregate — never the decision itself.
    pub fn needs_control_runtime(&self) -> bool {
        cfg!(feature = "redis_replay") && self.store.is_some()
    }
}

/// Whether `locator` opens with an RFC 3986 scheme followed by `://`.
fn is_scheme_bearing(locator: &str) -> bool {
    let Some((scheme, _)) = locator.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Classify the requested continuation-control state and check its columns.
///
/// Presence of the locator IS the request. `Some(Disabled)` when none is configured; `None`
/// with the refusal when the locator fails the shape guard, so no shared state is ever built
/// from an unchecked locator.
///
/// Only the build-independent shape of the URL is checked. Whether this binary has a Redis
/// client is layer B, and whether the store answers is layer C. A stated live-entry bound
/// must be in range, and with no store it bounds nothing and is refused.
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<ContinuationControlState>, Vec<String>) {
    let stated = config.continuation_control.max_live_entries;
    if let (None, Some(n)) = (&config.continuation_control.shared, stated) {
        return (
            None,
            vec![format!(
                "--continuation-max-live-entries {n} bounds the shared \
                 continuation store, and none is selected: give \
                 --continuation-control-redis-url, or omit the bound"
            )],
        );
    }
    let Some(store) = config.continuation_control.shared.as_ref() else {
        return (
            Some(ContinuationControlState {
                kind: ContinuationKind::Disabled,
            }),
            Vec::new(),
        );
    };
    let capacity = match stated.map(ContinuationCapacity::new) {
        None => ContinuationCapacity::DEFAULT,
        Some(Ok(capacity)) => capacity,
        Some(Err(refusal)) => return (None, vec![refusal]),
    };
    let url = store.locator();
    if !is_scheme_bearing(url) {
        return (
            None,
            vec![format!(
                "--continuation-control-redis-url {} is not a URL: give a \
                 scheme-bearing URL such as redis://host:6379, or omit the flag to run \
                 with MRTR continuation correlation OFF",
                RedactedLocator::of(url)
            )],
        );
    }
    (
        Some(ContinuationControlState {
            kind: ContinuationKind::Shared {
                endpoint: store.clone(),
                capacity,
            },
        }),
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn run(
        mutate: impl FnOnce(&mut DeploymentRequest),
    ) -> (Option<ContinuationControlState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let (state, violations) = run(|_| {});
        let state = state.expect("a legal locator names a state");
        assert!(!state.is_shared());
        assert_eq!(state.continuation_plan().shared_store(), None);
        assert!(violations.is_empty(), "{violations:?}");

        let (state, violations) = run(|c| {
            c.continuation_control.shared =
                Some(SharedStoreRequest::redis("redis://127.0.0.1:6379"));
        });
        let state = state.expect("a legal locator names a state");
        assert_eq!(
            state.continuation_plan().shared_store(),
            Some("redis://127.0.0.1:6379")
        );
        assert!(violations.is_empty(), "{violations:?}");
        assert!(state.is_shared());
    }

    /// A shared store carries its live-entry bound: the stated one when in range, the
    /// default when none was stated. Out of range, or stated with no store to bound, is
    /// refused and names no state.
    #[test]
    fn the_shared_store_carries_a_bound_and_an_unusable_bound_is_refused() {
        let shared = |c: &mut DeploymentRequest| {
            c.continuation_control.shared = Some(SharedStoreRequest::redis("redis://h:6379"));
        };
        let (state, _) = run(shared);
        assert_eq!(
            state.expect("legal").continuation_plan().shared(),
            Some(("redis://h:6379", ContinuationCapacity::DEFAULT))
        );
        let (state, _) = run(|c| {
            shared(c);
            c.continuation_control.max_live_entries = Some(50);
        });
        assert_eq!(
            state.expect("legal").continuation_plan().shared(),
            Some((
                "redis://h:6379",
                ContinuationCapacity::new(50).expect("in range")
            ))
        );
        let (state, _) = run(|_| {});
        assert_eq!(state.expect("legal").continuation_plan().shared(), None);

        for n in [0, u64::from(ContinuationCapacity::MAX_LIVE_ENTRIES) + 1] {
            let (state, violations) = run(|c| {
                shared(c);
                c.continuation_control.max_live_entries = Some(n);
            });
            assert!(state.is_none(), "{n} is out of range");
            assert!(violations[0].contains("--continuation-max-live-entries"));
        }
        let (state, violations) = run(|c| c.continuation_control.max_live_entries = Some(50));
        assert!(state.is_none(), "a bound with no store bounds nothing");
        assert!(violations[0].contains("--continuation-control-redis-url"));
    }

    /// The negative control for CF-12: absence is a posture the model names, so the
    /// classifier must produce a state rather than treat it as an under-specified one.
    #[test]
    fn disabled_is_a_state_and_not_a_missing_value() {
        let (state, violations) = run(|c| c.continuation_control.shared = None);
        let state = state.expect("absence names the Disabled state");
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
        let (state, violations) = run(|c| {
            c.continuation_control.shared = Some(SharedStoreRequest::redis("127.0.0.1:6379"));
        });
        assert!(state.is_none(), "a refused locator must name no state");
        assert!(
            violations.iter().any(|v| v.contains("is not a URL")),
            "{violations:?}"
        );
    }

    #[test]
    fn a_locator_whose_scheme_is_not_at_its_start_is_refused() {
        for bad in ["127.0.0.1:6379/?next=a://b", "://h:6379", " redis://h:6379"] {
            let (state, violations) = run(|c| {
                c.continuation_control.shared = Some(SharedStoreRequest::redis(bad));
            });
            assert!(state.is_none(), "{bad}: {state:?}");
            assert!(
                violations.iter().any(|v| v.contains("is not a URL")),
                "{bad}: {violations:?}"
            );
        }
        for good in ["rediss://h:6380", "redis+unix:///tmp/r.sock"] {
            let (state, violations) = run(|c| {
                c.continuation_control.shared = Some(SharedStoreRequest::redis(good));
            });
            assert!(state.is_some(), "{good}");
            assert!(violations.is_empty(), "{good}: {violations:?}");
        }
    }

    #[test]
    fn a_state_and_its_plan_debug_print_carries_no_credential() {
        let url = "redis://alice:hunter2@h:6379/0?token=s3cr3t";
        let (state, violations) = run(|c| {
            c.continuation_control.shared = Some(SharedStoreRequest::redis(url));
        });
        assert!(violations.is_empty(), "{violations:?}");
        let state = state.expect("a legal locator names a state");
        let plan = state.continuation_plan();
        for printed in [format!("{state:?}"), format!("{plan:?}")] {
            for secret in ["hunter2", "alice", "s3cr3t", url] {
                assert!(!printed.contains(secret), "{secret} leaked: {printed}");
            }
        }
        assert_eq!(plan.shared_store(), Some(url));
    }

    /// The clause fires exactly when the value has no `://`, which is the shape a
    /// credential-bearing typo takes. It names the locator rather than echoing it.
    #[test]
    fn the_locator_refusal_does_not_echo_a_credential() {
        let (_, violations) = run(|c| {
            c.continuation_control.shared = Some(SharedStoreRequest::redis(
                "mats:hunter2@redis.internal:6379",
            ));
        });
        let refusal = violations
            .iter()
            .find(|v| v.contains("--continuation-control-redis-url"))
            .expect("a value that names no store is refused");
        assert!(
            !refusal.contains("hunter2"),
            "the password reached the diagnostic: {refusal}"
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
            .expect("a legal locator names a state")
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
            .expect("absence names the Disabled state")
            .continuation_plan()
            .shared_store(),
            None,
            "the replay store's URL must no longer switch this machine on"
        );
    }
}
