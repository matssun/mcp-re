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
//! **`Disabled` is a state, not missing configuration.** Cross-replica MRTR is
//! *opportunistic*: nothing requests it, its absence is announced rather than refused, and
//! the dependent leg fails closed on its own — an answer reaching a replica with no
//! correlated continuation is refused with `mcp-re.continuation_binding_failed`, never
//! guessed. That is the codebase's own rule for opportunistic capabilities, and it is why
//! this `Disabled` behaves unlike `Admission = Off`, which is an operator's decision about
//! whether a gate applies at all.
//!
//! **This machine has no relation to `Replay` (CF-12).** The apparent dependency was an
//! alias: one field, `replay_redis_url`, carried two different facts — where admitted
//! nonces live, and where a retained continuation base lives. Sharing a backend technology
//! and a cargo feature with `Replay` is not a semantic edge. The endpoints may name the
//! same Redis, and when they do that is an operator's deployment choice.

use crate::deployment_request::DeploymentRequest;

/// Which continuation-control state a configuration requests.
///
/// `Redis` carries its locator. As with the CRL machine, presence IS the classification
/// here — the locator's presence is what makes the state `Redis` — so the state cannot
/// exist without the value that selected it and no fallible build step is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuationControlState {
    /// No shared store. Multi-round-trip flows are single-replica; a cross-replica answer
    /// is refused at the binding.
    Disabled,
    /// A shared Redis store, so a flow opened on one replica can be answered on another.
    Redis {
        /// Where retained continuation bases live.
        endpoint: String,
    },
}

impl ContinuationControlState {
    /// Whether a shared continuation store is requested.
    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Redis { .. })
    }
}

/// Recognise the requested state. Total: presence of the locator IS the request.
fn classify(config: &DeploymentRequest) -> ContinuationControlState {
    match &config.continuation_control_redis_url {
        Some(endpoint) => ContinuationControlState::Redis {
            endpoint: endpoint.clone(),
        },
        None => ContinuationControlState::Disabled,
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
    if let Some(url) = &config.continuation_control_redis_url {
        if !url.contains("://") {
            violations.push(format!(
                "--continuation-control-redis-url {url:?} is not a URL: give a \
                 scheme-bearing URL such as redis://host:6379, or omit the flag to run \
                 multi-round-trip flows single-replica"
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
        assert_eq!(state, ContinuationControlState::Disabled);
        assert!(violations.is_empty(), "{violations:?}");

        let (state, violations) = run(|c| {
            c.continuation_control_redis_url = Some("redis://127.0.0.1:6379".to_string());
        });
        assert_eq!(
            state,
            ContinuationControlState::Redis {
                endpoint: "redis://127.0.0.1:6379".to_string()
            }
        );
        assert!(violations.is_empty(), "{violations:?}");
        assert!(state.is_shared());
    }

    /// The negative control for CF-12: absence is a posture the model names, so the
    /// classifier must produce a state rather than treat it as an under-specified one.
    #[test]
    fn disabled_is_a_state_and_not_a_missing_value() {
        let (state, violations) = run(|c| c.continuation_control_redis_url = None);
        assert_eq!(state, ContinuationControlState::Disabled);
        assert!(
            violations.is_empty(),
            "absence must not be reported as a defect: {violations:?}"
        );
        assert!(!state.is_shared());
    }

    #[test]
    fn a_locator_that_cannot_name_a_store_is_refused() {
        let (_, violations) = run(|c| {
            c.continuation_control_redis_url = Some("127.0.0.1:6379".to_string());
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
            c.continuation_control_redis_url = Some("redis://127.0.0.1:6379".to_string());
        };
        assert_eq!(
            run(|c| {
                c.replay_durability_tier = Some(crate::ReplayDurabilityTier::Linearizable);
                shared(c);
            })
            .0,
            ContinuationControlState::Redis {
                endpoint: "redis://127.0.0.1:6379".to_string()
            }
        );
        assert_eq!(
            run(|c| {
                c.replay_redis_url = Some("redis://127.0.0.1:6379".to_string());
            })
            .0,
            ContinuationControlState::Disabled,
            "the replay store's URL must no longer switch this machine on"
        );
    }
}
