// SPDX-License-Identifier: Apache-2.0
//! The `Replay` configuration machine — `work/CONFIG-STATE-ATLAS.md` §C.1.
//!
//! Where admitted nonces live, and therefore what replay guarantee the deployment can
//! claim. **Two states**, both shared:
//!
//! | State | Required | Forbidden | Guards | Build |
//! |---|---|---|---|---|
//! | `SharedRedis` | `replay_redis_url`, a Redis quorum tier | `cpstore_etcd_endpoint` | tier meets the strict minimum | `redis_replay` |
//! | `SharedLinearizable` | `cpstore_etcd_endpoint`, the linearizable tier | `replay_redis_url` | — | `cpstore_etcd` |
//!
//! **The durability tier is the only selector.** There is no backend-KIND input beside it.
//! Both states are shared, both are named by their tier, and each tier requires exactly the
//! locator its own backend needs — so the tier plus its witness determines the state with
//! nothing left over to choose.
//!
//! A request that declares no tier names no state. That absence is a REFUSAL, not a
//! fallback to something weaker: there is no node-local store to drop back to, in this or
//! any build.
//!
//! The two sub-strict Redis tiers are **input forms that refuse** — they carry a replay
//! window the strict posture does not accept. They never inhabit [`ReplayState`], because a
//! validated state is one a deployment could be in. They remain in
//! [`ReplayDurabilityTier`] because the dispatcher gates on them at runtime, which is the
//! backstop against a state constructed in-process rather than parsed.
//!
//! Once a legal state IS classified, a missing `redis_replay` or `cpstore_etcd` is layer B
//! and belongs to materialization.
//!
//! **`replay_redis_url` is this machine's, exclusively (CF-12).** It once also decided
//! where the MRTR continuation store lived, which is why `SharedLinearizable` could not
//! forbid it without destroying cross-replica MRTR. `ContinuationControl` owns that fact
//! now, so the forbidden cell can finally be stated.

use crate::cli::DeploymentRequest;
use crate::replay_tier::ReplayDurabilityTier;

/// Which replay state a configuration requests. Only live states are representable.
///
/// Each state carries the locator its Required column names, so planning has nothing left
/// to look up. The DURABILITY TIER is deliberately not a field: the variant already names
/// it — `classify` sends `Linearizable` to `SharedLinearizable` and only
/// `RedisWaitQuorum` can reach `SharedRedis`, because those are exactly the two tiers
/// `meets_strict_production_minimum` accepts. Storing it beside the variant would be two
/// authorities over one fact, and would make `Etcd` paired with a Redis quorum tier
/// representable again. It is [derived](Self::durability_tier) instead, from the variant
/// plus the quorum parameters, which are NOT derivable and so are carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayState {
    /// A shared Redis store at a quorum-acknowledged durability tier.
    SharedRedis {
        /// Where admitted nonces live.
        url: String,
        /// Replica acknowledgements required before an insert counts as durable.
        quorum: u32,
        /// How long to wait for those acknowledgements before failing closed.
        timeout_ms: u64,
    },
    /// A shared linearizable CP store (etcd).
    SharedLinearizable {
        /// The CP store's endpoint.
        endpoint: String,
    },
}

impl ReplayState {
    /// The cargo feature materialization needs to establish this state (layer B).
    ///
    /// Stated here so the requirement is read off the classified state rather than
    /// re-derived from fields at each materialization site.
    pub fn required_feature(&self) -> &'static str {
        match self {
            Self::SharedRedis { .. } => "redis_replay",
            Self::SharedLinearizable { .. } => "cpstore_etcd",
        }
    }

    /// The tier this state IS, reconstructed rather than stored.
    ///
    /// A projection out of the classification. The variant decides which tier, and the
    /// carried quorum parameters supply what the variant alone cannot say.
    pub fn durability_tier(&self) -> ReplayDurabilityTier {
        match self {
            Self::SharedRedis {
                quorum, timeout_ms, ..
            } => ReplayDurabilityTier::RedisWaitQuorum {
                quorum: *quorum,
                timeout_ms: *timeout_ms,
            },
            Self::SharedLinearizable { .. } => ReplayDurabilityTier::Linearizable,
        }
    }
}

/// Which state the request most nearly names, before its locators are known to be present.
///
/// Separate from [`ReplayState`] for the same reason `TrustRevocation` has one: the column
/// checks below need to know which state's columns to apply, and that answer must exist
/// even when a required locator does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestedState {
    SharedRedis { quorum: u32, timeout_ms: u64 },
    SharedLinearizable,
}

/// Recognise which shared state the declared tier names, or why it names none.
///
/// The tier is the ONLY selector. There is no separate backend-kind input to reject first:
/// both live states are shared, so a request either declares a tier that names one of them
/// or it names no deployment at all.
fn classify(config: &DeploymentRequest) -> Result<RequestedState, String> {
    let Some(tier) = &config.replay_durability_tier else {
        // Absence is a refusal, never a fallback. This is the clause that makes an
        // otherwise-complete request with no replay configuration fail closed: there is no
        // implicit store to drop back to, so saying nothing about replay is saying the
        // deployment makes no replay-safety claim, and that does not start.
        return Err(
            "--replay-durability-tier is required: the tier IS the horizontal replay-safety \
             claim, and a deployment that declares none makes no claim at all. Declare \
             redis-wait-quorum:<quorum>:<timeout_ms> with --replay-redis-url, or \
             linearizable with --cpstore-etcd-endpoint"
                .to_string(),
        );
    };
    match tier {
        ReplayDurabilityTier::Linearizable => Ok(RequestedState::SharedLinearizable),
        ReplayDurabilityTier::RedisWaitQuorum { quorum, timeout_ms } => {
            Ok(RequestedState::SharedRedis {
                quorum: *quorum,
                timeout_ms: *timeout_ms,
            })
        }
        tier => Err(format!(
            "--replay-durability-tier {} is weaker than the strict-production minimum; \
             declare redis-wait-quorum:<quorum>:<timeout_ms> or a linearizable tier",
            tier.wire_name()
        )),
    }
}

/// The required and forbidden locators of a recognised state.
fn locator_violations(state: RequestedState, config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    match state {
        RequestedState::SharedRedis { .. } => {
            if config.replay_redis_url.is_none() {
                out.push(
                    "a redis-wait-quorum tier requires --replay-redis-url: the tier names \
                     the guarantee, the URL names the store that must deliver it"
                        .to_string(),
                );
            }
            if config.cpstore_etcd_endpoint.is_some() {
                out.push(
                    "--cpstore-etcd-endpoint has no effect without \
                     --replay-durability-tier linearizable"
                        .to_string(),
                );
            }
        }
        RequestedState::SharedLinearizable => {
            if config.cpstore_etcd_endpoint.is_none() {
                out.push(
                    "--replay-durability-tier linearizable requires a CP/linearizable store \
                     endpoint: --cpstore-etcd-endpoint <url>"
                        .to_string(),
                );
            }
            // CF-12's clean break. Before the split this value silently became the MRTR
            // continuation store's endpoint while replay ran on etcd — one field meaning
            // two different things depending on the tier beside it. It is refused rather
            // than reinterpreted, and the refusal names what replaces the overloaded use.
            if config.replay_redis_url.is_some() {
                out.push(
                    "--replay-redis-url is not valid with --replay-durability-tier \
                     linearizable: the replay store is the CP store named by \
                     --cpstore-etcd-endpoint. If a shared MRTR continuation store is \
                     wanted, configure it separately with \
                     --continuation-control-redis-url"
                        .to_string(),
                );
            }
        }
    }
    out
}

/// Classify the requested replay state and check its columns.
///
/// `Err` means the request names no state at all — a rejected input form, or a tier this
/// posture does not accept. There is nothing to put in `DeploymentConfigState` for those,
/// which is the point: they are not deployments.
pub fn classify_and_validate(config: &DeploymentRequest) -> (Option<ReplayState>, Vec<String>) {
    match classify(config) {
        Err(refusal) => (None, vec![refusal]),
        Ok(requested) => {
            let violations = locator_violations(requested, config);
            (build(requested, config), violations)
        }
    }
}

/// Build the state, once its locator is known to be present.
///
/// `None` never travels alone: `locator_violations` has already named the missing value.
fn build(requested: RequestedState, config: &DeploymentRequest) -> Option<ReplayState> {
    Some(match requested {
        RequestedState::SharedRedis { quorum, timeout_ms } => ReplayState::SharedRedis {
            url: config.replay_redis_url.clone()?,
            quorum,
            timeout_ms,
        },
        RequestedState::SharedLinearizable => ReplayState::SharedLinearizable {
            endpoint: config.cpstore_etcd_endpoint.clone()?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut DeploymentRequest));
    /// A state this machine must recognise, and how to request it.
    type Form = (ReplayState, fn(&mut DeploymentRequest));

    fn redis(config: &mut DeploymentRequest) {
        config.replay_redis_url = Some("redis://127.0.0.1:6379".to_string());
        config.replay_durability_tier = Some(ReplayDurabilityTier::RedisWaitQuorum {
            quorum: 1,
            timeout_ms: 100,
        });
    }

    fn linearizable(config: &mut DeploymentRequest) {
        config.replay_redis_url = None;
        config.replay_durability_tier = Some(ReplayDurabilityTier::Linearizable);
        config.cpstore_etcd_endpoint = Some("http://127.0.0.1:2379".to_string());
    }

    fn run(mutate: impl FnOnce(&mut DeploymentRequest)) -> (Option<ReplayState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let cases: Vec<Form> = vec![
            (
                ReplayState::SharedRedis {
                    url: "redis://127.0.0.1:6379".to_string(),
                    quorum: 1,
                    timeout_ms: 100,
                },
                redis,
            ),
            (
                ReplayState::SharedLinearizable {
                    endpoint: "http://127.0.0.1:2379".to_string(),
                },
                linearizable,
            ),
        ];
        for (expected, mutate) in cases {
            let (state, violations) = run(mutate);
            assert_eq!(
                state,
                Some(expected.clone()),
                "classified as the wrong state"
            );
            assert!(
                violations.is_empty(),
                "{expected:?} refused: {violations:?}"
            );
        }
    }

    #[test]
    fn each_state_names_the_feature_that_could_establish_it() {
        let (redis_state, _) = run(redis);
        let (etcd_state, _) = run(linearizable);
        assert_eq!(
            redis_state.expect("redis form is legal").required_feature(),
            "redis_replay"
        );
        assert_eq!(
            etcd_state
                .expect("linearizable form is legal")
                .required_feature(),
            "cpstore_etcd"
        );
    }

    /// The tier follows from the state, so the impossible pairing has no constructor.
    ///
    /// Before the witnesses moved, planning fetched `--replay-durability-tier` back out of
    /// the request and handed the SAME value to both arms, so `Etcd` carrying a Redis
    /// quorum tier was constructible in the type system even though layer A had ruled it
    /// out. Deriving removes it: each variant can only produce its own tier.
    #[test]
    fn the_tier_is_derived_from_the_state_not_stored_beside_it() {
        let (redis_state, _) = run(redis);
        assert_eq!(
            redis_state.expect("redis form is legal").durability_tier(),
            ReplayDurabilityTier::RedisWaitQuorum {
                quorum: 1,
                timeout_ms: 100,
            },
            "the Redis state reconstructs its quorum tier from its carried parameters"
        );
        let (etcd_state, _) = run(linearizable);
        assert_eq!(
            etcd_state
                .expect("linearizable form is legal")
                .durability_tier(),
            ReplayDurabilityTier::Linearizable,
            "the CP state can name no other tier"
        );
    }

    /// A request naming no durability tier names no state, and acquires none.
    ///
    /// The tier is the only selector, so its absence must produce nothing — not a weaker
    /// state, and not a default.
    #[test]
    fn no_declared_tier_yields_no_state() {
        let (state, violations) = run(|c| c.replay_durability_tier = None);
        assert!(
            state.is_none(),
            "a request with no declared tier must not become a validated state"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--replay-durability-tier")),
            "the refusal must name the missing tier: {violations:?}"
        );
    }

    #[test]
    fn a_sub_strict_tier_names_no_state() {
        let (state, violations) = run(|c| {
            redis(c);
            c.replay_durability_tier = Some(ReplayDurabilityTier::SingleStoreFailClosed);
        });
        assert!(state.is_none());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("strict-production minimum")),
            "{violations:?}"
        );
    }

    #[test]
    fn a_shared_store_with_no_declared_tier_names_no_state() {
        let (state, violations) = run(|c| {
            redis(c);
            c.replay_durability_tier = None;
        });
        assert!(state.is_none());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--replay-durability-tier")),
            "{violations:?}"
        );
    }

    #[test]
    fn each_state_names_every_locator_it_cannot_start_without() {
        let cases: Vec<Case> = vec![
            ("--replay-redis-url", |c| {
                redis(c);
                c.replay_redis_url = None;
            }),
            ("--cpstore-etcd-endpoint", |c| {
                linearizable(c);
                c.cpstore_etcd_endpoint = None;
            }),
        ];
        for (flag, mutate) in cases {
            let (_, violations) = run(mutate);
            assert!(
                violations.iter().any(|v| v.contains(flag)),
                "a state missing {flag} was accepted: {violations:?}"
            );
        }
    }

    #[test]
    fn a_locator_belonging_to_the_other_state_is_refused() {
        let cases: Vec<Case> = vec![
            ("--cpstore-etcd-endpoint", |c| {
                redis(c);
                c.cpstore_etcd_endpoint = Some("http://127.0.0.1:2379".to_string());
            }),
            ("--replay-redis-url", |c| {
                linearizable(c);
                c.replay_redis_url = Some("redis://127.0.0.1:6379".to_string());
            }),
        ];
        for (flag, mutate) in cases {
            let (_, violations) = run(mutate);
            assert!(
                violations.iter().any(|v| v.contains(flag)),
                "a dangling {flag} was accepted: {violations:?}"
            );
        }
    }

    /// The clean break, stated in the refusal an operator reads: the old overloaded use is
    /// refused, and the setting that replaces it is named.
    #[test]
    fn the_old_alias_names_its_replacement_rather_than_being_reinterpreted() {
        let (_, violations) = run(|c| {
            linearizable(c);
            c.replay_redis_url = Some("redis://127.0.0.1:6379".to_string());
        });
        let refusal = violations
            .iter()
            .find(|v| v.contains("--replay-redis-url"))
            .expect("the dangling replay locator is refused");
        assert!(
            refusal.contains("--continuation-control-redis-url"),
            "the refusal must name what replaces the overloaded use: {refusal}"
        );
    }
}
