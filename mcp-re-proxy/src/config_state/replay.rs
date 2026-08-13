// SPDX-License-Identifier: Apache-2.0
//! The `Replay` configuration machine — `work/CONFIG-STATE-ATLAS.md` §C.1.
//!
//! Where admitted nonces live, and therefore what replay guarantee the deployment can
//! claim. **Two states**, both shared:
//!
//! | State | Required | Forbidden | Guards | Build |
//! |---|---|---|---|---|
//! | `SharedRedis` | `replay_redis_url`, a Redis quorum tier | `cpstore_etcd_endpoint`, `replay_path` | tier meets the strict minimum | `redis_replay` |
//! | `SharedLinearizable` | `cpstore_etcd_endpoint`, the linearizable tier | `replay_redis_url`, `replay_path` | — | `cpstore_etcd` |
//!
//! `Memory`, `File`, and the two sub-strict Redis tiers are **input forms that refuse**.
//! They never inhabit [`ReplayState`], because a validated state is one a deployment could
//! be in and none of these can: `Memory` keeps nonces only in process memory, `File` has
//! no materialization path in any build (CF-01), and the sub-strict tiers carry a replay
//! window the strict posture does not accept.
//!
//! **`File`'s refusal is a product statement, not a build statement.** No build can
//! establish it, so naming a missing capability would name one nothing supplies. Once a
//! legal state IS classified, a missing `redis_replay` or `cpstore_etcd` is layer B and
//! belongs to materialization.
//!
//! **`replay_redis_url` is this machine's, exclusively (CF-12).** It once also decided
//! where the MRTR continuation store lived, which is why `SharedLinearizable` could not
//! forbid it without destroying cross-replica MRTR. `ContinuationControl` owns that fact
//! now, so the forbidden cell can finally be stated.

use crate::cli::{Config, ReplayKind};
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

/// Why a requested replay backend is not a deployment state at all.
///
/// Separate from the columns because these refusals are about the *input form*: there is
/// no state to check the parameters of.
fn rejected_input_form(config: &Config) -> Option<String> {
    match config.replay {
        ReplayKind::Memory => Some(
            "--replay-cache memory is non-durable: it keeps admitted nonces only in process \
             memory (and is the cache used when --replay-cache is omitted), so a proxy RESTART \
             forgets them and re-opens a replay window for any still-fresh captured envelope \
             until its expires_at+skew; production must use a durable replay store: \
             --replay-cache shared with a redis-wait-quorum:<quorum>:<timeout_ms> or \
             linearizable durability tier"
                .to_string(),
        ),
        // CF-01. Phrased as what deployments exist, not as what this build or serving path
        // can do: `ReplayPlan` has no file arm in any build, so there is no capability to
        // name and no alternative path to point at.
        ReplayKind::File => Some(
            "--replay-cache file is not a supported deployment state in the current serving \
             architecture; configure shared replay with an accepted durability tier: \
             --replay-cache shared with --replay-durability-tier \
             redis-wait-quorum:<quorum>:<timeout_ms> or linearizable"
                .to_string(),
        ),
        ReplayKind::Shared => None,
    }
}

/// Recognise which shared state the declared tier names, or why it names none.
fn classify(config: &Config) -> Result<RequestedState, String> {
    if let Some(refusal) = rejected_input_form(config) {
        return Err(refusal);
    }
    let Some(tier) = &config.replay_durability_tier else {
        return Err(
            "--replay-cache shared requires --replay-durability-tier: the tier IS the \
             horizontal replay-safety claim, and a shared store with none declared makes no \
             claim at all"
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
fn locator_violations(state: RequestedState, config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    // Forbidden in BOTH live states: the only state `replay_path` parameterizes is not one
    // a deployment can be in. It is `Option`-typed and mode-specific, so its presence is an
    // operator statement rather than a default (CF-04).
    if config.replay_path.is_some() {
        out.push(
            "--replay-path belongs to --replay-cache file, which is not a supported \
             deployment state; a shared replay store keeps no local file. Remove \
             --replay-path"
                .to_string(),
        );
    }
    match state {
        RequestedState::SharedRedis { .. } => {
            if config.replay_redis_url.is_none() {
                out.push("--replay-cache shared requires --replay-redis-url".to_string());
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
pub fn classify_and_validate(config: &Config) -> (Option<ReplayState>, Vec<String>) {
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
fn build(requested: RequestedState, config: &Config) -> Option<ReplayState> {
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
    type Case = (&'static str, fn(&mut Config));
    /// A state this machine must recognise, and how to request it.
    type Form = (ReplayState, fn(&mut Config));

    fn redis(config: &mut Config) {
        config.replay = ReplayKind::Shared;
        config.replay_path = None;
        config.replay_redis_url = Some("redis://127.0.0.1:6379".to_string());
        config.replay_durability_tier = Some(ReplayDurabilityTier::RedisWaitQuorum {
            quorum: 1,
            timeout_ms: 100,
        });
    }

    fn linearizable(config: &mut Config) {
        config.replay = ReplayKind::Shared;
        config.replay_path = None;
        config.replay_redis_url = None;
        config.replay_durability_tier = Some(ReplayDurabilityTier::Linearizable);
        config.cpstore_etcd_endpoint = Some("http://127.0.0.1:2379".to_string());
    }

    fn run(mutate: impl FnOnce(&mut Config)) -> (Option<ReplayState>, Vec<String>) {
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

    /// The rejected input forms produce NO state — they are not deployments.
    #[test]
    fn memory_and_file_never_become_states() {
        for kind in [ReplayKind::Memory, ReplayKind::File] {
            let (state, violations) = run(|c| {
                c.replay = kind;
                c.replay_path = Some("/replay".to_string());
            });
            assert!(state.is_none(), "{kind:?} became a validated state");
            assert!(!violations.is_empty());
        }
    }

    /// CF-01: the refusal is about which deployments exist, not about this build.
    #[test]
    fn the_file_refusal_is_a_product_statement() {
        let (_, violations) = run(|c| c.replay = ReplayKind::File);
        let refusal = violations.first().expect("file is refused");
        assert!(
            refusal.contains("not a supported deployment state"),
            "{refusal}"
        );
        for build_talk in ["build", "feature", "async serving path"] {
            assert!(
                !refusal.contains(build_talk),
                "a layer-A refusal must not name {build_talk:?}: {refusal}"
            );
        }
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

    #[test]
    fn a_path_for_a_state_no_deployment_can_be_in_is_refused_in_both_states() {
        for mutate in [redis as fn(&mut Config), linearizable] {
            let (_, violations) = run(|c| {
                mutate(c);
                c.replay_path = Some("/replay".to_string());
            });
            assert!(
                violations.iter().any(|v| v.contains("--replay-path")),
                "{violations:?}"
            );
        }
    }
}
