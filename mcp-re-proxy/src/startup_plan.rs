// SPDX-License-Identifier: Apache-2.0
//! Pure startup planning: what the proxy INTENDS to build, decided from validated
//! configuration alone (ADR-MCPRE-056 §5.2).
//!
//! Nothing in this module opens a socket, connects to a store, reads a file, spawns a
//! thread or reads the clock. A plan is a description of intent, not an observation — it
//! says "this deployment asked for the linearizable tier over etcd at this endpoint",
//! never "that endpoint answered". Establishing the latter is materialization's job, and
//! keeping the two apart is what lets the configuration matrix be tested entirely in
//! memory instead of by standing up backends.
//!
//! The distinction matters beyond testability. A plan that quietly performed I/O would
//! make "MCP-RE decided to construct X" and "MCP-RE successfully established X"
//! interchangeable claims, and every posture statement derived from them would inherit
//! the confusion.

use crate::cli::ReplayKind;
use crate::cli::ValidatedConfig;
use crate::replay_tier::ReplayDurabilityTier;

/// The authoritative replay tier this deployment asked for.
///
/// Carries the configuration each backend needs, already resolved and checked for
/// presence, so materialization has no config lookups left to fail on — only the
/// environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayPlan {
    /// In-process, single-replica. The tier `Proxy::new` is already constructed with.
    Memory,
    /// CP / linearizable, over the etcd v3 gateway.
    Etcd {
        endpoint: String,
        tier: ReplayDurabilityTier,
    },
    /// Horizontally scaled, over Redis.
    Redis {
        url: String,
        tier: ReplayDurabilityTier,
    },
}

impl ReplayPlan {
    /// Decide the tier from configuration. Deterministic, no I/O.
    ///
    /// The refusals here are the ones knowable from configuration alone: a kind the async
    /// serving plane does not offer, and a selected mode missing a value it requires.
    /// Refusals that depend on which backends were COMPILED IN stay with materialization
    /// — they are facts about the build, not about the request, they are reported after
    /// these today, and moving them here would change which diagnostic an operator sees
    /// first when both apply.
    pub fn from_config(config: &ValidatedConfig) -> Result<ReplayPlan, String> {
        match config.replay {
            ReplayKind::Memory => Ok(ReplayPlan::Memory),
            // Not a missing feature — a shape that does not fit the data plane at all
            // (ADR-MCPRE-051 §1).
            ReplayKind::File => Err(
                "--replay-cache file is not supported on the async serving path: a single \
                 file-backed cache does not fit the per-core share-nothing data plane. Use \
                 --replay-cache shared (redis/etcd) for durable cross-replica replay, or \
                 --replay-cache memory for single-replica development."
                    .to_string(),
            ),
            ReplayKind::Shared => {
                let tier = config
                    .replay_durability_tier
                    .as_ref()
                    .ok_or("--replay-cache shared requires --replay-durability-tier")?
                    .clone();
                if matches!(tier, ReplayDurabilityTier::Linearizable) {
                    let endpoint = config.cpstore_etcd_endpoint.clone().ok_or(
                        "--replay-durability-tier linearizable requires --cpstore-etcd-endpoint",
                    )?;
                    Ok(ReplayPlan::Etcd { endpoint, tier })
                } else {
                    let url = config
                        .replay_redis_url
                        .clone()
                        .ok_or("--replay-cache shared requires --replay-redis-url")?;
                    Ok(ReplayPlan::Redis { url, tier })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Config;

    /// A configuration that gets all the way through parsing AND validation, so the
    /// mutation each test applies is the only thing under test.
    ///
    /// Every path points at something that does not exist. That is deliberate: if
    /// planning ever starts reading the environment, these stop passing.
    fn base_argv(extra: &[&str]) -> Vec<String> {
        let mut argv: Vec<String> = [
            "--bind",
            "127.0.0.1:0",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "k1",
            "--delegated-trust-epoch",
            "epoch-1",
            "--signing-key-seed",
            "/nonexistent/seed",
            "--tls-cert",
            "/nonexistent/cert",
            "--tls-key",
            "/nonexistent/key",
            "--client-ca",
            "/nonexistent/ca",
            "--trust",
            "/nonexistent/trust",
            "--target-uri",
            "https://localhost/",
            "--trust-domain",
            "example.org",
            "--inner-http-url",
            "http://127.0.0.1:9/mcp",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        argv.extend(extra.iter().map(|s| (*s).to_string()));
        argv
    }

    fn parse(extra: &[&str]) -> Result<Config, String> {
        crate::cli::parse_args(&base_argv(extra))
    }

    /// Plan a configuration that came through the parser intact.
    fn plan_for(extra: &[&str]) -> Result<ReplayPlan, String> {
        let config = parse(extra).expect("args parse");
        let validated = ValidatedConfig::try_from(config).expect("config validates");
        ReplayPlan::from_config(&validated)
    }

    /// Plan a configuration that was MUTATED after parsing.
    ///
    /// `parse_args` performs its own completeness checks, so a shared tier missing its
    /// url or endpoint never survives the command line. Those checks are not what
    /// protects the runtime: `Config` has 76 public fields and `run` accepts anything
    /// that validates, so an embedder or harness that builds one in code reaches
    /// planning having run none of them. Mutating a parsed config is the cheapest exact
    /// reproduction of such a caller, and it is the only way these refusals are
    /// reachable at all.
    fn plan_for_mutated(
        extra: &[&str],
        mutate: impl FnOnce(&mut Config),
    ) -> Result<ReplayPlan, String> {
        let mut config = parse(extra).expect("args parse");
        mutate(&mut config);
        let validated = ValidatedConfig::try_from(config).expect("config validates");
        ReplayPlan::from_config(&validated)
    }

    const SHARED_REDIS: &[&str] = &[
        "--replay-cache",
        "shared",
        "--replay-durability-tier",
        "redis-wait-quorum:2:2000",
        "--replay-redis-url",
        "redis://127.0.0.1:6379",
    ];

    const SHARED_LINEARIZABLE: &[&str] = &[
        "--replay-cache",
        "shared",
        "--replay-durability-tier",
        "linearizable",
        "--cpstore-etcd-endpoint",
        "http://127.0.0.1:2379",
    ];

    /// The in-memory tier never reaches planning, because validation refuses it outright
    /// — it is non-durable, and a restart re-opens a replay window for any still-fresh
    /// captured envelope.
    ///
    /// `ReplayPlan::Memory` therefore exists as the total case over `ReplayKind` and as
    /// what `Proxy::new` is already constructed with, not as a reachable deployment. This
    /// is pinned so that a later change which makes planning accept memory has to fail a
    /// test rather than quietly restore a non-durable production tier.
    #[test]
    fn the_memory_tier_is_refused_by_validation_before_planning_sees_it() {
        // Refused on the command line...
        let from_argv = parse(&["--replay-cache", "memory"]).expect_err("memory must not parse");
        assert!(
            from_argv.contains("--replay-cache memory is non-durable"),
            "{from_argv}"
        );
        // ...and refused for a caller that never touched the command line, which is the
        // altitude that actually protects the runtime.
        let mut config = parse(SHARED_REDIS).expect("args parse");
        config.replay = ReplayKind::Memory;
        let err = ValidatedConfig::try_from(config).expect_err("memory must not validate");
        assert!(
            err.contains("--replay-cache memory is non-durable"),
            "{err}"
        );
    }

    /// A file cache validates but cannot be served: it is not a missing feature, it is a
    /// shape that does not fit the per-core share-nothing data plane.
    #[test]
    fn the_file_cache_is_refused_on_the_async_plane() {
        let err = plan_for(&[
            "--replay-cache",
            "file",
            "--replay-path",
            "/nonexistent/replay",
        ])
        .expect_err("file must be refused");
        assert!(
            err.contains("not supported on the async serving path"),
            "{err}"
        );
    }

    #[test]
    fn linearizable_plans_etcd_at_the_declared_endpoint() {
        assert_eq!(
            plan_for(SHARED_LINEARIZABLE).expect("plan"),
            ReplayPlan::Etcd {
                endpoint: "http://127.0.0.1:2379".to_string(),
                tier: ReplayDurabilityTier::Linearizable,
            }
        );
    }

    /// The declared WAIT parameters survive planning intact. Materialization sizes the
    /// client response timeout from them BEFORE connecting, so a plan that dropped them
    /// would silently restore the defect where a declared 2000ms wait could never exceed
    /// the redis library's 500ms per-command default.
    #[test]
    fn a_redis_tier_carries_its_url_and_its_wait_parameters() {
        match plan_for(SHARED_REDIS).expect("plan") {
            ReplayPlan::Redis { url, tier } => {
                assert_eq!(url, "redis://127.0.0.1:6379");
                assert_eq!(tier.wait_quorum_params(), Some((2, 2000)));
            }
            other => panic!("expected a redis plan, got {other:?}"),
        }
    }

    #[test]
    fn a_shared_tier_that_skipped_the_parser_still_needs_a_durability_tier() {
        let err = plan_for_mutated(SHARED_REDIS, |c| c.replay_durability_tier = None)
            .expect_err("an undeclared durability tier must be refused");
        assert!(err.contains("--replay-durability-tier"), "{err}");
    }

    #[test]
    fn a_shared_redis_tier_that_skipped_the_parser_still_needs_a_url() {
        let err = plan_for_mutated(SHARED_REDIS, |c| c.replay_redis_url = None)
            .expect_err("a redis tier without a url must be refused");
        assert!(err.contains("--replay-redis-url"), "{err}");
    }

    /// The linearizable claim is never silently downgraded to redis or to memory: with no
    /// CPStore endpoint the tier is refused, not resolved to something weaker.
    #[test]
    fn a_linearizable_tier_that_skipped_the_parser_still_needs_an_endpoint() {
        let err = plan_for_mutated(SHARED_LINEARIZABLE, |c| c.cpstore_etcd_endpoint = None)
            .expect_err("linearizable without an endpoint must be refused");
        assert!(err.contains("--cpstore-etcd-endpoint"), "{err}");
    }

    /// The property that makes the whole layer worth having, asserted rather than left
    /// incidental: a complete networked tier is planned against a TEST-NET-3 host that is
    /// never contacted, from a config whose every file path does not exist.
    #[test]
    fn planning_reaches_a_networked_tier_without_contacting_anything() {
        let plan = plan_for(&[
            "--replay-cache",
            "shared",
            "--replay-durability-tier",
            "redis-wait-quorum:2:2000",
            "--replay-redis-url",
            "redis://203.0.113.1:6379",
        ])
        .expect("a plan is produced without contacting anything");
        assert!(matches!(plan, ReplayPlan::Redis { .. }));
    }
}
