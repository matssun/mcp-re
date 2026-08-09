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
            //
            // The remedy names only `shared`, because it is the only one that can start:
            // `--replay-cache memory` is refused by validation in every build, so
            // recommending it would send an operator to a second dead end.
            ReplayKind::File => Err(
                "--replay-cache file is not supported on the async serving path: a single \
                 file-backed cache does not fit the per-core share-nothing data plane. Use \
                 --replay-cache shared with --replay-durability-tier (redis-wait-quorum or \
                 linearizable) for durable cross-replica replay."
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

    /// Whether establishing THIS tier needs the shared control runtime.
    ///
    /// Only the Redis tier: the etcd store drives its own requests and the in-memory
    /// tier does no I/O. One contributor to the aggregate — never the decision itself.
    pub fn needs_control_runtime(&self) -> bool {
        cfg!(feature = "redis_replay") && matches!(self, ReplayPlan::Redis { .. })
    }
}
/// The in-flight bound the inner plane must not sit below, or `None` to leave its default.
///
/// PURE: `cores` is passed in rather than resolved here, because resolving it reads
/// `available_parallelism` and §5.2 keeps planning free of the environment. The RULE is
/// the pure part and is what needed testing; the machine's core count is an input to it.
///
/// # Why the inner pool is raised to meet the fleet
///
/// The pool is PROCESS-WIDE — one instance behind the `Arc` every core shares — so a bound
/// below the fleet's aggregate admission ceiling means requests that passed every security
/// gate are answered with a signed `inner server unavailable` at a capacity cliff no
/// configured flag names. The shedding decision would move from the admission gate, where
/// it is deliberate and measured, to the inner pool, where it is an accident of core count.
///
/// `--max-in-flight-requests` is per-core, so it multiplies; `--max-in-flight-total` is
/// already fleet-wide. The per-core flag wins when both are set, matching the CLI's own
/// precedence.
pub fn inner_plane_ceiling(
    per_core: Option<usize>,
    total: Option<usize>,
    cores: usize,
) -> Option<usize> {
    per_core.map(|n| n.saturating_mul(cores)).or(total)
}

/// Whether that ceiling requires raising the inner plane's default bound.
///
/// Separate from [`inner_plane_ceiling`] because "what is the fleet's ceiling" and "does it
/// exceed the pool's default" are different questions, and only the second one decides
/// whether an operator sees a startup line.
pub fn inner_plane_raise(ceiling: Option<usize>, default_bound: usize) -> Option<usize> {
    ceiling.filter(|c| *c > default_bound)
}

/// A wall-clock reading below this Unix-seconds threshold is treated as a host-clock
/// fault: 2000-01-01 UTC, far below any plausible real deployment time, so a legitimate
/// clock never trips it while a 0/epoch clock always does.
pub const EPOCH_CLOCK_FAULT_THRESHOLD_SECS: i64 = 946_684_800;

/// Whether `now_unix` indicates the host clock is unset or broken rather than merely
/// inaccurate (audit #94 F5).
///
/// The reading comes from the environment, but deciding that a given reading is a FAULT
/// is a rule, and it is the part that had to be testable: the caller cannot conjure a
/// broken host clock to exercise it. A wall clock at/near the epoch makes every freshness
/// check fail closed, so the whole deployment denies every request; that is safe but
/// indistinguishable from a load or policy problem unless startup names the cause.
///
/// `now_unix()` clamps a pre-epoch `SystemTime` error to 0, so 0 is the sentinel this must
/// catch, and any negative value that ever reached here is a fault by the same argument.
pub fn host_clock_is_faulted(now_unix: i64) -> bool {
    now_unix < EPOCH_CLOCK_FAULT_THRESHOLD_SECS
}

/// The kid naming the ROOT issuer that delegated credentials chain to (ADR-MCPRE-052).
///
/// Planned, not materialized: it is a two-field derivation over configuration, and both
/// the trust plane and the signing plane are handed it rather than either producing it.
/// That ordering is forced — trust is established well before the root issuer is invoked
/// — but it is also correct, because the kid is a statement of INTENT about which issuer
/// this deployment will chain to, not evidence that the issuer answered.
///
/// `--delegated-issuer-kid` wins when set; otherwise the server key id names the issuer,
/// which is the single-key deployment where root and issuer coincide.
///
/// The invariant that makes it safe belongs to signing, and the two planes consume
/// opposite halves of it: this kid answers the Response slot, and it is never enrolled as
/// a REQUEST signer. Splitting the derivation across the two consumers would let them
/// disagree about which key that is, which is the one thing this must not permit.
pub fn response_issuer_kid(config: &ValidatedConfig) -> String {
    config
        .delegated_issuer_kid
        .clone()
        .unwrap_or_else(|| config.server_key_id.clone())
}

/// Whether the MRTR continuation store will be wired (ADR-MCPS-047).
///
/// Keyed on a shared Redis URL, NOT on the replay tier: a linearizable/etcd deployment
/// that also names a Redis URL still gets cross-replica continuation.
pub fn continuation_needs_control_runtime(config: &ValidatedConfig) -> bool {
    cfg!(feature = "redis_replay") && config.replay_redis_url.is_some()
}

/// Whether the §7 admission-currency gate will be wired (MCPRE-493).
///
/// Its Redis endpoint is its OWN; it has nothing to do with which replay tier was
/// chosen. Deriving it from replay once made admission unimplementable on the
/// CP/linearizable tier, and the natural resolution was to turn the control off.
pub fn admission_needs_control_runtime(config: &ValidatedConfig) -> bool {
    cfg!(feature = "redis_replay") && config.admission != crate::cli::AdmissionKind::Off
}

/// Aggregate the control-runtime requirement across EVERY capability that can need it.
///
/// No single consumer owns this decision; each declares, the aggregate decides.
///
/// The `cfg!` guards yield a compile-time `false` without `redis_replay`, and the
/// predicates beside them touch only configuration types present in every build — no
/// Redis-only symbol appears here. `cfg!` does not remove code from compilation the way
/// `#[cfg]` does, so a future contributor that names a feature-gated type would fail to
/// build in the default lane rather than being silently excluded. Keep them that way.
pub fn control_runtime_requirement(
    config: &ValidatedConfig,
    replay: &ReplayPlan,
) -> crate::control_runtime::ControlRuntimeRequirement {
    crate::control_runtime::ControlRuntimeRequirement::any([
        replay.needs_control_runtime(),
        continuation_needs_control_runtime(config),
        admission_needs_control_runtime(config),
    ])
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

    /// The explicit issuer kid wins; without one the server key id names the issuer.
    /// Both planes must be handed the SAME answer, which is why it is derived here.
    #[test]
    fn the_issuer_kid_falls_back_to_the_server_key_id() {
        let config = parse(SHARED_REDIS).expect("args parse");
        let validated = ValidatedConfig::try_from(config).expect("config validates");
        assert_eq!(
            response_issuer_kid(&validated),
            "k1",
            "with no --delegated-issuer-kid the server key id names the issuer"
        );

        let explicit = parse(&[SHARED_REDIS, &["--delegated-issuer-kid", "root-kms-1"]].concat())
            .expect("args parse");
        let validated = ValidatedConfig::try_from(explicit).expect("config validates");
        assert_eq!(response_issuer_kid(&validated), "root-kms-1");
    }

    // ---- control-runtime requirement -------------------------------------------
    //
    // Each contributor is asserted on its own, then the aggregation separately. A test
    // that only exercised the aggregate boolean could not tell which consumer had
    // stopped declaring its requirement — and the historical defect was exactly one
    // consumer's need being inferred from another's.

    /// The feature lane is the only one where any of these can be true, because every
    /// Redis-dependent capability refuses outright in a build without the backend.
    const REDIS: bool = cfg!(feature = "redis_replay");

    #[test]
    fn only_the_redis_replay_tier_declares_a_need() {
        let redis = plan_for(SHARED_REDIS).expect("plan");
        assert_eq!(redis.needs_control_runtime(), REDIS);

        let etcd = plan_for(SHARED_LINEARIZABLE).expect("plan");
        assert!(
            !etcd.needs_control_runtime(),
            "the etcd store drives its own requests"
        );
        assert!(
            !ReplayPlan::Memory.needs_control_runtime(),
            "the in-memory tier does no I/O"
        );
    }

    /// Keyed on the Redis URL, not the tier: an etcd deployment that also names one
    /// still gets cross-replica continuation, so it still declares the need.
    #[test]
    fn continuation_declares_on_the_redis_url_not_the_replay_tier() {
        let with_etcd_and_url = parse(&[
            "--replay-cache",
            "shared",
            "--replay-durability-tier",
            "linearizable",
            "--cpstore-etcd-endpoint",
            "http://127.0.0.1:2379",
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
        ])
        .expect("args parse");
        let validated = ValidatedConfig::try_from(with_etcd_and_url).expect("validates");
        assert_eq!(continuation_needs_control_runtime(&validated), REDIS);
        assert!(
            !ReplayPlan::from_config(&validated)
                .expect("plan")
                .needs_control_runtime(),
            "the tier is etcd, so replay itself declares nothing"
        );

        let no_url = parse(SHARED_LINEARIZABLE).expect("args parse");
        let validated = ValidatedConfig::try_from(no_url).expect("validates");
        assert!(!continuation_needs_control_runtime(&validated));
    }

    /// A COMPLETE admission configuration. Setting only `admission` used to be enough
    /// here, which was itself a symptom: the validation boundary did not check admission
    /// at all, so a half-configured gate reached planning. It does now (FF4), and a plan
    /// test must exercise a configuration a deployment could actually hold.
    fn with_admission(mut config: crate::cli::Config) -> crate::cli::Config {
        config.admission = crate::cli::AdmissionKind::Required;
        config.admission_authority_kid = Some("admission-root-1".to_string());
        config.admission_authority_pubkey_b64url =
            Some("1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg".to_string());
        config.admission_redis_url = Some("redis://127.0.0.1:6379".to_string());
        config
    }

    /// Admission's endpoint is its own. Declaring it independently is what stopped it
    /// being unimplementable on the CP/linearizable tier.
    #[test]
    fn admission_declares_independently_of_replay() {
        let off = ValidatedConfig::try_from(parse(SHARED_LINEARIZABLE).expect("parse"))
            .expect("validates");
        assert!(!admission_needs_control_runtime(&off));

        let on = with_admission(parse(SHARED_LINEARIZABLE).expect("parse"));
        let on = ValidatedConfig::try_from(on).expect("validates");
        assert_eq!(admission_needs_control_runtime(&on), REDIS);
        assert!(
            !ReplayPlan::from_config(&on)
                .expect("plan")
                .needs_control_runtime(),
            "admission must not need the replay tier to have asked first"
        );
    }

    /// The aggregation itself: any contributor is enough, none means none.
    #[test]
    fn the_requirement_is_the_or_of_every_contributor() {
        use crate::control_runtime::ControlRuntimeRequirement as Req;

        // Admission alone, on a tier that declares nothing.
        let admission_only = with_admission(parse(SHARED_LINEARIZABLE).expect("parse"));
        let admission_only = ValidatedConfig::try_from(admission_only).expect("validates");
        let plan = ReplayPlan::from_config(&admission_only).expect("plan");
        assert_eq!(
            control_runtime_requirement(&admission_only, &plan).is_required(),
            REDIS,
            "one contributor is enough"
        );

        // Nothing networked at all.
        let none = ValidatedConfig::try_from(parse(SHARED_LINEARIZABLE).expect("parse"))
            .expect("validates");
        let plan = ReplayPlan::from_config(&none).expect("plan");
        assert_eq!(
            control_runtime_requirement(&none, &plan),
            Req::NotRequired,
            "no contributor declared a need, so no substrate is built"
        );
    }
    /// The sentinel `now_unix()` produces for a pre-epoch `SystemTime` error, and the
    /// unset-clock reading it stands in for, must both be faults. A predicate that only
    /// caught literal 0 would pass a host reading a few days past the epoch.
    #[test]
    fn an_epoch_or_pre_epoch_clock_reading_is_a_fault() {
        assert!(host_clock_is_faulted(0));
        assert!(host_clock_is_faulted(-1));
        assert!(host_clock_is_faulted(86_400));
        assert!(host_clock_is_faulted(EPOCH_CLOCK_FAULT_THRESHOLD_SECS - 1));
    }

    /// The threshold is far enough below any real deployment time that a correct clock
    /// never trips it — otherwise the warning would fire on every start and stop meaning
    /// anything.
    #[test]
    fn a_plausible_deployment_clock_is_not_a_fault() {
        assert!(!host_clock_is_faulted(EPOCH_CLOCK_FAULT_THRESHOLD_SECS));
        // 2026-01-01 UTC.
        assert!(!host_clock_is_faulted(1_767_225_600));
        assert!(!host_clock_is_faulted(i64::MAX));
    }

    /// The per-core flag multiplies by the core count; the fleet-wide flag does not.
    #[test]
    fn the_per_core_bound_scales_with_cores_and_the_total_does_not() {
        assert_eq!(inner_plane_ceiling(Some(10), None, 8), Some(80));
        assert_eq!(inner_plane_ceiling(None, Some(10), 8), Some(10));
        assert_eq!(inner_plane_ceiling(None, None, 8), None);
    }

    /// The per-core flag wins when both are set, matching the CLI's own precedence. A
    /// deployment that set both and silently got the smaller one would shed at a bound no
    /// flag names.
    #[test]
    fn the_per_core_bound_wins_when_both_are_set() {
        assert_eq!(inner_plane_ceiling(Some(10), Some(999), 4), Some(40));
    }

    /// A huge per-core bound on a many-core box must not wrap. Saturating rather than
    /// wrapping matters because a wrapped ceiling would be SMALLER than the default and
    /// would silently lower the pool instead of raising it.
    #[test]
    fn a_ceiling_that_would_overflow_saturates_rather_than_wrapping() {
        let huge = inner_plane_ceiling(Some(usize::MAX), None, 64);
        assert_eq!(huge, Some(usize::MAX));
        assert_eq!(inner_plane_raise(huge, 1024), Some(usize::MAX));
    }

    /// The pool is raised only when the fleet's ceiling actually exceeds its default —
    /// equal is not "raised", or every start would print a line saying nothing changed.
    #[test]
    fn the_pool_is_raised_only_when_the_fleet_ceiling_exceeds_its_default() {
        assert_eq!(inner_plane_raise(Some(2048), 1024), Some(2048));
        assert_eq!(inner_plane_raise(Some(1024), 1024), None);
        assert_eq!(inner_plane_raise(Some(512), 1024), None);
        assert_eq!(inner_plane_raise(None, 1024), None);
    }
}
