// SPDX-License-Identifier: Apache-2.0
//! A materialized plane must not reach back into global configuration.
//!
//! ADR-MCPRE-056's completion criterion has three clauses, and this is the third: each
//! accepted deployment state is classified exactly once, planning consumes that retained
//! classification rather than rediscovering it, and **runtime materialization never reaches
//! back into global configuration to decide what posture it is supposed to establish**.
//!
//! # Why a source test, when the signature already proves most of it
//!
//! `TrustPlane::materialize(&TrustPlan, Arc<AtomicBool>)` is compile-time proof that no
//! configuration is PASSED. It proves nothing about a fully-qualified `crate::cli::…` path
//! written inline three months from now, which needs no import, changes no signature, and
//! reads as a one-line convenience at the point it is written.
//!
//! That is the whole failure mode. A plane does not reacquire its posture by taking a
//! `Config` parameter back; it does it by reading one field, once, because the plan did not
//! happen to carry it — and the honest fix in that moment is to widen the plan, not to
//! reach past it.
//!
//! # What this proves, and what it does not
//!
//! It proves that the production half of each module below — everything above its first
//! `#[cfg(test)]` — mentions no configuration type by name. It does NOT prove semantic
//! independence: a plane handed a closure that reads configuration, or a plan type that
//! grew a `Config` field, would satisfy this and violate the property. Keeping the claim
//! narrow is deliberate; a gate that overstates itself is what stops people looking.
//!
//! Test code is deliberately out of scope. A test may build a `ValidatedConfig` to drive
//! the production constructor — `trust_plane`'s own no-cadence teardown test does exactly
//! that, and it is the more convincing test for being end-to-end.

/// The modules under the rule, and the reason each is here.
///
/// Only planes that have been projected. A plane still taking `ValidatedConfig` is not a
/// violation of this rule — it is work not yet done, and listing it here would turn a
/// standing property into a failing test that has to be silenced.
const PROJECTED_PLANES: &[(&str, &str)] = &[(
    "MCP_RE_TRUST_PLANE_SRC",
    "trust_plane establishes the posture in TrustPlan (ADR-MCPRE-056 §8)",
)];

/// The names that would mean configuration had been reached for directly.
///
/// `Config` covers `ValidatedConfig` as a substring, deliberately: both are the same
/// mistake, and a rule that named only one would let the other through.
const CONFIGURATION_NAMES: &[&str] = &["cli::", "Config"];

/// The production half: everything above the first `#[cfg(test)]`.
fn production_half(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(at) => &source[..at],
        None => source,
    }
}

#[test]
fn a_projected_plane_names_no_configuration_type() {
    for (env_var, why) in PROJECTED_PLANES {
        let path = mcp_re_test_paths::resolve_runfile(env_var);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for (number, line) in production_half(&source).lines().enumerate() {
            for name in CONFIGURATION_NAMES {
                assert!(
                    !line.contains(name),
                    "{}:{}: names {name:?} — {why}. The plane establishes what its plan \
                     says; if the plan does not carry what is needed here, widen the plan \
                     rather than reading configuration past it.\n  {}",
                    path.display(),
                    number + 1,
                    line.trim()
                );
            }
        }
    }
}

/// The gate detects what it claims to. Without this, an expression error — a path that
/// never matches — leaves every assertion above vacuously true, and a green run would mean
/// nothing at all.
#[test]
fn the_rule_would_catch_a_reach_back() {
    let reaching = "fn materialize(plan: &TrustPlan) {\n    let _ = config.trust_path;\n}\n\
                    #[cfg(test)]\nmod tests {}\n";
    assert!(
        !production_half(reaching).contains("ValidatedConfig"),
        "the fixture must not pass for the wrong reason"
    );
    for source in [
        "let c: &crate::cli::Config = todo!();",
        "fn m(config: &ValidatedConfig) {}",
        "cli::Config::default();",
    ] {
        assert!(
            CONFIGURATION_NAMES.iter().any(|n| source.contains(n)),
            "the rule misses {source:?}"
        );
    }
}

/// The production half is what is measured, so the split has to be right: a rule that
/// stopped at the wrong line would scan test fixtures, where a `ValidatedConfig` is
/// legitimate, and report a violation that is not one.
#[test]
fn the_split_excludes_test_code() {
    let source = "fn materialize() {}\n#[cfg(test)]\nmod tests {\n    use crate::cli::Config;\n}\n";
    assert!(!production_half(source).contains("Config"));
    assert!(production_half(source).contains("materialize"));
}
