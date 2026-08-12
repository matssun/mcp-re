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

/// A projected plane, and what it must not name.
struct Plane {
    /// The runfile env key its source is delivered under.
    env: &'static str,
    /// Which plan it establishes.
    why: &'static str,
    /// `Config` field names whose POSTURE layer A already classified.
    ///
    /// This is the third check, and it catches what the other two cannot. A plane can take
    /// no `Config`, name no configuration type, and still receive primitive plan fields
    /// from which it reconstructs a classified state:
    ///
    /// ```ignore
    /// if plan.crl_paths.is_empty() { /* …no revocation… */ }
    /// ```
    ///
    /// That is the same defect one layer along — a second derivation of a fact layer A
    /// already decided. The rule is indirect but exact: these are the names the fields
    /// carry in `Config`, and a plan that carries the posture as a VARIANT has no reason
    /// to reuse them. A plane that names one is reading a primitive where a state exists.
    reconstructed: &'static [&'static str],
}

/// The modules under the rule, and the reason each is here.
///
/// Only planes that have been projected. A plane still taking `ValidatedConfig` is not a
/// violation of this rule — it is work not yet done, and listing it here would turn a
/// standing property into a failing test that has to be silenced.
const PROJECTED_PLANES: &[Plane] = &[
    Plane {
        env: "MCP_RE_TRUST_PLANE_SRC",
        why: "trust_plane establishes the posture in TrustPlan (ADR-MCPRE-056 §8)",
        reconstructed: &[
            "revocation_tier",
            "trust_reload_secs",
            "trust_epoch_redis_url",
        ],
    },
    Plane {
        env: "MCP_RE_TLS_PLANE_SRC",
        why: "tls_plane establishes the posture in TlsPlan (ADR-MCPRE-056 §8)",
        // NOT `max_client_cert_lifetime`. It is a validated INPUT the posture needs, not a
        // state layer A classified, so the plan carries it under its own name and the
        // plane renders it. The distinction is the whole test: is this an unresolved
        // decision, or a value required to establish a decided one?
        reconstructed: &["client_crl_paths", "client_crl_reload_secs"],
    },
];

/// The identifiers that would mean configuration had been reached for directly.
///
/// Matched as WHOLE identifiers, not as substrings. `Config` as a substring also matches
/// rustls' `ServerConfig` and this crate's `ServerConfigSnapshot`, which are the serving
/// TLS configuration — a materialized artifact with nothing to do with `cli::Config`. A
/// rule that conflated them would be unsatisfiable for the TLS plane, and the way such a
/// rule gets fixed is by deleting it.
///
/// `ValidatedConfig` is therefore listed separately: whole-identifier matching is what
/// excludes `ServerConfig`, and it excludes this too.
const CONFIGURATION_NAMES: &[&str] = &["cli", "Config", "ValidatedConfig"];

/// Whether `line` names `ident` as a whole identifier rather than inside a longer one.
fn names_identifier(line: &str, ident: &str) -> bool {
    let boundary = |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    line.match_indices(ident).any(|(at, _)| {
        boundary(line[..at].chars().next_back())
            && boundary(line[at + ident.len()..].chars().next())
    })
}

/// The production half: everything above the first `#[cfg(test)]`.
fn production_half(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(at) => &source[..at],
        None => source,
    }
}

/// The production half of `plane`, read from its delivered source.
fn production_source(plane: &Plane) -> (std::path::PathBuf, String) {
    let path = mcp_re_test_paths::resolve_runfile(plane.env);
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let half = production_half(&source).to_string();
    (path, half)
}

#[test]
fn a_projected_plane_names_no_configuration_type() {
    for plane in PROJECTED_PLANES {
        let (path, source) = production_source(plane);
        for (number, line) in source.lines().enumerate() {
            for name in CONFIGURATION_NAMES {
                assert!(
                    !names_identifier(line, name),
                    "{}:{}: names {name:?} — {}. The plane establishes what its plan says; \
                     if the plan does not carry what is needed here, widen the plan rather \
                     than reading configuration past it.\n  {}",
                    path.display(),
                    number + 1,
                    plane.why,
                    line.trim()
                );
            }
        }
    }
}

/// The third check: no plane reconstructs a state layer A already classified.
///
/// A plane can satisfy both checks above and still be handed primitives from which it
/// re-derives the posture — `paths.is_empty()` standing in for `CrlRevocation::None`. The
/// classification then exists and is ignored, which is CF-10's failure mode one layer
/// further along.
#[test]
fn a_projected_plane_reconstructs_no_classified_state() {
    for plane in PROJECTED_PLANES {
        let (path, source) = production_source(plane);
        for (number, line) in source.lines().enumerate() {
            for name in plane.reconstructed {
                assert!(
                    !names_identifier(line, name),
                    "{}:{}: names {name:?}, whose posture layer A classified — {}. Consume \
                     the classified state the plan carries; a primitive here means the \
                     plane is deciding again what has already been decided.\n  {}",
                    path.display(),
                    number + 1,
                    plane.why,
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
            CONFIGURATION_NAMES
                .iter()
                .any(|n| names_identifier(source, n)),
            "the rule misses {source:?}"
        );
    }
    // The other direction, which is what forced whole-identifier matching: the serving
    // TLS configuration is a materialized artifact, and a rule that flagged it would be
    // unsatisfiable for the plane that owns it.
    for allowed in [
        "snapshot: Arc<config_snapshot::ServerConfigSnapshot>,",
        "fn rebuild(&self) -> Result<rustls::ServerConfig, String> {}",
    ] {
        assert!(
            !CONFIGURATION_NAMES
                .iter()
                .any(|n| names_identifier(allowed, n)),
            "the rule flags the serving TLS configuration: {allowed:?}"
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
