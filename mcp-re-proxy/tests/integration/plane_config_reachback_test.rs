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
//! `DeploymentRequest` parameter back; it does it by reading one field, once, because the plan did not
//! happen to carry it — and the honest fix in that moment is to widen the plan, not to
//! reach past it.
//!
//! # What this proves, and what it does not
//!
//! It proves that the production half of each module below — everything above its first
//! `#[cfg(test)]` — mentions no configuration type by name. It does NOT prove semantic
//! independence: a plane handed a closure that reads configuration, or a plan type that
//! grew a `DeploymentRequest` field, would satisfy this and violate the property. Keeping the claim
//! narrow is deliberate; a gate that overstates itself is what stops people looking.
//!
//! Test code is deliberately out of scope. A test may build a `ValidatedDeployment` to drive
//! the production constructor — `trust_plane`'s own no-cadence teardown test does exactly
//! that, and it is the more convincing test for being end-to-end.

/// A projected plane, and what it must not name.
struct Plane {
    /// The runfile env key its source is delivered under.
    env: &'static str,
    /// Which plan it establishes.
    why: &'static str,
    /// `DeploymentRequest` field names whose POSTURE layer A already classified.
    ///
    /// This is the third check, and it catches what the other two cannot. A plane can take
    /// no `DeploymentRequest`, name no configuration type, and still receive primitive plan fields
    /// from which it reconstructs a classified state:
    ///
    /// ```ignore
    /// if plan.crl_paths.is_empty() { /* …no revocation… */ }
    /// ```
    ///
    /// That is the same defect one layer along — a second derivation of a fact layer A
    /// already decided. The rule is indirect but exact: these are the names the fields
    /// carry in `DeploymentRequest`, and a plan that carries the posture as a VARIANT has no reason
    /// to reuse them. A plane that names one is reading a primitive where a state exists.
    reconstructed: &'static [&'static str],
}

/// The modules under the rule, and the reason each is here.
///
/// Only planes that have been projected. A plane still taking `ValidatedDeployment` is not a
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
        // NOT `max_client_cert_lifetime`, and no longer for the old reason. It used to be
        // "a validated INPUT, not a state layer A classified"; it IS classified now, as
        // half of `ClientCredentialWindow`, and the plan carries the window rather than
        // two durations. It stays off this list because the plane prints the field name as
        // an operator-facing LABEL (`max_client_cert_lifetime=3600s`), and this rule
        // matches whole identifiers on a line without knowing a read from a string. The
        // seal is what enforces it here: there is no `Option<Duration>` left to
        // reconstruct a posture from.
        reconstructed: &["client_crl_paths", "client_crl_reload_secs"],
    },
    Plane {
        env: "MCP_RE_REPLAY_PLANE_SRC",
        why: "replay_plane establishes the tier in ReplayPlan (ADR-MCPRE-051 §4)",
        reconstructed: &[
            "replay_redis_url",
            "cpstore_etcd_endpoint",
            "replay_durability_tier",
        ],
    },
    Plane {
        env: "MCP_RE_SIGNING_PLANE_SRC",
        why: "signing_plane establishes the posture in SigningPlan (ADR-MCPRE-056 §8)",
        reconstructed: &["delegated_issuer_kid", "delegated_audience_hash"],
    },
    // Not a plane, and listed anyway. `build_delegated_signing` is where the signing
    // plane's configuration reading actually lived, so stopping the rule at the plane
    // boundary would have made SigningPlan cosmetic: the plane would take a plan and hand
    // the wiring a `DeploymentRequest` one line later.
    Plane {
        env: "MCP_RE_DELEGATED_WIRING_SRC",
        why: "delegated_wiring builds what SigningPlan decided (ADR-MCPRE-056 §8)",
        reconstructed: &[
            "delegated_issuer_kid",
            "delegated_audience_hash",
            "delegated_trust_epoch",
            "delegated_ttl_secs",
            "delegated_overlap_secs",
        ],
    },
];

/// The identifiers that would mean configuration had been reached for directly.
///
/// Matched as WHOLE identifiers, not as substrings. `DeploymentRequest` as a substring also matches
/// rustls' `ServerConfig` and this crate's `ServerConfigSnapshot`, which are the serving
/// TLS configuration — a materialized artifact with nothing to do with `deployment_request::DeploymentRequest`. A
/// rule that conflated them would be unsatisfiable for the TLS plane, and the way such a
/// rule gets fixed is by deleting it.
///
/// `ValidatedDeployment` is therefore listed separately: whole-identifier matching is what
/// excludes `ServerConfig`, and it excludes this too.
///
/// `deployment_request` is listed beside `cli` rather than instead of it. The request model
/// moved out of the parser's module, and a rule naming only `cli` would have stopped seeing
/// a plane that imported `KeySourceKind` or `BindingKind` from its new home — the selector
/// would still have matched every old spelling while answering a narrower question.
const CONFIGURATION_NAMES: &[&str] = &[
    "cli",
    "deployment_request",
    "DeploymentRequest",
    "ValidatedDeployment",
];

/// Whether `line` names `ident` as a whole identifier rather than inside a longer one.
fn names_identifier(line: &str, ident: &str) -> bool {
    let boundary = |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    line.match_indices(ident).any(|(at, _)| {
        boundary(line[..at].chars().next_back())
            && boundary(line[at + ident.len()..].chars().next())
    })
}

/// Whether `line` is a comment, and so reaches nothing.
///
/// A doc comment naming `deployment_request::DeploymentRequest` explains what the module does NOT do; a `//` line
/// naming it is commented-out code. Neither is a dependency, and the sibling
/// `startup_backedges` gate already ruled the same way about paths in comments — measuring
/// the spelling instead of the proposition is how these rules go wrong.
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
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
        for (number, line) in source.lines().enumerate().filter(|(_, l)| !is_comment(l)) {
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
        for (number, line) in source.lines().enumerate().filter(|(_, l)| !is_comment(l)) {
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
        !production_half(reaching).contains("ValidatedDeployment"),
        "the fixture must not pass for the wrong reason"
    );
    for source in [
        "let c: &crate::deployment_request::DeploymentRequest = todo!();",
        "fn m(config: &ValidatedDeployment) {}",
        "deployment_request::DeploymentRequest::default();",
        // The spelling the move made possible: a selector enum reached from the request
        // model's new home, naming neither `cli` nor a configuration TYPE.
        "use crate::deployment_request::KeySourceKind;",
    ] {
        assert!(
            CONFIGURATION_NAMES
                .iter()
                .any(|n| names_identifier(source, n)),
            "the rule misses {source:?}"
        );
    }
    // Prose about configuration is not a dependency on it, in either comment form.
    for prose in [
        "/// Infallible: it does not take a `DeploymentRequest` and re-decide anything.",
        "//! [`build_delegated_signing`] replaced its `DeploymentRequest` parameter with a plan.",
        "    // let c: &deployment_request::DeploymentRequest = todo!();",
    ] {
        assert!(is_comment(prose), "not recognised as a comment: {prose:?}");
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
/// stopped at the wrong line would scan test fixtures, where a `ValidatedDeployment` is
/// legitimate, and report a violation that is not one.
#[test]
fn the_split_excludes_test_code() {
    let source = "fn materialize() {}\n#[cfg(test)]\nmod tests {\n    use crate::deployment_request::DeploymentRequest;\n}\n";
    assert!(!production_half(source).contains("DeploymentRequest"));
    assert!(production_half(source).contains("materialize"));
}
