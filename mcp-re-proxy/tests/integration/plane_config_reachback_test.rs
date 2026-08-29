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
//! It proves that the production code of each module below mentions no configuration type
//! by name. It does NOT prove semantic independence: a plane handed a closure that reads
//! configuration, or a plan type that grew a `DeploymentRequest` field, would satisfy this
//! and violate the property. Keeping the claim narrow is deliberate; a gate that overstates
//! itself is what stops people looking.
//!
//! Test code is deliberately out of scope. A test may build a `ValidatedDeployment` to drive
//! the production constructor — `trust_plane`'s own no-cadence teardown test does exactly
//! that, and it is the more convincing test for being end-to-end.
//!
//! # "Production" means every line outside a test region
//!
//! It does NOT mean "above the first `#[cfg(test)]`", which is what this gate used to
//! measure. Rust places no constraint on where a test module sits, so a reach-back written
//! below one was invisible: the scan stopped at the attribute and reported a clean pass
//! over code it never read — and an inline `#[cfg(test)]` helper sits hundreds of lines
//! above the real test module in `trust_plane.rs`, `signing_plane.rs` and `tls_plane.rs`,
//! so the truncation point was not even the test module in three of the five files here.
//!
//! [`mcp_re_test_paths::rust_source`] owns the region definition, shared with the sibling
//! source-scanning gates and with `scripts/module_size_gate.py`, and
//! [`the_rule_would_catch_a_reach_back_below_the_test_module`] is this gate's own control
//! over it.

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
        why: "tls_plane establishes the posture in ChannelEstablishmentPlan (ADR-MCPRE-056 §8)",
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

/// Whether `line` names `ident` as a whole identifier rather than inside a longer one, and
/// as something other than an interior MODULE PATH segment.
///
/// `crate::revocation_tier::RevocationTier` shares a spelling with the `DeploymentRequest`
/// field it was named after, and the two are opposites under this rule: the field is the
/// primitive a plane must not re-read, while the module is where the classified STATE lives
/// — consuming which is the whole point. An interior `::name::` is therefore a path into a
/// state owner, never a field read, and a field read (`config.name`, `plan.name`) is never
/// interior to a path.
///
/// This distinction was invisible while the rule scanned only each plane's `mod.rs`. Widening
/// the scope to the plane's whole subtree surfaced it in `trust_plane/revocation_resolver.rs`,
/// which materialises the tier it is HANDED. Measuring the spelling instead of the
/// proposition is how these rules go wrong — the same reason comments are already skipped.
fn names_identifier(line: &str, ident: &str) -> bool {
    let boundary = |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    line.match_indices(ident).any(|(at, _)| {
        boundary(line[..at].chars().next_back())
            && boundary(line[at + ident.len()..].chars().next())
    })
}

/// Whether `line` READS `field` — as opposed to naming a module that shares its spelling.
///
/// `crate::revocation_tier::RevocationTier` shares a spelling with the `DeploymentRequest`
/// field it was named after, and the two are opposites under this rule: the field is the
/// primitive a plane must not re-read, while the module is where the classified STATE lives
/// — consuming which is the whole point. An interior `::name::` is therefore a path into a
/// state owner, never a field read, and a field read (`config.name`, `plan.name`) is never
/// interior to a path.
///
/// This distinction only matters for the per-plane FIELD list. The
/// [`CONFIGURATION_NAMES`] list is the opposite kind of rule — naming the configuration
/// model AT ALL is the violation there, module path included — so it keeps
/// [`names_identifier`].
///
/// The difference was invisible while the rule scanned only each plane's `mod.rs`. Widening
/// the scope to the plane's whole subtree surfaced it in `trust_plane/revocation_resolver.rs`,
/// which materialises the tier it is HANDED. Measuring the spelling instead of the
/// proposition is how these rules go wrong — the same reason comments are already skipped.
fn reads_field(line: &str, field: &str) -> bool {
    let boundary = |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    line.match_indices(field).any(|(at, _)| {
        let before = &line[..at];
        let after = &line[at + field.len()..];
        if before.ends_with("::") && after.starts_with("::") {
            return false; // an interior module path segment, not a field read
        }
        boundary(before.chars().next_back()) && boundary(after.chars().next())
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

/// A forbidden name found in production code: its line number, the name, and the line.
struct Reach {
    number: usize,
    name: String,
    line: String,
}

/// Every forbidden name `source` reaches for from production code.
///
/// This is the gate itself, taken as a function of source TEXT so that the self-control
/// below can run the real scan — region removal, comment filtering and whole-identifier
/// matching together — over a synthetic module. A control that exercised only the region
/// helper would leave the composition untested, which is the shape of bug this gate had.
fn reaches_for(source: &str, names: &[&str]) -> Vec<Reach> {
    scan(source, names, names_identifier)
}

/// Every FIELD `source` re-reads from production code — the per-plane list, scanned with
/// the module-path distinction [`reads_field`] draws.
fn re_reads(source: &str, fields: &[&str]) -> Vec<Reach> {
    scan(source, fields, reads_field)
}

fn scan(source: &str, names: &[&str], hit: fn(&str, &str) -> bool) -> Vec<Reach> {
    let mut found = Vec::new();
    for (number, line) in mcp_re_test_paths::rust_source::production_lines(source) {
        if is_comment(line) {
            continue;
        }
        for name in names {
            if hit(line, name) {
                found.push(Reach {
                    number,
                    name: (*name).to_string(),
                    line: line.trim().to_string(),
                });
            }
        }
    }
    found
}

/// Every reach rendered one per line, so a plane with several is reported once rather than
/// one test run per violation.
fn report(found: &[Reach]) -> String {
    found
        .iter()
        .map(|r| format!("  line {}: names {:?}\n    {}", r.number, r.name, r.line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `plane`'s delivered source, with the path it came from.
///
/// A plane that has grown an owner subtree is read WHOLE: the rule is about the plane, and
/// a scan of its `mod.rs` alone would report a clean pass over the subordinate owners that
/// hold most of it. The scope is the DIRECTORY, walked, rather than a list of files — a list
/// has to learn about the next file, and the failure mode of a stale list is a clean pass
/// over unmeasured code.
fn plane_source(plane: &Plane) -> (std::path::PathBuf, String) {
    let path = mcp_re_test_paths::resolve_runfile(plane.env);
    let read = |p: &std::path::Path| {
        std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    };
    if path.file_name().is_none_or(|name| name != "mod.rs") {
        let source = read(&path);
        return (path, source);
    }
    let root = path
        .parent()
        .unwrap_or_else(|| panic!("{} has no parent directory", path.display()))
        .to_path_buf();
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    files.sort();
    let source = files.iter().map(|f| read(f)).collect::<Vec<_>>().join("\n");
    (root, source)
}

fn collect_rust_files(dir: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read dir {dir:?}: {e}"));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
}

#[test]
fn a_projected_plane_names_no_configuration_type() {
    for plane in PROJECTED_PLANES {
        let (path, source) = plane_source(plane);
        let found = reaches_for(&source, CONFIGURATION_NAMES);
        assert!(
            found.is_empty(),
            "{} — {}. The plane establishes what its plan says; if the plan does not carry \
             what is needed here, widen the plan rather than reading configuration past \
             it.\n{}",
            path.display(),
            plane.why,
            report(&found)
        );
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
        let (path, source) = plane_source(plane);
        let found = re_reads(&source, plane.reconstructed);
        assert!(
            found.is_empty(),
            "{} — {}. Consume the classified state the plan carries; a primitive here means \
             the plane is deciding again what has already been decided.\n{}",
            path.display(),
            plane.why,
            report(&found)
        );
    }
}

/// The gate detects what it claims to. Without this, an expression error — a path that
/// never matches — leaves every assertion above vacuously true, and a green run would mean
/// nothing at all.
/// A path INTO a classified state's own module is not a reach-back; a read of the
/// same-named request field is.
#[test]
fn a_module_path_is_not_a_field_read() {
    assert!(!reads_field(
        "use crate::revocation_tier::RevocationTier;",
        "revocation_tier"
    ));
    assert!(!reads_field(
        "    tier: &crate::revocation_tier::RevocationTier,",
        "revocation_tier"
    ));
    assert!(reads_field(
        "    let tier = config.revocation_tier.clone();",
        "revocation_tier"
    ));
    assert!(reads_field(
        "    if plan.revocation_tier.is_none() {",
        "revocation_tier"
    ));
    // And the OTHER list keeps counting a module path: naming the configuration model at
    // all is the violation there.
    assert!(names_identifier(
        "use crate::deployment_request::KeySourceKind;",
        "deployment_request"
    ));
}

#[test]
fn the_rule_would_catch_a_reach_back() {
    let reaching = "fn materialize(plan: &TrustPlan) {\n    let _ = config.trust_path;\n}\n\
                    #[cfg(test)]\nmod tests {}\n";
    assert!(
        reaches_for(reaching, CONFIGURATION_NAMES).is_empty(),
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

/// Test code is out of scope, so a fixture cannot make the gate fail.
///
/// A rule that stopped at the wrong line would scan test modules, where a
/// `ValidatedDeployment` is legitimate, and report a violation that is not one.
#[test]
fn the_scan_excludes_test_code() {
    let source = "fn materialize() {}\n#[cfg(test)]\nmod tests {\n    use crate::deployment_request::DeploymentRequest;\n}\n";
    assert!(
        reaches_for(source, CONFIGURATION_NAMES).is_empty(),
        "a `ValidatedDeployment` inside a test module was read as a reach-back"
    );
}

/// **The control this gate was missing.** A reach-back written BELOW the test module is
/// caught.
///
/// The previous implementation measured "everything above the first `#[cfg(test)]`", which
/// is not the property it claims. Rust permits production items after a test module, and
/// three of the five modules scanned here carry an inline `#[cfg(test)]` helper hundreds of
/// lines above their test module — so the truncation point was not even the test module,
/// and every line below it was unexamined while the gate reported a clean pass.
///
/// This is a NEGATIVE control: it asserts the gate FIRES. Paired with
/// [`the_scan_excludes_test_code`] above it pins both directions, which is what stops the
/// fix from being "scan everything" — a rule that flagged the test module would be
/// unsatisfiable and would get deleted.
#[test]
fn the_rule_would_catch_a_reach_back_below_the_test_module() {
    let source = "fn materialize(plan: &TrustPlan) {}\n\
                  #[cfg(test)]\n\
                  mod tests {\n\
                  \x20   use crate::deployment_request::DeploymentRequest;\n\
                  }\n\
                  fn rematerialize(config: &ValidatedDeployment) {}\n";
    let found = reaches_for(source, CONFIGURATION_NAMES);
    assert_eq!(
        found.len(),
        1,
        "expected exactly the reach-back below the test module, got {:?}",
        found
            .iter()
            .map(|r| (r.number, &r.name))
            .collect::<Vec<_>>()
    );
    let reach = found.first().expect("one reach");
    assert_eq!(reach.name, "ValidatedDeployment");
    assert_eq!(
        reach.number, 6,
        "the violation must be reported at its real line, not at a filtered-copy offset"
    );
}

/// The same control for the reconstruction check, whose name list is per-plane.
///
/// Both scans share `reaches_for`, so this is not a duplicate assertion about the same
/// code path: it pins that the per-plane name list reaches the same corrected scan, and a
/// future split of the two checks cannot silently take one of them back to truncation.
#[test]
fn the_reconstruction_rule_also_looks_below_the_test_module() {
    let source = "fn materialize(plan: &TrustPlan) {}\n\
                  #[cfg(test)]\n\
                  mod tests {\n\
                  \x20   let _ = revocation_tier;\n\
                  }\n\
                  fn later() { let _ = plan.revocation_tier; }\n";
    let found = reaches_for(source, &["revocation_tier"]);
    assert_eq!(found.len(), 1, "the region-aware scan saw the wrong lines");
    assert_eq!(found.first().map(|r| r.number), Some(6));
}

/// An inline `#[cfg(test)]` helper above the test module does not end the scan.
///
/// This is the shape that made the old truncation worst in practice: the attribute the
/// scan stopped at was not the test module at all, so the file's entire body went
/// unexamined.
#[test]
fn an_inline_test_helper_does_not_end_the_scan() {
    let source = "fn a() {}\n\
                  #[cfg(test)]\n\
                  fn helper() {}\n\
                  fn materialize(config: &ValidatedDeployment) {}\n";
    let found = reaches_for(source, CONFIGURATION_NAMES);
    assert_eq!(found.first().map(|r| r.number), Some(4));
}
