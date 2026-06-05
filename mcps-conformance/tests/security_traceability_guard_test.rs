//! MCPS-070 (MCPS-EPIC-P6.6C) — security traceability manifest drift guard.
//!
//! The committed manifest at
//! `components/mcps/mcps-conformance/security_traceability_manifest.json` is the
//! SINGLE SOURCE OF TRUTH mapping each MCP-S security property (P6.6A + P6.6B) to
//! the Bazel test target AND the named test function that proves it. Docs say
//! "see the manifest" instead of quoting a literal count that rots.
//!
//! This guard FAILS on any drift:
//!
//!   1. an entry names a `bazel_target` that no `BUILD.bazel` (among the mcps
//!      packages this guard is handed) declares as an `nt_rust_test` rule — i.e.
//!      a target was renamed or removed;
//!   2. an entry names a `test_fn` that does not appear as a `fn <name>(` in the
//!      entry's `source` test file on disk — i.e. a test function was renamed or
//!      removed;
//!   3. an entry's `source` path does not match its `bazel_target` package, or the
//!      named source does not exist on disk;
//!   4. the recorded `counts.entries` disagrees with the actual number of entries;
//!   5. the four required server-cert-verification cases (trusted accepted,
//!      untrusted rejected, wrong identity, expired) are not all present.
//!
//! Every input is delivered through Bazel `data` runfiles and read from DISK at
//! test time (resolved via `$(rlocationpath)` against `TEST_SRCDIR`/`RUNFILES_DIR`,
//! the same scheme as the conformance drift_guard) — so a renamed target or fn is
//! caught by re-reading reality, never by a trusted-as-written assertion.
//!
//! std + serde_json only (no new crates).

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

// --- runfiles resolution (same scheme as the conformance drift_guard) --------

fn locate(env_key: &str) -> PathBuf {
    mcps_test_paths::resolve_runfile(env_key)
}

fn read(env_key: &str) -> String {
    let path = locate(env_key);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

fn manifest() -> Value {
    serde_json::from_str(&read("MCPS_SECURITY_MANIFEST"))
        .expect("security_traceability_manifest.json parses")
}

// --- manifest views ----------------------------------------------------------

fn entries(m: &Value) -> &Vec<Value> {
    m["entries"].as_array().expect("entries is an array")
}

fn entry_str<'a>(entry: &'a Value, key: &str) -> &'a str {
    entry[key]
        .as_str()
        .unwrap_or_else(|| panic!("entry missing string field '{key}': {entry}"))
}

// --- on-disk derivation ------------------------------------------------------

/// The map from `//<package>` label-prefix to the env var carrying that
/// package's BUILD.bazel runfile path. These are the packages every manifest
/// `bazel_target` is allowed to reference.
const BUILD_ENVS: &[(&str, &str)] = &[
    ("//mcps-conformance", "MCPS_BUILD_CONFORMANCE"),
    ("//mcps-core", "MCPS_BUILD_CORE"),
    ("//mcps-host", "MCPS_BUILD_HOST"),
    ("//mcps-policy", "MCPS_BUILD_POLICY"),
    ("//mcps-proxy", "MCPS_BUILD_PROXY"),
    ("//mcps-demo", "MCPS_BUILD_DEMO"),
    ("//mcps-demo-server", "MCPS_BUILD_DEMO_SERVER"),
    ("//mcps-transport", "MCPS_BUILD_TRANSPORT"),
];

/// Every `//<pkg>:<name>` test target declared by an `nt_rust_test(` rule in any
/// of the handed BUILD files. A hand-rolled scan (no Starlark parser): find each
/// `nt_rust_test(` and take the first `name = "..."` that follows it.
fn declared_test_targets() -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    for (package, env_key) in BUILD_ENVS {
        let text = read(env_key);
        for name in test_names_in_build(&text) {
            targets.insert(format!("{package}:{name}"));
        }
    }
    targets
}

fn test_names_in_build(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("nt_rust_test(") {
        let block_start = search_from + rel + "nt_rust_test(".len();
        if let Some(name_rel) = text[block_start..].find("name") {
            let after_name = block_start + name_rel;
            if let Some(q1_rel) = text[after_name..].find('"') {
                let q1 = after_name + q1_rel + 1;
                if let Some(q2_rel) = text[q1..].find('"') {
                    names.push(text[q1..q1 + q2_rel].to_string());
                }
            }
        }
        search_from = block_start;
    }
    names
}

/// Map a manifest `source` workspace-relative path (e.g.
/// `mcps-demo/tests/demo_negative_e2e_test.rs`) to the env var that delivers its
/// runfile. Sources are handed individually so the guard can read each one.
fn source_env_for(source: &str) -> &'static str {
    match source {
        "mcps-conformance/tests/object_suite_test.rs" => "MCPS_SRC_OBJECT_SUITE",
        "mcps-demo/tests/demo_negative_e2e_test.rs" => "MCPS_SRC_DEMO_NEGATIVE_E2E",
        "mcps-demo/tests/demo_transport_e2e_test.rs" => "MCPS_SRC_DEMO_TRANSPORT_E2E",
        "mcps-demo/tests/demo_e2e_persistent_test.rs" => "MCPS_SRC_DEMO_E2E_PERSISTENT",
        "mcps-demo/tests/demo_posture_e2e_test.rs" => "MCPS_SRC_DEMO_POSTURE_E2E",
        "mcps-demo-server/tests/received_log_test.rs" => "MCPS_SRC_RECEIVED_LOG",
        "mcps-transport/tests/mtls_client_test.rs" => "MCPS_SRC_MTLS_CLIENT",
        "mcps-host/tests/host_session_test.rs" => "MCPS_SRC_HOST_SESSION",
        "mcps-proxy/tests/persistent_scope_test.rs" => "MCPS_SRC_PERSISTENT_SCOPE",
        "mcps-proxy/tests/persistent_inner_test.rs" => "MCPS_SRC_PERSISTENT_INNER",
        "mcps-proxy/tests/persistent_session_test.rs" => "MCPS_SRC_PERSISTENT_SESSION",
        "mcps-proxy/tests/proxy_test.rs" => "MCPS_SRC_PROXY",
        "mcps-proxy/tests/key_source_test.rs" => "MCPS_SRC_KEY_SOURCE",
        "mcps-proxy/tests/dev_env_key_source_test.rs" => "MCPS_SRC_DEV_ENV_KEY_SOURCE",
        other => panic!(
            "manifest 'source' {other:?} has no runfile wired in the guard BUILD target. \
             Add a data entry + env var for it (so the guard can read the test fn)."
        ),
    }
}

/// `true` iff the text declares a free function `fn <name>(` (the form every
/// `#[test]` uses). Tolerates `pub`/`async` and arbitrary leading whitespace by
/// matching the `fn <name>(` token directly.
fn declares_fn(text: &str, name: &str) -> bool {
    let needle = format!("fn {name}(");
    text.contains(&needle)
}

// --- drift conditions --------------------------------------------------------

/// Condition (1): every `bazel_target` in the manifest is declared by some
/// BUILD.bazel as an `nt_rust_test`. A renamed/removed target fails here.
#[test]
fn every_bazel_target_is_declared_in_a_build_file() {
    let m = manifest();
    let declared = declared_test_targets();
    let mut missing: Vec<String> = Vec::new();
    for entry in entries(&m) {
        let target = entry_str(entry, "bazel_target");
        if !declared.contains(target) {
            missing.push(target.to_string());
        }
    }
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "manifest references bazel_target(s) that no BUILD.bazel declares as nt_rust_test \
         (renamed/removed?). Fix security_traceability_manifest.json or the BUILD file: {missing:?}"
    );
}

/// Condition (3a): every entry's `source` workspace-relative path agrees with its
/// `bazel_target` package prefix, so the source we grep belongs to the target we
/// assert. (`//mcps-demo:x` ⇒ source must start with `mcps-demo/`.)
#[test]
fn entry_source_matches_target_package() {
    let m = manifest();
    let mut mismatches: Vec<String> = Vec::new();
    for entry in entries(&m) {
        let target = entry_str(entry, "bazel_target");
        let source = entry_str(entry, "source");
        let package = target
            .split(':')
            .next()
            .and_then(|p| p.strip_prefix("//"))
            .unwrap_or("");
        if !source.starts_with(&format!("{package}/")) {
            mismatches.push(format!("{target} <-> {source}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "manifest entries whose source path does not belong to the target's package: {mismatches:?}"
    );
}

/// Condition (2) + (3b): every entry's `test_fn` appears as `fn <name>(` in the
/// entry's `source` file read from disk. A renamed/removed test fn fails here.
#[test]
fn every_test_fn_appears_in_its_source() {
    let m = manifest();
    let mut missing: Vec<String> = Vec::new();
    for entry in entries(&m) {
        let source = entry_str(entry, "source");
        let test_fn = entry_str(entry, "test_fn");
        let text = read(source_env_for(source));
        if !declares_fn(&text, test_fn) {
            missing.push(format!("{test_fn} (in {source})"));
        }
    }
    assert!(
        missing.is_empty(),
        "manifest references test_fn(s) absent from their source file (renamed/removed?). \
         Fix security_traceability_manifest.json or the test source: {missing:?}"
    );
}

/// Condition (4): the recorded count must equal the actual number of entries.
#[test]
fn recorded_count_is_derived_not_stale() {
    let m = manifest();
    let recorded = m["counts"]["entries"]
        .as_u64()
        .expect("counts.entries is a u64");
    let actual = entries(&m).len() as u64;
    assert_eq!(
        recorded, actual,
        "counts.entries ({recorded}) disagrees with the entries array length ({actual})"
    );
}

/// Condition (5): the four required server-cert-verification cases are all
/// present (the acceptance criterion explicitly demands keeping all four). We key
/// on each case's distinguishing `test_fn`, all in mtls_client_test.
#[test]
fn four_server_auth_cases_are_present() {
    let m = manifest();
    let fns: BTreeSet<String> = entries(&m)
        .iter()
        .filter(|e| entry_str(e, "bazel_target") == "//mcps-transport:mtls_client_test")
        .map(|e| entry_str(e, "test_fn").to_string())
        .collect();
    for required in [
        "trusted_server_and_client_round_trip_succeeds", // trusted accepted
        "untrusted_server_cert_is_rejected",             // untrusted rejected
        "wrong_server_identity_is_rejected",             // wrong identity
        "expired_server_cert_is_rejected",               // expired
    ] {
        assert!(
            fns.contains(required),
            "required server-auth case missing from the manifest: {required}"
        );
    }
}

/// Sanity: the guard actually parsed something from every source, so a silent
/// empty-set false-pass (e.g. a renamed env var resolving to an empty file)
/// cannot masquerade as "no drift".
#[test]
fn guard_inputs_are_non_empty() {
    let m = manifest();
    assert!(!entries(&m).is_empty(), "manifest has zero entries — wiring broken");
    assert!(
        declared_test_targets().len() >= 20,
        "parsed too few nt_rust_test targets from BUILD files — parser/wiring broken"
    );
    // The guard test target must itself be a declared target under mcps-conformance.
    assert!(
        declared_test_targets().contains("//mcps-conformance:security_traceability_guard_test"),
        "BUILD must declare the security_traceability_guard_test target itself"
    );
}

/// Self-check of the drift detector (Condition 1 + 2 mechanics): the guard's own
/// matchers MUST reject a renamed target and a renamed fn. This is the
/// "would fail on drift" demonstration kept green: it proves the negative path
/// without mutating the committed manifest. If `nt_rust_test` were renamed or a
/// referenced fn removed, `every_bazel_target_is_declared_in_a_build_file` /
/// `every_test_fn_appears_in_its_source` would fire exactly as asserted here.
#[test]
fn drift_detector_rejects_renamed_target_and_fn() {
    // A target absent from the declared set is reported missing.
    let declared = declared_test_targets();
    assert!(
        !declared.contains("//mcps-transport:mtls_client_test_RENAMED"),
        "a renamed target must NOT be found among declared targets (drift would be caught)"
    );
    // A fn absent from a source is reported missing.
    let host_session = read("MCPS_SRC_HOST_SESSION");
    assert!(
        declares_fn(&host_session, "signed_request_is_accepted_by_the_verifier"),
        "control: the real fn is found"
    );
    assert!(
        !declares_fn(&host_session, "signed_request_is_accepted_by_the_verifier_RENAMED"),
        "a renamed fn must NOT be found in the source (drift would be caught)"
    );
}
