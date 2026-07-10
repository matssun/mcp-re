//! MCPS-031 — drift-guarded conformance manifest.
//!
//! The committed manifest at `components/mcp-re/mcp-re-conformance/conformance_manifest.json`
//! is the SINGLE SOURCE OF TRUTH for the MCP-RE conformance corpus: every vector
//! (Core + Phase 5 authorization) and every `//components/mcp-re/...` Bazel
//! `rust_test` target. This guard FAILS on any drift:
//!
//!   1. a vector file exists on disk but is missing from the manifest;
//!   2. a manifest entry points at a vector that does not exist;
//!   3. a recorded count is stale (counts are DERIVED from the on-disk fixtures
//!      and the manifest's own enumerated lists — never trusted as written);
//!   4. a `rust_test` target is added/removed under `components/mcp-re` without a
//!      corresponding manifest update.
//!
//! Every input is delivered through Bazel `data` runfiles and read from DISK at
//! test time (resolved via `$(rlocationpath)` against `TEST_SRCDIR`/`RUNFILES_DIR`,
//! the same scheme as the stdio/full-stack harnesses) — so a hardcoded count
//! cannot silently rot: the guard re-counts reality and compares.
//!
//! std + serde_json only (no new crates; mcp-re-conformance already depends on
//! serde_json and may use std::fs — mcp-re-core stays pure).

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

// --- runfiles resolution (same scheme as the stdio harness) ------------------

/// Resolve a `$(rlocationpath)` env var to an on-disk path via the runfiles root.
fn locate(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

fn read(env_key: &str) -> String {
    let path = locate(env_key);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

fn manifest() -> Value {
    serde_json::from_str(&read("MCP_RE_MANIFEST")).expect("conformance_manifest.json parses")
}

// --- on-disk derivation ------------------------------------------------------

/// Scan the directory that physically holds the Core vector fixtures. We are
/// handed the committed `manifest.json` sentinel; its PARENT directory is the
/// vectors dir. Count `*.json` files, excluding the non-vector `manifest.json`.
fn on_disk_core_vector_files() -> BTreeSet<String> {
    let manifest_path = locate("MCP_RE_CORE_MANIFEST");
    let dir = manifest_path
        .parent()
        .expect("core manifest has a parent dir");
    let mut files = BTreeSet::new();
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}")) {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".json") && name != "manifest.json" {
            files.insert(name);
        }
    }
    files
}

/// The names of the Phase 5 authorization vectors actually present in the
/// committed `phase5_vectors.json` array.
fn on_disk_authorization_cases() -> Vec<String> {
    let json = read("MCP_RE_PHASE5");
    let arr: Vec<Value> = serde_json::from_str(&json).expect("phase5_vectors.json is an array");
    arr.iter()
        .map(|v| {
            v["name"]
                .as_str()
                .expect("each authorization vector has a name")
                .to_string()
        })
        .collect()
}

/// Parse `name = "..."` from every `nt_rust_test(...)` block in the BUILD files
/// delivered as data, producing the canonical `//components/mcp-re/<pkg>:<name>`
/// labels. A tiny hand-rolled scan (no Starlark parser): find each
/// `nt_rust_test(` and take the first `name = "..."` that follows it.
fn on_disk_test_targets() -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    for (env_key, package) in [
        ("MCP_RE_BUILD_CONFORMANCE", "//mcp-re-conformance"),
        ("MCP_RE_BUILD_CORE", "//mcp-re-core"),
        ("MCP_RE_BUILD_HOST", "//mcp-re-host"),
        ("MCP_RE_BUILD_POLICY", "//mcp-re-policy"),
        ("MCP_RE_BUILD_PROXY", "//mcp-re-proxy"),
        // Every remaining //components/mcp-re/... package with rust_test targets is
        // scanned (MCPS-082, audit M-11/M-13): the manifest's single-source-of-truth
        // claim covers EVERY such target. MCP-RE is HTTP-profile only — the stdio
        // bridge and the stdio demo-server/fileserver packages were removed.
        ("MCP_RE_BUILD_DEMO", "//mcp-re-demo"),
        ("MCP_RE_BUILD_TRANSPORT", "//mcp-re-transport"),
    ] {
        let text = read(env_key);
        for name in test_names_in_build(&text) {
            targets.insert(format!("{package}:{name}"));
        }
    }
    targets
}

/// Extract the `name` of every `nt_rust_test(` rule in one BUILD file's text.
fn test_names_in_build(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("nt_rust_test(") {
        let block_start = search_from + rel + "nt_rust_test(".len();
        // Find the first `name = "..."` after the rule opening.
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

// --- manifest views ----------------------------------------------------------

fn manifest_core_files(m: &Value) -> BTreeSet<String> {
    m["vectors"]["core"]["files"]
        .as_array()
        .expect("vectors.core.files is an array")
        .iter()
        .map(|v| v.as_str().expect("file name is a string").to_string())
        .collect()
}

fn manifest_authorization_cases(m: &Value) -> Vec<String> {
    m["vectors"]["authorization"]["cases"]
        .as_array()
        .expect("vectors.authorization.cases is an array")
        .iter()
        .map(|v| v.as_str().expect("case name is a string").to_string())
        .collect()
}

fn manifest_targets(m: &Value) -> BTreeSet<String> {
    m["bazel_test_targets"]
        .as_array()
        .expect("bazel_test_targets is an array")
        .iter()
        .map(|v| v.as_str().expect("target is a string").to_string())
        .collect()
}

fn manifest_count(m: &Value, key: &str) -> u64 {
    m["counts"][key]
        .as_u64()
        .unwrap_or_else(|| panic!("counts.{key} is a u64"))
}

// --- drift conditions --------------------------------------------------------

/// Condition (1) + (2): the manifest's enumerated Core vector files must EXACTLY
/// match the set of vector files physically on disk. A new file with no manifest
/// entry, or a manifest entry naming a deleted file, fails here.
#[test]
fn core_vector_files_match_disk_exactly() {
    let m = manifest();
    let recorded = manifest_core_files(&m);
    let on_disk = on_disk_core_vector_files();

    let missing_from_manifest: Vec<&String> = on_disk.difference(&recorded).collect();
    let missing_from_disk: Vec<&String> = recorded.difference(&on_disk).collect();

    assert!(
        missing_from_manifest.is_empty(),
        "Core vector(s) on disk but absent from the manifest (add them to \
         conformance_manifest.json vectors.core.files): {missing_from_manifest:?}"
    );
    assert!(
        missing_from_disk.is_empty(),
        "Manifest names Core vector(s) that do not exist on disk (remove them \
         from conformance_manifest.json): {missing_from_disk:?}"
    );
}

/// Condition (2) for the authorization corpus: every case named in the manifest
/// exists in the committed `phase5_vectors.json`, and vice versa.
#[test]
fn authorization_cases_match_disk_exactly() {
    let m = manifest();
    let recorded: BTreeSet<String> = manifest_authorization_cases(&m).into_iter().collect();
    let on_disk: BTreeSet<String> = on_disk_authorization_cases().into_iter().collect();
    assert_eq!(
        recorded, on_disk,
        "Phase 5 authorization vectors drifted: manifest vs phase5_vectors.json. \
         Update conformance_manifest.json vectors.authorization.cases."
    );
}

/// Condition (3): every recorded count must equal the value DERIVED from disk
/// (and from the manifest's own enumerated lists). Hardcoded counts that rot
/// are caught here.
#[test]
fn recorded_counts_are_derived_not_stale() {
    let m = manifest();

    let core_on_disk = on_disk_core_vector_files().len() as u64;
    let auth_on_disk = on_disk_authorization_cases().len() as u64;
    let targets_on_disk = on_disk_test_targets().len() as u64;

    assert_eq!(
        manifest_count(&m, "core_vector_files"),
        core_on_disk,
        "counts.core_vector_files is stale (disk has {core_on_disk})"
    );
    assert_eq!(
        manifest_count(&m, "authorization_vector_cases"),
        auth_on_disk,
        "counts.authorization_vector_cases is stale (disk has {auth_on_disk})"
    );
    assert_eq!(
        manifest_count(&m, "total_vectors"),
        core_on_disk + auth_on_disk,
        "counts.total_vectors is stale (disk has {})",
        core_on_disk + auth_on_disk
    );
    assert_eq!(
        manifest_count(&m, "bazel_test_targets"),
        targets_on_disk,
        "counts.bazel_test_targets is stale (BUILD files declare {targets_on_disk})"
    );

    // Cross-check: the recorded counts also match the manifest's enumerated
    // lists (so the lists and the counts cannot disagree with each other).
    assert_eq!(
        manifest_count(&m, "core_vector_files"),
        manifest_core_files(&m).len() as u64,
        "counts.core_vector_files disagrees with vectors.core.files length"
    );
    assert_eq!(
        manifest_count(&m, "authorization_vector_cases"),
        manifest_authorization_cases(&m).len() as u64,
        "counts.authorization_vector_cases disagrees with vectors.authorization.cases length"
    );
    assert_eq!(
        manifest_count(&m, "bazel_test_targets"),
        manifest_targets(&m).len() as u64,
        "counts.bazel_test_targets disagrees with bazel_test_targets length"
    );
}

/// Condition (4): the recorded `//components/mcp-re/...` rust_test target set must
/// EXACTLY match the targets declared in the committed BUILD files. Adding or
/// removing a `nt_rust_test` rule without updating the manifest fails here.
#[test]
fn bazel_test_targets_match_build_files_exactly() {
    let m = manifest();
    let recorded = manifest_targets(&m);
    let on_disk = on_disk_test_targets();

    let missing_from_manifest: Vec<&String> = on_disk.difference(&recorded).collect();
    let missing_from_build: Vec<&String> = recorded.difference(&on_disk).collect();

    assert!(
        missing_from_manifest.is_empty(),
        "rust_test target(s) declared in BUILD.bazel but absent from the manifest \
         (add to conformance_manifest.json bazel_test_targets): {missing_from_manifest:?}"
    );
    assert!(
        missing_from_build.is_empty(),
        "Manifest records rust_test target(s) that no longer exist in any BUILD.bazel \
         (remove from conformance_manifest.json): {missing_from_build:?}"
    );
}

/// Sanity: the guard actually parsed *something* from every source, so a silent
/// empty-set false-pass (e.g. a renamed env var resolving to an empty file)
/// cannot masquerade as "no drift".
#[test]
fn guard_inputs_are_non_empty() {
    assert!(
        !on_disk_core_vector_files().is_empty(),
        "scanned zero Core vector files — runfiles wiring is broken"
    );
    assert!(
        !on_disk_authorization_cases().is_empty(),
        "parsed zero authorization cases — runfiles wiring is broken"
    );
    assert!(
        on_disk_test_targets().len() >= 10,
        "parsed too few rust_test targets from BUILD files — parser/wiring broken"
    );
    // The guard test target must itself be recorded (it is a target under
    // components/mcp-re too) — proves the manifest includes the guard.
    assert!(
        manifest_targets(&manifest()).contains("//mcp-re-conformance:drift_guard_test"),
        "manifest must record the drift_guard_test target itself"
    );
}
