//! MCPS-070 (MCP-RE-EPIC-P6.6C) — security traceability manifest drift guard.
//!
//! The committed manifest at
//! `components/mcp-re/mcp-re-conformance/security_traceability_manifest.json` is the
//! SINGLE SOURCE OF TRUTH mapping each MCP-RE security property (P6.6A + P6.6B) to
//! the Bazel test target AND the named test function that proves it. Docs say
//! "see the manifest" instead of quoting a literal count that rots.
//!
//! This guard FAILS on any drift:
//!
//!   1. an entry names a `bazel_target` that no `BUILD.bazel` (among the mcp-re
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
    mcp_re_test_paths::resolve_runfile(env_key)
}

fn read(env_key: &str) -> String {
    let path = locate(env_key);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

fn manifest() -> Value {
    serde_json::from_str(&read("MCP_RE_SECURITY_MANIFEST"))
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

/// Every `property` string the manifest declares.
fn manifest_properties(m: &Value) -> Vec<String> {
    entries(m)
        .iter()
        .map(|e| entry_str(e, "property").to_string())
        .collect()
}

// --- §A claim-matrix derivation (ADR-MCPS-036 gate item 1) --------------------

/// One §A capability row: the capability label and the set of manifest-property
/// phrases its Required-conformance cell quotes (each split on the `…`/`...`
/// ellipsis into the fragments that must ALL appear in one manifest property).
struct ClaimRow {
    capability: String,
    /// Each element is one quoted citation, already split into its `…` fragments.
    cited: Vec<Vec<String>>,
}

/// Parse §A of the v0.5 claim matrix from DISK into its capability rows. §A is the
/// region between the `## §A` heading and the `## §B` heading; a capability row is
/// a markdown table row (`| … |`) with ≥ 6 cells that is neither the header
/// (`Capability …`) nor the `---` separator. The Required-conformance cell is the
/// 5th column (index 4); every double-quoted phrase in it is a manifest-property
/// citation, split on the `…`/`...` ellipsis into substring fragments.
fn parse_section_a(matrix: &str) -> Vec<ClaimRow> {
    let a = matrix
        .split_once("## §A")
        .and_then(|(_, after)| after.split_once("## §B").map(|(a, _)| a))
        .unwrap_or_else(|| panic!("claim matrix has no §A/§B sections"));
    let mut rows = Vec::new();
    for line in a.lines() {
        let t = line.trim();
        if !t.starts_with('|') {
            continue;
        }
        // Skip the `---`/`:---` separator row.
        if t.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')) {
            continue;
        }
        let cells: Vec<&str> = t.trim_matches('|').split('|').map(|c| c.trim()).collect();
        if cells.len() < 6 {
            continue;
        }
        // Skip the header row.
        if cells[0].eq_ignore_ascii_case("capability") {
            continue;
        }
        let capability = cells[0].trim_matches('*').trim().to_string();
        let required = cells[4];
        let cited = quoted_phrases(required)
            .into_iter()
            .map(|q| {
                q.split(['…'])
                    .flat_map(|s| s.split("..."))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<String>>()
            })
            .filter(|frags| !frags.is_empty())
            .collect();
        rows.push(ClaimRow { capability, cited });
    }
    rows
}

/// Every double-quoted (`"…"`) substring of `text`.
fn quoted_phrases(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some(rel) = text[i + 1..].find('"') {
                out.push(text[i + 1..i + 1 + rel].to_string());
                i = i + 1 + rel + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

// --- on-disk derivation ------------------------------------------------------

/// The map from `//<package>` label-prefix to the env var carrying that
/// package's BUILD.bazel runfile path. These are the packages every manifest
/// `bazel_target` is allowed to reference.
const BUILD_ENVS: &[(&str, &str)] = &[
    ("//mcp-re-conformance", "MCP_RE_BUILD_CONFORMANCE"),
    ("//mcp-re-core", "MCP_RE_BUILD_CORE"),
    ("//mcp-re-host", "MCP_RE_BUILD_HOST"),
    ("//mcp-re-policy", "MCP_RE_BUILD_POLICY"),
    ("//mcp-re-proxy", "MCP_RE_BUILD_PROXY"),
    ("//mcp-re-demo", "MCP_RE_BUILD_DEMO"),
    ("//mcp-re-transport", "MCP_RE_BUILD_TRANSPORT"),
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
/// `mcp-re-demo/tests/demo_negative_e2e_test.rs`) to the env var that delivers its
/// runfile. Sources are handed individually so the guard can read each one.
fn source_env_for(source: &str) -> &'static str {
    match source {
        "mcp-re-conformance/tests/object_suite_test.rs" => "MCP_RE_SRC_OBJECT_SUITE",
        "mcp-re-conformance/tests/discovery_enforcement_conformance_test.rs" => {
            "MCP_RE_SRC_DISCOVERY_ENFORCEMENT_CONFORMANCE"
        }
        "mcp-re-conformance/tests/method_transparency_test.rs" => "MCP_RE_SRC_METHOD_TRANSPARENCY",
        "mcp-re-conformance/tests/method_name_drift_guard_test.rs" => {
            "MCP_RE_SRC_METHOD_NAME_DRIFT_GUARD"
        }
        "mcp-re-conformance/tests/audit_vocabulary_guard_test.rs" => {
            "MCP_RE_SRC_AUDIT_VOCABULARY_GUARD"
        }
        "mcp-re-conformance/tests/forbidden_claim_guard_test.rs" => "MCP_RE_SRC_FORBIDDEN_CLAIM_GUARD",
        "mcp-re-conformance/tests/rfc9421_security_properties_test.rs" => {
            "MCP_RE_SRC_RFC9421_SECURITY_PROPERTIES"
        }
        "mcp-re-proxy/tests/keyset_admission_test.rs" => "MCP_RE_SRC_KEYSET_ADMISSION",
        // MCPRE-122 (ADR-MCPRE-052): the delegated-required validation matrix — the
        // serving contract, the production wiring (serve/verify/rotate/fail-closed),
        // the two-proxy client↔server round trip, and the frozen credential-
        // verification corpus. See docs/spec/delegated-required-validation-matrix.md.
        "mcp-re-proxy/tests/delegated_serving_test.rs" => "MCP_RE_SRC_DELEGATED_SERVING",
        "mcp-re-proxy/tests/delegated_production_wiring_test.rs" => "MCP_RE_SRC_DELEGATED_PROD_WIRING",
        "mcp-re-proxy/tests/delegated_client_server_e2e_test.rs" => "MCP_RE_SRC_DELEGATED_E2E",
        "mcp-re-conformance/tests/delegation_vectors_test.rs" => "MCP_RE_SRC_DELEGATION_VECTORS",
        // ADR-MCPRE-052 trust-anchor (master/root key) lifecycle — rotation overlap,
        // cutover, issuer revocation, and root issuance failure (§H of the matrix).
        "mcp-re-proxy/tests/root_key_lifecycle_test.rs" => "MCP_RE_SRC_ROOT_KEY_LIFECYCLE",
        // ADR-MCPRE-052 §I: signed trust-anchor-manifest root rotation with an
        // auto-provisioned root (the hermetic twin of the live KMS lane).
        "mcp-re-proxy/tests/root_authority_manifest_test.rs" => "MCP_RE_SRC_ROOT_AUTHORITY_MANIFEST",
        // ADR-MCPS-047: stateless cross-replica MRT continuation — open-on-A/answer-on-B
        // + fail-closed splice/one-shot binding.
        "mcp-re-proxy/tests/mrt_continuation_serving_test.rs" => "MCP_RE_SRC_MRT_CONTINUATION",
        // MCPS-72 (#252): the KMS-lifecycle offline negatives are in-crate
        // `#[cfg(test)]` unit tests, so their `source` is a `src/*.rs` file (not a
        // `tests/*.rs`). The generic provider-agnostic signer seam runs under the
        // default-feature `proxy_unit_test`; the GCP/AWS backend negatives run under
        // the both-KMS-features `proxy_ext_unit_test`. All three sources are read
        // from DISK the same way (runfile via the guard BUILD `data`).
        "mcp-re-proxy/src/kms_keysource.rs" => "MCP_RE_SRC_KMS_KEYSOURCE",
        "mcp-re-proxy/src/gcp_kms_keysource.rs" => "MCP_RE_SRC_GCP_KMS_KEYSOURCE",
        "mcp-re-proxy/src/aws_kms_keysource.rs" => "MCP_RE_SRC_AWS_KMS_KEYSOURCE",
        "mcp-re-transport/tests/mtls_client_test.rs" => "MCP_RE_SRC_MTLS_CLIENT",
        "mcp-re-host/tests/host_session_test.rs" => "MCP_RE_SRC_HOST_SESSION",
        "mcp-re-conformance/tests/http_harness_test.rs" => "MCP_RE_SRC_HTTP_HARNESS",
        "mcp-re-proxy/tests/proxy_transport_test.rs" => "MCP_RE_SRC_PROXY_TRANSPORT",
        "mcp-re-proxy/tests/proxy_test.rs" => "MCP_RE_SRC_PROXY",
        "mcp-re-proxy/tests/key_source_test.rs" => "MCP_RE_SRC_KEY_SOURCE",
        "mcp-re-proxy/tests/dev_env_key_source_test.rs" => "MCP_RE_SRC_DEV_ENV_KEY_SOURCE",
        // MCPS-62 (ADR-MCPS-023 §C, v0.10 Mode C): the attested-ingress serve-level
        // conformance vectors live in the Tier-3/Tier-4 assertion test file; the
        // Mode-C CLI guards + Mode-B strict-rejection conformance are in-crate
        // `#[cfg(test)]` unit tests in `cli.rs` (run under `proxy_unit_test`).
        "mcp-re-proxy/tests/proxy_lb_assertion_test.rs" => "MCP_RE_SRC_PROXY_LB_ASSERTION",
        "mcp-re-proxy/src/cli.rs" => "MCP_RE_SRC_CLI",
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
/// assert. (`//mcp-re-demo:x` ⇒ source must start with `mcp-re-demo/`.)
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
        .filter(|e| entry_str(e, "bazel_target") == "//mcp-re-transport:mtls_client_test")
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

/// ADR-MCPS-036 gate item 1 — "no traceability-mapped green test, no proposal
/// claim." EVERY §A capability claim in `docs/spec/v0.5-claim-matrix.md` must map
/// to at least one named test in the manifest. The matrix §A is read from DISK
/// (runfiles, same scheme as the sources) and each row's Required-conformance
/// citation(s) are matched against the manifest `property` set: a citation matches
/// when ALL of its `…`-split fragments are substrings of a single manifest
/// property. A row with no matched citation is an UNMAPPED §A claim and FAILS.
#[test]
fn every_section_a_claim_maps_to_a_manifest_entry() {
    let m = manifest();
    let props = manifest_properties(&m);
    let rows = parse_section_a(&read("MCP_RE_CLAIM_MATRIX"));
    assert!(
        rows.len() >= 13,
        "parsed too few §A capability rows ({}) — claim-matrix wiring/parse broken",
        rows.len()
    );
    let mut unmapped: Vec<String> = Vec::new();
    for row in &rows {
        let mapped = row.cited.iter().any(|frags| {
            props
                .iter()
                .any(|p| frags.iter().all(|f| p.contains(f.as_str())))
        });
        if !mapped {
            unmapped.push(format!("{} (citations: {:?})", row.capability, row.cited));
        }
    }
    assert!(
        unmapped.is_empty(),
        "§A capability claim(s) with NO mapped manifest entry — add a named green test \
         entry to security_traceability_manifest.json (no traceability-mapped green test, \
         no proposal claim — ADR-MCPS-036): {unmapped:?}"
    );
}

/// ADR-MCPS-036 gate items (b)/(c)/(d) — the three required guard pairs are each
/// represented by a named manifest entry, so the gate fails if any is dropped from
/// the spine: the #150 method-transparency PAIR (behavioral + static-drift), the
/// #151 audit-vocabulary drift guard, and the #155 forbidden-claim guard. Each is
/// keyed on its (bazel_target, test_fn) so a rename is caught by the other guards
/// re-reading reality.
#[test]
fn required_gate_guards_are_mapped() {
    let m = manifest();
    let present: BTreeSet<(String, String)> = entries(&m)
        .iter()
        .map(|e| {
            (
                entry_str(e, "bazel_target").to_string(),
                entry_str(e, "test_fn").to_string(),
            )
        })
        .collect();
    let required: &[(&str, &str)] = &[
        // #150 method-transparency pair (ADR-MCPS-030/034).
        (
            "//mcp-re-conformance:method_transparency_test",
            "accepted_verdict_is_identical_across_all_methods",
        ),
        (
            "//mcp-re-conformance:method_name_drift_guard_test",
            "no_banned_method_literal_in_non_test_core_src",
        ),
        // #151 audit-vocabulary drift guard (ADR-MCPS-035).
        (
            "//mcp-re-conformance:audit_vocabulary_guard_test",
            "every_audit_token_is_a_wire_code_or_a_fixed_event_type",
        ),
        // #155 forbidden-claim guard (ADR-MCPS-036 item 4).
        (
            "//mcp-re-conformance:forbidden_claim_guard_test",
            "no_forbidden_phrase_is_an_asserted_claim",
        ),
    ];
    let mut missing: Vec<String> = Vec::new();
    for (target, test_fn) in required {
        if !present.contains(&(target.to_string(), test_fn.to_string())) {
            missing.push(format!("{target}::{test_fn}"));
        }
    }
    assert!(
        missing.is_empty(),
        "required proposal-gate guard(s) not mapped in the traceability manifest \
         (method-transparency pair #150 / audit guard #151 / forbidden-claim guard #155 — \
         ADR-MCPS-036): {missing:?}"
    );
}

/// Sanity: the guard actually parsed something from every source, so a silent
/// empty-set false-pass (e.g. a renamed env var resolving to an empty file)
/// cannot masquerade as "no drift".
#[test]
fn guard_inputs_are_non_empty() {
    let m = manifest();
    assert!(
        !entries(&m).is_empty(),
        "manifest has zero entries — wiring broken"
    );
    assert!(
        declared_test_targets().len() >= 20,
        "parsed too few nt_rust_test targets from BUILD files — parser/wiring broken"
    );
    // The guard test target must itself be a declared target under mcp-re-conformance.
    assert!(
        declared_test_targets().contains("//mcp-re-conformance:security_traceability_guard_test"),
        "BUILD must declare the security_traceability_guard_test target itself"
    );
    // The claim matrix §A was actually read and parsed, so the §A-coverage check
    // cannot silently false-pass on an empty/broken runfile.
    assert!(
        parse_section_a(&read("MCP_RE_CLAIM_MATRIX")).len() >= 13,
        "parsed too few §A capability rows — claim-matrix runfile wiring is broken"
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
        !declared.contains("//mcp-re-transport:mtls_client_test_RENAMED"),
        "a renamed target must NOT be found among declared targets (drift would be caught)"
    );
    // A fn absent from a source is reported missing.
    let src = read("MCP_RE_SRC_METHOD_TRANSPARENCY");
    assert!(
        declares_fn(&src, "accepted_verdict_is_identical_across_all_methods"),
        "control: the real fn is found"
    );
    assert!(
        !declares_fn(&src, "accepted_verdict_is_identical_across_all_methods_RENAMED"),
        "a renamed fn must NOT be found in the source (drift would be caught)"
    );
}
