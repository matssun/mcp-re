//! ADR-MCPS-034 (extends ADR-MCPS-030) — static method-name drift guard.
//!
//! MCP-RE Core is method-transparent: no NON-TEST `mcp-re-core/src` code path may
//! reference a concrete MCP method-name literal, because doing so is the first
//! step toward an `if method == "tools/call"` branch that quietly erodes the
//! boundary (ADR-MCPS-030 / ADR-MCPS-034). This guard FAILS if any banned
//! method-name literal appears in non-test Core source.
//!
//! ## Banned set (ADR-MCPS-034)
//!
//! `tools/list`, `tools/call`, `resources/list`, `resources/read`,
//! `prompts/list`, `prompts/get`, `sampling/createMessage`,
//! `completion/complete`.
//!
//! ## Scope — narrow, by design
//!
//! - The bare JSON-RPC `"method"` field/word is NOT banned: Core must still
//!   preserve, sign, and canonicalize the full request object including `method`
//!   (ADR-MCPS-026). Only the concrete method-name *values* are forbidden.
//! - `#[cfg(test)]` modules, fixtures, and comments inside the test region are
//!   excluded: today every `tools/call` occurrence in Core is a `#[cfg(test)]`
//!   fixture (pipeline/constraints/signing test modules), and those are legal.
//!   The scanner truncates each file at its first `#[cfg(test)]` line and scans
//!   only the production region above it.
//!
//! ## Wiring (same scheme as the conformance drift_guard)
//!
//! The Core `src/` directory is delivered through Bazel `data` runfiles; the
//! guard resolves a sentinel file (`lib.rs`) and scans every `*.rs` in its
//! parent directory from DISK at test time (`$(rlocationpath)` against
//! `TEST_SRCDIR`/`RUNFILES_DIR`), with the `mcp-re-test-paths` cargo fallback. A
//! NEW Core source file is scanned automatically (the directory is re-read), so
//! the guard cannot be evaded by adding a file.
//!
//! std + serde_json's sibling std only (no new crates).

use std::path::PathBuf;

/// The concrete MCP method-name literals that must never appear in non-test
/// Core source (ADR-MCPS-034). Kept next to the guard, as the ADR requires.
const BANNED_METHOD_LITERALS: &[&str] = &[
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
    "sampling/createMessage",
    "completion/complete",
];

/// Resolve the runfile path for a Core source sentinel.
fn locate(env_key: &str) -> PathBuf {
    mcp_re_test_paths::resolve_runfile(env_key)
}

/// The `mcp-re-core/src` directory, derived from the delivered `lib.rs` sentinel's
/// parent (mirrors how the conformance drift_guard finds the vectors dir from
/// the committed `manifest.json`'s parent).
fn core_src_dir() -> PathBuf {
    let lib_rs = locate("MCP_RE_CORE_SRC_LIB");
    lib_rs
        .parent()
        .expect("mcp-re-core/src/lib.rs has a parent dir")
        .to_path_buf()
}

/// Every `*.rs` file physically in `mcp-re-core/src` (non-recursive: Core's
/// modules are flat files). A new module file is picked up automatically.
fn core_src_files() -> Vec<(String, PathBuf)> {
    let dir = core_src_dir();
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}")) {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".rs") {
            files.push((name, path));
        }
    }
    files.sort();
    files
}

/// The production (non-test) region of a Core source file: everything ABOVE the
/// first `#[cfg(test)]` line. Each Core module places its unit tests in a single
/// trailing `#[cfg(test)] mod tests { ... }`, so truncating there excludes test
/// fixtures (the only legitimate place a method-name literal may appear) while
/// keeping every real code path in scope.
fn production_region(text: &str) -> &str {
    match text.find("#[cfg(test)]") {
        Some(idx) => &text[..idx],
        None => text,
    }
}

/// The drift guard: no banned method-name literal may appear in the production
/// region of any non-test Core source file.
#[test]
fn no_banned_method_literal_in_non_test_core_src() {
    let mut violations: Vec<String> = Vec::new();
    for (name, path) in core_src_files() {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let production = production_region(&text);
        for &literal in BANNED_METHOD_LITERALS {
            if production.contains(literal) {
                violations.push(format!("{name}: {literal:?}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "banned MCP method-name literal(s) found in NON-TEST mcp-re-core/src — MCP-RE Core must be \
         method-transparent (ADR-MCPS-030/034). Move method-aware logic to a separate \
         profile/layer with its own ADR, or confine the literal to a #[cfg(test)] fixture: \
         {violations:?}"
    );
}

/// The bare `"method"` field/word is explicitly NOT banned (ADR-MCPS-034): Core
/// must still sign/canonicalize the full object including `method`. This proves
/// the guard does not over-reach: production Core legitimately contains the bare
/// word `method` (e.g. doc comments / the signed object), and that is fine.
#[test]
fn bare_method_word_is_not_banned() {
    let production_has_bare_method = core_src_files().iter().any(|(_, path)| {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        production_region(&text).contains("method")
    });
    assert!(
        production_has_bare_method,
        "expected the bare word 'method' to appear in production Core (it is signed/canonicalized \
         and must NOT be banned) — if this fails the wiring is broken, not the policy"
    );
    // And none of those bare occurrences is a banned literal (already asserted by
    // the guard above); this test exists to pin that the bare field is allowed.
}

/// Sanity: the guard actually scanned real files (a renamed env var resolving to
/// an empty directory must NOT masquerade as "no banned literals"). Also proves
/// the scanner's positive control: the banned literals DO exist in Core test
/// fixtures, so the production-region exclusion is load-bearing (without it the
/// guard would fire on legitimate `#[cfg(test)]` fixtures).
#[test]
fn guard_inputs_are_non_empty_and_exclusion_is_load_bearing() {
    let files = core_src_files();
    assert!(
        files.len() >= 10,
        "scanned too few mcp-re-core/src files ({}) — runfiles wiring is broken",
        files.len()
    );
    assert!(
        files.iter().any(|(n, _)| n == "lib.rs"),
        "expected mcp-re-core/src/lib.rs among the scanned files"
    );

    // Positive control: at least one banned literal appears in the FULL text of
    // some Core file (a #[cfg(test)] fixture) but NOT in its production region —
    // proving the production-region truncation is what keeps the guard green.
    let mut found_in_test_region_only = false;
    for (_, path) in &files {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let production = production_region(&text);
        for &literal in BANNED_METHOD_LITERALS {
            if text.contains(literal) && !production.contains(literal) {
                found_in_test_region_only = true;
            }
        }
    }
    assert!(
        found_in_test_region_only,
        "expected at least one banned literal in a #[cfg(test)] fixture (excluded from scope) — \
         if absent, the exclusion mechanism is untested and may be silently wrong"
    );
}
