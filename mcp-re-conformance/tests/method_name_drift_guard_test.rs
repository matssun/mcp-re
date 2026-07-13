// SPDX-License-Identifier: Apache-2.0
//! Method-name drift guard (ADR-MCPS-030/034), the STATIC half of the ADR-MCPS-036
//! #150 method-transparency pair. `mcp-re-core` is the pure verification firewall:
//! it must contain NO concrete MCP method-name literal in non-test source, so a
//! future change cannot silently make the Core verdict method-aware.

use std::path::PathBuf;

/// Concrete MCP method-name literals that MUST NOT appear in non-test Core source.
/// A match means Core is branching on (or otherwise encoding) a specific method —
/// a method-transparency violation.
const BANNED_METHOD_LITERALS: &[&str] = &[
    "tools/call",
    "tools/list",
    "resources/read",
    "resources/list",
    "resources/subscribe",
    "resources/templates/list",
    "prompts/get",
    "prompts/list",
    "completion/complete",
    "sampling/createMessage",
    "logging/setLevel",
    "roots/list",
];

/// The `mcp-re-core/src` directory, located from the workspace root the same way the
/// other traceability guards resolve their fixtures.
fn core_src_dir() -> PathBuf {
    let lib = mcp_re_test_paths::resolve_runfile("MCP_RE_CORE_SRC_LIB");
    lib.parent().expect("core src/lib.rs has a parent dir").to_path_buf()
}

/// The non-test region of a source file: everything BEFORE the first `#[cfg(test)]`
/// (unit tests live at file end by convention), so a method literal used only as a
/// test fixture is not a production drift.
fn non_test_region(text: &str) -> &str {
    match text.find("#[cfg(test)]") {
        Some(i) => &text[..i],
        None => text,
    }
}

#[test]
fn no_banned_method_literal_in_non_test_core_src() {
    let dir = core_src_dir();
    let mut found: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}")) {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let region = non_test_region(&text);
        for literal in BANNED_METHOD_LITERALS {
            if region.contains(literal) {
                found.push(format!("{:?} contains banned method literal {literal:?}", path.file_name().unwrap()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "mcp-re-core non-test source contains concrete MCP method-name literal(s) — Core must \
         stay method-transparent (ADR-MCPS-030/034): {found:?}"
    );
}
