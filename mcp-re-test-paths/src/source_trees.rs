// SPDX-License-Identifier: Apache-2.0
//! Which source TREES a guard walks, and which crate each names.
//!
//! A different fact from [`super::source_fallbacks`], which names individual source FILES a
//! guard parses. The distinction is not tidiness: a file entry says *read exactly this*, and
//! a tree entry says *walk everything under here*, which is what lets a guard state a
//! property over code nobody listed. ADR-MCPRE-066 §2.1 is about exactly that difference —
//! a guard reading a list of producers describes yesterday's producer set, and a guard
//! walking a tree measures today's.
//!
//! Each entry resolves to `<crate>/src/lib.rs`; the guard walks that sentinel's PARENT. The
//! sentinel is a file rather than a directory because Bazel delivers files, not directories,
//! through runfiles, and because a sentinel that does not exist fails loudly.

/// The workspace crates with a source tree, and the env key naming each one's sentinel.
///
/// `mcp-re-conformance` is absent because it has no `src/`. That the set here is exactly the
/// workspace is not asserted here — it is asserted by the guard that consumes it, against
/// the workspace manifest, so a new member cannot be scanned by nobody.
pub(super) const SOURCE_TREES: &[(&str, &str)] = &[
    ("MCP_RE_SRC_TREE_CORE", "mcp-re-core"),
    ("MCP_RE_SRC_TREE_PROXY", "mcp-re-proxy"),
    ("MCP_RE_SRC_TREE_HOST", "mcp-re-host"),
    ("MCP_RE_SRC_TREE_CLIENT_CORE", "mcp-re-client-core"),
    ("MCP_RE_SRC_TREE_CLIENT", "mcp-re-client"),
    ("MCP_RE_SRC_TREE_CLIENT_PROXY", "mcp-re-client-proxy"),
    ("MCP_RE_SRC_TREE_TRANSPORT", "mcp-re-transport"),
    ("MCP_RE_SRC_TREE_POLICY", "mcp-re-policy"),
    ("MCP_RE_SRC_TREE_HTTP_PROFILE", "mcp-re-http-profile"),
    ("MCP_RE_SRC_TREE_DEMO", "mcp-re-demo"),
    ("MCP_RE_SRC_TREE_TEST_PATHS", "mcp-re-test-paths"),
];

/// The sentinel path for `env_key`, or `None` if it names no source tree.
pub(super) fn sentinel_for(env_key: &str) -> Option<String> {
    SOURCE_TREES
        .iter()
        .find(|(key, _)| *key == env_key)
        .map(|(_, crate_dir)| format!("{crate_dir}/src/lib.rs"))
}

#[cfg(test)]
mod tests {
    use super::sentinel_for;
    use super::SOURCE_TREES;

    #[test]
    fn every_sentinel_exists_in_the_source_tree() {
        // Under Cargo the test runs from the crate root, so the workspace root is `..`.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the crate has a workspace root");
        for (key, crate_dir) in SOURCE_TREES {
            let path = root.join(format!("{crate_dir}/src/lib.rs"));
            assert!(path.exists(), "{key} names {path:?}, which does not exist");
        }
    }

    #[test]
    fn no_tree_is_declared_twice() {
        let mut keys: Vec<&str> = SOURCE_TREES.iter().map(|(k, _)| *k).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "a source-tree key is declared twice");
    }

    #[test]
    fn an_unknown_key_names_no_tree() {
        assert_eq!(sentinel_for("MCP_RE_NOT_A_TREE"), None);
        assert_eq!(
            sentinel_for("MCP_RE_SRC_TREE_CORE").as_deref(),
            Some("mcp-re-core/src/lib.rs")
        );
    }
}
