//! Resolve child-process binaries and data fixtures for integration tests
//! whether they run under Bazel runfiles or a plain Cargo build.
//!
//! Each known env-var name (Bazel injects these as `$(rlocationpath ...)`)
//! maps to a workspace-relative cargo path. The resolver tries the Bazel env
//! var first; if absent, it falls back to `<workspace-root>/target/<profile>/<bin>`
//! (or, for the data fixtures we ship, a fixed source-tree path).
//!
//! New env keys must be added to [`SOURCE_FALLBACKS`] — the resolver fails
//! loudly on unknown keys rather than silently returning an empty path.
//!
//! [`rust_source`] is the other half of the same job: the guards that resolve a source
//! path here then scan its text need one shared, tested definition of which lines are
//! production.

mod source_fallbacks;

pub mod rust_source;

use source_fallbacks::SOURCE_FALLBACKS;

use std::path::Path;
use std::path::PathBuf;

/// The one env key that resolves to a built binary rather than a source file,
/// so it is looked up under `target/<profile>/` instead of the source tree.
const PROXY_CLI_KEY: &str = "MCP_RE_PROXY_CLI";

/// Resolve a runfile-style path. Under Bazel `env_key` is set; under Cargo we
/// fall back to the canonical workspace layout.
///
/// Panics on an unresolvable lookup with a message that points at the most
/// likely cause: missing `cargo build --workspace --bins` for a cross-crate
/// binary, or an unknown env key that needs adding to [`SOURCE_FALLBACKS`].
pub fn resolve_runfile(env_key: &str) -> PathBuf {
    if let Ok(rel) = std::env::var(env_key) {
        let mut candidates: Vec<PathBuf> = Vec::new();
        for root_key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
            if let Ok(root) = std::env::var(root_key) {
                candidates.push(PathBuf::from(&root).join(&rel));
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join(&rel));
            if let Some(parent) = cwd.parent() {
                candidates.push(parent.join(&rel));
            }
        }
        candidates.push(PathBuf::from(&rel));
        if let Some(found) = candidates.into_iter().find(|c| c.exists()) {
            return found;
        }
        // `env_key` was set but the runfile root resolution failed — fall
        // through to the cargo fallback rather than panicking immediately.
    }
    cargo_fallback(env_key)
}

/// Cargo-mode fallback. Each Bazel env key maps to either a workspace-relative
/// bin (looked up at `target/<profile>/<bin>`) or a source-tree file.
fn cargo_fallback(env_key: &str) -> PathBuf {
    let workspace_root = workspace_root();
    if env_key == PROXY_CLI_KEY {
        return find_bin(&workspace_root, "mcp-re-proxy");
    }
    let Some((_, rel)) = SOURCE_FALLBACKS.iter().find(|(key, _)| *key == env_key) else {
        panic!(
            "mcp_re_test_paths: unknown runfile env key '{env_key}' — add it to \
             SOURCE_FALLBACKS in mcp-re-test-paths/src/lib.rs"
        );
    };
    workspace_root.join(rel)
}

/// Locate the workspace root by walking up from the test crate's manifest dir
/// until a `Cargo.toml` containing `[workspace]` is found. Each integration
/// test compiles with `CARGO_MANIFEST_DIR` pointing at its own crate dir.
fn workspace_root() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is always set when compiling Cargo integration tests");
    let mut dir: &Path = Path::new(&manifest);
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            if let Ok(text) = std::fs::read_to_string(&candidate) {
                if text.contains("[workspace]") {
                    return dir.to_path_buf();
                }
            }
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => panic!(
                "mcp_re_test_paths: walked past the filesystem root without finding a Cargo.toml \
                 that contains [workspace] (started from '{manifest}')"
            ),
        }
    }
}

/// Map a workspace-root path + bin name to the canonical `target/<profile>/<bin>`
/// location. Tries the current profile first (debug under `cargo test`), then
/// the opposite as a courtesy. Panics with a precise remediation message if
/// neither exists, since Cargo does NOT auto-build cross-crate bins for
/// integration tests.
fn find_bin(workspace_root: &Path, bin_name: &str) -> PathBuf {
    let exe_suffix = std::env::consts::EXE_SUFFIX;
    let bin_file = format!("{bin_name}{exe_suffix}");
    // CARGO_TARGET_DIR honors user overrides; default is <workspace-root>/target.
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("target"));
    let primary_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let other_profile = if primary_profile == "debug" {
        "release"
    } else {
        "debug"
    };
    for profile in [primary_profile, other_profile] {
        let candidate = target_dir.join(profile).join(&bin_file);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "mcp_re_test_paths: cargo binary '{bin_name}' not found under {}/{{debug,release}}/ \
         — run `cargo build --workspace --bins` first (cargo does not auto-build cross-crate \
         binaries for integration tests).",
        target_dir.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the Bazel side gets from the build: a fallback that names
    /// a file which is not there is a path no guard can read, and without this
    /// check it surfaces at whichever test first asks for it rather than here.
    #[test]
    fn the_fallback_table_names_only_files_that_exist() {
        let root = workspace_root();
        let missing: Vec<&str> = SOURCE_FALLBACKS
            .iter()
            .filter(|(_, rel)| !root.join(rel).exists())
            .map(|(key, _)| *key)
            .collect();
        assert!(
            missing.is_empty(),
            "SOURCE_FALLBACKS names path(s) that no longer exist — delete the entry if its \
             fixture is gone, or repoint it if the fixture moved: {missing:?}"
        );
    }

    /// A duplicated key would make the second entry unreachable, so the two
    /// paths could disagree indefinitely with only one of them ever used.
    #[test]
    fn no_key_is_declared_twice() {
        let mut keys: Vec<&str> = SOURCE_FALLBACKS.iter().map(|(key, _)| *key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "SOURCE_FALLBACKS declares a key twice");
    }

    /// The binary key must not also be in the source table: it resolves under
    /// `target/`, and a source-tree entry would silently shadow that.
    #[test]
    fn the_binary_key_is_not_also_a_source_fallback() {
        assert!(
            !SOURCE_FALLBACKS
                .iter()
                .any(|(key, _)| *key == PROXY_CLI_KEY),
            "{PROXY_CLI_KEY} resolves under target/, not the source tree"
        );
    }

    #[test]
    #[should_panic(expected = "unknown runfile env key")]
    fn an_unknown_key_is_refused_rather_than_resolved() {
        cargo_fallback("MCP_RE_NO_SUCH_KEY");
    }
}
