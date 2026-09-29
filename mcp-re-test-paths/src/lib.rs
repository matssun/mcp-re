//! Resolve child-process binaries and data fixtures for integration tests, under Bazel
//! runfiles.
//!
//! A test names each input it reads by an env key; its Bazel target sets that key to the
//! input's `$(rlocationpath ...)`, and lists the input in `data`, so the build refuses a
//! missing file before any test runs. [`resolve_runfile`] finds the path under the runfiles
//! root, and refuses — loudly — a key its target does not set or a path that is not there:
//! a guard that resolved its input to nothing would walk nothing, find nothing and report a
//! clean tree.
//!
//! [`rust_source`] is the other half of the same job: the guards that resolve a source
//! path here then scan its text need one shared, tested definition of which lines are
//! production.

pub mod rust_source;

use std::path::PathBuf;

/// The file or directory the test's Bazel target names under `env_key`.
///
/// Panics when the target does not set `env_key`, or sets it to a path found under no
/// runfiles root — both are wiring errors in the target, and a guard handed an empty path
/// instead would report a clean pass over nothing.
pub fn resolve_runfile(env_key: &str) -> PathBuf {
    let Ok(rel) = std::env::var(env_key) else {
        panic!(
            "mcp_re_test_paths: env key '{env_key}' is not set — add it to this test \
             target's `env` as `$(rlocationpath ...)`, with the input in its `data`"
        );
    };
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
    candidates.into_iter().find(|c| c.exists()).unwrap_or_else(|| {
        panic!(
            "mcp_re_test_paths: env key '{env_key}' names '{rel}', which is under no runfiles \
             root — list the input in this test target's `data`"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_runfile;

    /// The resolver's positive half: the target sets this key to its own crate root, and
    /// the key resolves to that file.
    #[test]
    fn a_key_the_target_sets_resolves_to_its_file() {
        let path = resolve_runfile("MCP_RE_TEST_PATHS_PROBE");
        let text = std::fs::read_to_string(&path).expect("the resolved file is readable");
        assert!(
            text.contains("pub fn resolve_runfile"),
            "{path:?} is not the file the target named"
        );
    }

    /// A key no target sets is refused, never resolved to an empty or guessed path.
    #[test]
    #[should_panic(expected = "is not set")]
    fn a_key_the_target_does_not_set_is_refused() {
        resolve_runfile("MCP_RE_NO_SUCH_KEY");
    }

    /// A key set to a path under no runfiles root is refused rather than returned.
    #[test]
    #[should_panic(expected = "is under no runfiles root")]
    fn a_key_naming_a_missing_file_is_refused() {
        resolve_runfile("MCP_RE_TEST_PATHS_MISSING");
    }
}
