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

use std::path::Path;
use std::path::PathBuf;

/// Bazel env key → workspace-relative source-tree path, for every fixture a
/// test reads off disk rather than executing.
///
/// The Bazel half of this mapping is checked by the build — `$(rlocationpath
/// f)` cannot resolve a file that is not in the tree — so only the cargo half
/// can name a fixture that is no longer there.
/// `the_fallback_table_names_only_files_that_exist` is its equivalent check.
const SOURCE_FALLBACKS: &[(&str, &str)] = &[
    // Conformance + traceability manifests
    (
        "MCP_RE_SECURITY_MANIFEST",
        "mcp-re-conformance/security_traceability_manifest.json",
    ),
    // ADR-MCPS-034: Core src sentinel (method-name drift guard scans its dir).
    ("MCP_RE_CORE_SRC_LIB", "mcp-re-core/src/lib.rs"),
    // ADR-MCPS-035: frozen error taxonomy + audit vocabulary (the audit drift
    // guard asserts every audit rejection reason ∈ McpReError::wire_code()).
    ("MCP_RE_CORE_SRC_ERROR", "mcp-re-core/src/error.rs"),
    ("MCP_RE_CORE_SRC_AUDIT", "mcp-re-core/src/audit.rs"),
    // The REAL producer of audit rejection reasons: the RFC 9421 serving path
    // reaches its verdict as an `HttpProfileError` and hands `wire_code()` to the
    // audit sink, so the vocabulary guard has to check THIS taxonomy is contained
    // in the frozen one — otherwise it only checks a vocabulary nothing emits.
    (
        "MCP_RE_PROFILE_SRC_ERROR",
        "mcp-re-http-profile/src/error.rs",
    ),
    // The THIRD producer feeding `request_rejected_code`: the replay-tier gate.
    // Scanning only the profile taxonomy left these tokens unchecked.
    (
        "MCP_RE_PROXY_SRC_DISPATCH",
        "mcp-re-proxy/src/http_profile_dispatch.rs",
    ),
    // ADR-MCPRE-056 §8: a projected plane's own source, read by the reach-back rule
    // that asserts materialization names no configuration type.
    // ADR-MCPRE-056 §8 fourth clause: the composition root's own source, read by the
    // raw-read inventory that pins which request fields it still consumes directly.
    ("MCP_RE_APP_SRC", "mcp-re-proxy/src/app.rs"),
    // ADR-MCPRE-057 §4: the serving path's own source, read by the transition-ownership
    // rule that asserts no event a stage establishes is also advanced by the assembly.
    (
        "MCP_RE_HTTP_PROFILE_SERVE_SRC",
        "mcp-re-proxy/src/http_profile_serve.rs",
    ),
    ("MCP_RE_TRUST_PLANE_SRC", "mcp-re-proxy/src/trust_plane.rs"),
    ("MCP_RE_TLS_PLANE_SRC", "mcp-re-proxy/src/tls_plane.rs"),
    (
        "MCP_RE_REPLAY_PLANE_SRC",
        "mcp-re-proxy/src/replay_plane.rs",
    ),
    (
        "MCP_RE_SIGNING_PLANE_SRC",
        "mcp-re-proxy/src/signing_plane.rs",
    ),
    (
        "MCP_RE_DELEGATED_WIRING_SRC",
        "mcp-re-proxy/src/delegated_wiring.rs",
    ),
    // The operator-facing guide whose worked example is fed to the real `parse_args`
    // + `ValidatedDeployment::try_from`, so a command line the docs teach cannot drift
    // into one the proxy refuses to start with.
    ("MCP_RE_SIDECAR_GUIDE", "docs/sidecar-deployment-guide.md"),
    // Per-crate BUILD.bazel (read by drift / traceability guards)
    ("MCP_RE_BUILD_CONFORMANCE", "mcp-re-conformance/BUILD.bazel"),
    ("MCP_RE_BUILD_CORE", "mcp-re-core/BUILD.bazel"),
    ("MCP_RE_BUILD_DEMO", "mcp-re-demo/BUILD.bazel"),
    ("MCP_RE_BUILD_HOST", "mcp-re-host/BUILD.bazel"),
    ("MCP_RE_BUILD_POLICY", "mcp-re-policy/BUILD.bazel"),
    ("MCP_RE_BUILD_PROXY", "mcp-re-proxy/BUILD.bazel"),
    ("MCP_RE_BUILD_TRANSPORT", "mcp-re-transport/BUILD.bazel"),
    // Per-test source files (read by the security-traceability guard)
    //
    // ADR-MCPS-034: the two method-transparency proof artifacts.
    (
        "MCP_RE_SRC_METHOD_TRANSPARENCY",
        "mcp-re-conformance/tests/method_transparency_test.rs",
    ),
    (
        "MCP_RE_SRC_METHOD_NAME_DRIFT_GUARD",
        "mcp-re-conformance/tests/method_name_drift_guard_test.rs",
    ),
    (
        "MCP_RE_SRC_KEY_SOURCE",
        "mcp-re-proxy/tests/key_source_test.rs",
    ),
    (
        "MCP_RE_SRC_DEV_ENV_KEY_SOURCE",
        "mcp-re-proxy/tests/dev_env_key_source_test.rs",
    ),
    (
        "MCP_RE_SRC_MTLS_CLIENT",
        "mcp-re-transport/tests/mtls_client_test.rs",
    ),
    (
        "MCP_RE_SRC_DELEGATED_SERVING",
        "mcp-re-proxy/tests/integration_async/delegated_serving_test.rs",
    ),
    (
        "MCP_RE_SRC_DELEGATED_PROD_WIRING",
        "mcp-re-proxy/tests/integration_async/delegated_production_wiring_test.rs",
    ),
    (
        "MCP_RE_SRC_DELEGATED_E2E",
        "mcp-re-proxy/tests/integration_async/delegated_client_server_e2e_test.rs",
    ),
    (
        "MCP_RE_SRC_DELEGATION_VECTORS",
        "mcp-re-conformance/tests/delegation_vectors_test.rs",
    ),
    (
        "MCP_RE_SRC_ROOT_KEY_LIFECYCLE",
        "mcp-re-proxy/tests/integration_async/root_key_lifecycle_test.rs",
    ),
    (
        "MCP_RE_SRC_ROOT_AUTHORITY_MANIFEST",
        "mcp-re-proxy/tests/integration_async/root_authority_manifest_test.rs",
    ),
    (
        "MCP_RE_SRC_MRT_CONTINUATION",
        "mcp-re-proxy/tests/integration_async/mrt_continuation_serving_test.rs",
    ),
    ("MCP_RE_SRC_CLI", "mcp-re-proxy/src/cli.rs"),
    // MCPS-72 (#252): KMS-lifecycle offline negatives are in-crate #[cfg(test)]
    // unit tests, so the traceability guard reads their src/*.rs (not tests/*.rs).
    (
        "MCP_RE_SRC_KMS_KEYSOURCE",
        "mcp-re-proxy/src/kms_keysource.rs",
    ),
    (
        "MCP_RE_SRC_GCP_KMS_KEYSOURCE",
        "mcp-re-proxy/src/gcp_kms_keysource.rs",
    ),
    (
        "MCP_RE_SRC_AWS_KMS_KEYSOURCE",
        "mcp-re-proxy/src/aws_kms_keysource.rs",
    ),
    // ADR-MCPS-036 gate spine: the conformance-guard test sources the
    // traceability manifest maps for the audit (#151) and forbidden-claim
    // (#155) guards, plus the §A claim matrix read by the §A-coverage check.
    (
        "MCP_RE_SRC_AUDIT_VOCABULARY_GUARD",
        "mcp-re-conformance/tests/audit_vocabulary_guard_test.rs",
    ),
    (
        "MCP_RE_SRC_FORBIDDEN_CLAIM_GUARD",
        "mcp-re-conformance/tests/forbidden_claim_guard_test.rs",
    ),
    // ADR-MCPRE-050 §A witnesses: the RFC 9421 security-property proofs that map
    // each §A capability claim to a green test.
    (
        "MCP_RE_SRC_RFC9421_SECURITY_PROPERTIES",
        "mcp-re-conformance/tests/rfc9421_security_properties_test.rs",
    ),
    ("MCP_RE_CLAIM_MATRIX", "docs/spec/v0.5-claim-matrix.md"),
    // ADR-MCPS-036: proposal-facing docs scanned by the forbidden-claim guard.
    (
        "MCP_RE_DOC_SECURITY_BOUNDARY",
        "docs/spec/security-boundary.md",
    ),
    ("MCP_RE_DOC_CLAIM_MATRIX", "docs/spec/v0.5-claim-matrix.md"),
    (
        "MCP_RE_DOC_THREAT_COVERAGE",
        "docs/spec/threat-coverage-matrix.md",
    ),
    ("MCP_RE_DOC_COMPOSABILITY", "docs/spec/composability.md"),
    ("MCP_RE_DOC_PROPOSAL_SCOPE", "docs/spec/proposal-scope.md"),
    (
        "MCP_RE_DOC_SECURITY_BOUNDARY_STUB",
        "docs/SECURITY_BOUNDARY.md",
    ),
];

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
