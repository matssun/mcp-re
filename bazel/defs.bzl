"""
Vendored VERBATIM from infrastructure/bazel_defs/rust/defs.bzl to keep the
mcp-re module self-contained / publishable (ADR-MCPS-010/012).

@nt_bazel_defs//rust:defs.bzl — shared Rust macros.

Thin wrappers over rules_rust with house defaults for the monorepo,
usable from any Bazel module that declares `nt_bazel_defs` as a direct
bazel_dep (the root monorepo and the nested nautilus_trader module).

Goals:
- Policy centralization (edition, lint_config, stamp, test harness)
- Standardized runfiles-based test fixture handling
- Feature parity with cargo-nextest (serial_tests for process isolation)
- Bazel-native: no Cargo path emulation, no directory-magic fixtures

Deliberately does NOT include nt_rust_service_image — that macro depends
on //platforms:linux_arm64 / //platforms:linux_x86_64 which live in the
root monorepo. Keep OCI service image packaging on the root side where
those labels resolve naturally.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------

def _merge_dicts(a, b):
    out = {}
    out.update(a)
    out.update(b)
    return out

def _default_rust_common_kwargs(
        edition = "2021",
        lint_config = None,
        tags = [],
        visibility = None,
        **kwargs):
    out = dict(kwargs)

    if "edition" not in out:
        out["edition"] = edition

    if lint_config != None and "lint_config" not in out:
        out["lint_config"] = lint_config

    if tags:
        out["tags"] = list(tags)

    if visibility != None and "visibility" not in out:
        out["visibility"] = visibility

    return out

def _fixture_env_and_data(
        fixture_files = None,
        env_prefix = "NT_FIXTURE_"):
    """Convert fixture files dict to data deps and environment variables.

    Converts {NAME: label} into:
      - data deps
      - env vars with $(rlocationpath ...) expansions
    """
    fixture_files = fixture_files or {}

    data = []
    env = {}

    for key, label in fixture_files.items():
        data.append(label)
        env[env_prefix + key] = "$(rlocationpath %s)" % label

    return data, env

# ----------------------------------------------------------------------
# Thin wrappers
# ----------------------------------------------------------------------

def nt_rust_library(
        name,
        srcs,
        deps = [],
        proc_macro_deps = [],
        data = [],
        compile_data = [],
        crate_features = [],
        crate_name = None,
        crate_root = None,
        edition = "2021",
        lint_config = None,
        visibility = None,
        tags = [],
        rustc_env = {},
        rustc_flags = [],
        **kwargs):
    """Thin wrapper over rust_library with house defaults."""
    extra = _default_rust_common_kwargs(
        edition = edition,
        lint_config = lint_config,
        visibility = visibility,
        tags = tags,
        **kwargs
    )

    rust_library(
        name = name,
        srcs = srcs,
        deps = deps,
        proc_macro_deps = proc_macro_deps,
        data = data,
        compile_data = compile_data,
        crate_features = crate_features,
        crate_name = crate_name,
        crate_root = crate_root,
        rustc_env = rustc_env,
        rustc_flags = rustc_flags,
        stamp = 0,
        **extra
    )

def nt_rust_binary(
        name,
        srcs = [],
        deps = [],
        data = [],
        compile_data = [],
        crate_features = [],
        crate_name = None,
        crate_root = None,
        edition = "2021",
        lint_config = None,
        visibility = None,
        tags = [],
        rustc_env = {},
        rustc_flags = [],
        **kwargs):
    """Thin wrapper over rust_binary with house defaults."""
    extra = _default_rust_common_kwargs(
        edition = edition,
        lint_config = lint_config,
        visibility = visibility,
        tags = tags,
        **kwargs
    )

    rust_binary(
        name = name,
        srcs = srcs,
        deps = deps,
        data = data,
        compile_data = compile_data,
        crate_features = crate_features,
        crate_name = crate_name,
        crate_root = crate_root,
        rustc_env = rustc_env,
        rustc_flags = rustc_flags,
        stamp = 0,
        **extra
    )

def nt_rust_test(
        name,
        crate = None,
        srcs = [],
        deps = [],
        proc_macro_deps = [],
        data = [],
        compile_data = [],
        fixture_files = None,
        fixture_env_prefix = "NT_FIXTURE_",
        env = {},
        env_inherit = [],
        crate_features = [],
        crate_name = None,
        crate_root = None,
        edition = "2021",
        lint_config = None,
        size = "medium",
        tags = [],
        rustc_env = {},
        rustc_flags = [],
        serial_tests = [],
        skip_tests = [],
        extra_args = [],
        auto_cargo_toml = True,
        bazel_build_cfg = True,
        use_libtest_harness = True,
        **kwargs):
    """Thin wrapper over rust_test.

    fixture_files is Bazel-native:
      {"BBO_1M": "//path/to:file.dbn.zst"}
    which becomes:
      - data += ["//path/to:file.dbn.zst"]
      - env["NT_FIXTURE_BBO_1M"] = "$(rlocationpath //path/to:file.dbn.zst)"

    serial_tests: test paths that need process isolation. Each entry
        generates an additional rust_test running exactly that test with
        --test-threads=1. The main target skips all serial entries.

    skip_tests: test paths to omit from the main target via --skip=.

    auto_cargo_toml: when True (default), Cargo.toml is added to
        compile_data so rstest's proc-macro-crate can locate the manifest.

    bazel_build_cfg: when True (default), `--cfg=bazel_build` is added to
        rustc_flags so upstream sources can gate tests with
        `#[cfg_attr(bazel_build, ignore)]`.
    """
    fixture_data, fixture_env = _fixture_env_and_data(
        fixture_files = fixture_files,
        env_prefix = fixture_env_prefix,
    )

    test_env = _merge_dicts(fixture_env, env)

    # De-dup: callers may pass the full directory via `data = glob(...)`
    # AND list individual sentinels via `fixture_files`; the shared labels
    # would otherwise appear twice and rust_test rejects duplicates.
    test_data = list(data)
    for label in fixture_data:
        if label not in test_data:
            test_data.append(label)

    test_compile_data = list(compile_data)
    if auto_cargo_toml and "Cargo.toml" not in test_compile_data:
        test_compile_data = ["Cargo.toml"] + test_compile_data

    test_rustc_flags = list(rustc_flags)
    if bazel_build_cfg and "--cfg=bazel_build" not in test_rustc_flags:
        test_rustc_flags = ["--cfg=bazel_build"] + test_rustc_flags

    skip_args = (
        ["--skip=" + t for t in skip_tests] +
        ["--skip=" + t for t in serial_tests]
    )
    test_args = skip_args + extra_args

    extra = _default_rust_common_kwargs(
        edition = edition,
        lint_config = lint_config,
        tags = tags,
        **kwargs
    )

    test_deps = list(deps)
    if fixture_files:
        test_deps.append("@rules_rust//rust/runfiles")

    rust_test(
        name = name,
        args = test_args,
        crate = crate,
        srcs = srcs,
        deps = test_deps,
        proc_macro_deps = proc_macro_deps,
        data = test_data,
        compile_data = test_compile_data,
        env = test_env,
        env_inherit = env_inherit,
        crate_features = crate_features,
        crate_name = crate_name,
        crate_root = crate_root,
        rustc_env = rustc_env,
        rustc_flags = test_rustc_flags,
        size = size,
        stamp = 0,
        use_libtest_harness = use_libtest_harness,
        **extra
    )

    for test in serial_tests:
        rust_test(
            name = name + "_" + test.replace("::", "__"),
            args = [test, "--exact", "--test-threads=1"],
            crate = crate,
            srcs = srcs,
            deps = test_deps,
            proc_macro_deps = proc_macro_deps,
            data = test_data,
            compile_data = test_compile_data,
            env = test_env,
            env_inherit = env_inherit,
            crate_features = crate_features,
            crate_name = crate_name,
            crate_root = crate_root,
            rustc_env = rustc_env,
            rustc_flags = test_rustc_flags,
            size = size,
            stamp = 0,
            use_libtest_harness = use_libtest_harness,
            edition = extra.get("edition", edition),
            lint_config = extra.get("lint_config"),
            tags = extra.get("tags", list(tags)),
        )
