"""The workspace version, as Cargo reports it through CARGO_PKG_VERSION.

rules_rust sets CARGO_PKG_VERSION from each target's `version` attribute and defaults it to
0.0.0. `//bazel:defs.bzl` passes this value to every Rust target, so `env!("CARGO_PKG_VERSION")`
means the same thing under Bazel as under a workspace member's manifest. scripts/bump_version.sh
moves it together with `VERSION`.
"""

WORKSPACE_VERSION = "0.17.0"
