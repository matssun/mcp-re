"""The LLVM coverage tools of the registered Rust toolchain, as a target.

`bazel coverage` reports lines and functions (LCOV has no region records). The region
floor `scripts/coverage.sh` enforces is read from the raw profiles with the same
`llvm-profdata`/`llvm-cov` the toolchain instrumented them for, which this rule names.
"""

def _rust_llvm_coverage_tools_impl(ctx):
    toolchain = ctx.toolchains["@rules_rust//rust:toolchain_type"]
    if not toolchain.llvm_cov or not toolchain.llvm_profdata:
        fail("the registered Rust toolchain ships no llvm-cov/llvm-profdata")
    return [DefaultInfo(
        files = depset([toolchain.llvm_cov, toolchain.llvm_profdata]),
        runfiles = ctx.runfiles(files = toolchain.llvm_lib),
    )]

rust_llvm_coverage_tools = rule(
    implementation = _rust_llvm_coverage_tools_impl,
    toolchains = ["@rules_rust//rust:toolchain_type"],
    doc = "Exposes the current Rust toolchain's llvm-cov and llvm-profdata.",
)
