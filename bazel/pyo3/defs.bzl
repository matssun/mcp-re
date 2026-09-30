"""A PyO3 extension module under the workspace lint policy.

`@rules_rust_pyo3//:defs.bzl%pyo3_extension` builds its shared library with a plain
`rust_shared_library` and forwards one keyword set to both the library and the Python rule,
so it cannot carry `lint_config`: the SDK's binding would be the one first-party crate
outside `//bazel:workspace_lints`. This is the same two-target shape — the shared library
built with the house lint policy, then wrapped by the module's `py_pyo3_library` — with the
macOS link flags the upstream macro applies. rules_rust_pyo3 is pinned (MODULE.bazel), so
loading its `private/` rule is loading a fixed file.
"""

load("@rules_rust//rust:defs.bzl", "rust_shared_library")
load("@rules_rust_pyo3//private:pyo3.bzl", "py_pyo3_library")

def nt_pyo3_extension(name, srcs, crate_root, module_name, deps = [], edition = "2021", imports = [], visibility = None, **kwargs):
    rust_shared_library(
        name = name + "_shared",
        srcs = srcs,
        crate_name = name,
        crate_root = crate_root,
        deps = [
            Label("@rules_rust_pyo3//private:current_rust_pyo3_toolchain"),
            Label("@rules_python//python/cc:current_py_cc_headers"),
        ] + deps,
        edition = edition,
        lint_config = Label("//bazel:workspace_lints"),
        rustc_flags = select({
            "@platforms//os:macos": [
                # https://pyo3.rs/v0.26.0/building-and-distribution.html#macos
                "-C",
                "link-arg=-undefined",
                "-C",
                "link-arg=dynamic_lookup",
                # https://github.com/PyO3/pyo3/issues/5035
                "--codegen=link-arg=-Wl,-no_fixup_chains",
            ],
            "//conditions:default": [],
        }),
        tags = ["manual"],
        visibility = ["//visibility:private"],
        **kwargs
    )
    py_pyo3_library(
        name = name,
        extension = name + "_shared",
        compilation_mode = "opt",
        imports = imports,
        module_name = module_name,
        stubs = 0,
        visibility = visibility,
    )
