"""The TypeScript SDK's Node addon, built by Bazel.

`nt_napi_addon` produces the two things `@napi-rs/cli`'s build produced from one crate:

  * `<name>` — the addon itself, named `<binary_name>.<platformArchABI>.node` the way the
    generated loader looks it up; a `rust_shared_library` under the house lint policy, with
    the link flags napi-build states for a Node addon (`NAPI_LINK_FLAGS`).
  * `<name>_type_defs` — the intermediate type definitions napi-derive writes while it
    expands `#[napi]` items. The CLI renders them into `binding.d.ts` and the loader's export
    list; `sdk/typescript/scripts/write-binding.mjs` does the same from this directory.

napi-derive writes those definitions as a side effect of macro expansion, into
`$NAPI_TYPE_DEF_TMP_FOLDER`. A side effect of a compile action is not an output Bazel
tracks, so `napi_type_defs` runs its own metadata-only rustc over the same sources and
dependencies with that folder set to a declared output directory.
"""

load("@rules_rust//rust:defs.bzl", "rust_shared_library")
load("@rules_rust//rust:rust_common.bzl", "CrateInfo", "DepInfo")

# What napi-build's `setup()` tells a linker for a Node addon: on macOS the N-API symbols
# resolve against the host process at load time; on glibc the addon is never unloaded,
# because a pthread-key destructor in an unloaded DSO segfaults at thread exit.
NAPI_LINK_FLAGS = select({
    "@platforms//os:macos": ["-C", "link-arg=-undefined", "-C", "link-arg=dynamic_lookup"],
    "@platforms//os:linux": ["-C", "link-arg=-Wl,-z,nodelete"],
})

def _search_path(file):
    return "-Ldependency=" + file.dirname

def _napi_type_defs_impl(ctx):
    toolchain = ctx.toolchains["@rules_rust//rust:toolchain_type"]
    out = ctx.actions.declare_directory(ctx.label.name)
    rmeta = ctx.actions.declare_file(ctx.label.name + ".rmeta")
    deps = ctx.attr.deps + ctx.attr.proc_macro_deps

    args = ctx.actions.args()
    args.add(ctx.file.crate_root)
    args.add("--crate-name=" + ctx.attr.crate_name)
    args.add("--crate-type=rlib")
    args.add("--edition=" + ctx.attr.edition)
    args.add("--emit=metadata=" + rmeta.path)
    args.add("--target=" + toolchain.target_flag_value)
    args.add("--sysroot=" + toolchain.sysroot)
    args.add("--cap-lints=allow")
    direct = []
    for dep in deps:
        crate = dep[CrateInfo]
        args.add("--extern={}={}".format(crate.name, crate.output.path))
        direct.append(crate.output)
    transitive = [dep[DepInfo].transitive_crate_outputs for dep in deps]
    args.add_all(depset(transitive = transitive), map_each = _search_path, uniquify = True)

    ctx.actions.run(
        executable = toolchain.rustc,
        arguments = [args],
        inputs = depset(ctx.files.srcs + direct, transitive = transitive + [toolchain.all_files]),
        outputs = [out, rmeta],
        env = {
            "CARGO_PKG_NAME": ctx.attr.crate_name,
            "NAPI_TYPE_DEF_TMP_FOLDER": out.path,
        },
        mnemonic = "NapiTypeDefs",
        progress_message = "Collecting napi type definitions of %{label}",
    )
    return [DefaultInfo(files = depset([out]))]

napi_type_defs = rule(
    implementation = _napi_type_defs_impl,
    attrs = {
        "crate_name": attr.string(mandatory = True),
        "crate_root": attr.label(allow_single_file = [".rs"], mandatory = True),
        "deps": attr.label_list(providers = [CrateInfo]),
        "edition": attr.string(mandatory = True),
        "proc_macro_deps": attr.label_list(cfg = "exec", providers = [CrateInfo]),
        "srcs": attr.label_list(allow_files = [".rs"]),
    },
    toolchains = ["@rules_rust//rust:toolchain_type"],
    doc = "The type definitions napi-derive writes while expanding a crate's `#[napi]` items.",
)

def _napi_addon_file_impl(ctx):
    out = ctx.actions.declare_file("{}.{}.node".format(ctx.attr.binary_name, ctx.attr.platform_arch_abi))
    ctx.actions.symlink(output = out, target_file = ctx.file.shared_library)
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles([out]))]

napi_addon_file = rule(
    implementation = _napi_addon_file_impl,
    attrs = {
        "binary_name": attr.string(mandatory = True),
        "platform_arch_abi": attr.string(mandatory = True),
        "shared_library": attr.label(allow_single_file = True, mandatory = True),
    },
    doc = "Names a Node addon the way the napi-rs loader looks it up.",
)

def nt_napi_addon(name, binary_name, srcs, crate_root, deps = [], proc_macro_deps = [], edition = "2021", visibility = None):
    """A Node addon and its napi type definitions, from one crate.

    Args:
        name: the addon target (`<binary_name>.<platformArchABI>.node`).
        binary_name: the package.json `napi.binaryName`.
        srcs: the crate's sources.
        crate_root: the crate root.
        deps: the crate's dependencies.
        proc_macro_deps: the crate's procedural macros (napi-derive).
        edition: the crate's edition.
        visibility: the addon's and type definitions' visibility.
    """
    crate_name = binary_name.replace("-", "_")
    rust_shared_library(
        name = name + "_shared",
        srcs = srcs,
        crate_name = crate_name,
        crate_root = crate_root,
        deps = deps,
        proc_macro_deps = proc_macro_deps,
        edition = edition,
        lint_config = Label("//bazel:workspace_lints"),
        rustc_flags = NAPI_LINK_FLAGS,
        visibility = ["//visibility:private"],
    )
    napi_addon_file(
        name = name,
        binary_name = binary_name,
        platform_arch_abi = select({
            Label("//platforms:is_macos_arm64"): "darwin-arm64",
            Label("//platforms:is_linux_x86_64"): "linux-x64-gnu",
            Label("//platforms:is_linux_arm64"): "linux-arm64-gnu",
        }),
        shared_library = name + "_shared",
        visibility = visibility,
    )
    napi_type_defs(
        name = name + "_type_defs",
        crate_name = crate_name,
        crate_root = crate_root,
        srcs = srcs,
        deps = deps,
        proc_macro_deps = proc_macro_deps,
        edition = edition,
        visibility = visibility,
    )
