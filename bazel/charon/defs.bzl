"""The Lean extraction's first half, as a Bazel rule — ADR-MCPRE-059 §8.

`charon_llbc` runs Charon over one library crate and writes its LLBC. The crate is the
ordinary Bazel target — its sources, crate root, edition and dependencies are read from its
providers — built on the nightly toolchain Charon's driver is compiled against
(`--@rules_rust//rust/toolchain/channel=nightly`), so the crates Charon reads are ones its
driver can load. WHAT is extracted is the manifest's: the lane passes each unit's
`extracted_symbols` as `--//bazel/charon:start_from`, so the action is keyed by it and no
second list decides it.

Runs only inside the pinned extraction container (`@charon`).
"""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@charon//:env.bzl", "CHARON_ENV")
load("@rules_rust//rust:rust_common.bzl", "CrateInfo", "DepInfo")

def _search_path(file):
    return "-Ldependency=" + file.dirname

def _charon_llbc_impl(ctx):
    charon = [f for f in ctx.files._charon if f.basename == "charon"]
    if not charon:
        fail("the extraction lane cannot run here: " + " ".join([f.path for f in ctx.files._charon]))
    start_from = ctx.attr._start_from[BuildSettingInfo].value
    if not start_from:
        fail("no --//bazel/charon:start_from: the manifest's extracted_symbols decide what is extracted")
    crate = ctx.attr.crate[CrateInfo]
    dep_info = ctx.attr.crate[DepInfo]
    llbc = ctx.actions.declare_file("{}.llbc".format(crate.name))

    args = ctx.actions.args()
    args.add("rustc")
    args.add("--preset=aeneas")
    # The distributed standard library, which the dependencies were compiled against.
    # Charon's own default builds a full-MIR sysroot by running Cargo; this lane runs none.
    args.add("--sysroot=default")
    for symbol in start_from:
        args.add("--start-from", symbol)
    args.add("--dest-file", llbc)
    args.add("--")
    args.add(crate.root)
    args.add("--crate-name=" + crate.name)
    args.add("--crate-type=lib")
    args.add("--edition=" + crate.edition)
    direct = []
    for dep in crate.deps.to_list() + crate.proc_macro_deps.to_list():
        if dep.crate_info:
            args.add("--extern={}={}".format(dep.crate_info.name, dep.crate_info.output.path))
            direct.append(dep.crate_info.output)
    args.add_all(dep_info.transitive_crate_outputs, map_each = _search_path, uniquify = True)

    ctx.actions.run(
        executable = charon[0],
        arguments = [args],
        inputs = depset(ctx.files._charon + direct, transitive = [crate.srcs, dep_info.transitive_crate_outputs]),
        outputs = [llbc],
        env = CHARON_ENV,
        mnemonic = "Charon",
        progress_message = "Extracting %{label} with the pinned Charon",
    )
    return [DefaultInfo(files = depset([llbc]))]

charon_llbc = rule(
    implementation = _charon_llbc_impl,
    attrs = {
        "crate": attr.label(mandatory = True, providers = [CrateInfo, DepInfo]),
        "_charon": attr.label(default = "@charon//:files"),
        "_start_from": attr.label(default = "//bazel/charon:start_from"),
    },
    doc = "Charon's LLBC for one crate, from the items `--//bazel/charon:start_from` names.",
)
