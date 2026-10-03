"""The Verus lane, as a Bazel rule — ADR-MCPRE-059 §16.

`verus_verify` runs the pinned prover (`@verus//:files`) over one library crate with its
specification features on, and records what it said. The crate is the ordinary Bazel
target: its sources, crate root, edition and dependencies are read from its providers, so
the prover checks exactly the crate Bazel builds. A dependency that is itself verified is
named in `verus_deps`; its Verus-compiled library and exported metadata replace the plain
one, which is how the prover sees the dependency's specifications.

The prover runs on the registered Rust toolchain — the `librustc_driver` Bazel compiles with
is the one `rust_verify` links — with an empty environment and no rustup. Outputs:

  * `<name>.json`    the prover's `--output-json` report (the lane reads this);
  * `<name>.log`     its diagnostics;
  * `<name>.status`  its exit status, recorded rather than propagated, so a failed proof is a
                     result the lane reports, not a build error that hides the report;
  * the Verus-compiled rlib and exported `.vir`, for downstream `verus_deps`.
"""

load("@rules_rust//rust:rust_common.bzl", "CrateInfo", "DepInfo")

VerusInfo = provider(
    doc = "A crate compiled and exported by the prover, for a dependent's verification.",
    fields = {
        "crate_name": "The crate name the dependent imports.",
        "rlib": "The Verus-compiled library.",
        "vir": "The exported Verus metadata.",
        "transitive": "depset of every upstream VerusInfo's rlib and vir.",
    },
)

def _search_path(file):
    return "-Ldependency=" + file.dirname

# `DYLD_*` is stripped from the environment of a system shell on macOS, so the driver's
# directory travels under a plain name and is exported here, for the prover alone.
_RUN = """set +e
export DYLD_LIBRARY_PATH="$PWD/$VERUS_DRIVER_DIR" LD_LIBRARY_PATH="$PWD/$VERUS_DRIVER_DIR"
"$@" >"$VERUS_REPORT" 2>"$VERUS_LOG"
status=$?
echo "$status" >"$VERUS_STATUS"
[ -f "$VERUS_RLIB" ] || : >"$VERUS_RLIB"
[ -f "$VERUS_VIR" ] || : >"$VERUS_VIR"
exit 0
"""

def _verus_verify_impl(ctx):
    install = ctx.files._verus
    by_name = {f.basename: f for f in install}
    if "verus" not in by_name:
        fail("the Verus lane cannot run here: " + " ".join([f.path for f in install]))
    toolchain = ctx.toolchains["@rules_rust//rust:toolchain_type"]
    crate = ctx.attr.crate[CrateInfo]
    dep_info = ctx.attr.crate[DepInfo]

    report = ctx.actions.declare_file(ctx.label.name + ".json")
    log = ctx.actions.declare_file(ctx.label.name + ".log")
    status = ctx.actions.declare_file(ctx.label.name + ".status")
    rlib = ctx.actions.declare_file("verus/lib{}.rlib".format(crate.name))
    vir = ctx.actions.declare_file("verus/{}.vir".format(crate.name))

    upstream = [d[VerusInfo] for d in ctx.attr.verus_deps]
    replaced = {u.crate_name: u for u in upstream}

    args = ctx.actions.args()
    args.add(by_name["verus"])
    args.add(crate.root)
    args.add("--crate-name=" + crate.name)
    args.add("--crate-type=lib")
    args.add("--edition=" + crate.edition)
    args.add("--sysroot=" + toolchain.sysroot)
    for feature in ctx.attr.spec_features:
        args.add("--cfg")
        args.add('feature="{}"'.format(feature))
    args.add("--compile")
    args.add("--output-json")
    args.add("--export", vir)
    args.add("-o", rlib)
    direct = []
    for dep in crate.deps.to_list():
        if not dep.crate_info or dep.crate_info.name in replaced:
            continue
        args.add("--extern={}={}".format(dep.crate_info.name, dep.crate_info.output.path))
        direct.append(dep.crate_info.output)
    for dep in crate.proc_macro_deps.to_list():
        if dep.crate_info:
            args.add("--extern={}={}".format(dep.crate_info.name, dep.crate_info.output.path))
            direct.append(dep.crate_info.output)
    for u in upstream:
        args.add("--extern={}={}".format(u.crate_name, u.rlib.path))
        args.add("--import", "{}={}".format(u.crate_name, u.vir.path))
        args.add("-Ldependency=" + u.rlib.dirname)
    args.add_all(dep_info.transitive_crate_outputs, map_each = _search_path, uniquify = True)

    driver_dirs = sorted({f.dirname: None for f in toolchain.rustc_lib.to_list() if "librustc_driver" in f.basename})
    if len(driver_dirs) != 1:
        fail("the Rust toolchain ships {} librustc_driver directories; the prover needs one".format(len(driver_dirs)))
    ctx.actions.run_shell(
        command = _RUN,
        arguments = [args],
        inputs = depset(
            install + direct,
            transitive = [
                crate.srcs,
                dep_info.transitive_crate_outputs,
                toolchain.all_files,
                toolchain.rustc_lib,
            ] + [u.transitive for u in upstream],
        ),
        outputs = [report, log, status, rlib, vir],
        env = {
            "VERUS_DRIVER_DIR": driver_dirs[0],
            "VERUS_LOG": log.path,
            "VERUS_REPORT": report.path,
            "VERUS_RLIB": rlib.path,
            "VERUS_STATUS": status.path,
            "VERUS_USE_RUSTUP": "0",
            "VERUS_VIR": vir.path,
            "VERUS_Z3_PATH": by_name["z3"].path,
        },
        mnemonic = "Verus",
        progress_message = "Verifying %{label} with the pinned Verus release",
    )
    return [
        DefaultInfo(files = depset([report, log, status])),
        VerusInfo(
            crate_name = crate.name,
            rlib = rlib,
            vir = vir,
            transitive = depset([rlib, vir], transitive = [u.transitive for u in upstream]),
        ),
    ]

verus_verify = rule(
    implementation = _verus_verify_impl,
    attrs = {
        "crate": attr.label(mandatory = True, providers = [CrateInfo, DepInfo]),
        "spec_features": attr.string_list(doc = "The crate's specification features, on for this run only."),
        "verus_deps": attr.label_list(providers = [VerusInfo]),
        "_verus": attr.label(default = "@verus//:files"),
    },
    toolchains = ["@rules_rust//rust:toolchain_type"],
    doc = "Verifies one crate with the pinned Verus release.",
)
