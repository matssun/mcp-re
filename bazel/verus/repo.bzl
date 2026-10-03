"""The pinned Verus install as a repository, read from the toolchain lock.

`verification/policy/toolchains.lock.toml` is the one statement of which Verus release is
pinned and where it is installed; this reads `[verus].install_root` from it rather than
restating the path. The install lives outside the workspace on the hosts that run the
Verus lane, so the repository links its files in, and every one of them is an input to
the actions that use it — a different prover is a different action.

A host without the install gets a repository that says so: `verus_verify` refuses at
analysis with the path it looked for, rather than failing on a missing file.
"""

def _install_root(lock_text):
    in_verus = False
    for line in lock_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_verus = stripped == "[verus]"
            continue
        if in_verus and stripped.startswith("install_root"):
            return stripped.split("=", 1)[1].strip().strip('"')
    return None

def _verus_install_impl(rctx):
    root = _install_root(rctx.read(rctx.attr.lock))
    if root == None:
        fail("{}: [verus] names no install_root".format(rctx.attr.lock))
    install = rctx.path(root)
    if not install.exists or not install.get_child("rust_verify").exists:
        rctx.file("UNAVAILABLE", "the pinned Verus release is not installed at {}\n".format(root))
        rctx.file("BUILD.bazel", 'filegroup(name = "files", srcs = ["UNAVAILABLE"], visibility = ["//visibility:public"])\n')
        return
    for entry in install.readdir():
        rctx.symlink(entry, entry.basename)
    rctx.file("BUILD.bazel", """filegroup(
    name = "files",
    srcs = glob(["**"], exclude = ["BUILD.bazel", "WORKSPACE", "REPO.bazel"]),
    visibility = ["//visibility:public"],
)
""")

verus_install = repository_rule(
    implementation = _verus_install_impl,
    attrs = {"lock": attr.label(allow_single_file = True, mandatory = True)},
    local = True,
    doc = "Links the Verus release `toolchains.lock.toml` pins into a repository.",
)
