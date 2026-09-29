"""The pinned extraction container's Charon, as a repository.

Charon runs only inside the pinned extraction container (ADR-MCPRE-059 §19), whose image
names it in `CHARON_EXE` and carries the nightly toolchain and full-MIR sysroot it runs
against. This links that binary in and records the container environment Charon reads —
where rustup keeps the nightly, where the MIR sysroot lives — so `charon_llbc` can state
its action's environment rather than inherit one. Outside the container the repository
says Charon is unavailable, and `charon_llbc` refuses at analysis.
"""

_ENV = ("HOME", "RUSTUP_HOME")

def _charon_install_impl(rctx):
    exe = rctx.os.environ.get("CHARON_EXE", "")
    path = rctx.path(exe) if exe else None
    if not exe or not path.exists:
        rctx.file("UNAVAILABLE", "no Charon here: CHARON_EXE is {}\n".format(exe or "unset"))
        rctx.file("BUILD.bazel", 'filegroup(name = "files", srcs = ["UNAVAILABLE"], visibility = ["//visibility:public"])\n')
        rctx.file("env.bzl", "CHARON_ENV = {}\n")
        return
    for entry in path.dirname.readdir():
        rctx.symlink(entry, "bin/" + entry.basename)
    env = {name: rctx.os.environ[name] for name in _ENV if name in rctx.os.environ}
    rustup = rctx.which("rustup")
    env["PATH"] = ":".join(([str(rustup.dirname)] if rustup else []) + ["/usr/bin", "/bin"])
    rctx.file("env.bzl", "CHARON_ENV = {}\n".format(repr(env)))
    rctx.file("BUILD.bazel", """filegroup(
    name = "files",
    srcs = glob(["bin/**"]),
    visibility = ["//visibility:public"],
)
""")

charon_install = repository_rule(
    implementation = _charon_install_impl,
    environ = ["CHARON_EXE", "HOME", "PATH", "RUSTUP_HOME"],
    local = True,
    doc = "Links the extraction container's Charon into a repository.",
)
