#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Workspace-lints gate — ADR-MCPRE-061 Amendment 1 §3, Group A.

The Group A protections are ONE `rust_lint_config`, `//bazel:workspace_lints`, which
`//bazel:defs.bzl` hands to every `nt_rust_*` target by default. Bazel is the Rust build
authority, so that target is the only copy of the policy: rustc applies its `rustc` half on
every build, and the clippy aspect (`--config=lint`) applies its `clippy` half.

A default is only as good as the targets that keep it. A target that passes its own
`lint_config`, or one written with a raw `rust_*` rule instead of the house macro, is
silently exempt, and nothing else in the build would notice — the policy is still there,
the lints are still spelled correctly, and the lane still exits 0. That is the shape this
repository has been bitten by twice: a configuration that parameterised nothing, and a gate
whose exemption was part of its measurement.

Two checks, and neither is optional:

  * MEMBERSHIP — every first-party Rust target in the build graph carries the policy.
    Reported with the count of targets examined, so an empty or mis-scoped query fails
    loudly instead of printing OK over nothing. `EXEMPT` names each target that is
    deliberately outside, with its reason.
  * --probe — the policy is ENFORCED, not merely attached. A deliberate violation of each
    half is compiled inside a real target, and each build must fail with the expected
    lint: `clippy::todo` under `--config=lint`, `non_ascii_idents` under a plain build
    (rustc names the command-line level it enforced: `-D non-ascii-idents`).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
POLICY = "//bazel:workspace_lints"
RUST_RULES = "rust_library|rust_binary|rust_test|rust_shared_library|rust_static_library|rust_proc_macro"

#: First-party Rust targets deliberately outside the policy, each with its reason.
EXEMPT: dict[str, str] = {
    "//mcp-re-proxy:mock_pkcs11": "a C-ABI PKCS#11 test fixture the e2e dlopens, not product code",
}

# The target each probe is compiled in. Small and feature-free, so a probe failure is
# unambiguously the probe.
PROBE_PACKAGE = "mcp-re-policy"
PROBE_TARGET = "//mcp-re-policy:mcp_re_policy"
PROBE_MODULE = "workspace_lints_probe"
PROBES = (
    # (what it proves, extra bazel flags, source, the lint that must fire)
    ("the clippy half", ["--config=lint"],
     "pub fn probe() -> u32 {\n    todo!()\n}\n", "clippy::todo"),
    ("the rustc half", [],
     "pub fn probé() -> u32 {\n    0\n}\n", "-D non-ascii-idents"),
)


def bazel(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bazel", *args], cwd=REPO, capture_output=True, text=True)


def query(expr: str) -> set[str]:
    proc = bazel("query", "--output=label", "--keep_going", expr)
    if proc.returncode not in (0, 3):
        raise SystemExit(f"workspace-lints gate: bazel query failed\n{proc.stderr[-1500:]}")
    return {line for line in proc.stdout.splitlines() if line.startswith("//")}


def membership() -> tuple[list[str], int]:
    """Every first-party Rust target carries the policy."""
    targets = query(f'kind("^({RUST_RULES}) rule$", //...)')
    if not targets:
        return ["the build graph holds no first-party Rust target — this gate examined "
                "nothing, which is not a pass"], 0
    carrying = query(f'attr(lint_config, "{POLICY}", kind("^({RUST_RULES}) rule$", //...))')
    problems = [
        f"{t}: does not carry `{POLICY}`. The Group A protections do NOT apply to it, and "
        f"nothing else in the build reports that. Build it with the `nt_rust_*` macro and "
        f"leave `lint_config` unset."
        for t in sorted(targets - carrying - EXEMPT.keys())
    ]
    problems += [f"EXEMPT names {t}, which is not a first-party Rust target"
                 for t in sorted(EXEMPT.keys() - targets)]
    return problems, len(targets)


def probe() -> int:
    """Compile each deliberate violation inside a real target; the policy must reject it."""
    lib = REPO / PROBE_PACKAGE / "src" / "lib.rs"
    probe_file = REPO / PROBE_PACKAGE / "src" / f"{PROBE_MODULE}.rs"
    original = lib.read_text()
    failures = 0
    try:
        lib.write_text(original.rstrip("\n") + f"\n\nmod {PROBE_MODULE};\n")
        for what, flags, source, expect in PROBES:
            probe_file.write_text(f"//! Temporary gate probe. Removed by the gate.\n{source}")
            proc = bazel("build", *flags, PROBE_TARGET)
            output = proc.stdout + proc.stderr
            if proc.returncode == 0:
                print(f"workspace-lints probe: FAIL — {what}: `{expect}` did NOT fire on a "
                      f"deliberate violation in {PROBE_TARGET}. `{POLICY}` is attached but "
                      f"is not reaching the build (a REMOVED lint reads as zero occurrences "
                      f"and enforces nothing).")
                failures += 1
            elif expect not in output:
                print(f"workspace-lints probe: FAIL — {what}: the build failed, but not with "
                      f"`{expect}`. A failure for another reason is not evidence the policy is "
                      f"enforced.\n{output[-1500:]}")
                failures += 1
            else:
                print(f"workspace-lints probe: {what}: `{expect}` fired  OK")
    finally:
        lib.write_text(original)
        probe_file.unlink(missing_ok=True)
    if failures:
        return 1
    print(f"workspace-lints probe: PASS — both halves of `{POLICY}` reject a deliberate "
          f"violation compiled inside {PROBE_TARGET}.")
    return 0


def main() -> int:
    if "--probe" in sys.argv:
        return probe()
    problems, examined = membership()
    if problems:
        print(f"workspace-lints gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"workspace-lints gate: OK — {examined} first-party Rust target(s) examined, all "
          f"carry `{POLICY}` except {len(EXEMPT)} exempt: "
          + "; ".join(f"{t} ({why})" for t, why in sorted(EXEMPT.items()))
          + ". Run with --probe to prove the policy is enforced, not merely attached.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
