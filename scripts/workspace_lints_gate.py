#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Workspace-lints gate — ADR-MCPRE-061 Amendment 1 §3, Group A.

The Group A protections live in `[workspace.lints]` in the root `Cargo.toml` rather than
as a `#![deny(...)]` block in thirteen crate roots. That buys one copy of the rationale
and keeps six already-registered files from growing, and it costs the thing this gate
repays: a workspace table applies to a member ONLY if that member opts in with

    [lints]
    workspace = true

A member that never opts in, or one added later by someone who does not know the
convention, is silently exempt. Nothing else in the build would notice — the table is
still there, the lints are still spelled correctly, and the lane still exits 0. That is
the shape this repository has already been bitten by twice: a configuration that
parameterised nothing, and a gate whose exemption was part of its measurement.

Two checks, and neither is optional:

  * MEMBERSHIP — every `[workspace] members` entry opts in. Reported with the count of
    members actually examined, so an empty or mis-globbed scan fails loudly instead of
    printing OK over nothing.
  * --probe — the table is ENFORCED, not merely present. A deliberately violating item is
    compiled inside a real workspace member and the build must fail with the expected
    lint. A threshold is not an enforcement; the thing that turns the lint on is, and this
    is what proves the opt-in mechanism carries the table to the member.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

REPO = Path(__file__).resolve().parent.parent
ROOT_MANIFEST = REPO / "Cargo.toml"

# The member the probe is compiled in. Any member would do; this one is small and has no
# feature gates, so a probe failure is unambiguously the probe.
PROBE_MEMBER = "mcp-re-policy"
PROBE_MODULE = "workspace_lints_probe"
# `clippy::todo` is in the Group A table and is unambiguous — no other lint fires on this.
PROBE_SRC = "//! Temporary gate probe. Removed by `workspace_lints_gate.py --probe`.\npub fn probe() -> u32 {\n    todo!()\n}\n"
PROBE_EXPECT = "clippy::todo"


def cargo() -> list[str]:
    """The pinned toolchain — Homebrew's cargo shadows rustup here and ignores
    `rust-toolchain.toml`, so the channel is named explicitly."""
    channel = "1.97.1"
    tc = REPO / "rust-toolchain.toml"
    if tc.exists():
        for line in tc.read_text().splitlines():
            if line.strip().startswith("channel"):
                channel = line.split("=")[1].strip().strip('"')
                break
    if shutil.which("rustup"):
        return ["rustup", "run", channel, "cargo"]
    return ["cargo"]


def declared_lints() -> tuple[list[str], list[str]]:
    data = tomllib.loads(ROOT_MANIFEST.read_text())
    lints = data.get("workspace", {}).get("lints", {})
    return sorted(lints.get("rust", {})), sorted(lints.get("clippy", {}))


def membership() -> tuple[list[str], int]:
    """Every workspace member opts into the table."""
    data = tomllib.loads(ROOT_MANIFEST.read_text())
    members = data.get("workspace", {}).get("members", [])
    if not members:
        return ["root Cargo.toml declares no workspace members — this gate examined "
                "nothing, which is not a pass"], 0
    problems: list[str] = []
    examined = 0
    for m in members:
        manifest = REPO / m / "Cargo.toml"
        if not manifest.exists():
            problems.append(f"{m}: declared as a workspace member but has no Cargo.toml")
            continue
        examined += 1
        crate = tomllib.loads(manifest.read_text())
        lints = crate.get("lints")
        if not isinstance(lints, dict) or lints.get("workspace") is not True:
            problems.append(
                f"{m}/Cargo.toml: missing `[lints]` / `workspace = true`. The Group A "
                f"protections in the root `[workspace.lints]` table do NOT apply to a "
                f"member that does not opt in, and nothing else in the build reports it."
            )
        for own in ("rust", "clippy"):
            if isinstance(lints, dict) and own in lints:
                problems.append(
                    f"{m}/Cargo.toml: has its own `[lints.{own}]` table. Cargo rejects "
                    f"that alongside `workspace = true`, and a per-crate table is a "
                    f"second lint authority. Move the entries to `[workspace.lints.{own}]`."
                )
    return problems, examined


def probe() -> int:
    """Compile a deliberate violation inside a real member; the table must reject it."""
    member = REPO / PROBE_MEMBER
    lib = member / "src" / "lib.rs"
    probe_file = member / "src" / f"{PROBE_MODULE}.rs"
    original = lib.read_text()
    try:
        probe_file.write_text(PROBE_SRC)
        lib.write_text(original.rstrip("\n") + f"\n\nmod {PROBE_MODULE};\n")
        proc = subprocess.run(
            cargo() + ["clippy", "-p", PROBE_MEMBER, "--lib", "--quiet",
                       "--message-format=json"],
            cwd=REPO, capture_output=True, text=True,
        )
        combined = proc.stdout + proc.stderr
        # Match the lint CODE, not the rendered message. `--message-format=short` omits
        # the code entirely, so a text match there would have compared against prose that
        # never contains it — a probe that fails on a correctly-firing lint.
        fired = set()
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                m = json.loads(line)
            except json.JSONDecodeError:
                continue
            if m.get("reason") != "compiler-message":
                continue
            code = ((m.get("message") or {}).get("code") or {}).get("code") or ""
            if code:
                fired.add(code)
    finally:
        lib.write_text(original)
        probe_file.unlink(missing_ok=True)

    if proc.returncode == 0:
        print(f"workspace-lints probe: FAIL — `{PROBE_EXPECT}` did NOT fire on a "
              f"deliberate violation in {PROBE_MEMBER}. The `[workspace.lints]` table is "
              f"present but is not reaching the member: check that its `[lints] "
              f"workspace = true` opt-in survives, and that the lint is spelled the way "
              f"this clippy names it (a REMOVED lint reads as zero occurrences and "
              f"enforces nothing).")
        return 1
    if PROBE_EXPECT not in fired:
        print(f"workspace-lints probe: FAIL — the probe build failed, but not with "
              f"`{PROBE_EXPECT}`. A failure for another reason is not evidence the table "
              f"is enforced. Lints that fired: {sorted(fired) or None}\n"
              f"{combined[-1500:]}")
        return 1
    print(f"workspace-lints probe: PASS — `{PROBE_EXPECT}` fired on a deliberate "
          f"violation compiled inside `{PROBE_MEMBER}`, so the root table reaches a "
          f"member through its `[lints] workspace = true` opt-in.")
    return 0


def main() -> int:
    if "--probe" in sys.argv:
        return probe()

    rust, clippy = declared_lints()
    if not rust and not clippy:
        print("workspace-lints gate: FAIL — the root `[workspace.lints]` table is empty. "
              "Every member opting into nothing is not a pass.")
        return 1

    problems, examined = membership()
    if problems:
        print(f"workspace-lints gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(f"workspace-lints gate: OK — {examined} workspace member(s) examined, all opt "
          f"into `[workspace.lints]`; {len(rust)} rust + {len(clippy)} clippy lint(s) "
          f"declared. Run with --probe to prove the table is enforced, not merely present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
