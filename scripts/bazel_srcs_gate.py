#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bazel srcs gate — a hand-listed `srcs` must match the crate's source directory.

Every crate but one lets Bazel `glob(["src/**/*.rs"])`, which cannot drift from what
cargo compiles. `mcp-re-proxy` hand-lists its sources (`_PROXY_LIB_SRCS`) because
three library flavors share the list, and a hand-list drifts: `src/audit_sink.rs`
landed with the ADR-MCPS-035 audit surface and was never added, so cargo built a
module Bazel could not find and every Bazel target downstream of the proxy library
failed with E0583.

The existing semantic-drift gate compares TARGETS, not sources, so it passed. The
only thing that caught this was a full `bazel test //...` — 30+ minutes, and per its
own commit message it "had never once completed during this audit", which is exactly
how the miss survived several rounds of review.

This is that check at one second: every `mod`/`pub mod` in a hand-listed crate's
lib.rs must have a corresponding entry in the BUILD list, and every listed file must
exist. Crates whose BUILD globs are skipped — they cannot drift by construction.

Run:  python3 scripts/bazel_srcs_gate.py
      python3 scripts/bazel_srcs_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))? )?mod ([a-z0-9_]+)\s*;", re.M)
SRC_ENTRY = re.compile(r'"(src/[A-Za-z0-9_/]+\.rs)"')
GLOBBED = re.compile(r"srcs\s*=\s*glob\(")


def check_crate(crate: Path) -> list[str]:
    """Findings for one crate. Empty when the BUILD globs or the list is complete."""
    build, lib = crate / "BUILD.bazel", crate / "src" / "lib.rs"
    if not build.is_file() or not lib.is_file():
        return []
    build_text = build.read_text(errors="replace")
    if GLOBBED.search(build_text):
        return []  # cannot drift

    findings: list[str] = []
    listed = {m for m in SRC_ENTRY.findall(build_text)}
    listed_stems = {Path(p).stem for p in listed}

    for mod in sorted(set(MOD_DECL.findall(lib.read_text(errors="replace")))):
        # `mod foo;` resolves to src/foo.rs OR src/foo/mod.rs — a directory module is
        # normally covered by a glob of its own; only flag when NEITHER form is listed.
        if mod in listed_stems:
            continue
        if any(p.startswith(f"src/{mod}/") for p in listed):
            continue
        if (crate / "src" / mod).is_dir():
            continue
        findings.append(
            f"{crate.name}/BUILD.bazel: `mod {mod};` in src/lib.rs is not in the "
            f"hand-listed srcs — cargo compiles it, Bazel cannot find it (E0583)"
        )

    for entry in sorted(listed):
        if not (crate / entry).is_file():
            findings.append(
                f"{crate.name}/BUILD.bazel: lists {entry}, which does not exist"
            )
    return findings


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for crate in sorted(root.glob("mcp-re-*")):
        if crate.is_dir():
            findings.extend(check_crate(crate))
    return findings


def selftest() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        crate = root / "mcp-re-thing"
        (crate / "src").mkdir(parents=True)
        (crate / "src" / "lib.rs").write_text("pub mod alpha;\npub mod beta;\n")
        (crate / "src" / "alpha.rs").write_text("")
        (crate / "src" / "beta.rs").write_text("")

        # A hand-list missing one module is the defect that shipped.
        (crate / "BUILD.bazel").write_text('srcs = ["src/lib.rs", "src/alpha.rs"]\n')
        f = scan(root)
        if len(f) != 1 or "mod beta" not in f[0]:
            print(f"SELFTEST FAILED: expected one missing-module finding, got {f}")
            return 1

        # Complete list passes.
        (crate / "BUILD.bazel").write_text(
            'srcs = ["src/lib.rs", "src/alpha.rs", "src/beta.rs"]\n'
        )
        if scan(root):
            print("SELFTEST FAILED: a complete hand-list was flagged")
            return 1

        # A listed file that does not exist is also a finding.
        (crate / "BUILD.bazel").write_text(
            'srcs = ["src/lib.rs", "src/alpha.rs", "src/beta.rs", "src/gone.rs"]\n'
        )
        f = scan(root)
        if len(f) != 1 or "does not exist" not in f[0]:
            print(f"SELFTEST FAILED: expected a stale-entry finding, got {f}")
            return 1

        # A globbing BUILD is skipped entirely, even when it looks incomplete.
        (crate / "BUILD.bazel").write_text('srcs = glob(["src/**/*.rs"]),\n')
        if scan(root):
            print("SELFTEST FAILED: a globbing BUILD was checked")
            return 1

    print("bazel srcs gate selftest: PASS")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    findings = scan(REPO)
    if findings:
        print("bazel srcs gate: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nA hand-listed srcs drifts silently: cargo globs the directory, Bazel "
            "does not. Add the file to the list.",
            file=sys.stderr,
        )
        return 1
    print("bazel srcs gate: OK — every hand-listed crate's srcs matches its lib.rs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
