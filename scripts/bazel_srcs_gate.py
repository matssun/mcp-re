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


def declared_mods(file: Path) -> list[str]:
    """The module names a Rust file declares, in source order."""
    return sorted(set(MOD_DECL.findall(file.read_text(errors="replace"))))


def check_module_tree(
    crate: Path, rel_dir: str, decl_file: Path, listed: set[str], seen: set[str]
) -> list[str]:
    """Findings for every module `decl_file` declares, recursively.

    RECURSIVE because a hand-list is flat but a module tree is not.
    `mod config_state;` resolves to a DIRECTORY, and the submodules inside it are
    hand-listed one by one — so a new `src/config_state/foo.rs` is exactly as
    invisible to Bazel as a new `src/foo.rs`, and stopping at the directory checked
    the one case that cannot drift while skipping the ones that can.
    """
    findings: list[str] = []
    listed_stems = {Path(p).stem for p in listed}
    where = f"src/{rel_dir}" if rel_dir else "src"

    for mod in declared_mods(decl_file):
        rel = f"{rel_dir}/{mod}" if rel_dir else mod
        if rel in seen:
            continue
        seen.add(rel)

        file_form = f"src/{rel}.rs"
        dir_form = f"src/{rel}/mod.rs"
        as_file = crate / file_form
        as_dir = crate / "src" / rel

        if file_form in listed:
            # A leaf module, listed. Nothing below it.
            continue
        if dir_form in listed:
            # A directory module whose own mod.rs is listed: its children are listed
            # individually too, so descend.
            findings.extend(
                check_module_tree(crate, rel, crate / dir_form, listed, seen)
            )
            continue
        if any(p.startswith(f"src/{rel}/") for p in listed):
            # Covered by sibling entries without a listed mod.rs — still descend if we
            # can find the declaration file.
            if (crate / dir_form).is_file():
                findings.extend(
                    check_module_tree(crate, rel, crate / dir_form, listed, seen)
                )
            continue
        if mod in listed_stems and not as_file.is_file() and not as_dir.is_dir():
            # Listed under some other path and not resolvable here; nothing to check.
            continue

        findings.append(
            f"{crate.name}/BUILD.bazel: `mod {mod};` in {where}/"
            f"{'mod.rs' if rel_dir else 'lib.rs'} is not in the hand-listed srcs — "
            f"cargo compiles it, Bazel cannot find it (E0583)"
        )
    return findings


def check_crate(crate: Path) -> list[str]:
    """Findings for one crate. Empty when the BUILD globs or the list is complete."""
    build, lib = crate / "BUILD.bazel", crate / "src" / "lib.rs"
    if not build.is_file() or not lib.is_file():
        return []
    build_text = build.read_text(errors="replace")
    if GLOBBED.search(build_text):
        return []  # cannot drift

    listed = {m for m in SRC_ENTRY.findall(build_text)}
    findings = check_module_tree(crate, "", lib, listed, set())

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

        # A NESTED module the hand-list misses. `mod alpha;` resolving to a directory
        # used to end the walk, on the assumption that a directory module carries a glob
        # of its own — but a hand-listed crate lists the directory's children one by one,
        # so `src/alpha/deep.rs` drifts exactly as `src/deep.rs` does. This is the case
        # that reached a 30-minute `bazel test //...` instead of this second.
        (crate / "src" / "alpha.rs").unlink()
        (crate / "src" / "alpha").mkdir()
        (crate / "src" / "alpha" / "mod.rs").write_text("pub mod deep;\n")
        (crate / "src" / "alpha" / "deep.rs").write_text("")
        (crate / "BUILD.bazel").write_text(
            'srcs = ["src/lib.rs", "src/alpha/mod.rs", "src/beta.rs"]\n'
        )
        f = scan(root)
        if len(f) != 1 or "mod deep" not in f[0]:
            print(f"SELFTEST FAILED: expected a nested missing-module finding, got {f}")
            return 1

        # And the same tree, complete, passes.
        (crate / "BUILD.bazel").write_text(
            'srcs = ["src/lib.rs", "src/alpha/mod.rs", "src/alpha/deep.rs", '
            '"src/beta.rs"]\n'
        )
        if scan(root):
            print("SELFTEST FAILED: a complete nested hand-list was flagged")
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
