#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test-target gate — a named test lane must name a target that exists, and a filter
must name a module that target holds.

WHAT THIS PROVES, exactly: every literal Bazel label a `bazel test` command in the CI
workflows or the repository scripts names is a test target of the build graph, and every
`--test_arg=<module>::` filter beside it names a module the target's crate root declares.
Non-literal labels (`"$BENCH"`) are skipped — there is nothing static to check.

The build graph is read from `verification/generated/rust-targets.json`, whose freshness
`tools/verification/rust-targets --check` holds to `bazel query`, so this gate runs where
no Bazel server does. The verification manifest's selectors are checked by the manifest
loader itself (`_manifest.valid_target`), not here.

WHAT IT DOES NOT PROVE: that the lane runs the tests its step name claims beyond the
module, or that the named test inside the module exists. `scripts/run_test_lane.sh`
refuses a lane that ran zero tests; `scripts/slo_invocation_gate.py` covers the SLO lane.

WHY IT MATTERS. Renaming or merging a test target breaks every table that names it, and
the tables are not in one place: the security traceability manifest, the guard tables,
the verification manifest, and — the one nothing catalogued — the named release-gate
steps in the workflows. Consolidating thirteen proxy test binaries once silently pointed
four release-gate lanes at names that no longer existed. A label that names nothing fails
its lane loudly; a module filter that names nothing selects ZERO tests and exits 0, which
is the failure that reads as a pass.

Run:  python3 scripts/test_target_gate.py
      python3 scripts/test_target_gate.py --selftest
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TABLE = Path("verification") / "generated" / "rust-targets.json"
TEST_KINDS = ("rust_test", "rust_doc_test")

SCAN_GLOBS = (
    ".github/workflows/*.yml",
    "scripts/*.sh",
    "scripts/*.sh.example",
)

BAZEL_TEST = re.compile(r"\bbazel\s+test\b")
LABEL = re.compile(r"(?<![\w$])(//[A-Za-z0-9_./-]*:[A-Za-z0-9_.+-]+)")
MODULE_FILTER = re.compile(r"--test_arg=([a-z][a-z0-9_]*)::")
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z0-9_]+)\s*[;{]", re.M)
# A run of lines belonging to one command: YAML folds with `>-`/`|`, and shells continue
# with a trailing backslash, so the command and its label can be lines apart. Blank lines,
# comments and a new `- name:` end the run.
BLOCK_BREAK = re.compile(r"^\s*(?:-\s+name:|#|$)")
# A line that prints a command — a usage message — names it without running it.
PRINTS = re.compile(r"^\s*(?:echo|printf)\b")


def load_targets(root: Path) -> dict[str, dict]:
    return json.loads((root / TABLE).read_text())["targets"]


def blocks(text: str) -> list[tuple[int, str]]:
    """(first line number, text) for each run of lines forming one command."""
    out: list[tuple[int, str]] = []
    start, buffer = 0, []
    for number, line in enumerate(text.splitlines(), start=1):
        if BLOCK_BREAK.match(line):
            if buffer:
                out.append((start, "\n".join(buffer)))
                buffer = []
            continue
        if not buffer:
            start = number
        buffer.append(line)
    if buffer:
        out.append((start, "\n".join(buffer)))
    return out


def root_modules(root: Path, row: dict) -> set[str]:
    """The modules the target's crate root declares — what a `module::` filter can name."""
    path = root / row["root"]
    return set(MOD_DECL.findall(path.read_text(encoding="utf-8"))) if path.is_file() else set()


def check(root: Path, targets: dict[str, dict]) -> tuple[list[str], int]:
    failures: list[str] = []
    named = 0
    for pattern in SCAN_GLOBS:
        for path in sorted(root.glob(pattern)):
            rel = path.relative_to(root)
            for number, block in blocks(path.read_text(encoding="utf-8")):
                block = "\n".join(line for line in block.splitlines() if not PRINTS.match(line))
                if not BAZEL_TEST.search(block):
                    continue
                labels = [lbl for lbl in LABEL.findall(block) if not lbl.startswith("//...")]
                for label in labels:
                    named += 1
                    row = targets.get(label)
                    if row is None or row["kind"] not in TEST_KINDS:
                        failures.append(
                            f"{rel}:{number}: `{label}` is not a test target of the build "
                            f"graph — it was renamed, merged or is not a test; repoint the lane"
                        )
                        continue
                    modules = root_modules(root, row)
                    for module in MODULE_FILTER.findall(block):
                        if module not in modules:
                            failures.append(
                                f"{rel}:{number}: filter `{module}::` names no module in "
                                f"`{label}` ({row['root']}) — libtest would select ZERO "
                                f"tests and exit 0"
                            )
    return failures, named


def selftest() -> int:
    failed = False
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "pkg" / "tests").mkdir(parents=True)
        (root / "pkg" / "tests" / "main.rs").write_text("mod real_mod;\npub mod other {\n}\n")
        targets = {
            "//pkg:real_test": {"kind": "rust_test", "root": "pkg/tests/main.rs"},
            "//pkg:a_library": {"kind": "rust_library", "root": "pkg/src/lib.rs"},
        }
        cases = [
            ("a named target that exists", "run: bazel test //pkg:real_test\n", ""),
            ("a named target that does not exist", "run: bazel test //pkg:ghost_test\n", "not a test target"),
            ("a library is not a test target", "run: bazel test //pkg:a_library\n", "not a test target"),
            (
                "a label split from its command across folded lines",
                "        run: >-\n          scripts/run_test_lane.sh bazel test --test_output=all\n"
                "          //pkg:ghost_test\n",
                "not a test target",
            ),
            ("a variable is not a static claim", 'run: bazel test "$BENCH"\n', ""),
            ("a build of a missing label is not a test lane", "run: bazel build //pkg:ghost\n", ""),
            ("the whole graph is not a label", "run: bazel test //... --test_output=errors\n", ""),
            (
                "a usage example in a comment is not an invocation",
                "# run_test_lane.sh bazel test //pkg:ghost_test\n",
                "",
            ),
            (
                "a usage message is not an invocation",
                '  echo "usage: $0 bazel test //pkg:target --test_arg=<module>::" >&2\n',
                "",
            ),
            (
                "a filter naming a declared module",
                "run: bazel test //pkg:real_test --test_arg=real_mod::\n",
                "",
            ),
            (
                "an inline module is declared too",
                "run: bazel test //pkg:real_test --test_arg=other::x\n",
                "",
            ),
            (
                "a filter naming no module selects nothing",
                "run: bazel test //pkg:real_test --test_arg=ghost_mod::\n",
                "names no module",
            ),
        ]
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        for label, content, expected in cases:
            (workflows / "ci.yml").write_text(content, encoding="utf-8")
            failures = check(root, targets)[0]
            ok = not failures if not expected else any(expected in f for f in failures)
            print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
            if not ok:
                failed = True
                print(f"        got {failures}")
    if failed:
        print("test-target gate: SELFTEST FAILED")
        return 1
    print("test-target gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    failures, named = check(REPO, load_targets(REPO))
    if failures:
        print("test-target gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    if named == 0:
        print("test-target gate: FAILED — no `bazel test` lane names a label; the scan read nothing")
        return 1
    print(f"test-target gate: OK — {named} label(s) named by `bazel test` lanes are test targets "
          f"of the build graph, and every module filter names a module the target declares")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
