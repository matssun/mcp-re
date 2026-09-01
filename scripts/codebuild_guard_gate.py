#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The CodeBuild context guard must refuse the wrong upload, not the right one.

`deploy/codebuild/mcp-re-slo-bench.yaml` uploads its source with
`git archive --format=zip HEAD` and its `pre_build` phase refuses to build if the context
carries operator credential material. That guard rests on one premise:

    every path it names is a path `git archive HEAD` CANNOT produce.

The premise is what makes a hit mean something. A path the archive always emits turns the
guard inside out — it refuses every correctly produced upload and says nothing about a
zipped working tree, which is the only thing it exists to detect. `.claude` was in the
list and eight files under it are TRACKED, so that is not hypothetical: the guard
rejected the good path and passed the bad one for as long as it existed.

The premise is a local fact — `git ls-files` decides it — so it is checked here rather
than remembered. Same for the credential-shaped `find`: a tracked `*.pem` would abort
every build.

WHAT THIS DOES NOT PROVE: that the upload really was produced by `git archive`, that the
guard runs, or that the named paths are the right ones to name. It proves only that every
path the guard refuses is one a correct upload does not contain, which is the property
that failed.

Run:  python3 scripts/codebuild_guard_gate.py
      python3 scripts/codebuild_guard_gate.py --selftest
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "deploy" / "codebuild" / "mcp-re-slo-bench.yaml"

#: The `for p in ... ; do` list, and the `-name`/`-o -name` set of the credential find.
LOOP = re.compile(r"for p in ([^;]+); do")
FIND_NAME = re.compile(r"-name '([^']+)'")


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    return [line for line in out.split("\0") if line]


def guarded_paths(text: str) -> list[str]:
    match = LOOP.search(text)
    return match.group(1).split() if match else []


def guarded_names(text: str) -> list[str]:
    return FIND_NAME.findall(text)


def defects(paths: list[str], names: list[str], tracked_files: list[str]) -> list[str]:
    """Every guard term a correct `git archive HEAD` upload would trip."""
    found = []
    for path in paths:
        prefix = f"{path.rstrip('/')}/"
        emitted = [f for f in tracked_files if f == path or f.startswith(prefix)]
        if emitted:
            found.append(
                f"the context guard refuses {path!r}, which `git archive HEAD` emits "
                f"({len(emitted)} tracked file(s), e.g. {emitted[0]}). Every correct "
                f"upload aborts pre_build, and a zipped working tree is not detected. "
                f"Name a path the archive cannot produce."
            )
    for name in names:
        emitted = [f for f in tracked_files if Path(f).match(name)]
        if emitted:
            found.append(
                f"the credential find refuses {name!r}, which matches tracked "
                f"{emitted[0]}. Every correct upload aborts pre_build."
            )
    return found


def selftest() -> int:
    """A guard term the archive emits must be refused; one it cannot emit must not be."""
    tracked_files = [".claude/settings.json", "src/main.rs", "docs/a.md"]
    cases = [
        (["work", ".claude"], [], "`git archive HEAD` emits", "a partly tracked directory"),
        (["work", ".aws"], [], None, "directories the archive cannot produce"),
        (["work"], ["*.rs"], "matches tracked", "a credential glob that hits the tree"),
        (["work"], ["*.pem"], None, "a credential glob nothing tracked matches"),
        ([".claude/settings.local.json"], [], None, "an untracked file inside a tracked tree"),
    ]
    for paths, names, needle, label in cases:
        found = defects(paths, names, tracked_files)
        if needle is None:
            if found:
                print(f"SELFTEST FAIL: refused {label}: {found}", file=sys.stderr)
                return 1
            continue
        if not any(needle in entry for entry in found):
            print(f"SELFTEST FAIL: accepted {label}", file=sys.stderr)
            return 1
    if not guarded_paths("  for p in work .aws .kube; do\n"):
        print("SELFTEST FAIL: the extractor stopped reading the guard loop", file=sys.stderr)
        return 1
    if guarded_names("-name '*.pem' -o -name 'kubeconfig'") != ["*.pem", "kubeconfig"]:
        print("SELFTEST FAIL: the extractor stopped reading the credential find", file=sys.stderr)
        return 1
    print("codebuild_guard_gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    text = TEMPLATE.read_text(encoding="utf-8")
    paths = guarded_paths(text)
    names = guarded_names(text)
    if not paths or not names:
        # An empty scope is the gate measuring nothing while printing OK.
        print(
            f"FAIL: no context guard found in {TEMPLATE.relative_to(REPO)}. Either the "
            f"guard is gone or the extractor has stopped matching; both are findings.",
            file=sys.stderr,
        )
        return 1
    found = defects(paths, names, tracked())
    for defect in found:
        print(f"FAIL: {defect}", file=sys.stderr)
    if found:
        return 1
    print(
        f"codebuild-guard gate: OK — {len(paths)} refused path(s) and {len(names)} "
        f"credential glob(s), none of which `git archive HEAD` can emit"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
