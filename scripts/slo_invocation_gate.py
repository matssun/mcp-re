#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLO-harness invocation gate — a documented command that measures NOTHING is a bug.

`mcp-re-proxy/tests/tls_load_harness_bench.rs` is the ADR-MCPRE-051 §7 load harness. It is
deliberately NOT an `#[ignore]` test: the whole file is gated to the `redis_replay` feature
lane and its Bazel target is `manual`, which is what keeps it out of the default battery.
So `-- --ignored` (or `--test_arg=--ignored`) selects ONLY ignored tests, runs **zero** of
them, exits **0**, and writes no report.

That is the worst possible failure shape — a lane that looks green while having measured
nothing. It had propagated into four places (the GKE SLO runbook, both `docs/bench/` docs,
and the bench image's own ENTRYPOINT) before anyone ran the command and noticed the report
file was missing.

The bench is a Bazel target, `//mcp-re-proxy:tls_load_harness_bench`, built against the
deploy flavor it measures. So the gate also refuses an invocation through Cargo, which
builds a different binary from a different feature set than the one that ships.

The fix when this fires is never to reword the prose — it is to call
`scripts/local_slo_lane.sh`, which pins all of it and asserts a test actually ran.

Run:  python3 scripts/slo_invocation_gate.py
      python3 scripts/slo_invocation_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Every tracked surface that can carry a runnable invocation: docs people copy from,
# scripts, container images, CI. `docs/archive/` is frozen pre-ADR-050 history and is
# excluded by construction — it narrates old runs and must not be "fixed".
SCAN_GLOBS = (
    "docs/**/*.md",
    "docs/**/*.sh",
    "scripts/*.py",
    "scripts/*.sh",
    "tools/**/*.sh",
    "deploy/**/Dockerfile*",
    ".github/workflows/*.yml",
    "*.md",
)

BENCH = "tls_load_harness_bench"

# A line that actually INVOKES the bench: `bazel run`/`bazel test` of its label (or of the
# `$BENCH` variable a script binds it to), the image's binary run with its own name as the
# filter, or Cargo. A mention of the file name in prose ("the harness,
# tls_load_harness_bench.rs, drives …") is not an invocation.
INVOCATION = re.compile(
    r"bazel\s+(?:run|test)\b[^\n]*(?://mcp-re-proxy:" + BENCH + r"\b|\$\{?BENCH\b)"
    r"|\b" + BENCH + r"\s+" + BENCH + r"\b"
    r"|cargo\s+test\b[^\n]*\b" + BENCH + r"\b"
)


def _is_archive(path: Path, root: Path) -> bool:
    return "archive" in path.relative_to(root).parts


def scan(root: Path) -> list[str]:
    """Return one finding per broken bench invocation."""
    findings: list[str] = []
    for glob in SCAN_GLOBS:
        for path in sorted(root.glob(glob)):
            if not path.is_file() or _is_archive(path, root):
                continue
            rel = path.relative_to(root)
            for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if not INVOCATION.search(line):
                    continue
                # This gate's OWN prose names the forbidden flag in order to explain
                # it; so do the runbooks' warning paragraphs. Only flag a line that is
                # a live invocation carrying the flag, which the regex above already
                # requires — but a line that merely quotes `-- --ignored` next to the
                # word NEVER/NOT is a warning, not a command.
                if re.search(r"\b(NEVER|NOT|never use|forbidden)\b", line):
                    continue
                if "--ignored" in line:
                    findings.append(
                        f"{rel}:{lineno}: `--ignored` selects ZERO tests here "
                        f"({BENCH} is not #[ignore]) — the run measures nothing and "
                        f"exits 0. Use `--exact`, or call scripts/local_slo_lane.sh"
                    )
                if re.search(r"\bcargo\s+test\b", line):
                    findings.append(
                        f"{rel}:{lineno}: the bench runs through Cargo, which builds a "
                        f"different binary from a different feature set than the one that "
                        f"ships. Run //mcp-re-proxy:tls_load_harness_bench, or call "
                        f"scripts/local_slo_lane.sh"
                    )
    return findings


def selftest() -> int:
    """The gate must FAIL on the exact command that shipped. A gate that only ever
    passes proves nothing."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "docs").mkdir()
        bad = root / "docs" / "bad.md"
        lane = root / "docs" / "lane.sh"
        label = f"//mcp-re-proxy:{BENCH}"

        def expect(name: str, text: str, path: Path, want: int) -> bool:
            path.write_text(text)
            got = scan(root)
            path.write_text("")
            if len(got) != want:
                print(f"SELFTEST FAILED: {name}: expected {want} finding(s), got {got}")
                return False
            return True

        cases = [
            # The exact shape that shipped, in each spelling the tree can hold.
            ("--ignored on bazel run", f"bazel run -c opt {label} -- --ignored\n", bad, 1),
            ("--ignored as a test_arg", f"bazel test {label} --test_arg=--ignored\n", bad, 1),
            ("--ignored behind the script's variable",
             'bazel run -c opt "$' + 'BENCH" -- --ignored\n', lane, 1),
            ("--ignored in the image's binary form", f"{BENCH} {BENCH} --ignored\n", bad, 1),
            # Cargo builds a different binary; with --ignored it is both defects.
            ("the bench through Cargo",
             f"cargo test -p mcp-re-proxy --test {BENCH} {BENCH} -- --exact\n", bad, 1),
            ("Cargo AND --ignored",
             f"cargo test -p mcp-re-proxy --test {BENCH} {BENCH} -- --ignored\n", bad, 2),
            # Prose that NAMES the flag to warn about it is not an invocation to fix.
            ("a warning paragraph",
             f"Use `--exact`, NEVER `bazel run {label} -- --ignored` — it selects zero "
             f"tests.\n", bad, 0),
            ("prose naming the harness", f"The load harness ({BENCH}.rs) drives it.\n", bad, 0),
            # The correct forms pass.
            ("the correct bazel run", f"bazel run -c opt {label} -- {BENCH} --exact --nocapture\n",
             bad, 0),
            ("the correct variable form",
             'bazel run -c opt "$' + f'BENCH" -- {BENCH} --exact --nocapture\n', lane, 0),
            ("the correct image form", f"{BENCH} {BENCH} --exact --nocapture\n", bad, 0),
        ]
        if not all(expect(*c) for c in cases):
            return 1

    print("slo invocation gate selftest: PASS")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    findings = scan(REPO)
    if findings:
        print("slo invocation gate: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nA bench invocation that selects no test exits 0 and writes no report — "
            "it is indistinguishable from a pass. Prefer scripts/local_slo_lane.sh.",
            file=sys.stderr,
        )
        return 1
    print(f"slo invocation gate: OK — every {BENCH} invocation runs the test it claims to")
    return 0


if __name__ == "__main__":
    sys.exit(main())
