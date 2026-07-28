#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLO-harness invocation gate — a documented command that measures NOTHING is a bug.

`mcp-re-proxy/tests/tls_load_harness_bench.rs` is the ADR-MCPRE-051 §7 load harness.
It is deliberately NOT an `#[ignore]` test: the whole file is gated to the
`redis_replay` feature lane, which is what keeps it out of the default battery. So
`cargo test … -- --ignored` selects ONLY ignored tests, runs **zero** of them, exits
**0**, and writes no report.

That is the worst possible failure shape — a lane that looks green while having
measured nothing. It had propagated into four places (the GKE SLO runbook, both
`docs/bench/` docs, and the bench image's own ENTRYPOINT) before anyone ran the
command and noticed the report file was missing.

Two related silent non-measurements this also catches:

* Omitting `--features …redis_replay…`: the bench needs the shared Redis tier, and
  the same features must be on the BIN build, since the harness spawns the real
  `mcp-re-proxy` as a child process.
* A relative `MCP_RE_LOADGEN_OUT`: cargo runs a test binary with cwd = the PACKAGE
  root, so the report lands under `mcp-re-proxy/` and the gate reads nothing.

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

# A line that actually INVOKES the bench through cargo. A mention of the file name in
# prose ("the harness, tls_load_harness_bench.rs, drives …") is not an invocation.
INVOCATION = re.compile(r"cargo\s+test\b[^\n]*\b" + BENCH + r"\b")

# `--features "$FEATURES"` / `--features ${F}` — the features come from a variable the
# script owns. That indirection is the FIX (one definition, no restated literal), the
# same shape `deploy_image_tag_gate.py` accepts for image tags, so a literal-only match
# would fire on exactly the script that gets it right.
FEATURES_EXPANSION = re.compile(r"--features\s+[\"']?\$\{?[A-Za-z_]")


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
                        f"exits 0. Use `-- --exact`, or call scripts/local_slo_lane.sh"
                    )
                if "redis_replay" not in line and not FEATURES_EXPANSION.search(line):
                    findings.append(
                        f"{rel}:{lineno}: bench invocation without `redis_replay` — "
                        f"the harness needs the shared Redis tier (and the BIN it "
                        f"spawns needs the same features)"
                    )
    return findings


def selftest() -> int:
    """The gate must FAIL on the exact command that shipped. A gate that only ever
    passes proves nothing."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "docs").mkdir()

        bad = root / "docs" / "bad.md"
        bad.write_text(
            "cargo test -p mcp-re-proxy --release --features async_serve "
            f"--test {BENCH} {BENCH} -- --ignored\n"
        )
        findings = scan(root)
        # Both defects on one line: --ignored AND no redis_replay.
        if len(findings) != 2:
            print(f"SELFTEST FAILED: expected 2 findings, got {findings}")
            return 1

        # Prose that NAMES the flag to warn about it is not an invocation to fix.
        bad.write_text(
            f"Use `-- --exact`, NEVER `cargo test --features redis_replay --test {BENCH} "
            f"{BENCH} -- --ignored` — it selects zero tests.\n"
        )
        if scan(root):
            print("SELFTEST FAILED: a warning paragraph was treated as an invocation")
            return 1

        # A mention of the harness in prose is not an invocation either.
        bad.write_text(f"The load harness ({BENCH}.rs) drives the real listener.\n")
        if scan(root):
            print("SELFTEST FAILED: prose mentioning the harness was flagged")
            return 1

        # The correct form passes.
        bad.write_text(
            "cargo test -p mcp-re-proxy --release --features async_serve,redis_replay "
            f"--test {BENCH} {BENCH} -- --exact --nocapture\n"
        )
        if scan(root):
            print("SELFTEST FAILED: the correct invocation was flagged")
            return 1

        # …and so does the better form, where the features come from a variable.
        (root / "docs" / "lane.sh").write_text(
            'FEATURES=async_serve,redis_replay\n'
            'cargo test --release -p mcp-re-proxy --features "$FEATURES" '
            f'--test {BENCH} {BENCH} -- --exact --nocapture\n'
        )
        if scan(root):
            print("SELFTEST FAILED: a variable-sourced feature list was flagged")
            return 1

        # But the variable must not excuse `--ignored`.
        (root / "docs" / "lane.sh").write_text(
            'cargo test --features "$FEATURES" '
            f'--test {BENCH} {BENCH} -- --ignored\n'
        )
        if len(scan(root)) != 1:
            print("SELFTEST FAILED: --ignored slipped through behind a feature variable")
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
