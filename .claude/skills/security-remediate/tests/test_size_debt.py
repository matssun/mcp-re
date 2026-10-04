"""Regression: in a remediation run, size growth is recorded and does not block.

Owner direction 2026-10-04: a fix is not held back because its file or function crossed
a size threshold; the growth goes to a register and refactoring is a separate project.

  1. classify: module growth, a new oversized file and too_many_lines growth are size;
     a disposition-transition problem or excessive_nesting is not, and one of them makes
     the whole report hard (positive control for the narrowing)
  2. rust_gate: a size-only module-size failure is `size-debt` and the tests still run
  3. finalize path: a committed writer's pending rows join the register with the commit;
     a reverted writer's rows are dropped

Run:  python3 .claude/skills/security-remediate/tests/test_size_debt.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))

import rust_gate  # noqa: E402
import size_debt  # noqa: E402
from rust_resolver import RustResolver  # noqa: E402

GREW = "  - mcp-re-proxy/src/a.rs: grew from 599 to 606 production lines — the ratchet only turns one way"
NEW = ("  - mcp-re-proxy/src/b.rs: 203 production lines exceeds 200 and is not in the debt "
       "registry — decompose it")
FN = "  - mcp-re-proxy: 61 `clippy::too_many_lines` in production code, baseline 60 — the ratchet only turns one way"
NEST = "  - mcp-re-proxy: 86 `clippy::excessive_nesting` in production code, baseline 85 — the ratchet only turns one way"
TRANSITION = "  - mcp-re-proxy/src/c.rs: status unreviewed -> reviewed-exception needs a review_ref"


def test_only_size_is_soft() -> None:
    soft, rows = size_debt.classify("m", "module-size gate: FAIL — 2 problem(s)\n%s\n%s\n" % (GREW, NEW))
    assert soft and [(r["path"], r["baseline"], r["measured"]) for r in rows] == [
        ("mcp-re-proxy/src/a.rs", 599, 606), ("mcp-re-proxy/src/b.rs", 200, 203)], rows
    soft, rows = size_debt.classify("c", "clippy-ratchet gate: FAIL — 1 problem(s)\n%s\n" % FN)
    assert soft and rows[0]["metric"] == "too_many_lines", rows
    assert size_debt.classify("c", "FAIL\n%s\n" % NEST) == (False, [])
    assert size_debt.classify("m", "FAIL\n%s\n%s\n" % (GREW, TRANSITION)) == (False, [])
    assert size_debt.classify("m", "module-size gate: FAIL — examined 0 files") == (False, [])
    print("  size: growth/new-oversize/too_many_lines soft; nesting, transitions, empty scope hard  OK")


def test_rust_gate_records_size_and_still_tests() -> None:
    saved = (rust_gate.compiling_targets, rust_gate.unit_test_targets, rust_gate._lint,
             rust_gate._rustfmt, rust_gate._run, rust_gate._test)
    rust_gate.compiling_targets = lambda files: ["//alpha:lib"] if files else []  # type: ignore[assignment]
    rust_gate.unit_test_targets = lambda targets: ["//alpha:test"]  # type: ignore[assignment]
    rust_gate._lint = lambda t, log: {"verdict": "ok"}  # type: ignore[assignment]
    rust_gate._rustfmt = lambda t, e, log: {"verdict": "ok"}  # type: ignore[assignment]
    rust_gate._run = lambda cmd, log: ((1, "module-size gate: FAIL — 1 problem(s)\n" + GREW + "\n")  # type: ignore[assignment]
                                       if cmd[-1] == rust_gate.SIZE_GATE else
                                       (1, "unit-closure gate: FAIL — 1 problem(s)\n  - x.rs: UC-1")
                                       if cmd[-1].endswith("unit_closure_gate.py") else (0, ""))
    rust_gate._test = lambda t, f, log: {"verdict": "ok", "ran": 3}  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory() as td:
            open(os.path.join(td, "keys.rs"), "w").write("#[test]\nfn t() {}\n")
            parts = rust_gate.gate(os.path.join(td, "keys.rs"), [], [], td, RustResolver(td),
                                   touched=["mcp-re-proxy/src/a.rs"])
    finally:
        (rust_gate.compiling_targets, rust_gate.unit_test_targets, rust_gate._lint,
         rust_gate._rustfmt, rust_gate._run, rust_gate._test) = saved
    by = {p["gate"]: p for p in parts}
    assert by["module-size"]["verdict"] == "size-debt", by
    assert by["module-size"]["debt"][0]["measured"] == 606, by
    registry = [p for p in parts if p["gate"] == "registry"]
    assert [p["verdict"] for p in registry] == ["new-failures", "ok", "ok", "ok"], registry
    assert "test" not in by, "a registry failure is the writer's and stops the gate"
    print("  rust gate: size-only is size-debt; a registry failure (unit closure) blames the writer  OK")


def test_a_size_only_failure_still_runs_the_tests() -> None:
    saved = (rust_gate.compiling_targets, rust_gate.unit_test_targets, rust_gate._lint,
             rust_gate._rustfmt, rust_gate._run, rust_gate._test)
    rust_gate.compiling_targets = lambda files: ["//alpha:lib"] if files else []  # type: ignore[assignment]
    rust_gate.unit_test_targets = lambda targets: ["//alpha:test"]  # type: ignore[assignment]
    rust_gate._lint = lambda t, log: {"verdict": "ok"}  # type: ignore[assignment]
    rust_gate._rustfmt = lambda t, e, log: {"verdict": "ok"}  # type: ignore[assignment]
    rust_gate._run = lambda cmd, log: ((1, "FAIL\n" + GREW + "\n")  # type: ignore[assignment]
                                       if cmd[-1] == rust_gate.SIZE_GATE else (0, ""))
    rust_gate._test = lambda t, f, log: {"verdict": "ok", "ran": 3}  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory() as td:
            open(os.path.join(td, "keys.rs"), "w").write("#[test]\nfn t() {}\n")
            parts = rust_gate.gate(os.path.join(td, "keys.rs"), [], [], td, RustResolver(td),
                                   touched=["mcp-re-proxy/src/a.rs"])
    finally:
        (rust_gate.compiling_targets, rust_gate.unit_test_targets, rust_gate._lint,
         rust_gate._rustfmt, rust_gate._run, rust_gate._test) = saved
    by = {p["gate"]: p for p in parts}
    assert by["module-size"]["verdict"] == "size-debt" and by["test"]["verdict"] == "ok", by
    print("  rust gate: a size-only failure is size-debt and the tests still run  OK")


def test_only_growth_in_touched_files_is_the_writers() -> None:
    _, rows = size_debt.classify("m", "FAIL\n%s\n%s\n%s\n" % (GREW, NEW, FN))
    mine = size_debt.attributable(rows, ["mcp-re-proxy/src/b.rs", "mcp-re-proxy/src/z.rs"])
    assert [(r["metric"], r["path"]) for r in mine] == [
        ("module-size", "mcp-re-proxy/src/b.rs"), ("too_many_lines", "mcp-re-proxy")], mine
    assert size_debt.attributable(rows, ["mcp-re-demo/src/x.rs"]) == []
    print("  size: a writer is charged only for growth in what it touched  OK")


def test_committed_rows_settle_and_reverted_rows_drop() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = os.path.join(td, "register.jsonl")
        _, rows = size_debt.classify("m", "FAIL\n%s\n" % GREW)
        size_debt.record(td, "x.rs", rows)
        size_debt.record(td, "y.rs", rows)
        assert size_debt.settle(td, "x.rs", "abc1234", reg, ["f1"]) == 1
        size_debt.drop(td, "y.rs")
        assert size_debt.settle(td, "y.rs", "def5678", reg) == 0
        got = [json.loads(l) for l in open(reg)]
        assert len(got) == 1 and got[0]["commits"] == ["abc1234"] and got[0]["findings"] == ["f1"], got
        assert size_debt.register_rows(rows, "batch", reg) == 0, "an already registered growth is not added twice"
        grown = [dict(rows[0], measured=610)]
        assert size_debt.register_rows(grown, "later", reg) == 1
        got = [json.loads(l) for l in open(reg)]
        assert len(got) == 1 and got[0]["after"] == 610 and got[0]["before"] == 599 \
            and got[0]["delta"] == 11 and got[0]["commits"] == ["abc1234", "later"], got
        assert got[0]["origin"] == "pre-existing-oversized", got
        size_debt.register_rows([{"metric": "module-size", "path": "fresh.rs", "before": 190,
                                  "after": 230}], "c3", reg)
        fresh = [json.loads(l) for l in open(reg) if '"fresh.rs"' in l][0]
        assert fresh["origin"] == "new-oversized" and fresh["delta"] == 40, fresh
    print("  size: rows carry before/after/delta/origin; reverted rows are dropped  OK")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print("%d/%d passed" % (len(tests), len(tests)))
