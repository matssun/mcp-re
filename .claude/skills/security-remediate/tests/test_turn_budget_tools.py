"""Regression: prepare.py / dispose.py / check.py — the three turn-budget tools.

Each tool replaces a run of agent turns with one call, so each must be at least as
strict as the turns it replaces. What is pinned here:

  dispose.py
    1. a complete package applies: ledger statuses, APPENDED notes (a recorded
       ruling survives), one `close` per terminal disposition, and counts DERIVED
       from identities — the positive control every refusal below is paired with
    2. an incomplete package is refused and writes NOTHING (ledger bytes and
       journal both unchanged)
    3. the cheap tier cannot close; a duplicate must name its twin; a work item
       must name the findings it discharges; a finding cannot be both disposed
       and ordered; the same attempt cannot be applied twice
  prepare.py
    4. anchors are located by content through line-number prefixes, and an
       absent excerpt is reported absent — not silently "found"
    5. the usage map counts a file only if it imports the name from THIS package:
       a same-named symbol from another package and a docstring mention are not
       uses (the `Scope` case: 155 false production sites under bare grep)
  check.py
    6. `pre` captures a baseline only where none exists
    7. `post` blames the change only for NEW failures, appends `gate-failed`
       exactly then, and reads a pyright run with no summary line as infra

Run:  python3 .claude/skills/security-remediate/tests/test_turn_budget_tools.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)

from _persist import read_jsonl  # noqa: E402
from prepare import locate  # noqa: E402

FILE = "components/x/src/x/mod.py"


def _py(script: str, *argv: str, cwd: str | None = None, env: dict | None = None):
    return subprocess.run([sys.executable, os.path.join(SCRIPTS, script), *argv],
                          capture_output=True, text=True, timeout=120, cwd=cwd, env=env)


def _ledger(td: str, rows: list[dict]) -> str:
    path = os.path.join(td, "ledger.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(dict({"path": FILE, "file": "mod.py", "category": "c",
                                      "notes": ""}, **r), sort_keys=True) + "\n")
    return path


ROWS = [
    {"id": "f1", "severity": "high", "title": "t1", "status": "open",
     "notes": "RULED by the owner: keep the v1 bytes frozen"},
    {"id": "f2", "severity": "medium", "title": "t2", "status": "open"},
    {"id": "f3", "severity": "low", "title": "t3", "status": "open"},
    {"id": "f4", "severity": "low", "title": "t4", "status": "regression"},
    {"id": "done", "severity": "low", "title": "old", "status": "fixed"},
]


def _package(td: str, **over) -> str:
    pkg = {"file": FILE,
           "disposed": [
               {"id": "f1", "status": "escalated", "reason": "two remedies", "ruling": "r-frame"},
               {"id": "f2", "status": "false-positive", "reason": "guarded upstream"},
               {"id": "f3", "status": "duplicate", "duplicate_of": "f2"}],
           "work": [{"id": "w1", "finding_ids": ["f4"], "anchor": "x = 1", "change": "x = 2",
                     "accept": "grep -n 'x = 2'", "standard": "coding"}],
           "delete_or_wire": []}
    pkg.update(over)
    path = os.path.join(td, "pkg.json")
    json.dump(pkg, open(path, "w", encoding="utf-8"))
    return path


def _dispose(td: str, pkg: str, *extra: str, tier: str = "senior", attempt: str = "att-1"):
    return _py("dispose.py", "--ledger", os.path.join(td, "ledger.jsonl"),
               "--log", os.path.join(td, "progress"), "--package", pkg,
               "--attempt", attempt, "--run", "run-1", "--tier", tier, "--model", "opus", *extra)


def test_dispose_applies_a_complete_package() -> None:
    with tempfile.TemporaryDirectory() as td:
        _ledger(td, ROWS)
        p = _dispose(td, _package(td))
        assert p.returncode == 0, p.stdout + p.stderr
        by_id = {r["id"]: r for r in read_jsonl(os.path.join(td, "ledger.jsonl"))}
        assert by_id["f1"]["status"] == "escalated" and by_id["f1"]["ruling_id"] == "r-frame"
        assert by_id["f2"]["status"] == "false-positive"
        assert by_id["f3"]["duplicate_of"] == "f2"
        assert by_id["f4"]["status"] == "regression", "a work item must not change status"
        assert by_id["f1"]["notes"].startswith("RULED by the owner"), "a recorded ruling was erased"
        assert "two remedies" in by_id["f1"]["notes"]
        assert by_id["f3"]["notes"] == "", "a duplicate needs no reason, and none was invented"
        ev = read_jsonl(os.path.join(td, "progress.jsonl"))
        closes = [e for e in ev if e["event"] == "close"]
        evaluate = [e for e in ev if e["event"] == "evaluate"]
        assert sorted(c["finding_id"] for c in closes) == ["f2", "f3"], closes
        assert len(evaluate) == 1
        assert evaluate[0]["counts"] == {"work": 1, "closed": 2, "escalated": 1, "disposed": 3}
        assert evaluate[0]["escalation_ids"] == ["f1"] and evaluate[0]["work_ids"] == ["w1"]
        assert not [e for e in ev if e["event"] == "no-code-change"], "work>0 has no terminal here"
        print("  dispose: complete package applied, counts derived, ruling note kept  OK")


def test_dispose_zero_work_writes_its_own_terminal_event() -> None:
    with tempfile.TemporaryDirectory() as td:
        _ledger(td, ROWS)
        pkg = _package(td, work=[], disposed=_package_disposed_all())
        p = _dispose(td, pkg)
        assert p.returncode == 0, p.stdout
        ev = [e["event"] for e in read_jsonl(os.path.join(td, "progress.jsonl"))]
        assert ev[-2:] == ["evaluate", "no-code-change"], ev
        print("  dispose: work=0 ends the attempt with no-code-change  OK")


def _package_disposed_all() -> list[dict]:
    # superseded needs no reason: the absent anchor is the evidence.
    return [{"id": f, "status": "superseded"} for f in ("f1", "f2", "f3", "f4")]


def test_dispose_bounds_a_reason_to_one_line() -> None:
    with tempfile.TemporaryDirectory() as td:
        _ledger(td, ROWS)
        essay = "line one\n\n" + "word " * 400
        pkg = _package(td, disposed=[
            {"id": "f1", "status": "escalated", "reason": "A or B?"},
            {"id": "f2", "status": "false-positive", "reason": essay},
            {"id": "f3", "status": "duplicate", "duplicate_of": "f2"}])
        assert _dispose(td, pkg).returncode == 0
        note = {r["id"]: r for r in read_jsonl(os.path.join(td, "ledger.jsonl"))}["f2"]["notes"]
        added = note.split("\n")[-1]
        assert "\n" not in added.split("] ", 1)[1] and len(added) < 360, added[:80]
        assert added.endswith("…")
        print("  dispose: a reason is stored as one bounded line  OK")


def _assert_refused(td: str, p, needle: str) -> None:
    before = open(os.path.join(td, "ledger.jsonl"), encoding="utf-8").read()
    assert p.returncode == 2, "expected refusal, got %d:\n%s" % (p.returncode, p.stdout)
    assert needle in p.stdout, "refusal did not name %r:\n%s" % (needle, p.stdout)
    assert "NOTHING was written" in p.stdout or "already has" in p.stdout
    assert open(os.path.join(td, "ledger.jsonl"), encoding="utf-8").read() == before


def test_dispose_refuses_and_writes_nothing() -> None:
    cases = [
        ("missing finding", dict(work=[]), "senior", "MISSING f4"),
        ("cheap closes", {}, "cheap", "cheap tier may not close"),
        ("dup without twin", dict(disposed=[
            {"id": "f1", "status": "escalated", "reason": "r"},
            {"id": "f2", "status": "false-positive", "reason": "r"},
            {"id": "f3", "status": "duplicate", "reason": "r"}]), "senior", "duplicate_of"),
        ("work names nothing", dict(work=[{"id": "w1", "anchor": "a", "change": "c",
                                           "accept": "t"}]), "senior", "discharges no finding"),
        ("both buckets", dict(work=[{"id": "f2", "anchor": "a", "change": "c", "accept": "t"},
                                    {"id": "f4", "anchor": "a", "change": "c", "accept": "t"}]),
         "senior", "ALSO disposed"),
        ("escalation without its question", dict(disposed=[
            {"id": "f1", "status": "escalated", "reason": ""},
            {"id": "f2", "status": "false-positive", "reason": "r"},
            {"id": "f3", "status": "superseded"}]), "senior", "escalated needs a one-line `reason`"),
        ("closure without its trace", dict(disposed=[
            {"id": "f1", "status": "escalated", "reason": "A or B?"},
            {"id": "f2", "status": "false-positive"},
            {"id": "f3", "status": "superseded"}]), "senior", "false-positive needs a one-line `reason`"),
        ("terminal already", dict(disposed=[
            {"id": "done", "status": "superseded", "reason": "r"}]), "senior", "not an actionable"),
        ("accepted risk is not a disposition", dict(disposed=[
            {"id": "f1", "status": "escalated", "reason": "A or B?"},
            {"id": "f2", "status": "accepted-risk", "reason": "intentional"},
            {"id": "f3", "status": "duplicate", "duplicate_of": "f2"}]), "senior",
         "'accepted-risk' is not a disposition"),
        ("wontfix is not a disposition", dict(disposed=[
            {"id": "f1", "status": "escalated", "reason": "A or B?"},
            {"id": "f2", "status": "false-positive", "reason": "r"},
            {"id": "f3", "status": "wontfix", "reason": "later"}]), "senior",
         "'wontfix' is not a disposition"),
        ("premise naming no ASM", dict(disposed=[
            {"id": "f1", "status": "escalated", "reason": "A or B?"},
            {"id": "f2", "status": "premise", "reason": "the store is trusted"},
            {"id": "f3", "status": "duplicate", "duplicate_of": "f2"}]), "senior",
         "premise names no ASM id"),
    ]
    for name, over, tier, needle in cases:
        with tempfile.TemporaryDirectory() as td:
            _ledger(td, ROWS)
            _assert_refused(td, _dispose(td, _package(td, **over), tier=tier), needle)
            assert not os.path.exists(os.path.join(td, "progress.jsonl")), name + ": journal written"
    print("  dispose: %d refusal cases, each wrote nothing  OK" % len(cases))


def test_dispose_refuses_a_second_apply_of_one_attempt() -> None:
    with tempfile.TemporaryDirectory() as td:
        _ledger(td, ROWS)
        pkg = _package(td)
        assert _dispose(td, pkg).returncode == 0
        # Re-open the findings so the package would validate again; only the
        # journal's memory of the attempt can refuse it now.
        _ledger(td, ROWS)
        _assert_refused(td, _dispose(td, pkg), "already has an `evaluate` event")
        assert _dispose(td, pkg, attempt="att-2").returncode == 0, "a NEW attempt must apply"
        print("  dispose: same attempt refused twice, new attempt applies  OK")


def test_locate_anchors_by_content() -> None:
    src = ["def f(x):", "    if x is None:", "        return default_value", "    return x",
           "    return x"]
    found = locate("12: if x is None:\n13:     return default_value", src)
    assert found["state"] == "found" and found["lines"] == [2], found
    assert locate("L4 | return x  # dup", src)["state"] == "absent"
    assert locate("    return x", src)["state"] == "ambiguous"
    assert locate("gone_function(arg)\n...\nreturn default_value", src)["state"] == "partial"
    assert locate("totally_gone(1, 2, 3)", src)["state"] == "absent"
    assert locate(None, src)["state"] == "no-anchor"
    print("  prepare: found / ambiguous / partial / absent / no-anchor  OK")


def _git_repo(td: str, files: dict) -> None:
    for rel, body in files.items():
        os.makedirs(os.path.join(td, os.path.dirname(rel)), exist_ok=True)
        open(os.path.join(td, rel), "w", encoding="utf-8").write(textwrap.dedent(body))
    for cmd in (["git", "init", "-q"], ["git", "add", "-A"]):
        subprocess.run(cmd, cwd=td, check=True, capture_output=True)


def test_usage_map_counts_only_bound_uses() -> None:
    with tempfile.TemporaryDirectory() as td:
        _git_repo(td, {
            FILE: "class Scope:\n    pass\n",
            # Positive: binds Scope from package `x`, constructs and subclasses it.
            "components/y/src/y/user.py": """
                from x.mod import Scope
                class Wider(Scope):
                    pass
                s = Scope()
            """,
            # Negative: same name, other package — Starlette's Scope in real life.
            "components/z/src/z/other.py": """
                from starlette.types import Scope
                def f(scope: Scope) -> Scope:
                    return Scope()
            """,
            # Negative: a mention in prose is not a use.
            "components/w/src/w/doc.py": '"""Explains how Scope is built."""\n',
            "components/y/tests/test_user.py": "from x.mod import Scope\nScope()\n",
        })
        ledger = _ledger(td, [])
        p = _py("prepare.py", "--ledger", ledger, "--file", FILE, cwd=td)
        assert p.returncode == 0, p.stdout + p.stderr
        line = [ln for ln in p.stdout.splitlines() if ln.startswith("- Scope:")]
        assert line, p.stdout
        assert "import=1 construct=1 subclass=1 ref=0 | tests=2" in line[0], line[0]
        assert "components/z/" not in p.stdout and "components/w/" not in p.stdout
        print("  prepare: usage map = bound uses only (other package + prose excluded)  OK")


STUB_GATE = r'''
import json, os, sys
sys.path.insert(0, %(scripts)r)
import bazel_gate
cmd = sys.argv[1]; tree = sys.argv[sys.argv.index("--tree") + 1]
store = sys.argv[sys.argv.index("--store") + 1]
os.makedirs(store, exist_ok=True)
calls = os.path.join(store, "calls.log")
open(calls, "a").write("%%s %%s\n" %% (cmd, tree))
if cmd == "baseline":
    open(bazel_gate._store_path(store, tree, "baseline"), "w").write("{}")
    print(json.dumps({"failing": 0, "total": 3}))
else:
    print(json.dumps(json.loads(os.environ["STUB_VERDICT"])))
    sys.exit(0 if json.loads(os.environ["STUB_VERDICT"])["verdict"] == "ok" else 1)
'''


def _check(td: str, phase: str, *extra: str, verdict: dict | None = None, tier: str = "local"):
    gate = os.path.join(td, "stub_gate.py")
    open(gate, "w", encoding="utf-8").write(STUB_GATE % {"scripts": SCRIPTS})
    env = dict(os.environ, STUB_VERDICT=json.dumps(verdict or {"verdict": "ok"}))
    base = ["--file", FILE, "--tier", tier, "--store", os.path.join(td, "gates"),
            "--gate-script", gate]
    if phase == "post":
        base += ["--log", os.path.join(td, "progress"), "--attempt", "att-1", "--run", "r",
                 "--work-dir", os.path.join(td, "work"), "--applied", "2", "--not-applied", "0",
                 "--tests-added", "1", "--prescan-script", os.path.join(SCRIPTS, "prescan.py")]
    return _py("check.py", phase, *base, *extra, cwd=td, env=env)


def test_check_pre_baselines_only_when_missing() -> None:
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "components/x/src/x"))
        first = _check(td, "pre")
        second = _check(td, "pre")
        assert first.returncode == 0 and second.returncode == 0, first.stdout + first.stderr
        assert json.loads(first.stdout)["trees"][0]["baseline"] == "captured"
        assert json.loads(second.stdout)["trees"][0]["baseline"] == "exists"
        calls = open(os.path.join(td, "gates", "calls.log")).read().split("\n")
        assert [c for c in calls if c] == ["baseline //components/x/..."], calls
        print("  check pre: baseline captured once, then reused  OK")


def test_check_post_blames_only_new_failures() -> None:
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "components/x/src/x"))
        open(os.path.join(td, FILE), "w").write("x = 1\n")
        ok = _check(td, "post", verdict={"verdict": "ok", "new_failures": [], "total": 3})
        assert ok.returncode == 0, ok.stdout + ok.stderr
        out = json.loads(ok.stdout)
        assert out["gate_verdict"] == "ok" and out["terminal_event"] is None
        events = [e["event"] for e in read_jsonl(os.path.join(td, "progress.jsonl"))]
        assert events == ["fix", "gate"], events

    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "components/x/src/x"))
        open(os.path.join(td, FILE), "w").write("x = 1\n")
        bad = _check(td, "post", verdict={"verdict": "new-failures",
                                          "new_failures": ["//components/x:t"], "total": 3})
        out = json.loads(bad.stdout)
        assert out["gate_verdict"] == "new-failures", out
        ev = read_jsonl(os.path.join(td, "progress.jsonl"))
        assert [e["event"] for e in ev] == ["fix", "gate", "gate-failed"], ev
        assert "//components/x:t" in ev[-1]["note"]
        assert ev[0]["counts"] == {"applied": 2, "not_applied": 0, "tests_added": 1}
    print("  check post: ok -> fix+gate; new-failures -> +gate-failed naming the target  OK")


def test_check_post_pyright_without_summary_is_infra_not_clean() -> None:
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "components/x/src/x"))
        open(os.path.join(td, FILE), "w").write("x = 1\n")
        oom = os.path.join(td, "oom.sh")
        open(oom, "w").write("#!/bin/sh\necho 'FATAL ERROR: heap limit'\nexit 250\n")
        os.chmod(oom, 0o755)
        p = _check(td, "post", "--pyright-cmd", oom, tier="wide",
                   verdict={"verdict": "ok", "new_failures": [], "total": 3})
        out = json.loads(p.stdout)
        assert out["gate_verdict"] == "infra", out
        assert out["gates"][0]["gate"] == "pyright" and out["gates"][0]["verdict"] == "infra"

        clean = os.path.join(td, "clean.sh")
        open(clean, "w").write("#!/bin/sh\necho '0 errors, 2 warnings, 0 informations'\n")
        os.chmod(clean, 0o755)
        os.remove(os.path.join(td, "progress.jsonl"))
        p = _check(td, "post", "--pyright-cmd", clean, tier="wide",
                   verdict={"verdict": "ok", "new_failures": [], "total": 3})
        assert json.loads(p.stdout)["gate_verdict"] == "ok", p.stdout
    print("  check post: pyright OOM -> infra; a real summary -> ok (positive control)  OK")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print("%d tests passed" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
