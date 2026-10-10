"""The ledger's disposition taxonomy is closed, and what it cannot close counts as open.

`accepted-risk` once held 187 rows that no count read. These tests pin the four ways the
ledger CLI keeps that from recurring — `set` refuses a non-disposition, `ingest` admits a
new finding only as open or informational, `check` fails on any row the taxonomy cannot
close, and `stats` counts every such row as open — and that the funnel skill's copy of
`ledger.py` is the same file, since an unfixed copy is the same hole behind another door.

Run:  python3 .claude/skills/security-remediate/tests/test_ledger_dispositions.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
LEDGER_PY = os.path.join(SCRIPTS, "ledger.py")
FUNNEL_LEDGER_PY = os.path.abspath(os.path.join(
    os.path.dirname(HERE), "..", "security-audit-funnel", "scripts", "ledger.py"))

ASSUMPTIONS = 'schema_version = 1\n\n[[assumption]]\nid = "ASM-0001"\n'


def _row(fid: str, status: str, **extra) -> dict:
    return dict({"id": fid, "file": "m.rs", "path": "c/m.rs", "severity": "medium",
                 "category": "c", "title": "t " + fid, "status": status, "verified": {},
                 "refs": {}, "notes": "", "first_seen": "r", "last_seen": "r", "rounds": ["r"]},
                **extra)


def _setup(td: str, rows: list[dict]) -> tuple[str, str]:
    led = os.path.join(td, "ledger.jsonl")
    with open(led, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    asm = os.path.join(td, "assumptions.toml")
    with open(asm, "w", encoding="utf-8") as fh:
        fh.write(ASSUMPTIONS)
    return led, asm


def _cli(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, LEDGER_PY, *argv], capture_output=True, text=True)


def test_set_refuses_a_non_disposition() -> None:
    with tempfile.TemporaryDirectory() as td:
        led, asm = _setup(td, [_row("a", "open")])
        before = open(led).read()
        for status in ("accepted-risk", "wontfix", "parked"):
            p = _cli("set", led, "--id", "a", "--status", status, "--assumptions", asm)
            assert p.returncode != 0, status
            assert "refused" in p.stderr, p.stderr
            assert open(led).read() == before, status + ": the ledger was written"
    print("  set: accepted-risk / wontfix / unknown refused, nothing written  OK")


def test_set_premise_and_constraint_name_their_authority() -> None:
    with tempfile.TemporaryDirectory() as td:
        led, asm = _setup(td, [_row("a", "open")])
        assert _cli("set", led, "--id", "a", "--status", "premise",
                    "--assumptions", asm).returncode != 0, "premise with no ASM was accepted"
        assert _cli("set", led, "--id", "a", "--status", "premise", "--premise", "ASM-0999",
                    "--assumptions", asm).returncode != 0, "an unregistered ASM was accepted"
        assert _cli("set", led, "--id", "a", "--status", "constraint", "--ruling", "agent-7",
                    "--assumptions", asm).returncode != 0, "an agent ruling id closed a constraint"
        p = _cli("set", led, "--id", "a", "--status", "premise", "--premise", "ASM-0001",
                 "--assumptions", asm)
        assert p.returncode == 0, p.stderr
        p = _cli("set", led, "--id", "a", "--status", "constraint", "--owner-ruling",
                 "Ruling 22.1", "--assumptions", asm)
        assert p.returncode == 0, p.stderr
    print("  set: premise needs a registered ASM, constraint an owner ruling  OK")


def test_ingest_admits_only_open_or_informational() -> None:
    with tempfile.TemporaryDirectory() as td:
        led, _ = _setup(td, [_row("a", "open")])
        prerun = os.path.join(td, "prerun.json")
        json.dump({"findings": [{"file": "x.rs", "title": "new one", "severity": "high"}]},
                  open(prerun, "w"))
        p = _cli("ingest", led, prerun, "--round", "r2", "--status", "accepted-risk")
        assert p.returncode != 0 and "refused" in p.stderr, p.stderr
        assert _cli("ingest", led, prerun, "--round", "r2").returncode == 0
    print("  ingest: --status accepted-risk refused  OK")


def test_check_fails_and_stats_count_open() -> None:
    rows = [_row("a", "fixed"), _row("b", "open"), _row("c", "accepted-risk"),
            _row("d", "premise", premise="ASM-0999"), _row("e", "constraint"),
            _row("f", "premise", premise="ASM-0001")]
    with tempfile.TemporaryDirectory() as td:
        led, asm = _setup(td, rows)
        p = _cli("check", led, "--assumptions", asm)
        assert p.returncode == 1, p.stdout
        for fid in ("c:", "d:", "e:"):
            assert fid in p.stdout, (fid, p.stdout)
        stats = json.loads(_cli("stats", led, "--assumptions", asm).stdout)
        assert stats["open"] == 4, stats
        assert stats["not_validly_closed"] == ["c", "d", "e"], stats
        led2, asm2 = _setup(td, [r for r in rows if r["id"] in ("a", "b", "f")])
        p = _cli("check", led2, "--assumptions", asm2)
        assert p.returncode == 0 and "1 open" in p.stdout, p.stdout
    print("  check: fails on the three invalid rows; stats counts them open (4)  OK")


def test_funnel_copy_is_the_same_file() -> None:
    assert open(LEDGER_PY).read() == open(FUNNEL_LEDGER_PY).read(), \
        "security-audit-funnel/scripts/ledger.py diverged from the remediation copy"
    print("  funnel ledger.py is identical  OK")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print("%d tests passed" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
