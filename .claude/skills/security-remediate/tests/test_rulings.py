"""Regression: the ruling queue counts DECISIONS, not findings or files.

  1. escalations sharing a `ruling_id` across different files are ONE decision
  2. an `owner-signature:` ruling id is a ratification, counted apart from decisions
  3. an escalation with no ruling id still falls back to its file (positive control
     for the old grouping)

Run:  python3 .claude/skills/security-remediate/tests/test_rulings.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "rulings.py")


def _row(i: str, path: str, sev: str, ruling: str | None) -> dict:
    r = {"id": i, "path": path, "severity": sev, "status": "escalated", "title": "t" + i,
         "notes": "n"}
    if ruling:
        r["ruling_id"] = ruling
    return r


def test_queue_groups_by_ruling_id_and_separates_ratifications() -> None:
    rows = [
        _row("a1", "x/one.rs", "high", "seal-vs-seam"),
        _row("a2", "y/two.rs", "medium", "seal-vs-seam"),
        _row("b1", "x/one.rs", "low", "owner-signature:asm-x"),
        _row("b2", "z/three.rs", "low", "owner-signature:asm-x"),
        _row("c1", "w/four.rs", "medium", None),
        _row("c2", "w/four.rs", "low", None),
        dict(_row("d1", "x/one.rs", "high", "seal-vs-seam"), status="open"),
    ]
    with tempfile.TemporaryDirectory() as td:
        ledger = os.path.join(td, "l.jsonl")
        out = os.path.join(td, "q.md")
        with open(ledger, "w") as fh:
            fh.write("\n".join(json.dumps(r) for r in rows) + "\n")
        p = subprocess.run([sys.executable, SCRIPT, "--ledger", ledger, "--out", out],
                           capture_output=True, text=True, check=True)
        text = open(out).read()
    assert "6 escalations -> 3 decisions + 1 ratifications over 4 files" in p.stdout, p.stdout
    assert text.count("`seal-vs-seam` — 2 finding(s)") == 1, text
    assert "## Ratifications" in text and "`owner-signature:asm-x` — 2 finding(s)" in text, text
    assert "### `w/four.rs`" in text, text
    assert "d1" not in text, text
    print("  rulings: one decision per ruling id across files; ratifications apart; file fallback  OK")


if __name__ == "__main__":
    test_queue_groups_by_ruling_id_and_separates_ratifications()
    print("1/1 passed")
