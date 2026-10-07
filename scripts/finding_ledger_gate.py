#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every finding-ledger row carries a valid disposition, and the open count is what it says.

`docs/security/finding-ledger.jsonl` is the record the security campaign's "zero open"
claims are read from. A count that leaves a status out is a count that can be emptied by
choosing that status: 187 rows once sat at `accepted-risk` — most of them set by an
adjudicating agent, none of them counted — while eight of them described defects still
present in the tree. So the taxonomy is closed, and the gate holds it on the merge path:

* `accepted-risk` and `wontfix` are refused. A real security defect is fixed, shown not to
  be a defect, or left open.
* `premise` must name an assumption `verification/policy/assumptions.toml` registers.
* `constraint` must name the owner ruling that accepted it (`owner_ruling = "Ruling N"`).
* A status outside the taxonomy is refused.

Everything not validly closed is counted open; the OK line states that count. The rules live
in the remediation lane's `ledger.py`, which `set`, `dispose.py` and this gate all call, so
the writer and the merge path cannot disagree about what a disposition is.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, ".claude", "skills", "security-remediate", "scripts"))
import ledger  # noqa: E402

LEDGER = os.path.join(ROOT, "docs", "security", "finding-ledger.jsonl")
ASSUMPTIONS = os.path.join(ROOT, ledger.ASSUMPTIONS_TOML)


def problems(rows: list[dict], assumptions: set | None) -> list[str]:
    if not rows:
        return ["the ledger holds no findings — an empty ledger checks nothing"]
    return [f"{r.get('id')}: {p}" for r in rows if (p := ledger.closure_problem(r, assumptions))]


def _read(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def selftest() -> int:
    registered = {"ASM-0001"}
    green = [
        {"id": "a", "status": "fixed"},
        {"id": "b", "status": "open"},
        {"id": "c", "status": "premise", "premise": "ASM-0001"},
        {"id": "d", "status": "constraint", "owner_ruling": "Ruling 22.1"},
        {"id": "e", "status": "false-positive"},
    ]
    if problems(green, registered):
        print(f"finding-ledger gate selftest: FAIL — the green shape was refused: "
              f"{problems(green, registered)}")
        return 1
    if sum(ledger.is_open(r, registered) for r in green) != 1:
        print("finding-ledger gate selftest: FAIL — the green shape does not count one open row")
        return 1
    cases = {
        "an accepted-risk row": {"id": "x", "status": "accepted-risk"},
        "a wontfix row": {"id": "x", "status": "wontfix"},
        "a status outside the taxonomy": {"id": "x", "status": "parked"},
        "a premise naming no ASM": {"id": "x", "status": "premise"},
        "a premise naming an unregistered ASM": {"id": "x", "status": "premise",
                                                 "premise": "ASM-0999"},
        "a constraint naming no owner ruling": {"id": "x", "status": "constraint",
                                                "ruling_id": "agent-cluster-7"},
    }
    for name, row in cases.items():
        if not problems(green + [row], registered):
            print(f"finding-ledger gate selftest: FAIL — {name} was not refused")
            return 1
        if not ledger.is_open(row, registered):
            print(f"finding-ledger gate selftest: FAIL — {name} is not counted open")
            return 1
    if not problems([], registered):
        print("finding-ledger gate selftest: FAIL — an empty ledger was not refused")
        return 1
    # The file path the gate reads, end to end: a written ledger with one refused row.
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ledger.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for r in green + [cases["an accepted-risk row"]]:
                fh.write(json.dumps(r) + "\n")
        if not problems(_read(path), registered):
            print("finding-ledger gate selftest: FAIL — a written accepted-risk row was not refused")
            return 1
    print(f"finding-ledger gate selftest: PASS ({len(cases) + 3} cases)")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    rows = _read(LEDGER)
    assumptions = ledger.registered_assumptions(ASSUMPTIONS)
    if assumptions is None:
        print(f"finding-ledger gate: FAIL — {ledger.ASSUMPTIONS_TOML} is missing, so no premise "
              f"can be checked")
        return 1
    found = problems(rows, assumptions)
    if found:
        print(f"finding-ledger gate: FAIL — {len(found)} row(s) carry no valid disposition")
        for problem in found:
            print(f"  - {problem}")
        return 1
    n_open = sum(ledger.is_open(r, assumptions) for r in rows)
    print(f"finding-ledger gate: OK — {len(rows)} row(s), each validly disposed; {n_open} open")
    return 0


if __name__ == "__main__":
    sys.exit(main())
