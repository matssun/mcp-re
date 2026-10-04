"""size_debt.py — size growth during a remediation run is recorded, not blocking.

Owner direction (2026-10-04): a security fix is not held back because the file or the
function it lands in crosses a size threshold. The fix lands, the growth is written to a
register, and whether the file needs a design review or a refactor is a separate project
after the run. The repository gates stay strict — `scripts/module_size_gate.py` and the
clippy ratchet still fail in CI and in `local_gate.sh` — so the register is the list that
must be settled (refactored, or growth-authorized by the owner) before the remediation
branch is integrated.

What counts as size, and therefore soft:
  module size   a registered file grew past its baseline; a file newly crossed the threshold
  function size `clippy::too_many_lines` above its per-crate baseline
Everything else either gate reports — a disposition transition, an allow-discipline
problem, `excessive_nesting`, any other lint — stays a hard failure.

  classify(gate, output) -> (soft, rows)   soft is True only when EVERY reported problem is
                                           size; rows describe each one
  record(work_dir, file, rows)             check.py: pending rows for this writer
  settle(work_dir, file, commit, register) finalize: a committed writer's rows join the
                                           tracked register with the commit that grew it
  drop(work_dir, file)                     finalize: a reverted writer's rows are discarded
"""
from __future__ import annotations

import hashlib
import json
import os
import re

REGISTER = "docs/security/remediation-size-debt.jsonl"

_PROBLEM = re.compile(r"^\s+- (.+)$", re.M)
_GREW = re.compile(r"^(\S+): grew from (\d+) to (\d+) production lines")
_NEW = re.compile(r"^(\S+): (\d+) production lines exceeds (\d+) and is not in the debt registry")
_FN = re.compile(r"^(\S+): (\d+) `clippy::too_many_lines` in production code, baseline (\d+)")


def classify(gate: str, output: str) -> tuple[bool, list[dict]]:
    """`gate` names the reporter, for the caller's log; both gates print `  - <problem>`."""
    del gate
    problems = _PROBLEM.findall(output)
    rows: list[dict] = []
    for p in problems:
        m = _GREW.match(p)
        if m:
            rows.append({"metric": "module-size", "path": m.group(1),
                         "baseline": int(m.group(2)), "measured": int(m.group(3))})
            continue
        m = _NEW.match(p)
        if m:
            rows.append({"metric": "module-size", "path": m.group(1),
                         "baseline": int(m.group(3)), "measured": int(m.group(2))})
            continue
        m = _FN.match(p)
        if m:
            rows.append({"metric": "too_many_lines", "path": m.group(1),
                         "baseline": int(m.group(3)), "measured": int(m.group(2))})
            continue
        return False, []
    return bool(rows), rows


def _pending(work_dir: str, file: str) -> str:
    d = os.path.join(work_dir, "size-debt")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, hashlib.sha1(file.encode()).hexdigest()[:12] + ".json")


def record(work_dir: str, file: str, rows: list[dict]) -> None:
    with open(_pending(work_dir, file), "w", encoding="utf-8") as fh:
        json.dump({"file": file, "rows": rows}, fh)


def drop(work_dir: str, file: str) -> None:
    p = _pending(work_dir, file)
    if os.path.exists(p):
        os.remove(p)


def settle(work_dir: str, file: str, commit: str, register: str = REGISTER,
           findings: list[str] | None = None) -> int:
    p = _pending(work_dir, file)
    if not os.path.exists(p):
        return 0
    rows = json.load(open(p, encoding="utf-8")).get("rows", [])
    os.makedirs(os.path.dirname(register) or ".", exist_ok=True)
    with open(register, "a", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(dict(r, remediated_file=file, commit=commit,
                                     findings=findings or []), sort_keys=True) + "\n")
    os.remove(p)
    return len(rows)


def register_rows(rows: list[dict], commit: str, register: str = REGISTER) -> int:
    """Rows the batch gate measured that no writer recorded (a hand commit): register them
    under the batch, keyed so a re-run adds nothing twice."""
    have = set()
    if os.path.exists(register):
        for line in open(register, encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                have.add((r["metric"], r["path"], r["measured"]))
    new = [r for r in rows if (r["metric"], r["path"], r["measured"]) not in have]
    with open(register, "a", encoding="utf-8") as fh:
        for r in new:
            fh.write(json.dumps(dict(r, remediated_file="", commit=commit, findings=[]),
                                sort_keys=True) + "\n")
    return len(new)
