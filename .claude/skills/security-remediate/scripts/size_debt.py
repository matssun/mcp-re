"""size_debt.py — size growth during a remediation run is recorded, not blocking.

Owner direction (2026-10-04): a security fix is not held back because the file or the
function it lands in crosses a size threshold. The fix lands, the growth is written to a
register, and whether the file needs a design review or a refactor is a separate project
after the run. The repository gates stay strict — `scripts/module_size_gate.py` and the
clippy ratchet still fail in CI and in `local_gate.sh` — so the register is the list that
must be settled (refactored, or growth-authorized by the owner) before the remediation
branch is integrated.

Owner correction (2026-10-04): the R11/R12 campaign order is (1) finish the security
remediation, (2) record every oversized or growing file as structural debt, (3) after the
campaign closes, run a separate decomposition campaign over that record. So the register is
the machine-readable input to that run, and it records every oversized file a writer
ENCOUNTERS (touches), grown or not, with:

  path, metric        the file (module-size) or crate (too_many_lines; `site` names the fn)
  before, after,      production lines before the first remediation commit that touched it,
  delta               after the latest, and the difference
  origin              `pre-existing-oversized` (over the threshold before this campaign
                      touched it — in config/module-size-debt.toml or not) or
                      `new-oversized` (crossed the threshold through this remediation)
  registry            the config/module-size-debt.toml entry (status, baseline) or null
  findings, commits   what caused each change

Every added line must still belong to the accepted work package; review enforces that
(`unordered_changes`), not this register.

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


def _registry_entry(path: str) -> dict | None:
    try:
        import tomllib
        doc = tomllib.load(open("config/module-size-debt.toml", "rb"))
    except (OSError, ValueError):
        return None
    for e in doc.get("debt", []):
        if e.get("path") == path:
            return {"status": e.get("status"), "baseline": e.get("baseline_prod_loc")}
    return None


def _shape(r: dict) -> dict:
    """The decomposition-run row: before/after/delta and origin, from the gate's numbers."""
    before = r.get("before", r.get("baseline"))
    after = r.get("after", r.get("measured"))
    out = {"metric": r["metric"], "path": r["path"], "before": before, "after": after}
    if r.get("site"):
        out["site"] = r["site"]
    if r["metric"] == "module-size":
        reg = _registry_entry(r["path"])
        out["registry"] = reg
        out["origin"] = ("pre-existing-oversized" if reg or (before or 0) > THRESHOLD
                         else "new-oversized")
    else:
        out["registry"] = None
        out["origin"] = "pre-existing-oversized" if (before or 0) > 0 else "new-oversized"
    return out


THRESHOLD = 200


def _merge(register: str, rows: list[dict], commit: str, findings: list[str]) -> int:
    """One register row per (metric, path): the size before the first remediation commit
    that touched it, the latest size, the delta, its origin, and every commit and finding
    that changed it. Returns how many rows changed."""
    book: dict[tuple[str, str], dict] = {}
    if os.path.exists(register):
        for line in open(register, encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                book[(r["metric"], r["path"])] = r
    changed = 0
    for raw in rows:
        r = _shape(raw)
        key = (r["metric"], r["path"])
        cur = book.get(key)
        if cur is None:
            book[key] = dict(r, delta=(r["after"] or 0) - (r["before"] or 0),
                             commits=[commit], findings=sorted(set(findings)))
            changed += 1
        elif r["after"] != cur["after"]:
            cur["after"] = r["after"]
            cur["delta"] = (cur["after"] or 0) - (cur["before"] or 0)
            cur["commits"] = cur["commits"] + ([commit] if commit not in cur["commits"] else [])
            cur["findings"] = sorted(set(cur["findings"]) | set(findings))
            cur["registry"] = r["registry"]
            changed += 1
    os.makedirs(os.path.dirname(register) or ".", exist_ok=True)
    with open(register, "w", encoding="utf-8") as fh:
        for key in sorted(book):
            fh.write(json.dumps(book[key], sort_keys=True) + "\n")
    return changed


def settle(work_dir: str, file: str, commit: str, register: str = REGISTER,
           findings: list[str] | None = None) -> int:
    p = _pending(work_dir, file)
    if not os.path.exists(p):
        return 0
    rows = json.load(open(p, encoding="utf-8")).get("rows", [])
    os.remove(p)
    return _merge(register, rows, commit, findings or [])


def register_rows(rows: list[dict], commit: str, register: str = REGISTER) -> int:
    """Rows the batch gate measured: merged under the commit, so a re-run or a growth some
    writer already registered changes nothing."""
    return _merge(register, rows, commit, [])


def encountered(touched: list[str], ref: str = "HEAD") -> list[dict]:
    """Every touched .rs file over the threshold now, with its size at `ref` — grown or not.
    The decomposition run needs the files the campaign worked in, not only the ones it grew."""
    import subprocess
    import sys
    sys.path.insert(0, "scripts")
    from module_size_gate import production_lines  # noqa: PLC0415
    rows = []
    for path in touched:
        if not path.endswith(".rs") or not os.path.isfile(path):
            continue
        # The gate's own population: tests, benches, examples and build scripts are not
        # production modules (module_size_gate.rust_sources).
        if any(p in {"tests", "benches", "examples"} for p in path.split("/")) \
                or path.endswith("build.rs"):
            continue
        after = production_lines(open(path, encoding="utf-8", errors="replace").read())
        if after <= THRESHOLD:
            continue
        old = subprocess.run(["git", "show", "%s:%s" % (ref, path)], capture_output=True,
                             text=True)
        before = production_lines(old.stdout) if old.returncode == 0 else 0
        rows.append({"metric": "module-size", "path": path, "before": before, "after": after})
    return rows


def attributable(rows: list[dict], touched: list[str]) -> list[dict]:
    """The rows this writer caused. The module-size gate measures the whole tree, so a file
    grown by an earlier, already-registered change is reported to every later writer; only
    a file the writer touched is the writer's growth. A function-size row is keyed by crate,
    so it is the writer's when the writer touched that crate."""
    crates = {t.split("/", 1)[0] for t in touched}
    return [r for r in rows if r["path"] in touched
            or (r["metric"] == "too_many_lines" and r["path"] in crates)]
