#!/usr/bin/env python3
"""next_file.py — worklist selector for the security-remediate loop.

Reads the file-keyed finding ledger and returns the next file to remediate,
leaf-first (dependencies before dependents, so a fixed dependency is already
clean when its dependents are reached). Pure stdlib — it is analysis tooling,
not production code.

Output (JSON) for the outer driver:
  {
    "exhausted": bool,             # no actionable (open/regression) findings left
    "file": "<path>" | null,       # the file to work next
    "related": ["<path>", ...],    # reverse-dep set to re-scan with the file
    "findings": [ {finding...} ],  # all open/regression findings on that file
    "blocked": {"escalated": n, "exhausted": n},  # findings needing a human
    "remaining_open_files": n
  }

`exhausted: true` with blocked > 0 means: nothing the loop can auto-progress;
only human-gated findings remain.

Ledger: one JSON object per line (see ledger.py for the status taxonomy). Required
fields per record: id, path (or file), severity, status, title, category.

Deps (optional, --deps): {"<file>": ["<file it imports>", ...], ...}. When given,
files are ordered topologically (imports first). The reverse-dep "related" set is
derived from it. Without it, ordering falls back to severity-then-path and
`related` is empty (the inner loop then re-scans only the file itself).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Statuses that still require work (block a file from being green).
# `needs-senior-eval` is what a CHEAP-tier evaluator sets when it wants to CLOSE a
# finding (false-positive / accepted-risk). A cheap model may act, but may not
# close: closing is terminal and its failure mode is invisible. The status keeps
# the finding actionable and promotes its whole file to the senior tier, so the
# promotion happens at most once and the loop cannot ping-pong.
from file_findings import ACTIONABLE  # noqa: E402
# Statuses that block a file but cannot be auto-progressed (need a human).
BLOCKED = {"escalated", "exhausted"}

_SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Categories whose findings are decidable from the file's own text: a declaration
# has the wrong shape, a symbol is unreferenced, a name breaks a convention. They
# need no call-graph reasoning, no exploitability judgment, no crypto argument.
# Everything NOT in this set implies a claim about behaviour, and goes senior.
_MECHANICAL = {"conformance", "dead-code", "typed-surface", "documentation", "naming"}


def _eval_tier(findings: list[dict]) -> tuple[str, str]:
    """Which evaluator tier this file needs, and why.

    Tier by the blast radius of being WRONG, not by how hard the task looks. A
    cheap evaluator is admitted only where every finding is mechanical and none is
    severe — and even then it may not close one (see ACTIONABLE).
    """
    if any(str(f.get("status", "")).lower() == "needs-senior-eval" for f in findings):
        return "senior", "a cheap evaluator asked to close a finding here"
    worst = max((_SEV_WEIGHT.get(str(f.get("severity", "")).lower(), 0) for f in findings), default=0)
    if worst >= 3:
        return "senior", "carries a critical or high"
    off = sorted({str(f.get("category", "?")).lower() for f in findings} - _MECHANICAL)
    if off:
        return "senior", "behavioural categories present: " + ", ".join(off[:4])
    return "cheap", "all findings mechanical, worst severity medium or below"


def _load_ledger(path: str) -> list[dict]:
    records: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def _latest_by_fingerprint(records: list[dict]) -> list[dict]:
    """A ledger is append-only; keep the last record per fingerprint."""
    latest: dict[str, dict] = {}
    for r in records:
        fp = r.get("id") or r.get("fingerprint") or f"{r.get('file')}|{r.get('title')}"
        latest[fp] = r
    return list(latest.values())


def _topo_order(files: list[str], deps: dict[str, list[str]], priority=None) -> list[str]:
    """Return files with dependencies before dependents (leaf-first).

    Edge file -> dep means `file` imports `dep`; deps must come first. Kahn's
    algorithm over the reversed graph. Cycles are broken deterministically by
    appending any remaining files in sorted order (a cycle has no valid leaf).

    Topology is a CONSTRAINT, not the objective: among the files that are ready
    at any step, `priority` picks which to emit. Without it the ready set is
    drained alphabetically, which buries a critical behind every migration whose
    name happens to sort earlier.
    """
    key = priority or (lambda f: (f,))
    fileset = set(files)
    # imports restricted to in-scope files
    imports = {f: [d for d in deps.get(f, []) if d in fileset] for f in files}
    indeg = {f: 0 for f in files}
    dependents: dict[str, list[str]] = defaultdict(list)
    for f, ds in imports.items():
        for d in ds:
            dependents[d].append(f)
            indeg[f] += 1  # f depends on d → f waits for d
    ready = sorted([f for f in files if indeg[f] == 0], key=key)
    order: list[str] = []
    while ready:
        f = ready.pop(0)
        order.append(f)
        for dep in sorted(dependents[f]):
            indeg[dep] -= 1
            if indeg[dep] == 0:
                ready.append(dep)
        ready.sort(key=key)
    if len(order) < len(files):  # cycle remainder
        order.extend(sorted(f for f in files if f not in set(order)))
    return order


def _max_sev(findings: list[dict]) -> int:
    return max((_SEV_WEIGHT.get(str(f.get("severity", "")).lower(), 0) for f in findings), default=0)


def _campaign_order(path: str | None) -> list[str]:
    """Paths in campaign order: a JSON list of paths or of `{"file": path}` rows."""
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return [row["file"] if isinstance(row, dict) else row for row in doc]


def select(ledger_path: str, deps_path: str | None, top: int = 1,
           rounds: set[str] | None = None, order_path: str | None = None) -> dict:
    records = _latest_by_fingerprint(_load_ledger(ledger_path))
    if rounds:
        # Only findings a live round reported; a row last seen in a superseded
        # round describes a tree that no longer exists.
        records = [r for r in records if rounds & set(r.get("rounds") or [r.get("last_seen")])]
    by_file_actionable: dict[str, list[dict]] = defaultdict(list)
    blocked = {"escalated": 0, "exhausted": 0}
    for r in records:
        status = str(r.get("status", "open")).lower()
        # Ledger keys findings by basename in `file`; `path` (full relpath) is
        # preferred for the worklist + leaf-first ordering when present.
        r_key = r.get("path") or r.get("file")
        if status in ACTIONABLE:
            by_file_actionable[r_key].append(r)
        elif status in BLOCKED:
            blocked[status] += 1

    deps: dict[str, list[str]] = {}
    rdeps: dict[str, list[str]] = {}
    importers: dict[str, int] = {}
    if deps_path:
        with open(deps_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        # Accept both shapes: the bare {file: [imports]} map, and the richer
        # deps_graph.py output, which also carries the reverse edges and the
        # monorepo-wide importer count that decides which gate a fix must pass.
        if isinstance(doc, dict) and "deps" in doc:
            deps = doc.get("deps", {})
            rdeps = doc.get("rdeps", {})
            importers = doc.get("importers", {})
        else:
            deps = doc

    open_files = list(by_file_actionable.keys())
    if not open_files:
        return {
            "exhausted": True,
            "file": None,
            "related": [],
            "findings": [],
            "blocked": blocked,
            "remaining_open_files": 0,
        }

    def _priority(f: str):
        fs = by_file_actionable.get(f, [])
        return (-_max_sev(fs), -len(fs), f)

    campaign = [f for f in _campaign_order(order_path) if f in by_file_actionable]
    if campaign:
        # An explicit campaign order is the owner's sequencing and outranks the
        # derived one; files it does not list follow in the derived order.
        rest = [f for f in open_files if f not in set(campaign)]
        tail = _topo_order(rest, deps, _priority) if deps else sorted(rest, key=_priority)
        order = campaign + [f for f in tail if f in by_file_actionable]
    elif deps:
        order = [f for f in _topo_order(open_files, deps, _priority) if f in by_file_actionable]
    else:
        # No dep graph: highest max-severity first, then most findings, then path.
        order = sorted(
            open_files,
            key=lambda f: (-_max_sev(by_file_actionable[f]), -len(by_file_actionable[f]), f),
        )

    chosen = order[0]
    # A batch of the next `top` files, so a driver can fan out read-only
    # evaluation ahead of the single writer without re-querying per file. The
    # order is the same one the single-file answer follows.
    batch = []
    for f in order[:max(1, top)]:
        n_i = importers.get(f, 0)
        fs = sorted(by_file_actionable[f],
                    key=lambda r: -_SEV_WEIGHT.get(str(r.get("severity", "")).lower(), 0))
        tier, why = _eval_tier(fs)
        batch.append({
            "file": f,
            "related": sorted(rdeps.get(f, [])) if rdeps else
                       (sorted(x for x, imps in deps.items() if f in imps) if deps else []),
            "findings": fs,
            "n_findings": len(fs),
            "importers": n_i,
            "gate_tier": "local" if n_i == 0 else ("wide" if n_i <= 50 else "platform"),
            "eval_tier": tier,
            "eval_tier_reason": why,
        })
    # related = reverse deps (files that import the chosen file) — the indirect
    # blast radius to re-scan alongside it.
    if rdeps:
        related = sorted(rdeps.get(chosen, []))
    elif deps:
        related = sorted(f for f, imps in deps.items() if chosen in imps)
    else:
        related = []
    # Gate tier. A file nothing imports can be gated locally; a widely imported
    # declaration cannot — CLAUDE.md rule 15: changed-file validation establishes
    # LOCAL correctness only, and says nothing about what binds the shape you edit.
    n_imp = importers.get(chosen, len(related))
    gate_tier = "local" if n_imp == 0 else ("wide" if n_imp <= 50 else "platform")

    return {
        "exhausted": False,
        "file": chosen,
        "related": related,
        "findings": sorted(
            by_file_actionable[chosen],
            key=lambda r: -_SEV_WEIGHT.get(str(r.get("severity", "")).lower(), 0),
        ),
        "blocked": blocked,
        "remaining_open_files": len(open_files),
        "importers": n_imp,
        "gate_tier": gate_tier,
        "eval_tier": batch[0]["eval_tier"] if batch else "senior",
        "eval_tier_reason": batch[0]["eval_tier_reason"] if batch else "",
        "batch": batch,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Select the next file for the security-remediate loop.")
    ap.add_argument("--ledger", required=True, help="path to finding-ledger.jsonl")
    ap.add_argument("--deps", default=None, help="optional {file: [imported files]} JSON for leaf-first order")
    ap.add_argument("--json", action="store_true", help="emit JSON (default)")
    ap.add_argument("--top", type=int, default=1,
                    help="also return the next N files as `batch`, for fan-out evaluation")
    ap.add_argument("--files-only", action="store_true",
                    help="print just the batch's file paths, one per line")
    ap.add_argument("--rounds", default="",
                    help="comma-separated live rounds (e.g. 2026-09-15@r11,2026-09-22@r12); "
                         "findings seen in none of them are ignored")
    ap.add_argument("--order", default=None,
                    help="JSON campaign order: a list of paths or of {\"file\": path} rows")
    args = ap.parse_args()
    rounds = {r.strip() for r in args.rounds.split(",") if r.strip()} or None
    result = select(args.ledger, args.deps, args.top, rounds, args.order)
    if args.files_only:
        for b in result.get("batch", []):
            print(b["file"])
        return 0
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
