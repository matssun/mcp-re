"""finalize.py — close a lane batch: commit what review accepted, revert what it did
not, and record `fixed` for exactly the findings the reviewer accepted. One call.

Per file in the workflow's `results`:

  accept, or partial whose rejections are all `anchor` / `scope`
      the rejected items never landed (an absent anchor or a missing path leaves
      no diff), so the tree holds only accepted work: commit `files_touched`, and
      mark the findings of `items_accepted` `fixed`. The rest stay actionable.
  anything else (reject, a `wrong-fix` / `evidence` / `other` rejection, an
  unordered change, review-failed)
      the diff holds something review did not accept: save it as a patch, return
      the paths to HEAD, record nothing. The file comes back on the next pass.
  gate-failed, no-code-change, dry-run
      nothing to do: `check.py` already reverted a red change, and a file with no
      work has no diff.
  accepted, but a touched file carries an undispositioned control
      a test the change added that no unit claims and no ADR-MCPRE-069 row covers.
      The census is held at its closure state (`scripts/control_census_gate.py`), so
      committing it would move the debt to whoever runs the next gate: revert with the
      patch kept, name the controls, record nothing. The evaluator's next package
      carries the disposition (a registration or a `control-dispositions.toml` row)
      with the change that needs it.

A finding is `fixed` only through this path — the reviewer's acceptance of a
landed diff — never through an evaluator's or worker's own claim.

Usage:
  finalize.py --results <workflow result JSON> --ledger L --work-dir DIR
              [--trailer "Co-Authored-By: ..."]... [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402
from _persist import exclusive  # noqa: E402

HARMLESS_REJECTS = {"anchor", "scope"}
NOTHING_TO_DO = {"gate-failed", "no-code-change", "dry-run", "blocked-platform", "agent-failed"}


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True)


def residue_by_carrier() -> dict[str, list[str]]:
    """The census's undispositioned controls, keyed by the file that carries each."""
    root = _git("rev-parse", "--show-toplevel").stdout.strip()
    sys.path.insert(0, os.path.join(root, "tools", "verification"))
    from _census import census  # noqa: PLC0415 — the tool path is set up above

    out: dict[str, list[str]] = {}
    for control in census().residue:
        out.setdefault(control.carrier, []).append(control.identity)
    return out


def undispositioned(paths: list[str], residue: dict[str, list[str]]) -> list[str]:
    """The controls in `paths` that ADR-MCPRE-069 has not yet dispositioned."""
    return sorted(c for p in paths for c in residue.get(p, []))


def decide(row: dict) -> str:
    verdict = row.get("verdict")
    if verdict in NOTHING_TO_DO:
        return "skip"
    if row.get("unordered_changes"):
        return "revert"
    if verdict == "accept":
        return "commit"
    if verdict == "partial" and row.get("accepted") and all(
            (r.get("cause") in HARMLESS_REJECTS) for r in row.get("rejected") or []):
        return "commit"
    return "revert"


def finding_ids(package: dict, work_ids: list[str]) -> list[str]:
    out: list[str] = []
    for item in package.get("work", []):
        if item.get("id") in work_ids:
            out += item.get("finding_ids") or [item["id"]]
    return sorted(set(out))


def _revert(paths: list[str], work_dir: str, tag: str) -> str:
    patch = os.path.join(work_dir, "review-rejected-%s.patch" % tag)
    tracked = _git("ls-files", "--", *paths).stdout.split()
    with open(patch, "w", encoding="utf-8") as fh:
        fh.write(_git("diff", "HEAD", "--", *tracked).stdout)
    if tracked:
        _git("checkout", "HEAD", "--", *tracked)
    for f in paths:
        if f not in tracked and os.path.isfile(f):
            os.remove(f)
    return patch


def main() -> int:
    ap = argparse.ArgumentParser(description="close a lane batch")
    ap.add_argument("--results", required=True)
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--trailer", action="append", default=[])
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    doc = json.load(open(a.results, encoding="utf-8"))
    rows = doc.get("results", doc) if isinstance(doc, dict) else doc
    # Measured once, over the tree holding every diff the batch landed: a carrier's
    # residue is attributable to the file whose change touched it.
    residue = residue_by_carrier() if any(decide(r) == "commit" for r in rows) else {}
    report = []
    for row in rows:
        action = decide(row)
        paths = row.get("files_touched") or []
        entry = {"file": row["file"], "verdict": row.get("verdict"), "action": action}
        if action == "commit" and not paths:
            entry["action"] = action = "skip"
            entry["why"] = "accepted but no files_touched — nothing to commit"
        held = undispositioned(paths, residue) if action == "commit" else []
        if held:
            entry.update(action="revert", why="undispositioned controls (ADR-MCPRE-069)",
                         undispositioned=held)
            action = "revert"
        if a.dry_run or action == "skip":
            report.append(entry)
            continue
        tag = os.path.basename(row["file"]).replace(".", "-")
        if action == "revert":
            entry["patch"] = _revert(paths, a.work_dir, tag)
            report.append(entry)
            continue
        package = json.load(open(row["package"], encoding="utf-8")) if row.get("package") else {}
        fixed = finding_ids(package, row.get("accepted") or [])
        items = {i.get("id"): i for i in package.get("work", [])}
        lines = ["security: %s — %d finding(s) remediated (lane review: %s)"
                 % (row["file"], len(fixed), row.get("verdict")), ""]
        for wid in row.get("accepted") or []:
            change = str(items.get(wid, {}).get("change", "")).split("\n")[0][:160]
            lines.append("- %s: %s" % (wid, change))
        if a.trailer:
            lines += [""] + a.trailer
        _git("add", "--", *paths)
        c = subprocess.run(["git", "commit", "-q", "-F", "-", "--", *paths],
                           input="\n".join(lines) + "\n", capture_output=True, text=True)
        if c.returncode != 0:
            entry.update(action="commit-failed", error=(c.stderr or c.stdout).strip()[-300:])
            report.append(entry)
            continue
        sha = _git("rev-parse", "--short", "HEAD").stdout.strip()
        with exclusive(a.ledger):
            by_id = ledger._load(a.ledger)
            for fid in fixed:
                if fid in by_id:
                    by_id[fid]["status"] = "fixed"
                    by_id[fid]["verified"] = {"method": "review-accepted", "commit": sha}
            ledger._save(a.ledger, by_id)
        entry.update(commit=sha, fixed=fixed)
        report.append(entry)
    if not a.dry_run and _git("status", "--porcelain", "--", a.ledger).stdout.strip():
        # Every disposition the batch wrote — the evaluators' closures and the
        # `fixed` above — in one commit of its own, after the code it describes.
        msg = "ledger: %d file(s) of a lane batch dispositioned\n" % len(report)
        if a.trailer:
            msg += "\n" + "\n".join(a.trailer) + "\n"
        _git("add", "--", a.ledger)
        subprocess.run(["git", "commit", "-q", "-F", "-", "--", a.ledger], input=msg,
                       capture_output=True, text=True)
        report.append({"ledger_commit": _git("rev-parse", "--short", "HEAD").stdout.strip()})
    print(json.dumps(report, indent=1))
    return 1 if any(r.get("action") == "commit-failed" for r in report) else 0


if __name__ == "__main__":
    sys.exit(main())
