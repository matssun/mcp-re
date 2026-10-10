"""dispose.py — apply an evaluator's whole package to the ledger and the journal, in ONE call.

(Invoked as `python3 dispose.py …`; no shebang — see reduce.py for why.)

WHY: on a lane run the evaluators spent ~155 of 848 Bash calls on bookkeeping —
one `ledger.py set` per disposition, one `progress.py close` per closure, the
`evaluate` event, the terminal event — and more on re-reading `ledger.py --help`
and the journal to rediscover the protocol. Every one of those turns re-sent the
agent's whole context. The package already holds every decision; this reads it
and writes all of them.

It also moves two checks from prose into code:

  * COMPLETENESS. Every actionable finding on the file must reach exactly one of
    `disposed[]` or a `work[]` item. A package that leaves a finding out is
    REFUSED and nothing is written — a partial apply would let the ledger's
    "every finding reaches a terminal disposition" rule depend on trusting the
    agent's arithmetic.
  * COUNTS. `work / disposed / closed / escalated` are computed from the
    identities, never typed by the agent. Tick 1 had four evaluators counting
    duplicates one way and four the other; tick 2 had `closed=0` beside four
    duplicate closures. A number derived from the record cannot disagree with it.

Package contract (the evaluator writes this, then runs this script once):
  disposed[]  {id, status, [reason], [duplicate_of], [premise], [cluster], [ruling], [issue], [method]}
              status: false-positive | premise | superseded | duplicate
                      (terminal) or escalated | needs-senior-eval (blocking)
              `reason` — one line — is required ONLY where someone acts on it:
              escalated / needs-senior-eval (a question for the human or the
              senior tier) and false-positive / premise (irreversible; the
              only trace if the call was wrong). A duplicate says it with
              `duplicate_of`; a premise names its registered ASM in `premise`;
              superseded needs nothing. A real defect is never closed here: it
              is ordered as work, or escalated.
              `accepted-risk` / `wontfix` are refused: they are not dispositions.
  work[]      {id, anchor, change, accept, standard, [finding_ids]}
              `id` is a finding id, or a work id with `finding_ids` naming the
              findings it discharges
  delete_or_wire[]  informational; each id must ALSO be in disposed[] or work[]

Nothing is written unless everything validates. Exit 0 applied, 2 refused.

Usage:
  dispose.py --ledger <ledger.jsonl> --log <progress> --package <pkg.json> \\
             --attempt <attempt_id> --run <run_id> --tier senior|cheap --model <m> \\
             [--epoch <policy_epoch>] [--dry-run] [--note "<one line>"]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402
import progress  # noqa: E402
from _persist import exclusive, read_jsonl  # noqa: E402

from file_findings import ACTIONABLE  # noqa: E402
TERMINAL = {"false-positive", "premise", "superseded", "duplicate"}
BLOCKING = {"escalated", "needs-senior-eval"}
# Where a reason is read by another actor. Everywhere else it is output tokens
# nobody consumes.
REASONED = {"escalated", "needs-senior-eval", "false-positive", "premise"}
# An escalation is the human's whole brief — question, what was checked, the
# alternatives — so it gets room; every other reason is one line.
REASON_MAX = {"escalated": 800}
REASON_MAX_DEFAULT = 300
# The can't-close rule, enforced where it is cheapest to enforce: a cheap tier may
# act but not retire a finding behind an authoritative-sounding reason.
CLOSES = {"false-positive", "premise"}


def _covered(item: dict, actionable: set) -> list:
    """The finding ids a work item discharges."""
    ids = [str(x) for x in (item.get("finding_ids") or [])]
    wid = str(item.get("id", ""))
    if wid in actionable and wid not in ids:
        ids.insert(0, wid)
    return ids


def validate(pkg: dict, rows: dict, path: str, tier: str) -> tuple[list, dict]:
    """Every refusal reason at once, so one retry fixes them all — plus the plan."""
    errs: list[str] = []
    on_file = {i: r for i, r in rows.items() if (r.get("path") or r.get("file")) == path}
    actionable = {i for i, r in on_file.items() if str(r.get("status", "")).lower() in ACTIONABLE}

    disposed: dict = {}
    for d in pkg.get("disposed") or []:
        fid, st = str(d.get("id", "")), str(d.get("status", "")).lower()
        where = "disposed[%s]" % fid
        if fid in disposed:
            errs.append("%s: listed twice" % where)
        if fid not in actionable:
            errs.append("%s: not an actionable finding on this file (ledger status: %s)"
                        % (where, on_file.get(fid, {}).get("status", "NOT ON THIS FILE")))
        if st in ledger.REFUSED_STATUSES:
            errs.append("%s: %r is not a disposition — order the fix as work, show it is not a "
                        "defect, or escalate it" % (where, st))
        elif st not in TERMINAL | BLOCKING:
            errs.append("%s: status %r is not one of %s" % (where, st, sorted(TERMINAL | BLOCKING)))
        if st == "premise":
            problem = ledger.closure_problem({"status": st, "premise": d.get("premise")},
                                             ledger.registered_assumptions())
            if problem:
                errs.append("%s: %s" % (where, problem))
        if st in REASONED and not str(d.get("reason", "")).strip():
            errs.append("%s: %s needs a one-line `reason` — someone acts on it" % (where, st))
        if st == "duplicate":
            twin = str(d.get("duplicate_of", ""))
            if not twin or twin == fid or twin not in rows:
                errs.append("%s: `duplicate` needs `duplicate_of` naming ANOTHER ledger id" % where)
        if tier == "cheap" and st in CLOSES:
            errs.append("%s: the cheap tier may not close as %s — set `needs-senior-eval` with "
                        "the reasoning instead" % (where, st))
        if tier == "senior" and st == "needs-senior-eval":
            errs.append("%s: you ARE the senior tier — decide it" % where)
        disposed[fid] = dict(d, id=fid, status=st)

    work_ids: list[str] = []
    by_work: dict = {}
    for w in pkg.get("work") or []:
        wid = str(w.get("id", ""))
        where = "work[%s]" % wid
        cov = _covered(w, actionable)
        if not cov:
            errs.append("%s: discharges no finding — use a finding id as `id`, or list them "
                        "in `finding_ids`" % where)
        for fid in cov:
            if fid not in actionable:
                errs.append("%s: finding %s is not actionable on this file" % (where, fid))
            if fid in disposed:
                errs.append("%s: finding %s is ALSO disposed — one or the other" % (where, fid))
            by_work.setdefault(fid, wid)
        for k in ("anchor", "change", "accept"):
            if not str(w.get(k, "")).strip():
                errs.append("%s: no `%s` — the worker cannot execute it" % (where, k))
        work_ids.append(wid)
    if len(set(work_ids)) != len(work_ids):
        errs.append("work ids are not unique: %s" % work_ids)

    for d in pkg.get("delete_or_wire") or []:
        fid = str(d.get("id", ""))
        if fid not in disposed and fid not in by_work:
            errs.append("delete_or_wire[%s]: must ALSO be disposed or ordered as work" % fid)

    for fid in sorted(actionable - set(disposed) - set(by_work)):
        errs.append("MISSING %s [%s] %s — every actionable finding needs a disposition or a "
                    "work item" % (fid, on_file[fid].get("severity"), on_file[fid].get("title")))

    plan = {"disposed": disposed, "work_ids": work_ids, "covered": by_work,
            "actionable": sorted(actionable)}
    return errs, plan


def _reason(d: dict) -> str:
    """One line, bounded. The package is the full record; the ledger and the
    journal carry the line a reader acts on."""
    r = " ".join(str(d.get("reason") or "").split())
    cap = REASON_MAX.get(d.get("status", ""), REASON_MAX_DEFAULT)
    return r if len(r) <= cap else r[:cap - 1] + "…"


def _note(existing: str, attempt: str, tier: str, reason: str) -> str:
    """Append, never replace: `notes` also carries the owner's rulings, and an
    evaluator's reason overwriting a recorded human decision would erase it."""
    if not reason:
        return existing
    entry = "[%s %s] %s" % (attempt, tier, reason)
    return (existing.rstrip() + "\n" + entry) if existing.strip() else entry


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--log", required=True, help="progress log base path (no extension)")
    ap.add_argument("--package", required=True)
    ap.add_argument("--file", default="", help="expected package.file; refused on mismatch")
    ap.add_argument("--attempt", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--tier", required=True, choices=["senior", "cheap"])
    ap.add_argument("--model", default="")
    ap.add_argument("--epoch", default="")
    ap.add_argument("--dry-run", action="store_true",
                    help="the lane is evaluate-only: write `dry-run` as the terminal event")
    ap.add_argument("--note", default="", help="one line for the evaluate event")
    a = ap.parse_args()

    try:
        pkg = json.load(open(a.package, encoding="utf-8"))
    except (OSError, ValueError) as e:
        print("REFUSED: cannot read package %s: %s" % (a.package, e))
        return 2
    path = str(pkg.get("file", ""))
    if a.file and a.file != path:
        print("REFUSED: package.file is %r, not %r; NOTHING was written." % (path, a.file))
        return 2

    # Idempotency: a second run for the same attempt would double every event.
    if os.path.exists(a.log + ".jsonl"):
        for r in read_jsonl(a.log + ".jsonl"):
            if r.get("attempt_id") == a.attempt and r.get("event") == "evaluate":
                print("REFUSED: attempt %s already has an `evaluate` event — this package was "
                      "applied. Use a new attempt id for a re-evaluation." % a.attempt)
                return 2

    with exclusive(a.ledger):
        rows = ledger._load(a.ledger)
        errs, plan = validate(pkg, rows, path, a.tier)
        if errs:
            print("REFUSED: %d problem(s); NOTHING was written.\n" % len(errs)
                  + "\n".join("  - " + e for e in errs))
            return 2
        for fid, d in plan["disposed"].items():
            e = rows[fid]
            e["status"] = d["status"]
            method = d.get("method") or ("review-adjudicated" if d["status"] == "needs-senior-eval"
                                         else "manual-source")
            e.setdefault("verified", {})["method"] = method
            e["notes"] = _note(str(e.get("notes") or ""), a.attempt, a.tier, _reason(d))
            if d.get("duplicate_of"):
                e["duplicate_of"] = str(d["duplicate_of"])
            if d.get("premise"):
                e["premise"] = str(d["premise"])
            if d.get("cluster"):
                e["cluster_id"] = str(d["cluster"])
            if d.get("ruling"):
                e["ruling_id"] = str(d["ruling"])
            if d.get("issue"):
                e.setdefault("refs", {})["issue"] = d["issue"]
        ledger._save(a.ledger, rows)

    closed = [d for d in plan["disposed"].values() if d["status"] in TERMINAL]
    blocked = [d for d in plan["disposed"].values() if d["status"] in BLOCKING]
    common = dict(log=a.log, file=path, attempt=a.attempt, run=a.run, epoch=a.epoch,
                  tier=a.tier, model=a.model)

    for d in closed:
        progress.cmd_close(argparse.Namespace(
            **common, role="evaluator", id=d["id"], status=d["status"],
            severity=str(rows[d["id"]].get("severity", "")), reason=_reason(d),
            duplicate_of=str(d.get("duplicate_of") or ""), cluster=str(d.get("cluster") or ""),
            ruling=str(d.get("ruling") or ""), evidence_ref=a.package))

    rulings = sorted({str(d.get("ruling")) for d in blocked if d.get("ruling")})
    counts = {"work": len(plan["work_ids"]), "closed": len(closed), "escalated": len(blocked),
              "disposed": len(closed) + len(blocked)}
    # The counts are fields already; a note exists only to say what blocks.
    note = a.note or str(pkg.get("blocked_on") or "")

    def append(event: str) -> None:
        progress.cmd_append(argparse.Namespace(
            **common, role="evaluator", event=event,
            counts=",".join("%s=%d" % kv for kv in counts.items()), note=note,
            work_ids=",".join(plan["work_ids"]),
            escalation_ids=",".join(d["id"] for d in blocked),
            finding_ids="", ruling=rulings[0] if len(rulings) == 1 else "",
            reject_causes="", evidence_ref=a.package))

    append("evaluate")
    terminal = "dry-run" if a.dry_run else "no-code-change" if not plan["work_ids"] else None
    if terminal:
        append(terminal)

    print(json.dumps({"applied": True, "file": path, **counts,
                      "delete_or_wire": len(pkg.get("delete_or_wire") or []),
                      "terminal_event": terminal or "(worker + reviewer carry it)",
                      "escalation_ids": [d["id"] for d in blocked],
                      "rulings": rulings,
                      "work_ids": plan["work_ids"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
