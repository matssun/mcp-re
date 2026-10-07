#!/usr/bin/env python3
"""progress.py — the tailable record of a long remediation run.

A lane that runs for hours or days is otherwise silent. This is not only
observability: the risk in a long campaign is not one bad file, it is a bad
POLICY applied consistently — an evaluator that closes too freely, a worker whose
anchors keep missing — discovered at file 600 instead of file 20. The log is what
makes that catchable, and `stats` is what makes it measurable.

Writes ONE file: <log>.jsonl, the append-only record, one line per stage event.
There is no second, human-formatted copy: nothing read it, and a view that can
drift from the record is a liability. `render` prints the human view on demand
and `watch` tails it for anomalies — both read the JSONL.

EVERY ROLE APPENDS ITS OWN EVENT. A single writer would leave silent holes
whenever an agent dies mid-stage; per-role events also give stage granularity
instead of one line an hour. `reconcile` closes the gap the other way: a file
with no terminal event gets a `lost` line, so a crash is visible as a crash
rather than as a shorter log.

Subcommands:
  append     one stage event (role, outcome, counts)
  close      a terminal disposition — its own verbose line, because
             false-positive / premise are the irreversible decisions
  reconcile  synthesize `lost` for files that never reached a terminal event
  stats      calibration: closure rate, work rate, escalation rate, streaks
  watch      read JSONL on stdin, emit ONLY anomaly lines (for Monitor)
  render     print the human view of the JSONL
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _persist import append_line, exclusive  # noqa: E402

SCHEMA_VERSION = 1

# An attempt ends in EXACTLY ONE of these. `gate-failed` was already listed here
# before the repair, but nothing ever APPENDED it — the workflow only returned it
# as a verdict — so a handled gate failure left the attempt looking abandoned and
# reconcile synthesized a false `lost`. A terminal event must be written, never
# inferred from the absence or the exit code of some other event.
TERMINAL_EVENTS = {"review", "no-code-change", "gate-failed", "exhausted", "lost",
                   "dry-run", "not-started"}

# Events whose `counts` are a SNAPSHOT of the attempt's disposition tally, not a
# delta. `evaluate` and the terminal event repeat the same numbers, so anything
# that sums them double-counts. The reducer treats these as assertions to CHECK
# against the identities it replayed, never as state to accumulate.
SNAPSHOT_EVENTS = {"evaluate", "no-code-change", "dry-run", "gate-failed", "exhausted"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short(p: str, keep: int = 3) -> str:
    parts = (p or "").split("/")
    return "/".join(parts[-keep:]) if len(parts) > keep else (p or "")


def _next_seq(log: str) -> int:
    """Monotonic sequence number from an O(1) sidecar counter.

    A gap in `seq` (…18429, 18430, 18432…) proves an event is missing, which
    file order alone cannot show. The counter is a tiny separate file read and
    bumped inside the lock — deliberately NOT derived by scanning the journal for
    its max, which would be O(n) per append and, worse, would reintroduce the
    read-whole-file/rewrite pattern that destroyed 365 ledger rows.
    """
    counter = log + ".seq"
    try:
        with open(counter, encoding="utf-8") as fh:
            n = int(fh.read().strip() or "0")
    except (OSError, ValueError):
        n = 0
    n += 1
    tmp = counter + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(str(n))
        fh.flush()
        os.fsync(fh.fileno())
    os.rename(tmp, counter)
    return n


def _envelope(rec: dict) -> dict:
    """Stamp the identity fields every event carries, whatever its type."""
    rec.setdefault("schema_version", SCHEMA_VERSION)
    rec.setdefault("event_id", "evt-" + uuid.uuid4().hex[:16])
    rec.setdefault("ts", _now())
    return rec


def _append(log: str, rec: dict) -> None:
    """Append one event under the lock, so `seq` and the record stay in step.

    The journal write itself is O_APPEND and would be safe unlocked; the lock is
    here only because `seq` must be handed out exactly once. Scope it to the
    counter bump plus the append and nothing else — a lock held across an
    agent's real work is how a lane deadlocks.
    """
    rec = _envelope(rec)
    with exclusive(log + ".jsonl"):
        rec["seq"] = _next_seq(log)
        append_line(log + ".jsonl", json.dumps(rec, sort_keys=True))


def _counts(spec: str | None) -> dict:
    out: dict[str, int] = {}
    for part in (spec or "").split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        try:
            out[k.strip()] = int(v)
        except ValueError:
            pass
    return out


def _ids(spec: str | None) -> list:
    """Comma-separated identities -> list. Empty stays empty, never [""]."""
    return [x.strip() for x in (spec or "").split(",") if x.strip()]


def cmd_append(a) -> int:
    c = _counts(a.counts)
    rec = {"file": a.file, "role": a.role, "event": a.event,
           "tier": a.tier, "model": a.model, "counts": c, "note": (a.note or "")[:400]}
    # The correlation key. File path + arrival order cannot distinguish a retry
    # from the attempt it replaced: `state.py` was evaluated, went `lost`, and
    # on re-dispatch its second attempt would silently overwrite the first in
    # every per-file tally. One attempt = one id, shared by all its events.
    rec["attempt_id"] = a.attempt or ("att-" + uuid.uuid4().hex[:12])
    rec["run_id"] = a.run or ""
    # Which policy regime produced this event. An aggregate rate computed across
    # a rule change measures neither regime: after the escalation criterion was
    # replaced, the campaign-wide escalation_rate still carried every escalation
    # made under the superseded rule and would have swamped the new signal for
    # many ticks. Stats are filtered by epoch, never averaged across one.
    if a.epoch:
        rec["policy_epoch"] = a.epoch
    # Counts are a checksum over the attempt, not a delta to accumulate.
    if c:
        rec["counts_kind"] = "attempt_snapshot" if a.event in SNAPSHOT_EVENTS else "stage_delta"
    # Identities for everything that can remain OUTSTANDING. Without these the
    # journal can say "8 escalations" but not WHICH eight, so no reducer can
    # report what is still awaiting a ruling without reading English prose.
    for field, spec in (("work_ids", a.work_ids), ("escalation_ids", a.escalation_ids),
                        ("finding_ids", a.finding_ids)):
        vals = _ids(spec)
        if vals:
            rec[field] = vals
    if a.ruling:
        rec["ruling_id"] = a.ruling
    # Cause-separated rejection reasons. A bare `rejected=6` cannot drive any
    # decision: rejection for scope, for insufficient evidence, and for a wrong
    # fix call for opposite corrections.
    causes = _ids(a.reject_causes)
    if causes:
        rec["reject_causes"] = causes
    # `note` stays bounded and human-readable; the full reasoning lives in the
    # artifact this points at. The journal records the transition, not the case.
    if a.evidence_ref:
        rec["evidence_ref"] = a.evidence_ref
    _append(a.log, rec)
    return 0


def cmd_close(a) -> int:
    rec = {"file": a.file, "role": a.role, "event": "close",
           "status": a.status, "id": a.id, "finding_id": a.id, "severity": a.severity,
           "tier": a.tier, "model": a.model, "note": (a.reason or "")[:600]}
    rec["attempt_id"] = a.attempt or ""
    rec["run_id"] = a.run or ""
    if a.epoch:
        rec["policy_epoch"] = a.epoch
    # Structural, not prose. "Duplicate of 0907afb94e8f36bf" in a note cannot be
    # reduced to a unique-defect count without an LLM parsing English; as a field
    # it collapses N observations onto one defect deterministically.
    if a.duplicate_of:
        rec["duplicate_of"] = a.duplicate_of
    if a.cluster:
        rec["cluster_id"] = a.cluster
    # A shared ruling discharges a whole escalation set at once. 30 escalations
    # collapsing onto ~4 architectural questions is an aggregation problem, not
    # 30 independent human decisions.
    if a.ruling:
        rec["ruling_id"] = a.ruling
    if a.evidence_ref:
        rec["evidence_ref"] = a.evidence_ref
    _append(a.log, rec)
    return 0


def _load(log: str) -> list[dict]:
    p = log + ".jsonl"
    if not os.path.exists(p):
        return []
    out = []
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def _attempts(rows: list) -> dict:
    """Group events into attempts. Legacy rows without `attempt_id` fall back to
    the file path, which is exactly the ambiguity `attempt_id` was added to end —
    so the fallback is for reading old history, never for writing new."""
    out: dict = defaultdict(list)
    for r in rows:
        key = r.get("attempt_id") or ("legacy:" + r.get("file", ""))
        out[key].append(r)
    return out


def cmd_reconcile(a) -> int:
    """Synthesize `lost` ONLY where no terminal event exists.

    Two distinctions the pre-repair version collapsed, both of which produced
    false alarms — and a log that cries wolf stops being read:

      lost         an attempt STARTED and never reached a terminal event.
      not-started  a file in the batch that was never attempted at all. Not a
                   death; usually the batch was cut short.

    And it no longer infers anything from a gate exit code. A handled gate
    failure is terminal because the workflow APPENDS `gate-failed`, not because
    reconcile guessed from `gate exit=1`.
    """
    seen = _load(a.log)
    expected = [f for f in (a.files.split(",") if a.files else []) if f]
    attempts = _attempts(seen)

    lost, terminal_files, started_files = [], set(), set()
    for key, evs in attempts.items():
        files = {e.get("file", "") for e in evs if e.get("file")}
        has_terminal = any(e.get("event") in TERMINAL_EVENTS for e in evs)
        started_files |= files
        if has_terminal:
            terminal_files |= files
        else:
            lost.append((key, sorted(files)))

    if not expected:
        expected = sorted(started_files)
    not_started = sorted(f for f in expected if f not in started_files)

    for key, files in sorted(lost, key=lambda kv: kv[1]):
        f = files[0] if files else "?"
        rec = {"file": f, "role": "orchestrator", "event": "lost", "counts": {},
               "attempt_id": key if not key.startswith("legacy:") else "",
               "note": "no terminal event — the stage died or was skipped"}
        _append(a.log, rec)
    for f in not_started:
        rec = {"file": f, "role": "orchestrator", "event": "not-started", "counts": {},
               "note": "in the batch but never attempted — not a death"}
        _append(a.log, rec)

    print(json.dumps({"expected": len(expected), "attempts": len(attempts),
                      "terminal_files": len(terminal_files),
                      "lost": len(lost), "lost_attempts": [k for k, _ in lost],
                      "lost_files": sorted({f for _, fs in lost for f in fs}),
                      "not_started": not_started}, indent=1))
    return 0


def cmd_stats(a) -> int:
    rows = _load(a.log)
    # NEVER average across a policy change. The campaign-wide escalation_rate
    # after the criterion was replaced still counted every escalation made under
    # the superseded rule, so it measured neither regime and would have buried
    # the new signal for many ticks. Filter to one epoch (or one run) instead.
    scope = {}
    if getattr(a, "epoch", ""):
        rows = [r for r in rows if r.get("policy_epoch") == a.epoch]
        scope["policy_epoch"] = a.epoch
    if getattr(a, "run", ""):
        rows = [r for r in rows if r.get("run_id") == a.run]
        scope["run_id"] = a.run
    if not scope:
        scope["warning"] = ("unfiltered: spans every policy epoch, so any rate "
                            "below mixes regimes and measures none of them")
    ev = Counter(r.get("event") for r in rows)
    closes = Counter(r.get("status") for r in rows if r.get("event") == "close")
    per_file: dict[str, dict] = defaultdict(dict)
    for r in rows:
        if r.get("event") == "evaluate":
            per_file[r["file"]] = r.get("counts", {})
    files = list(per_file)
    work = sum(1 for f in files if per_file[f].get("work", 0) > 0)
    esc = sum(per_file[f].get("escalated", 0) for f in files)
    disp = sum(per_file[f].get("disposed", 0) for f in files)
    # Longest run of consecutive evaluated files that produced no work item —
    # the loop turning findings into rulings instead of fixes.
    streak = best = 0
    for r in rows:
        if r.get("event") != "evaluate":
            continue
        if r.get("counts", {}).get("work", 0) == 0:
            streak += 1
            best = max(best, streak)
        else:
            streak = 0
    # Did the two rule fixes change behaviour? These are the counters that answer
    # it, and they are deliberately CAUSE-SEPARATED: "6 rejected" is a number,
    # "6 rejected for scope" is a diagnosis. A rejection for insufficient
    # evidence and one for a wrong fix call for opposite corrections, so a single
    # rejected count cannot drive any decision.
    ordered = sum(per_file[f].get("work", 0) for f in files)
    applied = sum(r.get("counts", {}).get("applied", 0)
                  for r in rows if r.get("event") == "fix")
    not_applied = sum(r.get("counts", {}).get("not_applied", 0)
                      for r in rows if r.get("event") == "fix")
    reviews = [r for r in rows if r.get("event") == "review"]
    rejected = sum(r.get("counts", {}).get("rejected", 0) for r in reviews)
    by_cause = Counter()
    for r in reviews:
        for cause in (r.get("reject_causes") or []):
            by_cause[cause] += 1
    rulings = {r.get("ruling_id") for r in rows if r.get("ruling_id")}
    tests_added = sum(r.get("counts", {}).get("tests_added", 0)
                      for r in rows if r.get("event") == "fix")
    reopened = sum(r.get("counts", {}).get("reopened", 0) for r in reviews)

    out = {"scope": scope,
           "events": dict(ev), "files_evaluated": len(files),
           "files_with_work": work,
           "work_rate": round(work / len(files), 3) if files else None,
           "findings_disposed": disp, "escalated": esc,
           "escalation_rate": round(esc / disp, 3) if disp else None,
           "closes": dict(closes), "max_zero_work_streak": best,
           "current_zero_work_streak": streak,
           "work_ordered": ordered,
           "work_applied": applied,
           "work_not_applied": not_applied,
           "items_rejected": rejected,
           "rejected_by_cause": dict(by_cause),
           "shared_rulings": len(rulings),
           "tests_added": tests_added,
           "items_reopened_after_review": reopened}
    print(json.dumps(out, indent=1))
    return 0


def cmd_watch(a) -> int:
    """Read JSONL events on stdin; print ONLY anomalies.

    Deliberately dumb and cheap: a filter that runs for days and wakes a model
    only on a hit. It NOTIFIES — it must never be able to stop the lane, because
    the safety story here rests on there being exactly one writer.
    """
    zero_streak = 0
    reject_streak = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        f, ev = _short(r.get("file", "")), r.get("event")
        c = r.get("counts", {}) or {}

        if ev == "evaluate":
            if c.get("work", 0) == 0:
                zero_streak += 1
                if zero_streak >= a.zero_work_streak:
                    print("ALERT zero-work-streak=%d — the lane is producing rulings, not fixes (last: %s)"
                          % (zero_streak, f))
            else:
                zero_streak = 0
            disposed = c.get("disposed", 0)
            closed = c.get("closed", 0)
            if disposed and closed / disposed >= a.close_rate:
                print("ALERT close-rate %d/%d on %s — an evaluator may be closing too freely"
                      % (closed, disposed, f))
        elif ev == "gate":
            if r.get("counts", {}).get("exit", 0) != 0:
                print("ALERT gate FAILED on %s — %s" % (f, (r.get("note") or "")[:160]))
        elif ev == "review":
            v = (r.get("note") or "")
            if r.get("counts", {}).get("rejected", 0) or "reject" in v.lower():
                reject_streak += 1
                print("ALERT review REJECTED on %s%s" % (f, " (%d in a row)" % reject_streak
                                                         if reject_streak > 1 else ""))
            else:
                reject_streak = 0
        elif ev == "fix":
            if c.get("not_applied", 0) >= a.anchor_misses:
                print("ALERT %d anchors did not match on %s — packets are stale, re-derive rather than retry"
                      % (c["not_applied"], f))
        elif ev == "lost":
            print("ALERT no terminal event for %s — a stage died" % f)
        elif ev == "close" and r.get("severity") in ("critical", "high"):
            print("ALERT a %s finding was CLOSED as %s on %s — %s"
                  % (r.get("severity"), r.get("status"), f, (r.get("note") or "")[:160]))
        elif ev == "regression":
            print("ALERT REGRESSION on %s — a fixed finding reappeared" % f)
        sys.stdout.flush()
    return 0


def cmd_render(a) -> int:
    for r in _load(a.log):
        if r.get("event") == "close":
            print("%s  CLOSE  %-16s %-10s %s" % (r["ts"], r.get("status"), r.get("id"), _short(r["file"])))
        else:
            c = r.get("counts", {}) or {}
            print("%s  %-26s %-8s %-58s %s" % (
                r["ts"], r.get("role", ""), r.get("event", ""), _short(r.get("file", "")),
                " ".join("%s=%s" % kv for kv in sorted(c.items()))))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    ad = sub.add_parser("append")
    ad.add_argument("--log", required=True)
    ad.add_argument("--file", required=True)
    ad.add_argument("--role", required=True)
    ad.add_argument("--event", required=True,
                    help="evaluate | fix | gate | review | no-code-change | gate-failed | exhausted | regression")
    ad.add_argument("--tier", default="")
    ad.add_argument("--model", default="")
    ad.add_argument("--counts", default="", help="k=v,k=v (work, disposed, closed, escalated, applied, not_applied, exit, rejected) — a CHECKSUM over the attempt, not a delta to sum")
    ad.add_argument("--note", default="", help="bounded, human-readable; put the full reasoning in --evidence-ref")
    ad.add_argument("--attempt", default="", help="attempt id shared by every event of ONE file-processing attempt")
    ad.add_argument("--run", default="", help="run id, e.g. audit-2026-09-22")
    ad.add_argument("--epoch", default="", help="policy epoch; stats are filtered by it, never averaged across one")
    ad.add_argument("--work-ids", dest="work_ids", default="",
                    help="comma-separated ids of the work items this event created/resolved")
    ad.add_argument("--escalation-ids", dest="escalation_ids", default="",
                    help="comma-separated ids of escalations raised — WHICH ones, not how many")
    ad.add_argument("--finding-ids", dest="finding_ids", default="",
                    help="comma-separated finding ids this event covers")
    ad.add_argument("--ruling", default="", help="shared ruling id that discharges these escalations")
    ad.add_argument("--reject-causes", dest="reject_causes", default="",
                    help="review only: comma-separated causes, one per rejected item — "
                         "scope | evidence | wrong-fix | anchor | other")
    ad.add_argument("--evidence-ref", dest="evidence_ref", default="",
                    help="path to the immutable artifact holding the full reasoning")
    ad.set_defaults(fn=cmd_append)

    cl = sub.add_parser("close")
    cl.add_argument("--log", required=True)
    cl.add_argument("--file", required=True)
    cl.add_argument("--id", required=True)
    cl.add_argument("--status", required=True)
    cl.add_argument("--severity", default="")
    cl.add_argument("--reason", required=True)
    cl.add_argument("--role", default="evaluator")
    cl.add_argument("--tier", default="")
    cl.add_argument("--model", default="")
    cl.add_argument("--attempt", default="", help="the attempt this closure belongs to")
    cl.add_argument("--run", default="")
    cl.add_argument("--epoch", default="")
    cl.add_argument("--duplicate-of", dest="duplicate_of", default="",
                    help="finding id this one duplicates — a FIELD, not a sentence in --reason")
    cl.add_argument("--cluster", default="", help="cluster id: several observations of ONE defect")
    cl.add_argument("--ruling", default="", help="shared ruling id discharging this escalation")
    cl.add_argument("--evidence-ref", dest="evidence_ref", default="",
                    help="path to the artifact holding the full adjudication")
    cl.set_defaults(fn=cmd_close)

    rc = sub.add_parser("reconcile")
    rc.add_argument("--log", required=True)
    rc.add_argument("--files", default="", help="comma-separated files the batch was supposed to cover")
    rc.set_defaults(fn=cmd_reconcile)

    st = sub.add_parser("stats")
    st.add_argument("--log", required=True)
    st.add_argument("--epoch", default="", help="only events from this policy epoch")
    st.add_argument("--run", default="", help="only events from this run id")
    st.set_defaults(fn=cmd_stats)

    wt = sub.add_parser("watch")
    wt.add_argument("--zero-work-streak", type=int, default=5)
    wt.add_argument("--close-rate", type=float, default=0.5)
    wt.add_argument("--anchor-misses", type=int, default=2)
    wt.set_defaults(fn=cmd_watch)

    rn = sub.add_parser("render")
    rn.add_argument("--log", required=True)
    rn.set_defaults(fn=cmd_render)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
