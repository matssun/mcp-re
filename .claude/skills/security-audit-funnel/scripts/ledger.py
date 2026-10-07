#!/usr/bin/env python3
"""Finding ledger + reconcile for the security-audit-funnel.

A finding ledger is the durable, version-controlled record of every audit finding
ever seen for a target and how it was DISPOSITIONED, so a later round never re-pays
the expensive Stage-3 verify cost on a finding already adjudicated. The ledger is a
JSONL file (one finding per line) checked into the audited repo (e.g.
`docs/security/finding-ledger.jsonl`); git history is the audit trail.

Disposition taxonomy (`status`):
  open              active, real, tracked — re-surface as "already tracked"
  escalated / needs-senior-eval   waiting on a decision; counted open
  fixed             remediated in code (carry the commit) — re-surface = REGRESSION (loud)
  false-positive    adjudicated not a real defect
  premise           the finding is the statement of a registered assumption; `premise`
                    names its ASM id in verification/policy/assumptions.toml
  constraint        a demonstrated architectural constraint an owner ruling accepted;
                    `owner_ruling` names the ruling ("Ruling 22.1")
  superseded        the finding's location no longer exists (code removed/relocated)
  duplicate         another observation of a finding named by `duplicate_of`
  positive-control  an INFO finding confirming a good control is present
  informational     an info-severity finding kept off the remediation worklist
  handled-prior-round   filed + closed in a prior round, exact resolution not re-derived

`accepted-risk` and `wontfix` are not dispositions: a real security defect is fixed,
disproved, or stays open. `set` refuses them, `check` fails on any row carrying them,
and `stats` counts every row that is not validly closed as open — a `premise` naming no
registered assumption and a `constraint` naming no owner ruling included.

`verified.method` records HOW a disposition was reached — never overclaim:
  gate-3skeptic | manual-source | fix-merged | review-adjudicated | intentional-posture
  | closed-issue | removed-code

Fingerprint (`id`): sha1(file-basename | sorted significant title tokens). Line
numbers and exact wording drift between rounds, so the id is deliberately coarse;
reconcile() ALSO emits fuzzy candidate matches (same file+category) that a human/LLM
must confirm rather than silently suppressing them.

Subcommands:
  fingerprint  --file F --title T
  ingest       LEDGER PRERUN --round R [--status S] [--method M]
  reconcile    LEDGER PRERUN
  set          LEDGER --id ID [--status S] [--method M] [--issue N] [--pr N] [--note ..]
               [--premise ASM-NNNN] [--owner-ruling "Ruling N"]
  stats        LEDGER [--assumptions TOML]
  check        LEDGER [--assumptions TOML]
"""
import argparse
import hashlib
import json
import os
import re
import sys
import tomllib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _persist import atomic_write_lines, exclusive  # noqa: E402

_STOP = {
    "the", "a", "an", "is", "are", "be", "on", "of", "to", "in", "for", "and",
    "or", "not", "no", "but", "with", "vs", "it", "its", "as", "at", "by", "via",
    "that", "this", "from", "into", "only", "any", "all", "can", "could", "may",
    "when", "if", "then", "than", "so", "a", "per", "each", "both",
}
SUPPRESS = {"fixed", "false-positive", "superseded", "positive-control", "informational",
            "premise", "constraint"}
# Statuses kept OFF the remediation worklist. `informational` = an info-severity
# finding: captured durably and emitted in the per-run info digest issue, but
# NOT worked by the file-by-file loop (ADR-SEC-023 funnel policy: critical→low
# are all dealt with; info is "might look into, or not").

OPEN_STATUSES = {"open", "escalated", "needs-senior-eval", "regression"}
CLOSED_STATUSES = {"fixed", "false-positive", "premise", "constraint", "superseded",
                   "duplicate", "positive-control", "informational", "handled-prior-round"}
# Not dispositions. "Real, and we decided to live with it" closes nothing: the defect
# is still there, and a ledger that counts it closed reports a zero that measures nothing.
REFUSED_STATUSES = {"accepted-risk", "wontfix"}
ASSUMPTIONS_TOML = "verification/policy/assumptions.toml"
_ASM = re.compile(r"^ASM-\d{4}$")
_OWNER_RULING = re.compile(r"^Ruling \d+(\.\d+)?\b")


def registered_assumptions(path=ASSUMPTIONS_TOML):
    """The ASM ids registered in `path`, or None when the registry is not present."""
    if not path or not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return {a["id"] for a in tomllib.load(fh).get("assumption", [])}


def closure_problem(e, assumptions):
    """Why `e` is not a valid disposition, or None. `assumptions` None skips the ASM lookup."""
    st = e.get("status")
    if st in REFUSED_STATUSES:
        return "status %r is not a disposition: fix it, disprove it, or leave it open" % st
    if st not in OPEN_STATUSES | CLOSED_STATUSES:
        return "status %r is not in the taxonomy" % st
    if st == "premise":
        asm = str(e.get("premise", ""))
        if not _ASM.match(asm):
            return "premise names no ASM id (`premise` = %r)" % asm
        if assumptions is not None and asm not in assumptions:
            return "premise %s is not registered in %s" % (asm, ASSUMPTIONS_TOML)
    if st == "constraint" and not _OWNER_RULING.match(str(e.get("owner_ruling", ""))):
        return "constraint names no owner ruling (`owner_ruling` = %r)" % e.get("owner_ruling")
    return None


def is_open(e, assumptions):
    """Open unless validly closed: a row the taxonomy cannot close counts as open."""
    return e.get("status") in OPEN_STATUSES or closure_problem(e, assumptions) is not None


def _basename(file_or_loc):
    """File basename from a `module`/`location` string (strips `:line`, dirs)."""
    s = (file_or_loc or "").split(":")[0].strip()
    return os.path.basename(s) if s else ""


def _norm_tokens(title):
    toks = re.findall(r"[a-z0-9]+", (title or "").lower())
    toks = [t for t in toks if t not in _STOP and len(t) > 1]
    return sorted(set(toks))


def fingerprint(file_or_loc, title):
    base = _basename(file_or_loc)
    key = base + "|" + " ".join(_norm_tokens(title))
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def _load(path):
    if not os.path.exists(path):
        return {}
    out = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            out[e["id"]] = e
    return out


def _save(path, by_id):
    """Atomically store the ledger. MUST be called inside `exclusive(path)`.

    The write itself is atomic (temp file + rename), so no reader can observe a
    partial ledger. That is necessary and NOT sufficient: the caller must also
    hold the lock across its own `_load()`, or two writers each store their own
    delta over the same base snapshot and the loser's change is silently lost.
    See `_persist` for the incident this pair of rules was written against.
    """
    # Stable order: by file then id, so diffs are readable.
    rows = sorted(by_id.values(), key=lambda e: (e.get("file", ""), e["id"]))
    atomic_write_lines(path, [json.dumps(e, sort_keys=True) for e in rows])


def _findings_of(prerun):
    """Accept several prerun shapes; return a list of finding dicts."""
    if isinstance(prerun, list):
        return prerun
    for k in ("rawFindings", "findings"):
        if isinstance(prerun.get(k), list):
            return prerun[k]
    # 06-14 shape: act_now / defer buckets.
    out = []
    for k in ("act_now", "defer"):
        v = prerun.get(k)
        if isinstance(v, list):
            out.extend(v)
    return out


def _file_of(f):
    return _basename(f.get("location") or f.get("module") or f.get("file") or "")


def cmd_fingerprint(a):
    print(fingerprint(a.file, a.title))


def cmd_ingest(a):
    if a.status and a.status not in OPEN_STATUSES | {"informational"}:
        sys.exit(f"ingest: --status {a.status!r} refused — a new finding enters open or "
                 f"informational; a disposition is a `set` that names its evidence")
    prerun = json.load(open(a.prerun))
    findings = _findings_of(prerun)
    # Same rule as cmd_set: the lock covers load -> mutate -> store. Ingest is
    # also the RECOVERY path (deterministic fingerprints re-add lost rows and
    # leave existing dispositions untouched), so it must not itself race.
    with exclusive(a.ledger):
        by_id = _load(a.ledger)
        added = updated = 0
        for f in findings:
            fid = fingerprint(_file_of(f), f.get("title"))
            sev = (f.get("severity") or "").lower()
            # critical→low enter the worklist as `open` (all must be dealt with).
            # info is captured off-worklist as `informational` (per-run digest issue).
            status = a.status or ("informational" if sev == "info" else "open")
            method = a.method or ("catalog-logged" if status == "informational"
                                  else "review-adjudicated")
            if fid in by_id:
                e = by_id[fid]
                e["last_seen"] = a.round
                loc = (f.get("location") or f.get("module") or f.get("file") or "").split(":")[0].strip()
                if loc:
                    e["path"] = loc
                if f.get("line") is not None:
                    e["line"] = f.get("line")
                e.setdefault("rounds", [])
                if a.round not in e["rounds"]:
                    e["rounds"].append(a.round)
                updated += 1
            else:
                by_id[fid] = {
                    "id": fid,
                    "file": _file_of(f),
                    # Full repo-relative path and line: the basename alone is not
                    # actionable for a fixer, and next_file.py keys the worklist on
                    # `path` when present.
                    "path": (f.get("location") or f.get("module") or f.get("file") or "").split(":")[0].strip(),
                    "line": f.get("line"),
                    "category": f.get("category", ""),
                    "severity": sev,
                    "title": f.get("title", ""),
                    "status": status,
                    "verified": {"method": method, "round": a.round},
                    "refs": {},
                    "first_seen": a.round,
                    "last_seen": a.round,
                    "rounds": [a.round],
                    "notes": "",
                }
                added += 1
        _save(a.ledger, by_id)
    print(f"ingest: +{added} new, {updated} updated -> {a.ledger} "
          f"({len(by_id)} total)")


def cmd_reconcile(a):
    by_id = _load(a.ledger)
    by_file = {}
    for e in by_id.values():
        by_file.setdefault(e["file"], []).append(e)
    prerun = json.load(open(a.prerun))
    findings = _findings_of(prerun)
    new, tracked, regression, suppressed, candidates = [], [], [], [], []
    for f in findings:
        fid = fingerprint(_file_of(f), f.get("title"))
        e = by_id.get(fid)
        rec = {"file": _file_of(f), "title": f.get("title", ""),
               "severity": (f.get("severity") or "").lower(), "id": fid}
        if e is None:
            # Fuzzy: same file + same category is a candidate recurrence.
            cands = [x for x in by_file.get(rec["file"], [])
                     if x.get("category") and x["category"] == f.get("category")]
            if cands:
                rec["candidates"] = [{"id": c["id"], "status": c["status"],
                                      "title": c["title"]} for c in cands]
                candidates.append(rec)
            else:
                new.append(rec)
        elif e["status"] == "fixed":
            rec["was"] = e["refs"]
            regression.append(rec)
        elif e["status"] in SUPPRESS:
            rec["status"] = e["status"]
            suppressed.append(rec)
        else:  # open / escalated / handled-prior-round / duplicate
            rec["status"] = e["status"]
            rec["refs"] = e.get("refs", {})
            tracked.append(rec)
    out = {
        "summary": {
            "new": len(new), "tracked": len(tracked),
            "regression": len(regression), "suppressed": len(suppressed),
            "fuzzy_candidates": len(candidates),
        },
        "new": new, "regression": regression,
        "fuzzy_candidates": candidates, "tracked": tracked,
        "suppressed_count_by_status": _count_by(suppressed, "status"),
    }
    print(json.dumps(out, indent=1))


def _count_by(rows, key):
    out = {}
    for r in rows:
        out[r.get(key, "?")] = out.get(r.get(key, "?"), 0) + 1
    return out


def cmd_set(a):
    # The lock spans load -> mutate -> store. Narrowing it to the store alone
    # reintroduces lost-update: that is the defect that cost 365 findings.
    with exclusive(a.ledger):
        by_id = _load(a.ledger)
        e = by_id.get(a.id)
        if e is None:
            sys.exit(f"set: id {a.id} not in ledger")
        if a.status:
            e["status"] = a.status
        if a.premise:
            e["premise"] = a.premise
        if a.owner_ruling:
            e["owner_ruling"] = a.owner_ruling
        if a.method:
            e.setdefault("verified", {})["method"] = a.method
        if a.issue:
            e.setdefault("refs", {})["issue"] = a.issue
        if a.pr:
            e.setdefault("refs", {})["pr"] = a.pr
        if a.note:
            e["notes"] = a.note
        # A duplicate/cluster relationship is a FIELD, not a sentence in `notes`.
        # `status=duplicate` with the twin named only in prose cannot be reduced
        # to a unique-defect count without an LLM reading English.
        if a.duplicate_of:
            e["duplicate_of"] = a.duplicate_of
        if a.cluster:
            e["cluster_id"] = a.cluster
        if a.ruling:
            e["ruling_id"] = a.ruling
        problem = closure_problem(e, registered_assumptions(a.assumptions))
        if problem:
            sys.exit(f"set {a.id}: refused — {problem}")
        _save(a.ledger, by_id)
    print(f"set {a.id}: status={e['status']} refs={e.get('refs')}")


def cmd_stats(a):
    by_id = _load(a.ledger)
    assumptions = registered_assumptions(a.assumptions)
    by_status, by_sev, open_by_sev = {}, {}, {}
    for e in by_id.values():
        by_status[e["status"]] = by_status.get(e["status"], 0) + 1
        by_sev[e["severity"]] = by_sev.get(e["severity"], 0) + 1
        if is_open(e, assumptions):
            open_by_sev[e["severity"]] = open_by_sev.get(e["severity"], 0) + 1
    invalid = sorted(e["id"] for e in by_id.values() if closure_problem(e, assumptions))
    print(json.dumps({"total": len(by_id), "by_status": by_status,
                      "by_severity": by_sev, "open": sum(open_by_sev.values()),
                      "open_by_severity": open_by_sev,
                      "not_validly_closed": invalid}, indent=1))


def cmd_check(a):
    by_id = _load(a.ledger)
    if not by_id:
        sys.exit(f"check: {a.ledger} holds no findings — an empty ledger checks nothing")
    assumptions = registered_assumptions(a.assumptions)
    problems = [(i, p) for i, e in sorted(by_id.items())
                if (p := closure_problem(e, assumptions))]
    for i, p in problems:
        print(f"  - {i}: {p}")
    if problems:
        print(f"ledger check: FAIL — {len(problems)} of {len(by_id)} row(s) carry no valid disposition")
        return 1
    n_open = sum(1 for e in by_id.values() if is_open(e, assumptions))
    print(f"ledger check: OK — {len(by_id)} row(s), {n_open} open")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(required=True)

    fp = sub.add_parser("fingerprint")
    fp.add_argument("--file", required=True)
    fp.add_argument("--title", required=True)
    fp.set_defaults(fn=cmd_fingerprint)

    ig = sub.add_parser("ingest")
    ig.add_argument("ledger")
    ig.add_argument("prerun")
    ig.add_argument("--round", required=True)
    ig.add_argument("--status")
    ig.add_argument("--method")
    ig.set_defaults(fn=cmd_ingest)

    rc = sub.add_parser("reconcile")
    rc.add_argument("ledger")
    rc.add_argument("prerun")
    rc.set_defaults(fn=cmd_reconcile)

    st = sub.add_parser("set")
    st.add_argument("ledger")
    st.add_argument("--id", required=True)
    st.add_argument("--status")
    st.add_argument("--method")
    st.add_argument("--issue", type=int)
    st.add_argument("--pr", type=int)
    st.add_argument("--note")
    st.add_argument("--duplicate-of", dest="duplicate_of",
                    help="finding id this one duplicates (structural, not prose)")
    st.add_argument("--cluster", help="cluster id: several observations of ONE defect")
    st.add_argument("--ruling", help="shared ruling id that discharges this escalation")
    st.add_argument("--premise", help="status=premise: the registered ASM id it states")
    st.add_argument("--owner-ruling", dest="owner_ruling",
                    help='status=constraint: the owner ruling that accepted it ("Ruling 22.1")')
    st.add_argument("--assumptions", default=ASSUMPTIONS_TOML)
    st.set_defaults(fn=cmd_set)

    st2 = sub.add_parser("stats")
    st2.add_argument("ledger")
    st2.add_argument("--assumptions", default=ASSUMPTIONS_TOML)
    st2.set_defaults(fn=cmd_stats)

    ck = sub.add_parser("check")
    ck.add_argument("ledger")
    ck.add_argument("--assumptions", default=ASSUMPTIONS_TOML)
    ck.set_defaults(fn=cmd_check)

    a = p.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
