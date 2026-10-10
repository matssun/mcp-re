#!/usr/bin/env python3
"""rulings.py — the human decision queue for the security-remediate lane.

An escalation is not a unit of work for a human: several findings usually wait on
ONE decision, and evaluators mark the duplicates as they go. This renders the
`escalated` rows as a ruling queue — grouped by the row's `ruling_id` across files
(an escalation without one is grouped by file), duplicates folded under the finding
that carries the decision — so the orchestrator hands over N decisions, not N
findings. A `ruling_id` prefixed `owner-signature:` is not a choice: one remedy
survives, but it lands on an owner-ratified surface, so it is listed apart as a
ratification.

Async by design: the lane never blocks on this. It records escalations, keeps
working other files, and this file is what the human answers between ticks.

Usage:
  rulings.py --ledger <ledger.jsonl> [--out RULINGS.md] [--since <round>]
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import defaultdict

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
DUP = re.compile(r"duplicate of ([0-9a-f]{8,})", re.I)
SIGN = "owner-signature:"
SEV_NAME = {v: k.upper() for k, v in SEV.items()}


def _worst(rows: list[dict]) -> int:
    return min(SEV.get(str(r.get("severity", "")).lower(), 9) for r in rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--since", default=None, help="only escalations first seen in this round")
    ap.add_argument("--packages", default=None,
                    help="evaluator work-package dir; its per-file `blocked_on` states THE decision, "
                         "which is a truer unit than one decision per escalated finding")
    a = ap.parse_args()

    rows = []
    with open(a.ledger, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    esc = [r for r in rows if str(r.get("status", "")).lower() == "escalated"]
    if a.since:
        esc = [r for r in esc if a.since in (r.get("rounds") or [])]

    # Fold: a row whose note says "duplicate of <id>" waits on that id's ruling.
    folded: dict[str, list[dict]] = defaultdict(list)
    primary: dict[str, dict] = {}
    for r in sorted(esc, key=lambda r: SEV.get(str(r.get("severity", "")).lower(), 9)):
        m = DUP.search(r.get("notes") or "")
        if m and m.group(1) != r["id"]:
            folded[m.group(1)].append(r)
        else:
            primary[r["id"]] = r
    # A fold target that is not itself escalated becomes its own decision.
    for tgt, kids in list(folded.items()):
        if tgt not in primary:
            primary[kids[0]["id"]] = kids[0]
            folded[kids[0]["id"]] = kids[1:]
            del folded[tgt]

    by_file: dict[str, list[dict]] = defaultdict(list)
    by_ruling: dict[str, list[dict]] = defaultdict(list)
    for r in primary.values():
        if r.get("ruling_id"):
            by_ruling[r["ruling_id"]].append(r)
        else:
            by_file[r.get("path") or r.get("file")].append(r)
    signature = sorted(k for k in by_ruling if k.startswith(SIGN))
    decisions = sorted((k for k in by_ruling if not k.startswith(SIGN)),
                       key=lambda k: (_worst(by_ruling[k]), k))
    signature.sort(key=lambda k: (_worst(by_ruling[k]), k))

    # The evaluator that read the file usually states, once, the single decision
    # its escalations wait on. Prefer that over one decision per finding.
    blocked_on: dict[str, str] = {}
    if a.packages and os.path.isdir(a.packages):
        for name in sorted(os.listdir(a.packages)):
            if not name.endswith(".json"):
                continue
            try:
                doc = json.load(open(os.path.join(a.packages, name), encoding="utf-8"))
            except (OSError, ValueError):
                continue
            b = (doc.get("blocked_on") or "").strip()
            if doc.get("file") and b:
                blocked_on[doc["file"]] = b
    n_decisions = len(decisions) + sum(1 if blocked_on.get(f) else len(rs)
                                       for f, rs in by_file.items())
    files = {r.get("path") or r.get("file") for r in primary.values()}

    L = ["# Ruling queue — security-remediate\n",
         "%d escalated finding(s) collapse to **%d decision(s)** and **%d ratification(s)** "
         "over %d file(s). Each entry below blocks the findings folded under it; the lane is "
         "not waiting on you — it records these and keeps working other files.\n"
         % (len(esc), n_decisions, len(signature), len(files)),
         "Answer a decision by setting its finding's ledger status, e.g.\n",
         "```bash",
         "python3 .claude/skills/security-remediate/scripts/ledger.py set <ledger> \\",
         "  --id <id> --status open --method review-adjudicated --note \"RULED: <the decision>\"",
         "```",
         "`open` returns it to the worklist with the ruling recorded; `constraint` "
         "with `--owner-ruling \"Ruling N\"` records a demonstrated architectural "
         "constraint you accepted. There is no accepted-risk: a real defect is fixed.\n"]

    for title, keys in (("Decisions", decisions), ("Ratifications — one surviving text, "
                                                   "owner-ratified surface", signature)):
        if keys:
            L.append("\n## %s\n" % title)
        for k in keys:
            rs = by_ruling[k]
            paths = sorted({r.get("path") or r.get("file") for r in rs})
            L.append("\n### [%s] `%s` — %d finding(s)\n"
                     % (SEV_NAME[_worst(rs)], k, len(rs) + sum(len(folded.get(r["id"], []))
                                                               for r in rs)))
            L.append("- **files**: %s" % ", ".join("`%s`" % p for p in paths))
            for r in sorted(rs, key=lambda r: SEV.get(str(r.get("severity", "")).lower(), 9)):
                kids = folded.get(r["id"], [])
                L.append("- [%s] %s `%s`%s" % (
                    str(r.get("severity", "")).upper(), r.get("title", ""), r["id"],
                    (" (+ %s)" % ", ".join("`%s`" % c["id"] for c in kids)) if kids else ""))
            L.append("- **evaluator**: %s" % (rs[0].get("notes") or "(no note recorded)"))
            L.append("- **decision**: " if not k.startswith(SIGN) else "- **ratified**: ")

    if by_file:
        L.append("\n## Escalations with no ruling id, by file\n")
    for f in sorted(by_file, key=lambda f: min(SEV.get(str(r.get("severity", "")).lower(), 9)
                                               for r in by_file[f])):
        L.append("\n### `%s`\n" % f)
        if blocked_on.get(f):
            L.append("> **THE DECISION for this file** — the evaluator that read it states every "
                     "escalation below waits on this one thing:\n>\n> %s\n"
                     % blocked_on[f].replace("\n", " "))
            L.append("- **ruling**: \n")
            L.append("<details><summary>the %d finding(s) it blocks</summary>\n" % len(by_file[f]))
        for r in sorted(by_file[f], key=lambda r: SEV.get(str(r.get("severity", "")).lower(), 9)):
            kids = folded.get(r["id"], [])
            L.append("\n#### [%s] %s  `%s`\n" % (str(r.get("severity", "")).upper(),
                                                r.get("title", ""), r["id"]))
            L.append("- **evaluator's finding**: %s" % (r.get("notes") or "(no note recorded)"))
            if kids:
                L.append("- **also waiting on this decision** (%d): %s"
                         % (len(kids), ", ".join("`%s`" % k["id"] for k in kids)))
            L.append("- **decision**: " if not blocked_on.get(f) else "")
        if blocked_on.get(f):
            L.append("\n</details>\n")
    out = "\n".join(L) + "\n"
    if a.out:
        open(a.out, "w").write(out)
        print("wrote %s: %d escalations -> %d decisions + %d ratifications over %d files"
              % (a.out, len(esc), n_decisions, len(signature), len(files)))
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
