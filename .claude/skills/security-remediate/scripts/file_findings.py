#!/usr/bin/env python3
"""file_findings.py — every actionable finding on ONE file, joined to its audit packet.

The ledger holds the DISPOSITION truth (id, status, severity, title); the audit
packet holds the CONTENT a fixer needs (the verbatim evidence excerpt, the claim,
the impact, the suggested remediation, which lens reported it). This joins them so
an evaluator makes one call instead of grepping two artifacts.

The evidence excerpt is the anchor: line numbers come from the audit pin and drift
as soon as anything above them is edited, so a fixer must locate a finding by its
text, not its number.

Usage:
  file_findings.py --ledger <ledger.jsonl> --file <repo-relative path> [--packets <dir>] [--all]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# The one definition of "still needs a decision"; next_file.py and dispose.py import it.
# `needs-senior-eval`: a cheap evaluator proposed a closure the senior tier must decide.
# `provisional`: the audit packet could not decide the claim, so the evaluator must,
# with the whole tree in view. `confirmed`: verified real, not yet fixed.
ACTIONABLE = {"open", "regression", "needs-senior-eval", "provisional", "confirmed"}
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def packet_for(packets_dir: str, path: str) -> dict:
    """Find the packet by its declared `file`, never by its filename.

    Packet filenames are slugs (hyphenated, truncated); matching on them silently
    returns nothing for any path whose basename contains an underscore, and a
    missing packet looks identical to a clean file.
    """
    if not packets_dir or not os.path.isdir(packets_dir):
        return {}
    for name in sorted(os.listdir(packets_dir)):
        if not name.endswith(".json"):
            continue
        try:
            doc = json.load(open(os.path.join(packets_dir, name), encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if doc.get("file") == path:
            return doc
    return {}


def collect(ledger: str, path: str, packets: str | None, include_all: bool = False) -> dict:
    """The joined view for one file. `main` prints it; `prepare.py` embeds it."""
    rows = []
    with open(ledger, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if (r.get("path") or r.get("file")) != path:
                continue
            if not include_all and str(r.get("status", "")).lower() not in ACTIONABLE:
                continue
            rows.append(r)

    pkt = packet_for(packets, path)
    # Join on (line, title): the packet is the same round's content for this id.
    content = {}
    for f in pkt.get("findings", []):
        content[(f.get("line"), f.get("title"))] = f
        content[f.get("title")] = f

    out = []
    for r in sorted(rows, key=lambda r: SEV.get(str(r.get("severity", "")).lower(), 9)):
        c = content.get((r.get("line"), r.get("title"))) or content.get(r.get("title")) or {}
        out.append({
            "id": r["id"], "severity": r.get("severity"), "category": r.get("category"),
            "title": r.get("title"), "status": r.get("status"),
            "line_at_audit_pin": r.get("line"),
            "lens": r.get("lens"), "unit": r.get("unit"),
            "claim": c.get("claim"), "evidence_anchor": c.get("evidence"),
            "impact": c.get("impact"), "suggested_remediation": c.get("remediation"),
            "confidence": c.get("confidence"), "provisional": c.get("provisional"),
            "reported_by": c.get("reported_by"),
            "notes": r.get("notes") or None,
        })
    return {"file": path, "n": len(out),
            "packet_found": bool(pkt),
            "liveness": pkt.get("liveness"),
            "findings": out}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--packets", default=None)
    ap.add_argument("--all", action="store_true", help="include already-terminal findings too")
    a = ap.parse_args()
    print(json.dumps(collect(a.ledger, a.file, a.packets, a.all), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
