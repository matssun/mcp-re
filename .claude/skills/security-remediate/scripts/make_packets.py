"""make_packets.py — per-file audit packets from one or more rounds' findings.json.

`file_findings.py` joins the ledger (disposition truth) to a per-file packet
(finding content). Review rounds emit one flat findings list; this regroups it by
file and maps each finding's content fields onto the packet vocabulary, so every
round lands in the same shape whatever its lens prompt called the fields.

Usage:
  make_packets.py --out <dir> <findings.json> [<findings.json> ...]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict

# packet field <- the first finding field present, in this order
FIELD_MAP = {
    "claim": ("claim", "detail", "description"),
    "impact": ("impact", "why_it_matters"),
    "remediation": ("remediation", "suggested_fix", "recommendation"),
    "evidence": ("evidence", "excerpt"),
    "confidence": ("confidence",),
    "reported_by": ("lens", "reported_by"),
    "needs_outside_packet": ("needs_outside_packet",),
    "round_id": ("id",),
}


def _first(f: dict, keys: tuple[str, ...]):
    for k in keys:
        if f.get(k) not in (None, ""):
            return f[k]
    return None


def packet_rows(paths: list[str]) -> dict[str, list[dict]]:
    by_file: dict[str, list[dict]] = defaultdict(list)
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            doc = json.load(fh)
        for f in doc if isinstance(doc, list) else doc.get("findings", []):
            path = (f.get("file") or f.get("location") or "").split(":")[0].strip()
            if not path:
                continue
            row = {"title": f.get("title"), "line": f.get("line"), "severity": f.get("severity"),
                   "provisional": bool(f.get("needs_outside_packet"))}
            for dst, src in FIELD_MAP.items():
                v = _first(f, src)
                if v is not None:
                    row[dst] = v
            by_file[path].append(row)
    return by_file


def main() -> int:
    ap = argparse.ArgumentParser(description="per-file audit packets from findings.json rounds")
    ap.add_argument("--out", required=True)
    ap.add_argument("findings", nargs="+")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    by_file = packet_rows(a.findings)
    for path, rows in sorted(by_file.items()):
        name = hashlib.sha1(path.encode()).hexdigest()[:12] + ".json"
        with open(os.path.join(a.out, name), "w", encoding="utf-8") as fh:
            json.dump({"file": path, "findings": rows}, fh, indent=1)
    print("make_packets: %d file(s), %d finding(s) -> %s"
          % (len(by_file), sum(len(r) for r in by_file.values()), a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
