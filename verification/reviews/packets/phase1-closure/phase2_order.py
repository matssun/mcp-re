#!/usr/bin/env python3
"""ADR-MCPRE-068 Phase-2 dependency order, derived from the frozen graph.

NOT "work row 1 of the N1 table". The ratified scheduler orders by effective
consequence severity, then by how many higher propositions an obligation blocks,
then puts shared enabling lanes ahead of the individual obligations they unblock.
A lane that unblocks eleven Critical leaves outranks an isolated Medium leaf, and
that is a property of the graph rather than of the table's row order.
"""
import collections, json, subprocess, sys, pathlib
try: import tomllib
except ModuleNotFoundError: import tomli as tomllib

REPO = pathlib.Path(subprocess.run(["git","rev-parse","--show-toplevel"],
                    capture_output=True,text=True,check=True).stdout.strip())
def load(rel): return tomllib.loads((REPO/rel).read_text())

theorems = load("verification/policy/theorems.toml")
T   = {t["id"]: t for t in theorems["theorem"]}
ROOTS = list(theorems["root_theorems"])
U   = {u["id"]: u for u in load("verification/policy/verification.toml")["unit"]}
DEBT= load("config/assurance-obligation-debt.toml")["obligation"]

# which theorems a unit carries, and which roots reach those theorems
carries = collections.defaultdict(set)
for t in T.values():
    for s in t.get("supported_by", []):
        carries[s.split("://",1)[-1]].add(t["id"])

def closure(root):
    seen, stack = {root}, [root]
    while stack:
        for d in T.get(stack.pop(), {}).get("depends_on", []):
            if d not in seen: seen.add(d); stack.append(d)
    return seen
root_closure = {r: closure(r) for r in ROOTS}

SEV = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# A SHARED ENABLING LANE is not guessed from the unit name: it is the ecosystem the
# unit's production carrier lives in, which is what decides whether one falsifier
# mechanism can serve many obligations. Units whose paths share an ecosystem need the
# same lane built once.
def lane(uid):
    paths = U.get(uid, {}).get("paths", [])
    if any(p.endswith(".py") or "/python" in p or p.startswith("sdk/python") for p in paths): return "python-falsifier-lane"
    if any(p.endswith((".ts",".js")) or "/typescript" in p for p in paths): return "node-falsifier-lane"
    return "cargo-mutation-lane"

rows = []
for r in DEBT:
    uid = r["unit"]
    ths = carries.get(uid, set())
    blocking_roots = sorted(x for x in ROOTS if root_closure[x] & ths)
    # fan-out: how many propositions above this one stop being established if it is
    fanout = sum(1 for t in T if closure(t) & ths and t not in ths)
    rows.append({
        "unit": uid,
        "effective": r["effective_severity"],
        "root_reachable": r.get("root_reachable", False),
        "theorems": sorted(ths),
        "blocking_roots": blocking_roots,
        "fanout": fanout,
        "lane": lane(uid),
        "evidence_class": U.get(uid, {}).get("evidence_class"),
    })

lanes = collections.defaultdict(lambda: {"rows": 0, "critical": 0, "roots": set()})
for x in rows:
    L = lanes[x["lane"]]
    L["rows"] += 1
    L["critical"] += x["effective"] == "critical"
    L["roots"] |= set(x["blocking_roots"])

rows.sort(key=lambda x: (-SEV.get(x["effective"],0), -x["fanout"], -len(x["blocking_roots"]), x["unit"]))
print(json.dumps({
    "lanes": {k: {"rows": v["rows"], "critical": v["critical"],
                  "roots_unblocked": sorted(v["roots"])} for k, v in lanes.items()},
    "ordered": rows,
}, indent=1))
