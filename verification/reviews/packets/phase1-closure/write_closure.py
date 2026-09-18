#!/usr/bin/env python3
"""Render the Phase-1 closure report from a frozen derivation.

Consumes only the two derivations (phase1_closure.py, phase2_order.py). It carries
no number of its own, so a figure that is wrong here is wrong in the tree.
"""
import json, sys, collections

C = json.load(open(sys.argv[1]))
P = json.load(open(sys.argv[2]))
sh = C["census"]["shape"]
out = []
w = out.append

w("# ADR-MCPRE-068 Phase 1 — closure report\n")
w(f"Frozen main SHA: `{C['main_sha']}`\n")
w("Every figure below is derived from that tree. No count is carried forward from a")
w("branch, a packet, or an earlier measurement; the historical trajectory at the end is")
w("explanatory and is explicitly not an authority for any final number.\n")

w("## Final state\n")
w("| | |")
w("|---|---|")
w(f"| declared system roots | {len(C['roots'])} |")
w(f"| theorems | {C['theorems_total']} |")
w(f"| propositions (units) | {C['units_total']} |")
w(f"| premises, live | {C['premises_live']} of {C['premises_total']} "
  f"({len(C['premises_withdrawn'])} withdrawn) |")
for k, v in sorted(C["evidence_classes"].items(), key=lambda x: -x[1]):
    w(f"| evidence class `{k}` | {v} |")
for k, v in sorted(C["premise_classes"].items(), key=lambda x: -x[1]):
    w(f"| premise class `{k}` | {v} |")
w(f"| N1 open obligations | **{C['n1_open']}** |")
for k in ("critical", "high", "medium"):
    if k in C["n1_by_effective"]:
        w(f"| N1 {k} | {C['n1_by_effective'][k]} |")
w(f"| N1 root-reachable | {C['n1_root_reachable']} |")
w(f"| N1 not root-reachable | {C['n1_not_root_reachable']} |")
w("")

w("## Per root — final state and the reason it reached it\n")
w("| root | closure (thm/unit) | new units | reason(s) |")
w("|---|---|---|---|")
for r, v in C["root_state"].items():
    w(f"| {r} | {v['closure_theorems']} / {v['closure_units']} | "
      f"{v['units_new_since_baseline']} | {'; '.join(v['reasons'])} |")
w("")
for r, v in C["root_state"].items():
    if v["formal_carriers_added"]:
        w(f"* **{r}** gained formal carriers: "
          + ", ".join(f"`{x}`" for x in v["formal_carriers_added"]))
w("")

w("## Phase-2 order, derived from the frozen graph\n")
w("| enabling lane | N1 rows | critical | roots unblocked |")
w("|---|---|---|---|")
for k, v in sorted(P["lanes"].items(), key=lambda x: -x[1]["critical"]):
    w(f"| `{k}` | {v['rows']} | {v['critical']} | {', '.join(v['roots_unblocked'])} |")
w("")
w("First ten individual obligations, severity then fan-out:\n")
w("| effective | blocks | roots | lane | proposition |")
w("|---|---|---|---|---|")
for x in P["ordered"][:10]:
    w(f"| {x['effective']} | {x['fanout']} | {len(x['blocking_roots'])} | "
      f"`{x['lane']}` | `{x['unit']}` |")
w("")

w("## Repository-state condition\n")
held = C["branches_holding_unmerged_registry_changes"]
w(f"* correction records citing a packet not in the tree: "
  f"**{len(C['records_citing_a_missing_packet'])}**")
w(f"* campaign branches examined: {C['campaign_branches_examined']}; holding a record, "
  f"probe or unit main has never held: **{len(held)}**")
if held:
    for b, v in held.items():
        w(f"  * `{b}`: {v}")
w(f"* unit ids that have ever stood on main: {C['unit_ids_ever_on_main']} "
  f"(a branch holding a superseded id is not holding unmerged work)")
w("")

w("## Gates at the frozen SHA\n")
for name, g in C["gates"].items():
    w(f"* `{name}` rc={g['rc']} — {g['tail'][-1] if g['tail'] else ''}")
w("")

print("\n".join(out))
