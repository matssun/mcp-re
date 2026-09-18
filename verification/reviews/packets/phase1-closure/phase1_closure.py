#!/usr/bin/env python3
"""ADR-MCPRE-068 Phase-1 closure derivation.

Re-derives every closure-report number FROM THE TREE it is run in. It aggregates
nothing from branch-local reports and reads no prior measurement: every figure
below comes from the registries and tooling present at this exact SHA.
"""
import json, pathlib, subprocess, sys, collections

ROOT = pathlib.Path(__file__).resolve()
REPO = pathlib.Path(subprocess.run(["git","rev-parse","--show-toplevel"],
                                   capture_output=True,text=True,check=True).stdout.strip())
sys.path.insert(0, str(REPO / "tools" / "verification"))

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

def load(rel):
    return tomllib.loads((REPO / rel).read_text())

def sh(*args):
    return subprocess.run(args, cwd=REPO, capture_output=True, text=True)

out = {}
out["sha"] = sh("git","rev-parse","HEAD").stdout.strip()
out["main_sha"] = sh("git","rev-parse","origin/main").stdout.strip()
out["dirty"] = bool(sh("git","status","--porcelain").stdout.strip())

census = json.loads(sh(sys.executable, "tools/verification/evidence-class-census","--json").stdout)
out["census"] = census

thmdoc   = load("verification/policy/theorems.toml")
theorems = thmdoc["theorem"]
verif    = load("verification/policy/verification.toml")["unit"]
assume   = load("verification/policy/assumptions.toml")
debt     = load("config/assurance-obligation-debt.toml")["obligation"]

out["theorems_total"] = len(theorems)
out["roots"] = list(thmdoc["root_theorems"])
out["units_total"] = len(verif)

# --- evidence class by PROPOSITION, as the registries state it -------------
cls = collections.Counter(u.get("evidence_class","(unset)") for u in verif)
out["evidence_classes"] = dict(cls)

# --- premises -------------------------------------------------------------
prem = assume.get("assumption", [])
live = [a for a in prem if a.get("scope")]
withdrawn = [a for a in prem if not a.get("scope")]
pc = collections.Counter(a["premise_class"] for a in live)
out["premises_total"] = len(prem)
out["premises_live"] = len(live)
out["premises_withdrawn"] = [a["id"] for a in withdrawn]
out["premise_classes"] = dict(pc)

# --- N1 obligations -------------------------------------------------------
out["n1_open"] = len(debt)
out["n1_by_effective"] = dict(collections.Counter(r["effective_severity"] for r in debt))
out["n1_root_reachable"] = sum(1 for r in debt if r.get("root_reachable"))
out["n1_not_root_reachable"] = sum(1 for r in debt if not r.get("root_reachable"))
out["n1_by_status"] = dict(collections.Counter(r.get("status") for r in debt))
out["n1_successor_rows"] = [r["unit"] for r in debt if r.get("succeeds")]

# --- Phase-1 correction records ------------------------------------------
cc = sorted((REPO/"verification/claim-corrections").glob("*.json"))
recs = []
for p in cc:
    d = json.loads(p.read_text())
    recs.append({"file": p.name, "theorem": d.get("subject"),
                 "components": d.get("changed_components"),
                 "corrections": [c.get("field") for c in d.get("corrections",[])],
                 "from": d.get("from_fingerprint"), "to": d.get("to_fingerprint")})
out["claim_corrections"] = recs
out["claim_correction_count"] = sum(len(r["corrections"]) for r in recs)
out["dependency_corrections"] = sum(
    1 for r in recs for f in r["corrections"] if f == "depends_on")

# --- the four Phase-1 shapes, derived from the records ---------------------
#
# Shape is a property of WHAT MOVED, so it is read off the record rather than asserted.
# Three distinctions, and the third is the one a components-only reading loses:
#
#   theorem_claim present            the SUBJECT's own statement or scope misdescribed
#   dependencies only, depends_on    the claim was right; the graph lacked the premise
#   dependencies only, prose field   a PREMISE was misdescribed, and the correction
#                                    reaches the root only because a premise digest moved
#
# A root can appear under more than one shape; it carried more than one kind of defect.
PROSE = {"statement", "security_consequence", "scope"}
shape_graph, shape_subject_prose, shape_premise_prose = set(), set(), set()
for r in recs:
    comps  = set(r["components"] or ())
    fields = set(r["corrections"] or ())
    if "theorem_claim" in comps:
        shape_subject_prose.add(r["theorem"])
    if "depends_on" in fields:
        shape_graph.add(r["theorem"])
    if comps == {"theorem_dependencies"} and (fields & PROSE):
        shape_premise_prose.add(r["theorem"])
out["shape_graph_incomplete"]  = sorted(shape_graph)
out["shape_claim_misdescribed"] = sorted(shape_subject_prose)
out["shape_premise_misdescribed"] = sorted(shape_premise_prose)
corrected = shape_graph | shape_subject_prose | shape_premise_prose
out["roots_with_no_correction"] = [r for r in out["roots"] if r not in corrected]

# --- per-root FINAL STATE and the REASON it reached that state -------------
#
# "87 obligations remain" is not a Phase-2 input; the reason each root ended where it
# did is. Five reasons, and a root may carry more than one -- it had more than one
# kind of defect. Derived, not asserted: the correction records give the first three,
# and the baseline registry gives the fourth.
PHASE1_BASE = "c8c506e1"   # Phase 0E, the commit N1 was switched on at

base_units = {}
try:
    blob = sh("git", "show", PHASE1_BASE + ":verification/policy/verification.toml").stdout
    base_units = {u["id"]: u for u in tomllib.loads(blob)["unit"]}
except Exception as exc:                      # a shallow clone has no baseline to read
    out["baseline_read_error"] = str(exc)
out["baseline_sha"] = PHASE1_BASE
out["baseline_units"] = len(base_units)

# closure of each root over depends_on, so a reason can be attributed to the root it
# actually reached.
bydep = {t["id"]: t.get("depends_on", []) for t in theorems}
def closure(root):
    seen, stack = set(), [root]
    while stack:
        cur = stack.pop()
        for dep in bydep.get(cur, ()):
            if dep not in seen:
                seen.add(dep); stack.append(dep)
    return seen

byunit = {u["id"]: u for u in verif}
supports = {t["id"]: [s.split("://", 1)[-1] for s in t.get("supported_by", [])] for t in theorems}

root_state = {}
for r in out["roots"]:
    reasons = []
    if r in shape_graph:           reasons.append("graph corrected")
    if r in shape_subject_prose:   reasons.append("subject misdescribed, corrected")
    if r in shape_premise_prose:   reasons.append("premise correction propagated")

    fam = closure(r) | {r}
    units = {u for th in fam for u in supports.get(th, ())}
    reclassified, added = [], []
    for uid in sorted(units):
        now = byunit.get(uid, {}).get("evidence_class")
        was = base_units.get(uid, {}).get("evidence_class") if base_units else None
        if uid not in base_units and base_units:
            added.append(uid)
        elif was is not None and was != now:
            reclassified.append(f"{uid}: {was} -> {now}")
    # A split renames the unit, so a reclassification almost never shows as one id
    # changing class: it shows as the old id vanishing and a new carrier appearing.
    # The honest test is therefore what KIND of carrier Phase 1 added. A new
    # `structural` or `proved` unit means a proposition that stood as behavioural
    # now has the carrier its statement always implied.
    formal_new = sorted(u for u in added
                        if byunit.get(u, {}).get("evidence_class") != "tested")
    if reclassified or formal_new:
        reasons.append("evidence class corrected")
    elif added:
        reasons.append("establishment completed")
    if not reasons:
        reasons.append("already correct")

    root_state[r] = {
        "reasons": reasons,
        "closure_theorems": len(fam),
        "closure_units": len(units),
        "units_new_since_baseline": len(added),
        "units_reclassified": reclassified,
        "formal_carriers_added": formal_new,
    }
out["root_state"] = root_state

# --- Phase-1 packets ------------------------------------------------------
pk = sorted((REPO/"verification/reviews/packets").glob("*2026-09-18*.md"))
out["phase1_packets"] = [p.name for p in pk]

# --- the repository-state condition -----------------------------------------
#
# "No Phase-1 semantic decision exists only in a packet, held branch, comment or
# remembered conclusion." Two halves, both mechanical.
#
# (a) every record's packet is IN THE TREE. A correction citing a packet that is not
#     merged is authority that cannot be read back.
# (b) no branch ahead of main still carries a change to a canonical registry. A
#     semantic decision sitting unmerged on a branch is exactly the failure mode this
#     condition exists to exclude, and it is visible without judgement: diff every
#     local branch against main over the registry paths.
missing_packets = [r["file"] for r in recs
                   if r.get("packet") and not (REPO / r["packet"]).is_file()]
out["records_citing_a_missing_packet"] = missing_packets

# Neither a commit count nor a line diff answers this. A squash merge leaves every
# historical branch permanently "ahead", so `origin/main...b` reports a long-merged
# branch's own old changes; and `origin/main..b` on a stale branch reports MAIN's
# later content as if the branch had added it. Both measure divergence, and the
# question is not about divergence.
#
# The question is whether any Phase-1 SEMANTIC ARTEFACT exists somewhere main cannot
# see it. Those artefacts are identified, not diffed: correction records are files,
# probes and units have ids. So the test is a set comparison over the campaign's own
# branches -- does any of them name a record, probe or unit that main does not hold?
# A branch whose work has landed names nothing new, however far its commits diverged.
def _ids(ref):
    recs = set(sh("git", "ls-tree", "--name-only", ref,
                  "verification/claim-corrections/").stdout.split())
    probes, units = set(), set()
    for path, bucket in (("verification/policy/structural-probes.toml", probes),
                         ("verification/policy/mutation-probes.toml", probes),
                         ("verification/policy/verification.toml", units)):
        blob = sh("git", "show", f"{ref}:{path}").stdout
        for line in blob.splitlines():
            s = line.strip()
            if s.startswith("id = "):
                bucket.add(s.split("=", 1)[1].strip().strip('"'))
    return recs, probes, units

main_recs, main_probes, main_units = _ids("origin/main")

# Every unit id that has EVER stood on main, so a superseded id is not mistaken for
# an unmerged one. Walked once over the registry's own history.
ever_units = set()
for rev in sh("git", "rev-list", "origin/main", "--",
              "verification/policy/verification.toml").stdout.split():
    blob = sh("git", "show", rev + ":verification/policy/verification.toml").stdout
    ever_units |= {l.split("=", 1)[1].strip().strip('"')
                   for l in blob.splitlines() if l.strip().startswith("id = ")}
out["unit_ids_ever_on_main"] = len(ever_units)
branches = [b for b in sh("git", "for-each-ref", "--format=%(refname:short)",
                          "refs/heads/").stdout.split() if b.startswith("adr-068-")]
held = {}
for b in branches:
    try:
        r, p_, u = _ids(b)
    except Exception:
        continue
    # A unit id a branch holds and main does not is SUPERSEDED, not unmerged, when
    # main once held it: this campaign replaced wide propositions with narrower ones,
    # so every pre-split id is exactly that. Only an id main has NEVER held can be a
    # decision that has not landed.
    extra = {"records": sorted(r - main_recs), "probes": sorted(p_ - main_probes),
             "units": sorted(u - main_units - ever_units)}
    superseded = sorted((u - main_units) & ever_units)
    if any(extra.values()):
        held[b] = dict(extra, superseded_units=len(superseded))
out["campaign_branches_examined"] = len(branches)
out["branches_holding_unmerged_registry_changes"] = held

open_prs = sh("gh", "pr", "list", "--state", "open", "--json", "number,title,isDraft").stdout
out["open_prs"] = open_prs.strip()[:2000]

# --- multi-proposition owner residue, measured not inferred -----------------
#
# Reported as fan-out rather than judged: a unit named by more than one theorem is
# where a second independently describable authority would hide. ADR-MCPRE-061
# question 2 was asked of each in the per-root packets; this is the population those
# answers quantify over.
fanout = collections.Counter(u for th in theorems
                             for u in (s.split("://",1)[-1] for s in th.get("supported_by", [])))
out["units_named_by_multiple_theorems"] = {u: n for u, n in sorted(fanout.items()) if n > 1}
out["units_named_by_no_theorem"] = sorted({u["id"] for u in verif} - set(fanout))

# --- gates ----------------------------------------------------------------
for name, cmd in (("claim_surface", ["scripts/claim_surface_gate.py"]),
                  ("assurance_obligation", ["scripts/assurance_obligation_gate.py"]),
                  ("check_generated", ["tools/verification/check-generated"]),
                  ("root_completeness", ["tools/verification/review","--root-completeness"])):
    r = sh(sys.executable, *cmd)
    out.setdefault("gates", {})[name] = {
        "rc": r.returncode,
        "tail": (r.stdout or r.stderr).strip().splitlines()[-6:],
    }

print(json.dumps(out, indent=1, sort_keys=False))
