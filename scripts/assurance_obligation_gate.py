#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The N1 obligation ratchet — ADR-MCPRE-068 §9.4, Phase 0E.

N1: any proposition classified `tested` whose EFFECTIVE consequence severity is Medium,
High or Critical must name a registered falsifier attacking its production property.
Switching that on against a tree that predates the rule would have meant discharging 63
obligations in one change, so the residue is recorded in
`config/assurance-obligation-debt.toml` and this gate holds it.

WHAT MAKES IT A RATCHET RATHER THAN A WAIVER, and every clause below is one of the four
mechanical consequences the ratification attached to the registry:

    a unit that OWES and is not registered      -> FAIL. The registry is closed to new
                                                   work: an obligation that did not exist
                                                   at the baseline is discharged or fails.
    a registered unit that no longer owes       -> FAIL until the row is removed. A dead
                                                   row hides the next live one, the same
                                                   rule `merge_path_gate.EXEMPT` follows.
    a row whose effective severity has MOVED    -> FAIL. The obligation is not the one the
                                                   row records, so the row does not cover
                                                   it. Raising severity is "materially
                                                   changed" and may not buy a new entry.
    the registry GREW against origin/main      -> FAIL. It may only shrink, except by
                                                   SUCCESSION (below), the one way a
                                                   row count may rise.
    a status returning to `unreviewed`          -> FAIL. The lifecycle is one-way.
    a reviewed row with no live `review_ref`    -> FAIL. A completed review points at a
                                                   record, not at a memory of one.

SUCCESSION — the one way a row count may rise, and why it is not a loophole.

ADR-MCPRE-068 Phase 1 decomposes a root's one wide proposition into the several narrow
propositions it was always the conjunction of. A wide `tested` unit that OWED a falsifier
becomes several narrow `tested` units that owe one each. Under the rules above that is
indistinguishable from new work: the predecessor's row goes dead and every successor is an
unregistered owing unit. Phase 1 could then land no decomposition of an obligated
proposition at all — the ratchet built to stop obligations APPEARING would be stopping them
from being stated more precisely, which is the opposite of its purpose.

So a row may carry `succeeds` and `decomposition_ref`, and five things must hold together:

    the row is NOT already in the base registry        succession authorizes an ADDITION;
                                                       once the row is in the base it is an
                                                       ordinary row and the fields are
                                                       provenance
    the predecessor is a row in the BASE registry      succession refines an obligation that
                                                       already existed; it cannot invent one
    the predecessor is gone from the registry AND      the wide proposition no longer exists
    from the measured population                       or no longer owes. One that still
                                                       owes keeps its own row and succeeds
                                                       nothing
    every successor's effective severity is at most    a decomposition may not RAISE what is
    the predecessor's                                  at stake
    every successor unit's `paths` are a SUBSET of     the obligation is refined over the
    the predecessor's paths at the base                 same production code. New code cannot
                                                       ride a succession
    `decomposition_ref` names a file this tree holds   the decomposition points at its record
                                                       rather than at a memory of one

ONE AUTHORIZATION BUYS ONE TRANSITION, by the mechanism the module-size registry's
`growth_ref` uses: after merge the predecessor is no longer in the base registry, so a later
row naming it fails the first clause. A spent succession matches nothing.

AND THE MERGE IS WHAT SPENDS IT, which is why succession is validated only for rows the base
does NOT already hold. Once a successor row is in the base registry it is an ordinary
pre-existing row; its `succeeds` and `decomposition_ref` stay as PROVENANCE — a reader of the
registry can still see where the obligation came from — but they authorize nothing, because
there is nothing left to authorize. Validating them again would fail every merged
decomposition forever, on the strength of a predecessor its own merge removed. That is not
the ratchet working; it is the ratchet refusing the state it just created.

Succession discharges NOTHING. Successor rows are ordinary open obligations, INCOMPLETE like
every other row, bounding the same production code measured more finely.

WHAT IT DELIBERATELY DOES NOT DO. It does not make a registered obligation satisfied. Rows
stay INCOMPLETE, `review` prints them as open obligations, and an incomplete proposition
does not satisfy a root assurance dependency. The registry bounds the population and
records what closing a row would mean; it never subtracts from the obligation.

Run:  python3 scripts/assurance_obligation_gate.py
      python3 scripts/assurance_obligation_gate.py --selftest
      python3 scripts/assurance_obligation_gate.py --base origin/main
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REGISTRY_REL = "config/assurance-obligation-debt.toml"
REGISTRY = REPO / REGISTRY_REL

sys.path.insert(0, str(REPO / "tools" / "verification"))

STATUSES = ("unreviewed", "reviewed-action-required", "reviewed-exception")
REVIEWED = STATUSES[1:]

_KEYS = {
    "unit",
    "obligation",
    "effective_severity",
    "direct_consequence_severity",
    "inherited_severity",
    "root_reachable",
    "status",
    "review_ref",
    "succeeds",
    "decomposition_ref",
}
_OPTIONAL = {"review_ref", "succeeds", "decomposition_ref"}

#: The registry whose `paths` decide whether a successor refines the SAME production code.
#:
#: Read at the base revision rather than here, because that is the tree the predecessor's
#: obligation was measured over. A successor could otherwise be given the predecessor's
#: paths in the same commit that widens them.
UNITS_REL = "verification/policy/verification.toml"


def owing() -> dict[str, dict]:
    """Every `tested` proposition that owes a falsifier now, with the severities it owes at.

    The one authority on WHO OWES is `_assurance_graph`, deliberately: the loader and
    `review` read the same derivation, and a gate that recomputed severity its own way could
    hold a baseline against a population nobody else agrees on.
    """
    import _assurance_graph as graph
    import _manifest
    import _theorems

    units = _manifest.load_verification()
    theorems = _theorems.load_theorems({unit["id"] for unit in units["unit"]})
    return graph.unmet_obligations(theorems, units)


def current_unit_paths() -> dict[str, set[str]]:
    """Each unit's declared `paths` as this tree has them."""
    import _manifest

    return {
        unit["id"]: set(unit.get("paths", []))
        for unit in _manifest.load_verification().get("unit", [])
    }


def load_registry(path: Path = REGISTRY) -> dict[str, dict]:
    """The registry, validated strictly — an unknown key is a failure, not an ignored field.

    A missing file is an empty registry rather than an error, and that is not a loophole:
    with no rows, every owing proposition is unregistered and fails immediately.
    """
    if not path.is_file():
        return {}
    with path.open("rb") as handle:
        doc = tomllib.load(handle)
    rows: dict[str, dict] = {}
    for index, row in enumerate(doc.get("obligation", [])):
        where = f"{path.name} [[obligation]] #{index + 1}"
        unknown = set(row) - _KEYS
        if unknown:
            raise ValueError(f"{where}: unknown key(s) {sorted(unknown)}")
        missing = _KEYS - _OPTIONAL - set(row)
        if missing:
            raise ValueError(f"{where}: missing required key(s) {sorted(missing)}")
        if row["status"] not in STATUSES:
            raise ValueError(
                f"{where}: `status` is {row['status']!r}, not one of {list(STATUSES)}."
            )
        if not str(row["obligation"]).strip():
            raise ValueError(
                f"{where}: `obligation` is empty. A row names the obligation it owes, or "
                f"the registry cannot say what closing the row would mean."
            )
        if row["unit"] in rows:
            raise ValueError(f"{where}: duplicate unit {row['unit']!r}")
        rows[row["unit"]] = row
    return rows


def base_registry(base: str, repo: Path = REPO) -> dict[str, dict] | None:
    """The registry as `base` has it, or None when that revision is unavailable.

    UNAVAILABLE IS NOT EMPTY, the same rule the class-transition ratchet follows: a checkout
    that cannot resolve `origin/main` has no baseline, and reading that as "the registry was
    empty" would turn every existing row into an illegal addition.
    """
    proc = subprocess.run(
        ["git", "show", f"{base}:{REGISTRY_REL}"], cwd=repo, capture_output=True
    )
    if proc.returncode != 0:
        return None
    doc = tomllib.loads(proc.stdout.decode("utf-8"))
    return {row["unit"]: row for row in doc.get("obligation", [])}


def _severity_rank(name: str) -> int:
    """The severity's rank in the one declared vocabulary.

    Imported rather than restated: `_evidence_class` is the single authority on the closed
    vocabulary and its order, and a second copy here would let the gate compare severities
    the graph does not recognise.
    """
    from _evidence_class import SEVERITY_ORDER

    return SEVERITY_ORDER[name]


def base_unit_paths(base: str, repo: Path = REPO) -> dict[str, set[str]] | None:
    """Each unit's declared `paths` at `base`, or None when that revision is unavailable.

    UNAVAILABLE IS NOT EMPTY, the same rule `base_registry` follows: an empty mapping would
    read as "the predecessor declared no paths", under which every successor's paths are
    trivially NOT a subset and a legitimate succession fails — or, with the test inverted,
    every one passes. Neither is a fact about the tree.
    """
    proc = subprocess.run(
        ["git", "show", f"{base}:{UNITS_REL}"], cwd=repo, capture_output=True
    )
    if proc.returncode != 0:
        return None
    doc = tomllib.loads(proc.stdout.decode("utf-8"))
    return {unit["id"]: set(unit.get("paths", [])) for unit in doc.get("unit", [])}


def succession_defects(
    registry: dict[str, dict],
    measured: dict[str, dict],
    before: dict[str, dict] | None,
    base_paths: dict[str, set[str]] | None,
    now_paths: dict[str, set[str]],
    repo: Path = REPO,
) -> tuple[list[str], set[str]]:
    """Validate every row claiming succession; return its defects and the rows it excuses.

    A row is EXCUSED from the shrink-only rule only if it survives every clause here, so a
    malformed succession does not both fail and buy growth.
    """
    found: list[str] = []
    excused: set[str] = set()
    for unit in sorted(registry):
        row = registry[unit]
        predecessor = str(row.get("succeeds") or "").strip()
        reference = str(row.get("decomposition_ref") or "").strip()
        if not predecessor and not reference:
            continue
        if before is not None and unit in before:
            # SPENT BY ITS OWN MERGE. The row is in the base, so it is an ordinary
            # pre-existing obligation and these fields are provenance rather than authority.
            # Re-validating them would fail every merged decomposition forever, against a
            # predecessor its own merge removed.
            continue
        if not predecessor or not reference:
            found.append(
                f"registry row for {unit!r} declares only one half of a succession "
                f"(succeeds={predecessor!r}, decomposition_ref={reference!r}). A succession "
                f"is an obligation refined over recorded reasoning: both halves, or neither."
            )
            continue
        if not (repo / reference).is_file():
            found.append(
                f"registry row for {unit!r} names decomposition_ref {reference!r}, which "
                f"this tree does not hold. A decomposition points at its record rather than "
                f"at a memory of one."
            )
            continue
        if predecessor == unit:
            found.append(
                f"registry row for {unit!r} succeeds itself. A succession replaces one "
                f"proposition with narrower ones; a row that is its own predecessor records "
                f"no decomposition and would renew its own authorization every merge."
            )
            continue
        if predecessor in registry or predecessor in measured:
            found.append(
                f"registry row for {unit!r} succeeds {predecessor!r}, which still owes: it "
                f"is {'in the registry' if predecessor in registry else 'measured as owing'}."
                f" A predecessor that still exists keeps its own row and is succeeded by "
                f"nothing — otherwise one obligation would be registered twice."
            )
            continue
        if before is None:
            found.append(
                f"registry row for {unit!r} claims succession from {predecessor!r}, and the "
                f"base revision is unavailable, so it cannot be checked. A succession is an "
                f"authorization against the base; an uncheckable one is refused rather than "
                f"assumed."
            )
            continue
        if predecessor not in before:
            found.append(
                f"registry row for {unit!r} succeeds {predecessor!r}, which the base "
                f"registry does not hold. Succession refines an obligation that already "
                f"existed — it cannot invent one, and an authorization spent by an earlier "
                f"merge names nothing here."
            )
            continue
        ceiling = before[predecessor].get("effective_severity")
        mine = row.get("effective_severity")
        if _severity_rank(str(mine)) > _severity_rank(str(ceiling)):
            found.append(
                f"registry row for {unit!r} succeeds {predecessor!r} at effective severity "
                f"{mine!r}, above the predecessor's {ceiling!r}. A decomposition may state "
                f"an obligation more precisely; it may not raise what is at stake."
            )
            continue
        if base_paths is None:
            found.append(
                f"registry row for {unit!r} claims succession from {predecessor!r}, and "
                f"{UNITS_REL} is unavailable at the base, so the production code the "
                f"obligation covers cannot be compared."
            )
            continue
        widened = sorted(now_paths.get(unit, set()) - base_paths.get(predecessor, set()))
        if widened:
            found.append(
                f"registry row for {unit!r} succeeds {predecessor!r} but declares path(s) "
                f"{widened} the predecessor did not cover. A succession refines an "
                f"obligation over the SAME production code; new code does not ride one."
            )
            continue
        excused.add(unit)
    return found, excused


def defects(
    measured: dict[str, dict],
    registry: dict[str, dict],
    before: dict[str, dict] | None,
    repo: Path = REPO,
    base_paths: dict[str, set[str]] | None = None,
    now_paths: dict[str, set[str]] | None = None,
) -> list[str]:
    """Every way the registry and the measured obligations disagree."""
    found: list[str] = []
    succession, excused = succession_defects(
        registry, measured, before, base_paths, now_paths or {}, repo
    )
    found.extend(succession)

    for unit in sorted(set(measured) - set(registry)):
        found.append(
            f"unit {unit!r} owes a falsifier under N1 (effective severity "
            f"{measured[unit]['effective_severity']!r}) and is not in the registry. The "
            f"migration ratchet is CLOSED to new work: a proposition that gains an "
            f"obligation by being added, reclassified, or raised in severity discharges it "
            f"or fails. Register a `mutation://` falsifier that attacks its production "
            f"property, or reclassify the proposition into a class whose mechanics it "
            f"actually satisfies."
        )

    for unit in sorted(set(registry) - set(measured)):
        found.append(
            f"registry row for {unit!r} names an obligation that is no longer owed — the "
            f"unit has a falsifier, has been reclassified, has dropped below Medium, or no "
            f"longer exists. Remove the row. A dead row hides the next live one."
        )

    for unit in sorted(set(measured) & set(registry)):
        row, now = registry[unit], measured[unit]
        for field in ("effective_severity", "direct_consequence_severity", "inherited_severity"):
            if row.get(field) != now[field]:
                found.append(
                    f"registry row for {unit!r} records {field} {row.get(field)!r} but the "
                    f"graph now derives {now[field]!r}. The obligation is not the one this "
                    f"row covers. A materially changed proposition may not ride an existing "
                    f"entry: discharge it, or correct the row only when the change is a "
                    f"derivation correction rather than a new obligation."
                )
        if row.get("root_reachable") != now["root_reachable"]:
            found.append(
                f"registry row for {unit!r} records root_reachable "
                f"{row.get('root_reachable')!r} but the graph now says "
                f"{now['root_reachable']!r}. Reachability is a derived fact and the row "
                f"must state the current one — it changes nothing about the obligation, "
                f"and a stale copy of it is a reader's false premise."
            )
        if row["status"] in REVIEWED:
            ref = str(row.get("review_ref") or "").strip()
            if not ref:
                found.append(
                    f"registry row for {unit!r} is {row['status']!r} with no `review_ref`. "
                    f"A completed review names its record; both reviewed states carry one."
                )
            elif not (repo / ref).is_file():
                found.append(
                    f"registry row for {unit!r} names review_ref {ref!r}, which this tree "
                    f"does not hold. A completed review must point at a record rather than "
                    f"at a memory of one."
                )

    if before is None:
        return found

    added = sorted(set(registry) - set(before) - excused)
    if added:
        found.append(
            f"the registry GREW against the base: {added}. It may only shrink — the "
            f"population it bounds was fixed at the baseline, and a registry that can grow "
            f"is a waiver with extra steps. The one exception is SUCCESSION, and these rows "
            f"do not carry a valid one: a decomposition of an obligation the base registry "
            f"held names it in `succeeds` beside the `decomposition_ref` that records it."
        )
    for unit in sorted(set(registry) & set(before)):
        was, now = before[unit].get("status"), registry[unit].get("status")
        if now == "unreviewed" and was in REVIEWED:
            found.append(
                f"registry row for {unit!r} returned to 'unreviewed' from {was!r}. The "
                f"lifecycle is one-way: nothing that has been investigated becomes "
                f"uninvestigated."
            )
    return found


def selftest() -> int:
    """Every rule, and both of its directions."""
    failed = False
    base_row = {
        "unit": "u",
        "obligation": "a mutation:// falsifier",
        "effective_severity": "high",
        "direct_consequence_severity": "high",
        "inherited_severity": "none",
        "root_reachable": False,
        "status": "unreviewed",
    }
    now = {
        "u": {
            "effective_severity": "high",
            "direct_consequence_severity": "high",
            "inherited_severity": "none",
            "root_reachable": False,
        }
    }
    reg = {"u": dict(base_row)}
    raised = {"u": {**now["u"], "effective_severity": "critical"}}
    reviewed = {"u": {**base_row, "status": "reviewed-exception", "review_ref": "README.md"}}

    cases = [
        ("a registered owing unit passes", now, reg, reg, None),
        ("an UNregistered owing unit fails", now, {}, {}, "CLOSED to new work"),
        ("a registered unit that stopped owing fails", {}, reg, reg, "no longer owed"),
        ("a severity that MOVED is not covered by the old row", raised, reg, reg, "not the one this"),
        (
            "a stale root_reachable is refused",
            {"u": {**now["u"], "root_reachable": True}},
            reg,
            reg,
            "root_reachable",
        ),
        ("the registry may not GROW", now, reg, {}, "GREW against the base"),
        ("the registry MAY shrink", {}, {}, reg, None),
        (
            "a status may not return to unreviewed",
            now,
            reg,
            {"u": {**base_row, "status": "reviewed-action-required"}},
            "one-way",
        ),
        (
            "a reviewed row with a live review_ref passes",
            now,
            reviewed,
            reviewed,
            None,
        ),
        (
            "a reviewed row with NO review_ref fails",
            now,
            {"u": {**base_row, "status": "reviewed-exception"}},
            {"u": {**base_row, "status": "reviewed-exception"}},
            "no `review_ref`",
        ),
        (
            "a reviewed row naming a document that does not exist fails",
            now,
            {"u": {**reviewed["u"], "review_ref": "docs/nope-not-here.md"}},
            {"u": {**reviewed["u"], "review_ref": "docs/nope-not-here.md"}},
            "does not hold",
        ),
        (
            "an unavailable base checks the registry but not the ratchet",
            now,
            reg,
            None,
            None,
        ),
    ]
    for label, measured, registry, before, expect in cases:
        found = defects(measured, registry, before, REPO, {}, {})
        ok = (not found) if expect is None else any(expect in entry for entry in found)
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failed = True
            print(f"        got {found}")

    # SUCCESSION, in both directions. Every clause is a way a decomposition could smuggle in
    # an obligation the base registry never held, so every clause is tested for refusing it
    # AND the whole mechanism is tested for admitting the legitimate case — a gate that only
    # ever refuses would make Phase 1 impossible in exactly the way the rule exists to avoid.
    wide = {**base_row, "unit": "wide", "effective_severity": "critical"}
    def narrow(unit, **over):
        row = {
            **base_row,
            "unit": unit,
            "effective_severity": "high",
            "succeeds": "wide",
            "decomposition_ref": "README.md",
        }
        row.update(over)
        return row

    split = {"a": narrow("a"), "b": narrow("b")}
    split_measured = {
        "a": {**now["u"], "effective_severity": "high"},
        "b": {**now["u"], "effective_severity": "high"},
    }
    was = {"wide": wide}
    base_p = {"wide": {"src/one.py", "src/two.py"}}
    now_p = {"a": {"src/one.py"}, "b": {"src/two.py"}}

    succession_cases = [
        ("a valid succession is admitted", split_measured, split, was, base_p, now_p, None),
        (
            "half a succession is refused",
            split_measured,
            {**split, "b": {k: v for k, v in split["b"].items() if k != "succeeds"}},
            was,
            base_p,
            now_p,
            "only one half",
        ),
        (
            "a decomposition_ref this tree lacks is refused",
            split_measured,
            {**split, "a": narrow("a", decomposition_ref="docs/nope-not-here.md")},
            was,
            base_p,
            now_p,
            "does not hold",
        ),
        (
            "succeeding oneself is refused",
            split_measured,
            {**split, "a": narrow("a", succeeds="a")},
            was,
            base_p,
            now_p,
            "succeeds itself",
        ),
        (
            "a predecessor the base did not hold is refused",
            split_measured,
            split,
            {},
            base_p,
            now_p,
            "does not hold",
        ),
        (
            "a predecessor that still owes is refused",
            {**split_measured, "wide": {**now["u"], "effective_severity": "critical"}},
            split,
            was,
            base_p,
            now_p,
            "still owes",
        ),
        (
            "a successor above the predecessor's severity is refused",
            {**split_measured, "a": {**now["u"], "effective_severity": "critical"}},
            {**split, "a": narrow("a", effective_severity="critical")},
            {"wide": {**wide, "effective_severity": "high"}},
            base_p,
            now_p,
            "above the predecessor",
        ),
        (
            "a successor covering code the predecessor did not is refused",
            split_measured,
            split,
            was,
            base_p,
            {**now_p, "b": {"src/two.py", "src/brand-new.py"}},
            "did not cover",
        ),
        (
            "an unavailable base refuses the succession rather than assuming it",
            split_measured,
            split,
            None,
            base_p,
            now_p,
            "cannot be checked",
        ),
        (
            "an unavailable unit registry refuses it rather than assuming it",
            split_measured,
            split,
            was,
            None,
            now_p,
            "cannot be compared",
        ),
        (
            "a row ALREADY IN THE BASE is not re-validated — the merge spent it",
            split_measured,
            split,
            {**was, **split},
            base_p,
            now_p,
            None,
        ),
        (
            "a malformed succession does not also buy growth",
            split_measured,
            {**split, "a": narrow("a", decomposition_ref="docs/nope-not-here.md")},
            was,
            base_p,
            now_p,
            "GREW against the base",
        ),
    ]
    for label, measured, registry, before, bpaths, npaths, expect in succession_cases:
        found = defects(measured, registry, before, REPO, bpaths, npaths)
        ok = (not found) if expect is None else any(expect in entry for entry in found)
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failed = True
            print(f"        got {found}")

    # The parser: a mistyped declaration must not read as an absent one.
    import tempfile

    parser_cases = [
        ("an unknown key", 'unit = "u"\nobligation = "x"\neffective_severity = "high"\n'
         'direct_consequence_severity = "high"\ninherited_severity = "none"\n'
         'root_reachable = false\nstatus = "unreviewed"\nnope = 1\n', "unknown key"),
        ("a missing key", 'unit = "u"\nobligation = "x"\n', "missing required key"),
        ("an unknown status", 'unit = "u"\nobligation = "x"\neffective_severity = "high"\n'
         'direct_consequence_severity = "high"\ninherited_severity = "none"\n'
         'root_reachable = false\nstatus = "fine-actually"\n', "not one of"),
        ("an empty obligation", 'unit = "u"\nobligation = "  "\neffective_severity = "high"\n'
         'direct_consequence_severity = "high"\ninherited_severity = "none"\n'
         'root_reachable = false\nstatus = "unreviewed"\n', "names the obligation"),
    ]
    for label, body, expect in parser_cases:
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as handle:
            handle.write("[[obligation]]\n" + body)
            temp = Path(handle.name)
        try:
            load_registry(temp)
            print(f"  FAIL  the parser refuses {label}")
            failed = True
        except ValueError as exc:
            ok = expect in str(exc)
            print(f"  {'ok  ' if ok else 'FAIL'}  the parser refuses {label}")
            if not ok:
                failed = True
                print(f"        got {exc}")
        finally:
            temp.unlink()

    print(f"\nassurance-obligation gate selftest: {'FAILED' if failed else 'passed'}")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--base", default="origin/main")
    args = parser.parse_args()
    if args.selftest:
        return selftest()

    registry = load_registry()
    measured = owing()
    before = base_registry(args.base)
    found = defects(
        measured,
        registry,
        before,
        base_paths=base_unit_paths(args.base),
        now_paths=current_unit_paths(),
    )
    if found:
        for entry in found:
            print(f"FAIL: {entry}", file=sys.stderr)
        return 1

    if before is None:
        print(
            f"assurance-obligation gate: registry consistent with {len(measured)} measured "
            f"obligation(s), but {args.base} is unavailable so the shrink-only and "
            f"one-way-status rules were NOT checked. That is a fact about this checkout."
        )
        return 0
    states = {status: 0 for status in STATUSES}
    for row in registry.values():
        states[row["status"]] += 1
    reachable = sum(1 for row in registry.values() if row.get("root_reachable"))
    # Counted against the BASE, not against the presence of a `succeeds` field: once a
    # successor row is in the base it is pre-existing, and its succession fields are
    # provenance. A summary that counted the field would keep reporting an authorization
    # that was spent merges ago.
    admitted = sum(1 for unit, row in registry.items() if row.get("succeeds") and unit not in before)
    origin = (
        "all pre-existing at the baseline"
        if not admitted
        else f"{len(registry) - admitted} pre-existing at the baseline and {admitted} "
        f"admitted by SUCCESSION from a row the base held"
    )
    print(
        f"assurance-obligation gate: OK — {len(registry)} open N1 obligation(s), all "
        f"measured and {origin} "
        f"({states['unreviewed']} unreviewed, {states['reviewed-action-required']} "
        f"reviewed-action-required, {states['reviewed-exception']} reviewed-exception; "
        f"{reachable} root-reachable). Registry did not grow, no status returned to "
        f"unreviewed, and every row names an obligation that is still owed. Each remains "
        f"INCOMPLETE — the registry bounds the population, it does not discharge anything."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
