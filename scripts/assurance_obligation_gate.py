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
    the registry GREW against origin/main       -> FAIL. It may only shrink.
    a status returning to `unreviewed`          -> FAIL. The lifecycle is one-way.
    a reviewed row with no live `review_ref`    -> FAIL. A completed review points at a
                                                   record, not at a memory of one.

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
}
_OPTIONAL = {"review_ref"}


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


def defects(
    measured: dict[str, dict],
    registry: dict[str, dict],
    before: dict[str, dict] | None,
    repo: Path = REPO,
) -> list[str]:
    """Every way the registry and the measured obligations disagree."""
    found: list[str] = []

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

    added = sorted(set(registry) - set(before))
    if added:
        found.append(
            f"the registry GREW against the base: {added}. It may only shrink — the "
            f"population it bounds was fixed at the baseline, and a registry that can grow "
            f"is a waiver with extra steps."
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
        found = defects(measured, registry, before)
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
    found = defects(measured, registry, before)
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
    print(
        f"assurance-obligation gate: OK — {len(registry)} open N1 obligation(s), all "
        f"measured and all pre-existing at the baseline "
        f"({states['unreviewed']} unreviewed, {states['reviewed-action-required']} "
        f"reviewed-action-required, {states['reviewed-exception']} reviewed-exception; "
        f"{reachable} root-reachable). Registry did not grow, no status returned to "
        f"unreviewed, and every row names an obligation that is still owed. Each remains "
        f"INCOMPLETE — the registry bounds the population, it does not discharge anything."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
