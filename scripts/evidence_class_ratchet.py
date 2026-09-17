#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The evidence-class transition ratchet — ADR-MCPRE-068 §9.4, Phase 0D.

THE FAILURE CLASS, stated by the ADR as the reason this exists:

    A downgrade from `proved` to `tested` passes registry adequacy TRIVIALLY. Delete the
    formal URI, delete the class, and nothing notices the claim got weaker.

Registry adequacy is a property of one record read alone: does this unit's declared class
agree with its declared evidence? A unit that drops its prover and rewrites itself as a
tested one is internally consistent and says nothing about what it used to be. Only a
comparison against `origin/main` can see the CHANGE, and that is what this gate is.

    every `evidence_class` that differs from origin/main needs a transition record
    naming `unit`, `from_evidence_class` and `to_evidence_class`

IT IS NOT A WAIVER, and the distinction is the whole design. The record does not excuse the
destination class's mechanics — the loader enforces those on every run, and a transition to
a class the unit cannot satisfy still fails. What the record buys is that the change was
WRITTEN DOWN: a reclassification is a security-relevant statement about what kind of thing
establishes a claim, and the defect is a class moving silently, not a class moving.

IT IS DELIBERATELY NOT A TOTAL ORDER. `proved > structural > tested > measured` is the
wrong shape: the four are incomparable establishment modes rather than strength tiers, and
a `structural` proposition is not a weaker `proved` one. So the ratchet constrains
UNRECORDED CHANGE, never direction — a rule ranking them would refuse the honest
reclassifications this phase exists to perform.

A DEAD RECORD IS A DEFECT TOO. A record naming a transition that is neither happening now
nor already landed on `main` is a claim about nothing, and it hides the next one that
matters — the same rule `merge_path_gate.EXEMPT` follows for a dead exemption.

WHAT IT DOES NOT PROVE: that the new class is the right one. That is 0D's judgement, and a
gate that could decide it would be deciding what a proposition MEANS.

Run:  python3 scripts/evidence_class_ratchet.py
      python3 scripts/evidence_class_ratchet.py --selftest
      python3 scripts/evidence_class_ratchet.py --base origin/main
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = "verification/policy/verification.toml"
RECORDS = REPO / "config" / "evidence-class-transitions.toml"

_RECORD_KEYS = {"unit", "from_evidence_class", "to_evidence_class", "ref", "note"}
_OPTIONAL = {"note"}


def classes(doc: dict) -> dict[str, str]:
    """`{unit id: evidence_class}` for one manifest document."""
    return {
        unit["id"]: unit.get("evidence_class")
        for unit in doc.get("unit", [])
        if unit.get("evidence_class")
    }


def base_manifest(base: str) -> dict | None:
    """The manifest as `base` has it, or None when that revision is unavailable.

    UNAVAILABLE IS NOT EMPTY. A shallow clone, a fresh fork, or a detached CI checkout that
    cannot resolve `origin/main` has no baseline to compare against — and treating that as
    "no unit had a class" would read every class in the tree as a brand-new declaration and
    demand a transition record for all 127. The caller reports it and stops rather than
    inventing a comparison.
    """
    proc = subprocess.run(
        ["git", "show", f"{base}:{MANIFEST}"],
        cwd=REPO,
        capture_output=True,
    )
    if proc.returncode != 0:
        return None
    return tomllib.loads(proc.stdout.decode("utf-8"))


def load_records(path: Path = RECORDS) -> list[dict]:
    """The transition registry, validated strictly — an unknown key is a failure."""
    if not path.is_file():
        return []
    with path.open("rb") as handle:
        doc = tomllib.load(handle)
    records = doc.get("transition", [])
    for index, record in enumerate(records):
        where = f"{path.name} [[transition]] #{index + 1}"
        unknown = set(record) - _RECORD_KEYS
        if unknown:
            raise ValueError(f"{where}: unknown key(s) {sorted(unknown)}")
        missing = _RECORD_KEYS - _OPTIONAL - set(record)
        if missing:
            raise ValueError(f"{where}: missing required key(s) {sorted(missing)}")
        if not str(record["ref"]).strip():
            raise ValueError(
                f"{where}: `ref` is empty. A transition names where it was decided — a "
                f"PR, an ADR section, or a review record — or it is a change with no "
                f"recorded reason, which is the state this registry exists to end."
            )
    return records


def defects(before: dict[str, str], after: dict[str, str], records: list[dict]) -> list[str]:
    """Every transition without a record, and every record without a transition."""
    found: list[str] = []
    stated = {
        (r["unit"], r["from_evidence_class"], r["to_evidence_class"]): r for r in records
    }
    moved = {
        unit: (before[unit], after[unit])
        for unit in sorted(set(before) & set(after))
        if before[unit] != after[unit]
    }
    for unit, (was, now) in moved.items():
        if (unit, was, now) not in stated:
            found.append(
                f"unit {unit!r} moved from evidence_class {was!r} to {now!r} with no "
                f"transition record. A class that moves silently is the defect this "
                f"ratchet exists for — the record does not excuse the destination class's "
                f"mechanics, which the loader enforces anyway; it records that the change "
                f"was made deliberately. Add a [[transition]] to "
                f"{RECORDS.relative_to(REPO)} naming unit, from_evidence_class, "
                f"to_evidence_class and ref."
            )
    for (unit, was, now), _record in sorted(stated.items()):
        if moved.get(unit) == (was, now):
            continue
        # Already landed: `main` now holds the destination, so the transition this record
        # describes is history rather than a claim about the diff. Kept, because the
        # registry is the log of how each class got where it is.
        if before.get(unit) == now:
            continue
        found.append(
            f"transition record for {unit!r} names {was!r} -> {now!r}, which is neither "
            f"happening in this diff nor already landed on the base ({unit!r} is "
            f"{before.get(unit)!r} there). A record about nothing hides the next one that "
            f"matters."
        )
    return found


def selftest() -> int:
    """Every rule, and both of its directions."""
    failed = False
    record = {
        "unit": "u",
        "from_evidence_class": "tested",
        "to_evidence_class": "structural",
        "ref": "PR #969",
    }
    cases = [
        ("an unrecorded move is refused", {"u": "tested"}, {"u": "structural"}, [], "moved from"),
        ("a recorded move is allowed", {"u": "tested"}, {"u": "structural"}, [record], None),
        (
            "a record naming the WRONG direction does not cover the move",
            {"u": "structural"},
            {"u": "tested"},
            [record],
            "moved from",
        ),
        ("an unchanged class needs no record", {"u": "tested"}, {"u": "tested"}, [], None),
        ("a new unit is not a transition", {}, {"u": "structural"}, [], None),
        (
            "a landed transition is history, not a dead record",
            {"u": "structural"},
            {"u": "structural"},
            [record],
            None,
        ),
        (
            "a record about a transition that never happened is dead",
            {"u": "tested"},
            {"u": "tested"},
            [record],
            "hides the next one",
        ),
        (
            "a downgrade is refused UNRECORDED and allowed RECORDED — direction is not the rule",
            {"u": "proved"},
            {"u": "tested"},
            [{**record, "from_evidence_class": "proved", "to_evidence_class": "tested"}],
            None,
        ),
    ]
    for label, before, after, records, expect in cases:
        found = defects(before, after, records)
        ok = (not found) if expect is None else any(expect in entry for entry in found)
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failed = True
            print(f"        got {found}")

    # The registry parser: an unknown key must not read as an absent one, and an empty
    # `ref` must not read as a stated reason.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        for body, why in [
            ('[[transition]]\nunit = "u"\nfrom_evidence_class = "tested"\n'
             'to_evidence_class = "structural"\nref = "x"\nexpect_red = "a probe key"\n',
             "an unknown key"),
            ('[[transition]]\nunit = "u"\nfrom_evidence_class = "tested"\n'
             'to_evidence_class = "structural"\nref = "  "\n', "an empty ref"),
            ('[[transition]]\nunit = "u"\nfrom_evidence_class = "tested"\nref = "x"\n',
             "a missing key"),
        ]:
            path = Path(tmp) / "t.toml"
            path.write_text(body, encoding="utf-8")
            try:
                load_records(path)
            except ValueError:
                print(f"  ok    {why} is refused")
                continue
            print(f"  FAIL  {why} was accepted", file=sys.stderr)
            failed = True

    if failed:
        return 1
    print("evidence-class ratchet: selftest passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--base", default="origin/main", help="the revision to compare against")
    args = parser.parse_args()
    if args.selftest:
        return selftest()

    try:
        records = load_records()
    except ValueError as exc:
        print(f"evidence-class ratchet: FAILED\n  - {exc}", file=sys.stderr)
        return 1

    base = base_manifest(args.base)
    if base is None:
        print(
            f"evidence-class ratchet: SKIPPED — {args.base} does not resolve, so there is "
            f"no baseline to compare against. Unavailable is not empty: reading it as "
            f"'no unit had a class' would demand a transition record for every unit."
        )
        return 0
    with (REPO / MANIFEST).open("rb") as handle:
        head = tomllib.load(handle)

    before, after = classes(base), classes(head)
    if not after:
        print(
            "evidence-class ratchet: FAILED\n  - no unit in the working manifest declares "
            "an evidence_class. An empty scope is the gate measuring nothing while "
            "printing OK.",
            file=sys.stderr,
        )
        return 1
    found = defects(before, after, records)
    if found:
        print("evidence-class ratchet: FAILED", file=sys.stderr)
        for defect in found:
            print(f"  - {defect}", file=sys.stderr)
        return 1
    moved = sum(1 for unit in set(before) & set(after) if before[unit] != after[unit])
    print(
        f"evidence-class ratchet: OK — {len(after)} unit(s) classified, {moved} "
        f"reclassification(s) against {args.base}, each with a transition record, and "
        f"{len(records)} record(s) all naming a transition that happened"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
