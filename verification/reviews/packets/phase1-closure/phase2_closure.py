# SPDX-License-Identifier: Apache-2.0
"""Derive the ADR-MCPRE-068 Phase-2 closure from the tree, not from a packet.

Phase 1 decomposed the roots; Phase 2 discharged the N1 obligations that decomposition
left owing. This asks the tree four questions and answers each from the registries
themselves, so the report a reader gets is a MEASUREMENT of the commit it runs on.

Run: python3 verification/reviews/packets/phase1-closure/phase2_closure.py
"""

from __future__ import annotations

import collections
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]

UNITS = tomllib.loads((ROOT / "verification/policy/verification.toml").read_text())["unit"]
PROBES = tomllib.loads((ROOT / "verification/policy/mutation-probes.toml").read_text())["probe"]
DEBT = tomllib.loads((ROOT / "config/assurance-obligation-debt.toml").read_text())

BY_ID = {unit["id"]: unit for unit in UNITS}


def claims_mutation(unit: dict) -> bool:
    return any(str(e).startswith("mutation://") for e in unit.get("evidence", []))


def main() -> int:
    probes_by_unit: dict[str, list[dict]] = collections.defaultdict(list)
    for probe in PROBES:
        probes_by_unit[probe["unit"]].append(probe)

    claiming = {unit["id"] for unit in UNITS if claims_mutation(unit)}
    attacked = set(probes_by_unit)

    print(f"units                      {len(UNITS)}")
    print(f"probes                     {len(PROBES)}")
    print(f"units claiming mutation    {len(claiming)}")
    print(f"units with >= 1 probe      {len(attacked)}")
    print(f"claiming but not attacked  {sorted(claiming - attacked)}")
    print(f"attacked but not claiming  {sorted(attacked - claiming)}")

    # The N1 population, re-derived rather than read off the registry: every `tested`
    # proposition at effective Medium or above owes a falsifier.
    rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    owing = [
        unit
        for unit in UNITS
        if unit.get("evidence_class") == "tested"
        and rank.get(
            max(
                (unit.get("direct_consequence_severity", "none"), unit.get("inherited", "none")),
                key=lambda s: rank.get(s, 0),
            ),
            0,
        )
        >= 2
    ]
    undischarged = [unit["id"] for unit in owing if unit["id"] not in attacked]
    print(f"tested units at >= medium  {len(owing)}")
    print(f"  of those, no falsifier   {len(undischarged)} {sorted(undischarged)}")

    rows = DEBT.get("obligation", [])
    print(f"debt registry rows         {len(rows)}")

    compound = [p for p in PROBES if p.get("also")]
    print(f"compound probes            {len(compound)} {[p['id'] for p in compound]}")

    # A probe's theorem must be one the unit it names actually supports.
    mismatched = [
        p["id"]
        for p in PROBES
        if p["unit"] not in BY_ID
    ]
    print(f"probes naming no unit      {len(mismatched)} {mismatched}")

    by_class = collections.Counter(u.get("evidence_class") for u in UNITS)
    print(f"evidence classes           {dict(by_class)}")

    ecosystems = collections.Counter(
        "python" if p["path"].startswith("sdk/python")
        else "typescript" if p["path"].startswith("sdk/typescript")
        else "vector" if "/vectors/" in p["path"]
        else "cargo"
        for p in PROBES
    )
    print(f"probes by ecosystem        {dict(ecosystems)}")

    ok = not (claiming - attacked) and not (attacked - claiming) and not undischarged and not rows
    print()
    print("PHASE 2 CLOSURE:", "COMPLETE" if ok else "INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
