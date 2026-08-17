# SPDX-License-Identifier: Apache-2.0
"""The views that cross all three catalogues — ADR-MCPRE-059 §8.2, §9, Phase T3.

Every derived REVERSE edge in the generated set lives here, and only here. An assumption's
consumers, a unit's theorems, a theorem's dependents: none of those is stored anywhere, and
§8.2 forbids storing them. They are computed at render time by walking the forward edges the
catalogues declare, which is what keeps a second authority from growing beside the first.

Separated from the theorem-only views because these are invalidated by a change to ANY of
the three catalogues, and that is a different dependency set — the same distinction the
fingerprint components draw, expressed in the module layout.
"""

from __future__ import annotations

from _view_format import header, one_line, table


def _supporters(theorems: dict) -> dict[str, list[str]]:
    """unit id → the theorems it supports. Derived; never stored (§8.2)."""
    supporters: dict[str, list[str]] = {}
    for row in theorems.get("theorem", []):
        for target in row.get("supported_by", []):
            supporters.setdefault(str(target).removeprefix("unit://"), []).append(row["id"])
    return supporters


def _scoped_units(entry: dict, units: list[dict]) -> list[str]:
    """The units an assumption is scoped to, in declaration order of the unit catalogue."""
    return sorted(
        unit["id"] for unit in units if f"unit://{unit['id']}" in entry.get("scope", [])
    )


def assumption_consumers(theorems: dict, verification: dict, assumptions: dict) -> str:
    """Which claims a trusted assumption reaches — the derived `consumed_by` view (§8.2).

    Computed at render time from the forward edges: assumption scope names units, units
    support theorems. Storing this direction is exactly what the ADR forbids.
    """
    units = verification.get("unit", [])
    supporters = _supporters(theorems)
    rows = []
    for entry in sorted(assumptions.get("assumption", []), key=lambda row: row["id"]):
        scoped = _scoped_units(entry, units)
        reached = sorted({tid for unit in scoped for tid in supporters.get(unit, [])})
        rows.append(
            (
                entry["id"],
                # Not truncated. A shortened description in a table reads as the whole of
                # what is trusted, and the one assumption whose wording matters most is the
                # long one. Nothing in these views bounds what it shows, so there is no
                # limit to disclose — and if one is ever added, it must be stated on the
                # page, because silent truncation reads as coverage.
                one_line(entry["description"]),
                ", ".join(scoped) or "_no unit_",
                ", ".join(reached) or "_no theorem_",
            )
        )

    body = header(
        "Assumption consumers",
        "What each trusted assumption reaches, derived by following scope → unit →\n"
        "theorem. An assumption several claims stand on is ONE node, not several\n"
        "independent results, and this view exists so it cannot read as the latter.",
    )
    body += "\n" + table(
        rows, ("id", "what is trusted", "scoped to units", "reaches theorems")
    )
    shared = [row for row in rows if row[3] != "_no theorem_" and "," in row[3]]
    body += (
        f"\n{len(shared)} assumption(s) are reached by more than one theorem.\n"
        if shared
        else "\nNo assumption is currently reached by more than one theorem.\n"
    )
    return body


def owner_view(theorems: dict, verification: dict) -> str:
    units = {unit["id"]: unit for unit in verification.get("unit", [])}
    by_owner: dict[str, list[dict]] = {}
    for row in theorems.get("theorem", []):
        by_owner.setdefault(row["owner"], []).append(row)

    body = header(
        "Owner view",
        "Each review unit and the claims it is the semantic authority for. A unit with no\n"
        "theorem is shown too: an unclaimed unit is a question for the specification work,\n"
        "not an omission to hide.",
    )
    rows = [
        (
            unit_id,
            unit["class"],
            ", ".join(sorted(row["id"] for row in by_owner.get(unit_id, []))) or "_none_",
            str(len(unit.get("assumptions", []))),
        )
        for unit_id, unit in sorted(units.items())
    ]
    body += "\n" + table(rows, ("unit", "class", "owns theorems", "assumptions"))
    orphans = sorted(set(by_owner) - set(units))
    if orphans:
        body += f"\n**Theorems owned by no declared unit: {', '.join(orphans)}.**\n"
    return body


def structural_blast_radius(theorems: dict, verification: dict, assumptions: dict) -> str:
    """What each catalogue object would invalidate if it moved — structure only.

    Deliberately not the live view. This one answers "what work would a change here
    create", from the declared edges alone, and is therefore stable enough to commit. The
    live question — what is dirty NOW and which component moved — needs the attestation
    store and belongs to `review-frontier`.

    Three sections because the three object kinds invalidate different things, and a single
    merged table would have to blur that into one vague "affects" column.
    """
    body = header(
        "Structural blast radius",
        "If this object changes, what must be re-established. Derived from the declared\n"
        "edges only — it says what WOULD be invalidated, never what IS dirty. For the live\n"
        "answer, including which component moved (`DIRTY_SELF` vs `DIRTY_ASSUMPTION` vs\n"
        "`DIRTY_CONTRACT`), run `tools/verification/review-frontier`, which reads the\n"
        "attestations this view cannot see.",
    )
    body += "\n## Review units\n\n" + _unit_radius(theorems, verification)
    body += "\n## Theorems\n\n" + _theorem_radius(theorems)
    body += "\n## Assumptions\n\n" + _assumption_radius(verification, assumptions)
    return body


def _unit_radius(theorems: dict, verification: dict) -> str:
    supporters = _supporters(theorems)
    edges = verification.get("edge", [])
    rows = []
    for unit in sorted(verification.get("unit", []), key=lambda row: row["id"]):
        downstream = sorted(
            f"{edge['to']} ({edge['kind']}{', sealed' if edge.get('sealed') else ''})"
            for edge in edges
            if edge["from"] == unit["id"]
        )
        rows.append(
            (
                f"unit://{unit['id']}",
                "source, contracts or evidence",
                ", ".join(sorted(supporters.get(unit["id"], []))) or "_no theorem_",
                ", ".join(downstream) or "_no consumer_",
            )
        )
    return table(
        rows, ("object", "a change to", "re-establishes theorems", "propagates to units")
    )


def _theorem_radius(theorems: dict) -> str:
    dependents: dict[str, list[str]] = {}
    for row in theorems.get("theorem", []):
        for dep in row.get("depends_on", []):
            dependents.setdefault(dep, []).append(row["id"])
    rows = [
        (
            row["id"],
            "statement, consequence, scope or review requirement",
            "specification review",
            ", ".join(sorted(dependents.get(row["id"], []))) or "_no dependent_",
        )
        for row in sorted(theorems.get("theorem", []), key=lambda row: row["id"])
    ]
    return table(rows, ("object", "a change to", "invalidates", "and every claim above"))


def _assumption_radius(verification: dict, assumptions: dict) -> str:
    units = verification.get("unit", [])
    rows = [
        (
            entry["id"],
            "description, justification, scope or mechanism",
            ", ".join(_scoped_units(entry, units)) or "_no unit_",
            "assumption review",
        )
        for entry in sorted(assumptions.get("assumption", []), key=lambda row: row["id"])
    ]
    return table(rows, ("object", "a change to", "dirties units", "and invalidates"))
