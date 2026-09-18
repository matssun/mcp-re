# SPDX-License-Identifier: Apache-2.0
"""Negative controls over N3's severity derivation — ADR-MCPRE-068 §9, Phase 0E.

A derived security fact is only worth more than a stored one if the derivation is the thing
that is checked. These are the ways `effective_severity` could be wrong while still
producing a number:

  * it could stop at the root set, which is the reading the ratification REJECTED. A unit
    supporting an intermediate Critical theorem must inherit Critical whatever sits above;
  * it could propagate only one hop, so a unit three edges below a Critical root reads Low;
  * it could take a minimum, or the last value seen, rather than a maximum;
  * it could lower a proposition whose own label is higher than anything depending on it;
  * it could default an absent label to `none` and quietly make the least-considered claims
    the least obligated, which Ruling 1 forbids in as many words;
  * it could depend on iteration order, which a cycle would make visible and which a
    partial topological order would hide.

And the positive control without which none of the above proves anything: a graph with no
inheritance leaves every proposition at its own declared severity.

Run: python3 tools/verification/test_assurance_graph.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _assurance_graph as graph  # noqa: E402


def units(*pairs) -> dict:
    return {
        "unit": [
            {"id": uid, "evidence_class": "tested", "direct_consequence_severity": sev, **extra}
            for uid, sev, extra in pairs
        ]
    }


def theorems(*rows, roots=()) -> dict:
    return {
        "root_theorems": list(roots),
        "theorem": [
            {
                "id": tid,
                "direct_consequence_severity": sev,
                "supported_by": [f"unit://{u}" for u in supports],
                "depends_on": list(deps),
            }
            for tid, sev, supports, deps in rows
        ],
    }


def effective(doc_t, doc_u) -> dict[str, str]:
    return {
        node.split("://", 1)[1]: row["effective"]
        for node, row in graph.severities(doc_t, doc_u).items()
    }


def test_a_unit_with_no_dependent_keeps_its_own_severity():
    """The positive control. Without it the rest prove only that numbers come out."""
    got = effective(theorems(), units(("u", "high", {})))
    assert got["u"] == "high", got


def test_a_unit_inherits_from_the_theorem_that_names_it():
    got = effective(
        theorems(("THM-1", "critical", ["u"], [])), units(("u", "low", {}))
    )
    assert got["u"] == "critical", got


def test_inheritance_is_TRANSITIVE_and_not_one_hop():
    """Three edges down from Critical is still Critical.

    A one-hop implementation passes the test above and fails here, which is why both exist.
    """
    got = effective(
        theorems(
            ("THM-1", "critical", [], ["THM-2"]),
            ("THM-2", "low", [], ["THM-3"]),
            ("THM-3", "low", ["u"], []),
        ),
        units(("u", "info", {})),
    )
    assert got["u"] == "critical", got
    assert got["THM-3"] == "critical", got


def test_an_INTERMEDIATE_theorems_severity_reaches_the_unit_with_no_root_above():
    """The reading the ratification rejected, stated as a control.

    Ruling 1's literal text quantifies over declared ROOTS. Under that reading this unit
    inherits nothing, because no root is involved at all. N3 as accepted quantifies over
    every dependent, so the intermediate theorem's own declared consequence reaches it.
    """
    got = effective(
        theorems(("THM-1", "critical", ["u"], []), roots=()),
        units(("u", "low", {})),
    )
    assert got["u"] == "critical", got


def test_severity_is_a_MAXIMUM_over_dependents_not_a_minimum_or_the_last_seen():
    got = effective(
        theorems(
            ("THM-1", "critical", ["u"], []),
            ("THM-2", "info", ["u"], []),
            ("THM-3", "medium", ["u"], []),
        ),
        units(("u", "none", {})),
    )
    assert got["u"] == "critical", got


def test_a_dependent_NEVER_LOWERS_a_propositions_own_label():
    """`effective = max(direct, inherited)`, so inheritance can only raise."""
    got = effective(
        theorems(("THM-1", "info", ["u"], [])), units(("u", "critical", {}))
    )
    assert got["u"] == "critical", got


def test_an_ABSENT_label_is_not_read_as_none_by_the_derivation():
    """Ruling 1: missing does not mean `none`.

    The derivation preserves the absence as `direct: None` — `_evidence_class.severity_problem`
    is what REPORTS it, and a default here would hide the record that rule exists to surface.
    The proposition still inherits, because a maximum over an absent own-label is the
    inherited one.
    """
    doc_u = {"unit": [{"id": "u", "evidence_class": "tested"}]}
    rows = graph.severities(theorems(("THM-1", "high", ["u"], [])), doc_u)
    row = rows[graph.key(graph.UNIT, "u")]
    assert row["direct"] is None, row
    assert row["effective"] == "high", row


def test_a_cycle_RAISES_rather_than_producing_an_order_dependent_answer():
    """A severity that depends on iteration order is the one thing a derived fact may not be.

    `depends_on` cycles are refused upstream by `_theorems._check_acyclic`; this control is
    about what happens if a future edge kind arrives without that check.
    """
    cyclic = theorems(
        ("THM-1", "low", [], ["THM-2"]),
        ("THM-2", "low", [], ["THM-1"]),
    )
    try:
        graph.severities(cyclic, units())
    except graph.CycleError as exc:
        assert "cycle" in str(exc), exc
        return
    raise AssertionError("a cyclic proposition graph produced a severity")


def test_root_reachability_is_transitive_and_excludes_what_no_root_reaches():
    doc_t = theorems(
        ("THM-1", "high", [], ["THM-2"]),
        ("THM-2", "high", ["reached"], []),
        ("THM-9", "high", ["orphan"], []),
        roots=["THM-1"],
    )
    doc_u = units(("reached", "low", {}), ("orphan", "low", {}))
    seen = graph.root_reachable(doc_t, doc_u, doc_t["root_theorems"])
    assert graph.key(graph.UNIT, "reached") in seen, seen
    assert graph.key(graph.UNIT, "orphan") not in seen, seen


def test_NOT_ROOT_REACHABLE_does_not_reduce_the_obligation():
    """S5's exact meaning, as a control.

    The ratification: NOT-ROOT-REACHABLE means only that no declared root depends on the
    proposition. It is not low importance, not complete assurance, and not permission to
    omit evidence — so a unit no root reaches still owes a falsifier on its own label.
    """
    doc_t = theorems(("THM-9", "high", ["orphan"], []), roots=())
    doc_u = units(("orphan", "critical", {"evidence": ["test://x"]}))
    owed = graph.unmet_obligations(doc_t, doc_u)
    assert "orphan" in owed, owed
    assert owed["orphan"]["root_reachable"] is False, owed
    assert owed["orphan"]["effective_severity"] == "critical", owed


def test_a_falsifier_discharges_the_obligation_and_a_wrong_scheme_does_not():
    """N4: the obligation is discharged only in its own class's falsifier form."""
    doc_t = theorems(("THM-1", "critical", ["u"], []))
    with_mutation = units(("u", "high", {"evidence": ["test://x", "mutation://x"]}))
    with_structural = units(("u", "high", {"evidence": ["test://x", "structural://x"]}))
    assert "u" not in graph.unmet_obligations(doc_t, with_mutation)
    assert "u" in graph.unmet_obligations(doc_t, with_structural)


def test_a_below_floor_proposition_owes_nothing_until_it_INHERITS_above_it():
    """The severity gate, in both directions — and the reason N1 needed N3 first."""
    doc_u = units(("u", "low", {"evidence": ["test://x"]}))
    assert "u" not in graph.unmet_obligations(theorems(), doc_u)
    assert "u" in graph.unmet_obligations(theorems(("THM-1", "medium", ["u"], [])), doc_u)


def test_only_TESTED_propositions_take_the_mutation_obligation():
    """Ruling 4: `measured` takes no mutation obligation, and the formal classes owe their
    own falsifier forms, which per-record class adequacy already enforces."""
    doc_t = theorems(("THM-1", "critical", ["m", "s", "p"], []))
    doc_u = {
        "unit": [
            {"id": "m", "evidence_class": "measured", "direct_consequence_severity": "high"},
            {"id": "s", "evidence_class": "structural", "direct_consequence_severity": "high"},
            {"id": "p", "evidence_class": "proved", "direct_consequence_severity": "high"},
        ]
    }
    assert graph.unmet_obligations(doc_t, doc_u) == {}


def test_the_LIVE_registries_derive_without_a_cycle_and_the_result_is_NON_EMPTY():
    """An empty join reads as a clean tree.

    Every control above runs on a fixture. This one runs on the real registries, and asserts
    the derivation produced propositions rather than merely not raising — a `severities`
    that silently returned `{}` would make every control above vacuous against the tree they
    exist to protect.
    """
    import _manifest
    import _theorems

    doc = _manifest.load_verification()
    live = _theorems.load_theorems({unit["id"] for unit in doc.get("unit", [])})
    rows = graph.severities(live, doc)
    assert len(rows) >= len(doc["unit"]) + len(live["theorem"]), len(rows)
    raised = [node for node, row in rows.items() if row["direct"] != row["effective"]]
    assert raised, "no proposition inherits anything, which would make N3 inert"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
