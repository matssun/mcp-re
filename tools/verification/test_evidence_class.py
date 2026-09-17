# SPDX-License-Identifier: Apache-2.0
"""The ADR-MCPRE-068 evidence-class ontology and its registry adequacy.

The single property under test: **a class the evidence does not support is a validation
FAILURE, not a weaker claim** (N4). Everything else here exists to stop that from being
satisfied vacuously — in particular the negative controls, which check that the rules can
still go RED. A gate that reads a declared class is an unusually easy place to be green
about a field nobody filled in honestly (§9.2), so every rule below is exercised in both
directions.

The live-registry cases at the bottom are the ones that would catch a migration that
declared a vocabulary and left the registry behind it.

Run with `python3 -m pytest tools/verification/test_evidence_class.py`, or directly.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _evidence_class import (  # noqa: E402
    EVIDENCE_CLASSES,
    MEASUREMENT_KEYS,
    OBLIGATION_FLOOR,
    SEVERITIES,
    SEVERITY_ORDER,
    class_problems,
    severity_problem,
)
from _manifest import POLICY_DIR, SCHEMA_VERSION  # noqa: E402


def _tested(**over):
    unit = {
        "id": "x",
        "evidence_class": "tested",
        "evidence": ["test://x/battery"],
        "tested_symbols": ["lib#x::tests::t"],
    }
    unit.update(over)
    return unit


# --------------------------------------------------------------------------------------
# The vocabulary is closed, and closed in the right places
# --------------------------------------------------------------------------------------


def test_the_four_establishing_classes_are_exactly_the_ruling_gave():
    assert set(EVIDENCE_CLASSES) == {"proved", "structural", "tested", "measured"}


def test_a_premise_class_is_never_a_unit_class():
    """Ruling 2's whole point: the two vocabularies answer different questions.

    A unit classified `external-boundary` would be saying MCP-RE establishes the
    proposition by not establishing it. The wrapper is `tested` or `proved`; the outside
    guarantee is a premise record.
    """
    for name in ("assumed", "external-boundary", "review-obligation"):
        problems = class_problems("u", _tested(evidence_class=name))
        assert problems, f"{name} was accepted as a unit evidence class"
        assert "premise_class" in problems[0]


def test_severity_is_ordered_and_medium_is_the_obligation_floor():
    assert list(SEVERITIES) == ["none", "info", "low", "medium", "high", "critical"]
    assert SEVERITY_ORDER["critical"] > SEVERITY_ORDER["high"] > SEVERITY_ORDER["medium"]
    assert OBLIGATION_FLOOR == SEVERITY_ORDER["medium"]


# --------------------------------------------------------------------------------------
# Severity: absent is a failure, and that is the rule, not an oversight
# --------------------------------------------------------------------------------------


def test_a_missing_severity_is_a_problem_and_never_reads_as_none():
    """Ruling 1: "Do not permit missing to mean `none`."

    Reading absent as the lowest severity would leave the least considered claims the
    least obligated, which is exactly backwards — an unstated consequence is an
    unconsidered one.
    """
    problem = severity_problem("t", {"id": "THM-0001"})
    assert problem is not None
    assert "does NOT mean" in problem


def test_a_severity_outside_the_vocabulary_is_a_problem():
    assert severity_problem("t", {"direct_consequence_severity": "sev:high"}) is not None
    assert severity_problem("t", {"direct_consequence_severity": "HIGH"}) is not None


def test_every_declared_severity_is_accepted():
    for name in SEVERITIES:
        assert severity_problem("t", {"direct_consequence_severity": name}) is None


# --------------------------------------------------------------------------------------
# The class is CHECKED against the evidence, in both directions
# --------------------------------------------------------------------------------------


def test_a_well_formed_tested_unit_has_no_problems():
    assert class_problems("u", _tested()) == []


def test_a_missing_class_is_a_problem_and_names_the_other_key():
    """`evidence_class` and `class` are two vocabularies, and the message must say so.

    A reader who sees "missing class" on a unit that plainly has `class = "V0"` goes
    looking for a typo. The failure is a different field entirely.
    """
    unit = _tested()
    del unit["evidence_class"]
    problems = class_problems("u", unit)
    assert len(problems) == 1
    assert "V0/V1/V2" in problems[0]


def test_proved_without_a_formal_uri_is_refused():
    problems = class_problems("u", _tested(evidence_class="proved"))
    assert any("verus://" in p for p in problems)


def test_proved_requires_the_selection_its_own_prover_reads():
    """`proved_symbols` and `lean_theorems` are not interchangeable.

    A Verus unit naming only Lean theorems has named nothing the Verus lane can select,
    and the lane would then ask only whether the crate verified SOMETHING.
    """
    verus = {
        "id": "x",
        "evidence_class": "proved",
        "evidence": ["verus://x/spec"],
        "lean_theorems": ["X.thm"],
    }
    assert any("proved_symbols" in p for p in class_problems("u", verus))
    lean = {
        "id": "x",
        "evidence_class": "proved",
        "evidence": ["lean://x/model"],
        "proved_symbols": ["x::f"],
    }
    assert any("lean_theorems" in p for p in class_problems("u", lean))


def test_tested_without_named_members_is_refused():
    unit = _tested()
    del unit["tested_symbols"]
    assert any("tested_symbols" in p for p in class_problems("u", unit))


def test_structural_without_a_compile_refusal_probe_is_refused():
    unit = _tested(evidence_class="structural")
    assert any("structural://" in p for p in class_problems("u", unit))


def test_measured_requires_all_four_of_rulings_elements():
    unit = {
        "id": "x",
        "evidence_class": "measured",
        "evidence": ["measured://x/census"],
        "measurement_protocol": "scripts/x.py",
    }
    problems = class_problems("u", unit)
    assert len(problems) == 1
    for key in MEASUREMENT_KEYS:
        if key != "measurement_protocol":
            assert key in problems[0]


def test_a_complete_measured_unit_is_accepted():
    unit = {"id": "x", "evidence_class": "measured", "evidence": ["measured://x/census"]}
    unit.update({key: "something" for key in MEASUREMENT_KEYS})
    assert class_problems("u", unit) == []


def test_measurement_fields_on_a_non_measured_unit_are_refused():
    """The converse direction, and it is not symmetry for its own sake.

    A `tested` unit carrying `measurement_scope` has declared an apparatus no lane reads.
    A field nothing consumes reads as coverage and measures nothing — the same defect the
    manifest already refuses for an extraction selection on a non-V2 unit.
    """
    unit = _tested(measurement_scope="the workspace")
    assert any("no lane reads them" in p for p in class_problems("u", unit))


def test_all_the_problems_are_reported_not_just_the_first():
    """A unit migrated to the wrong class usually has several.

    Reporting one per loader run is how a migration takes a week, and the person fixing it
    learns nothing about the shape of the mistake.
    """
    unit = _tested(evidence_class="structural", measurement_scope="the workspace")
    problems = class_problems("u", unit)
    assert len(problems) == 2, problems
    assert any("structural://" in p for p in problems)
    assert any("no lane reads them" in p for p in problems)


# --------------------------------------------------------------------------------------
# The live registries — the cases that catch a vocabulary declared and not migrated
# --------------------------------------------------------------------------------------


def _load(name):
    return tomllib.loads((POLICY_DIR / name).read_text(encoding="utf-8"))


def test_the_schema_version_was_bumped_for_the_new_required_keys():
    """A schema change alters what a fingerprint MEANS, so the bump is not bookkeeping.

    Adding a required key without it would leave every standing attestation reading as
    current evidence about a record shape that no longer exists.
    """
    assert SCHEMA_VERSION >= 2
    assert _load("verification.toml")["schema_version"] == SCHEMA_VERSION
    assert _load("theorems.toml")["schema_version"] == SCHEMA_VERSION


def test_every_live_unit_declares_an_adequate_class_and_a_severity():
    for index, unit in enumerate(_load("verification.toml")["unit"]):
        where = f"[[unit]] #{index} {unit.get('id')!r}"
        assert class_problems(where, unit) == [], class_problems(where, unit)
        assert severity_problem(where, unit) is None


def test_every_live_theorem_declares_a_severity():
    for index, entry in enumerate(_load("theorems.toml")["theorem"]):
        where = f"[[theorem]] #{index} {entry.get('id')!r}"
        assert severity_problem(where, entry) is None


def test_no_live_record_stores_a_derived_severity():
    """N3: `effective_severity` and `inherited_severity` are derived and never stored.

    A stored copy is a value that can disagree with the graph it was computed from, and
    the disagreement would be invisible — nothing re-derives a field that is simply there.
    """
    derived = {"effective_severity", "inherited_severity", "severity", "consequence_severity"}
    for name, key in (("verification.toml", "unit"), ("theorems.toml", "theorem")):
        for entry in _load(name)[key]:
            assert not derived & set(entry), f"{name} {entry.get('id')}"


def test_the_root_declaration_is_still_a_flat_list_of_ids():
    """S1 struck: a root's severity IS its theorem's `direct_consequence_severity`.

    A `consequence_severity` on the root entry would be a second representation of one
    fact, which is the duplicated authority the theorem loader rejects by name.
    """
    roots = _load("theorems.toml")["root_theorems"]
    assert roots and all(isinstance(entry, str) for entry in roots)


def test_every_root_theorems_severity_resolves():
    doc = _load("theorems.toml")
    by_id = {entry["id"]: entry for entry in doc["theorem"]}
    for root in doc["root_theorems"]:
        assert by_id[root]["direct_consequence_severity"] in SEVERITY_ORDER


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
