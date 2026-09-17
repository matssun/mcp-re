# SPDX-License-Identifier: Apache-2.0
"""The premise ontology's false-green catalogue — ADR-MCPRE-068 §7, Phase 0C.

Forty-seven records with one shape made the only question anybody asks unanswerable:
*which Critical or High root ultimately rests on something we merely assume?* Typing them
answers it only if the types cannot be stated loosely, so every way a premise could look
typed while saying nothing is a case below:

  * an untyped LIVE premise, and a typed WITHDRAWN one. Both directions matter: the first
    is the state this phase exists to end, and the second makes a retired record read as a
    live one;
  * an `external-boundary` with no owner, or an owner that names a THING — "Redis" is not a
    statement of what is guaranteed across which interface;
  * a `review-obligation` whose discharging event is PROSE. A sentence cannot be evaluated,
    and that is the field this one replaces;
  * an event of an unknown kind, an unknown predicate, or a predicate missing an operand.
    The vocabulary is closed, because an open one lets a record state a condition the gate
    silently cannot evaluate;
  * a class carrying a field its class does not read — coverage that measures nothing;
  * an OBSERVABLE event that has already come true while the record still exists. That is a
    FAIL, not a pass and not a silent discharge: the registry would be asserting debt the
    tree says is paid.

Run: python3 tools/verification/test_premise_class.py
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _load_tool import load_tool  # noqa: E402
from _manifest import (  # noqa: E402
    ASSUMPTIONS_SCHEMA_VERSION,
    ASSUMPTIONS_TOML,
    ManifestError,
    load_assumptions,
    load_toolchains,
    load_verification,
)
from _premise import (  # noqa: E402
    EVENT_KINDS,
    PREDICATES,
    PREMISE_CLASSES,
    STALE_CAUSE,
    class_problem,
    has_come_true,
    is_live,
    open_obligations,
    roots_reaching_premises,
)

lane = load_tool("check-assumptions", "check_assumptions_lane")

REGISTRY = load_assumptions()
ENTRIES = {entry["id"]: entry for entry in REGISTRY.get("assumption", [])}
TOOLCHAINS = load_toolchains()
VERIFICATION = load_verification()

OWNER = (
    "The Rust standard library, across `u8::is_ascii_digit`: its documented predicate over "
    "the ASCII digit code points."
)


def _entry(**overrides) -> dict:
    entry = {
        "id": "ASM-TEST",
        "scope": ["unit://x", "boundary://b"],
        "premise_class": "assumed",
    }
    entry.update(overrides)
    return {k: v for k, v in entry.items() if v is not None}


def _expect(entry: dict, fragment: str, live: bool = True) -> None:
    problem = class_problem("where", entry, live)
    assert problem is not None, f"expected a refusal mentioning {fragment!r}"
    assert fragment in problem, f"got: {problem}"


def _expect_ok(entry: dict, live: bool = True) -> None:
    problem = class_problem("where", entry, live)
    assert problem is None, f"unexpected refusal: {problem}"


# --- the class itself ------------------------------------------------------------------


def test_a_live_premise_must_be_typed():
    _expect(_entry(premise_class=None), "missing `premise_class`")


def test_a_withdrawn_premise_must_NOT_be_typed():
    """A withdrawn assumption trusts nothing — that is what withdrawing it meant. Typing it
    would make a retired premise read as a live one, which is the same defect pointed the
    other way, and `_require_boundary_edge` already draws the line in that place."""
    _expect(_entry(scope=[]), "withdrawn premise", live=False)
    _expect_ok(_entry(premise_class=None, scope=[]), live=False)


def test_an_evidence_class_is_not_a_premise_class():
    """`proved`/`structural`/`tested`/`measured` answer how MCP-RE ESTABLISHES something,
    which is the question a premise exists because nobody answered (Ruling 2)."""
    for wrong in ("tested", "structural", "proved", "measured"):
        _expect(_entry(premise_class=wrong), "EVIDENCE classes")


def test_the_three_classes_are_the_three_questions():
    assert PREMISE_CLASSES == ("assumed", "external-boundary", "review-obligation")


# --- external boundary (C2) ------------------------------------------------------------


def test_an_external_boundary_names_its_owner():
    _expect(_entry(premise_class="external-boundary"), "requires `boundary_owner`")


def test_an_owner_that_names_a_THING_is_not_an_owner_statement():
    """"Redis", alone, is not an owner statement: WHAT is guaranteed, across WHICH
    interface, under WHICH configuration is."""
    _expect(_entry(premise_class="external-boundary", boundary_owner="Redis"), "names a thing")
    _expect_ok(_entry(premise_class="external-boundary", boundary_owner=OWNER))


def test_an_external_boundary_schedules_no_discharge():
    """It is not discharged BY US, so an event here would record a debt nobody owes."""
    _expect(
        _entry(
            premise_class="external-boundary",
            boundary_owner=OWNER,
            discharging_event={"kind": "owner-event", "statement": "someday"},
        ),
        "carries no `discharging_event`",
    )


# --- review obligation (C3, C5) --------------------------------------------------------


def test_a_discharging_event_may_not_be_PROSE():
    _expect(
        _entry(premise_class="review-obligation", discharging_event="when vstd specifies it"),
        "TABLE",
    )


def test_a_review_obligation_has_no_boundary_owner():
    _expect(
        _entry(
            premise_class="review-obligation",
            boundary_owner=OWNER,
            discharging_event={"kind": "owner-event", "statement": "x"},
        ),
        "carries no `boundary_owner`",
    )


def test_the_event_vocabulary_is_closed():
    assert EVENT_KINDS == ("registry-fact", "tree-fact", "owner-event")
    _expect(
        _entry(premise_class="review-obligation", discharging_event={"kind": "someday"}),
        "not one of",
    )
    _expect(
        _entry(
            premise_class="review-obligation",
            discharging_event={"kind": "tree-fact", "predicate": "vibes", "site": "a#b"},
        ),
        "vocabulary is CLOSED",
    )


def test_a_predicate_missing_an_operand_is_refused():
    _expect(
        _entry(
            premise_class="review-obligation",
            discharging_event={"kind": "tree-fact", "predicate": "site-absent"},
        ),
        "missing",
    )


def test_an_owner_event_states_what_is_being_watched_for():
    """It is the one kind nothing observes, so the statement is the whole record of it."""
    _expect(
        _entry(premise_class="review-obligation", discharging_event={"kind": "owner-event"}),
        "states what the owner is watching for",
    )
    _expect_ok(
        _entry(
            premise_class="review-obligation",
            discharging_event={"kind": "owner-event", "statement": "a theorem reads the key"},
        )
    )


def test_an_assumed_premise_carries_neither_conditional_field():
    """A field nothing reads is a declaration that looks like coverage. What makes an
    assumed premise stop being acceptable belongs in `justification`."""
    _expect(_entry(boundary_owner=OWNER), "'assumed'")
    _expect(_entry(discharging_event={"kind": "owner-event", "statement": "x"}), "'assumed'")


# --- C4: the observable event that has already happened --------------------------------


def _obligation(event: dict) -> dict:
    return _entry(id="ASM-TEST", premise_class="review-obligation", discharging_event=event)


def test_a_toolchain_that_moved_off_the_pin_is_STALE():
    pinned = TOOLCHAINS["verus"]["release"]
    event = {"kind": "registry-fact", "predicate": "toolchain-version-differs", "tool": "verus"}
    assert has_come_true(_obligation({**event, "from": pinned}), VERIFICATION, TOOLCHAINS) is None
    problem = has_come_true(_obligation({**event, "from": "0.0.0"}), VERIFICATION, TOOLCHAINS)
    assert problem is not None and STALE_CAUSE in problem, problem


def test_a_unit_that_gained_the_evidence_the_premise_stood_in_for_is_STALE():
    unit = VERIFICATION["unit"][0]
    event = {"kind": "registry-fact", "predicate": "unit-has-evidence-scheme", "unit": unit["id"]}
    problem = has_come_true(_obligation({**event, "scheme": "test"}), VERIFICATION, TOOLCHAINS)
    assert problem is not None and STALE_CAUSE in problem, problem
    assert (
        has_come_true(_obligation({**event, "scheme": "lean"}), VERIFICATION, TOOLCHAINS) is None
    )


def test_a_premise_about_a_site_the_tree_no_longer_holds_is_STALE():
    event = {"kind": "tree-fact", "predicate": "site-absent"}
    here = "tools/verification/_premise.py#anything"
    assert has_come_true(_obligation({**event, "site": here}), VERIFICATION, TOOLCHAINS) is None
    gone = "mcp-re-core/src/deleted_last_year.rs#parse"
    problem = has_come_true(_obligation({**event, "site": gone}), VERIFICATION, TOOLCHAINS)
    assert problem is not None and STALE_CAUSE in problem, problem


def test_an_owner_event_is_never_decided_by_the_gate():
    """The gate does not guess whether an unobservable event happened. It reports the
    obligation as OPEN, against every root whose closure reaches it."""
    event = {"kind": "owner-event", "statement": "a theorem begins to concern Display output"}
    assert has_come_true(_obligation(event), VERIFICATION, TOOLCHAINS) is None


def test_the_lane_reports_no_stale_obligation_today():
    """And it is a real evaluation rather than a constant: the case above proves the same
    function goes red on a perturbed record."""
    assert lane.stale_obligations() == []


# --- the registry as it stands ---------------------------------------------------------


def test_every_live_premise_is_typed_and_every_withdrawn_one_is_not():
    for entry in REGISTRY["assumption"]:
        problem = class_problem(entry["id"], entry, is_live(entry))
        assert problem is None, problem


def test_the_estate_is_fully_typed_and_the_split_is_the_measured_one():
    counts = {name: 0 for name in PREMISE_CLASSES}
    withdrawn = 0
    for entry in REGISTRY["assumption"]:
        if is_live(entry):
            counts[entry["premise_class"]] += 1
        else:
            withdrawn += 1
    assert sum(counts.values()) + withdrawn == 47, counts
    assert withdrawn == 4, "ASM-0015, ASM-0022, ASM-0042 and ASM-0043 trust nothing"
    assert all(count for count in counts.values()), (
        f"a class nothing uses is a class nobody had to think about: {counts}"
    )


def test_the_schema_version_is_enforced():
    """A registry written against schema 1 loading under schema-2 tooling would be read as a
    fully typed estate with 47 untyped records in it."""
    doc = tomllib.loads(ASSUMPTIONS_TOML.read_text(encoding="utf-8"))
    assert doc["schema_version"] == ASSUMPTIONS_SCHEMA_VERSION


def test_open_obligations_are_reportable_and_each_names_its_event():
    obligations = open_obligations(REGISTRY)
    assert obligations, "an estate with no open obligation would be a claim worth checking"
    for entry in obligations:
        event = entry["discharging_event"]
        assert event["kind"] in EVENT_KINDS
        if event["kind"] != "owner-event":
            assert event["predicate"] in PREDICATES[event["kind"]]


def test_the_root_to_premise_composition_is_not_empty():
    """§7's missing half, and the case that catches it being missing again. Both ends of the
    join carry `unit://` URIs; comparing one against the other verbatim produced an empty
    intersection for all twelve roots and printed "no root rests on any premise", which
    reads exactly like a clean result."""
    from _theorems import load_theorems

    theorems = load_theorems(
        {unit["id"] for unit in VERIFICATION.get("unit", [])},
        [e for e in VERIFICATION.get("edge", []) if e.get("kind") == "PROOF_DEPENDENCY"],
    )
    reach = roots_reaching_premises(theorems, VERIFICATION, REGISTRY)
    assert reach, "twelve roots are declared; a view with no rows is measuring nothing"
    total = sum(len(ids) for rows in reach.values() for ids in rows.values())
    assert total > 0, "no root reaching any premise is a JOIN THAT FAILED, not a clean tree"
    reached = {asm for rows in reach.values() for ids in rows.values() for asm in ids}
    assert all(ENTRIES[asm].get("premise_class") for asm in reached)


def test_a_withdrawn_premise_reaches_no_root():
    """It trusts nothing, so it is nobody's premise. A retired record appearing under a root
    would be the live/withdrawn confusion arriving by the back door."""
    from _theorems import load_theorems

    theorems = load_theorems(
        {unit["id"] for unit in VERIFICATION.get("unit", [])},
        [e for e in VERIFICATION.get("edge", []) if e.get("kind") == "PROOF_DEPENDENCY"],
    )
    reach = roots_reaching_premises(theorems, VERIFICATION, REGISTRY)
    reached = {asm for rows in reach.values() for ids in rows.values() for asm in ids}
    withdrawn = {entry["id"] for entry in REGISTRY["assumption"] if not is_live(entry)}
    assert not (reached & withdrawn), sorted(reached & withdrawn)


def test_the_toolchain_ceiling_obligation_is_pinned_to_the_version_in_the_lock():
    """ASM-0021 is held open by two measured ceilings under the pinned Verus. A bump is the
    event, so the version it names and the version the lock pins are ONE fact."""
    event = ENTRIES["ASM-0021"]["discharging_event"]
    assert event["predicate"] == "toolchain-version-differs"
    assert event["from"] == TOOLCHAINS["verus"]["release"]


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
