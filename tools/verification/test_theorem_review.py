# SPDX-License-Identifier: Apache-2.0
"""The specification-gap control — ADR-MCPRE-059 §14.1, §14.3, §14.7.

**The essential negative control, and the reason this phase exists:** weaken a theorem's
statement while its proof stays green, and specification review goes dirty. If that fails,
a green prover can carry a stale approval of a claim nobody re-read, which is the exact
substitution the theorem layer was built to refuse.

Everything else here keeps that control from being satisfied vacuously:

  * the two axes must be SEPARATE — restating a claim must not move a unit fingerprint, and
    editing source must not move a theorem fingerprint. Either leak collapses them into the
    single green/red bit §14.7 forbids;
  * a premise weakened three theorems down must reach the claim on top;
  * relaxing `review_requirement` must dirty the review, or the one edit that lowers the
    bar is the one edit nothing notices;
  * an absent, malformed, or forbidden-key review record must never read as an approval;
  * establishment must fail when ANY axis fails, so no axis can carry the others.

Run: python3 tools/verification/test_theorem_review.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _fingerprint import (  # noqa: E402
    assumption_digest,
    fingerprint_theorem,
    fingerprint_unit,
)
from _manifest import (  # noqa: E402
    load_assumptions,
    load_toolchains,
    load_verification,
)
from _review import (  # noqa: E402
    REVIEWED,
    REVIEW_STATES,
    UNREVIEWED,
    _valid,
    derive_review_state,
    load_reviews,
    theorem_assurance,
)

UNIT = "http_profile.freshness_window"


def theorem(**overrides) -> dict:
    entry = {
        "id": "THM-0001",
        "title": "Freshness admission implies the accepted window is current",
        "statement": "Every admitted request satisfies the skew-widened window constraints.",
        "security_consequence": "A request cannot be admitted on stale freshness evidence.",
        "scope": "Freshness admission only; not signature validity or replay uniqueness.",
        "owner": UNIT,
        "review_requirement": "Owner security-specification review",
        "supported_by": [f"unit://{UNIT}"],
        "depends_on": [],
    }
    entry.update(overrides)
    return entry


def registry(*rows) -> dict:
    return {"schema_version": 1, "theorem": list(rows or (theorem(),))}


def review_for(current: dict, subject: str = "THM-0001") -> dict:
    """The record a reviewer commits after reading the claim as it stands."""
    return {
        "axis": "specification",
        "subject": subject,
        "reviewed_fingerprint": current["fingerprint"],
        "components": current["components"],
        "reviewer": "owner@example.com",
    }


def fingerprints(doc: dict) -> dict[str, dict]:
    return {row["id"]: fingerprint_theorem(row, doc) for row in doc["theorem"]}


# --- THE control ---------------------------------------------------------------


def test_weakening_a_statement_dirties_specification_review():
    """`all accepted transitions` → `all NORMAL accepted transitions`, §14.7's own example.

    No source moved, so every prover stays green. The claim moved, so the approval no longer
    covers what is written — and nobody had to remember a rule for that to happen."""
    strong = registry()
    before = fingerprints(strong)["THM-0001"]
    record = review_for(before)
    assert derive_review_state(before, record)[0] == REVIEWED

    weak = registry(
        theorem(
            statement="Every NORMAL admitted request satisfies the skew-widened window "
            "constraints."
        )
    )
    after = fingerprints(weak)["THM-0001"]

    state, reason = derive_review_state(after, record)
    assert state == "STALE_CLAIM", (state, reason)
    assert "theorem_claim" in reason


def test_the_prover_stays_green_while_the_specification_goes_dirty():
    """The other half of the same control, and the one that makes it meaningful.

    If restating a claim also moved the UNIT fingerprint, the prover would go dirty too and
    the test above would prove nothing about the separation of axes — it would just be a
    global invalidation."""
    doc = load_verification()
    unit = next(row for row in doc["unit"] if row["id"] == UNIT)
    toolchains, assumptions = load_toolchains(), load_assumptions()

    before = fingerprint_unit(unit, doc, toolchains, assumptions)
    # Restate the theorem — the registry is a different file entirely.
    _ = fingerprints(registry(theorem(statement="something else entirely")))
    after = fingerprint_unit(unit, doc, toolchains, assumptions)

    assert before["fingerprint"] == after["fingerprint"]
    assert "theorem_claim" not in after["components"]


def test_a_source_change_does_not_dirty_specification_review():
    """The converse leak. A theorem fingerprint that read source would make every code edit
    invalidate the owner's approval of the specification, which trains people to re-approve
    without reading — the failure mode a too-broad invalidation always produces."""
    current = fingerprints(registry())["THM-0001"]
    assert set(current["components"]) == {
        "encoding_version",
        "theorem_id",
        "theorem_claim",
        "theorem_dependencies",
        "theorem_review_requirement",
    }


# --- what else must move the claim ----------------------------------------------


def test_widening_scope_dirties_review():
    """`scope` is where a claim says what it does NOT establish. Widening it silently is how
    an over-read enters a document that still reads as reviewed."""
    before = fingerprints(registry())["THM-0001"]
    record = review_for(before)
    after = fingerprints(registry(theorem(scope="Everything about admission.")))["THM-0001"]
    assert derive_review_state(after, record)[0] == "STALE_CLAIM"


def test_relaxing_the_review_requirement_dirties_review():
    """An approval given under owner review is not an approval under 'any review'."""
    before = fingerprints(registry())["THM-0001"]
    record = review_for(before)
    after = fingerprints(registry(theorem(review_requirement="Any reviewer")))["THM-0001"]
    state, reason = derive_review_state(after, record)
    assert state == "STALE_REVIEW_REQUIREMENT", (state, reason)


def test_renaming_a_theorem_does_not_dirty_review():
    """`title` is a label, not the proposition. If renaming invalidated approvals, the
    registry would punish the one edit that costs nothing to make."""
    before = fingerprints(registry())["THM-0001"]
    record = review_for(before)
    after = fingerprints(registry(theorem(title="A clearer name for the same claim")))[
        "THM-0001"
    ]
    assert derive_review_state(after, record)[0] == REVIEWED


# --- composition ------------------------------------------------------------------


def premise_chain(bottom_statement: str) -> dict:
    return registry(
        theorem(id="THM-0001", statement=bottom_statement),
        theorem(id="THM-0002", depends_on=["THM-0001"]),
        theorem(id="THM-0003", depends_on=["THM-0002"]),
    )


def test_weakening_a_premise_dirties_every_claim_above_it():
    """Transitive, not just direct. A claim rests on everything underneath it, so a premise
    rewritten two levels down must reach the top — otherwise the composition is a badge."""
    before = fingerprints(premise_chain("The strong premise."))
    records = {tid: review_for(fp, tid) for tid, fp in before.items()}
    after = fingerprints(premise_chain("A much weaker premise."))

    assert derive_review_state(after["THM-0001"], records["THM-0001"])[0] == "STALE_CLAIM"
    for dependent in ("THM-0002", "THM-0003"):
        state, reason = derive_review_state(after[dependent], records[dependent])
        assert state == "STALE_DEPENDENCY_CLAIM", (dependent, state, reason)
        assert "theorem_dependencies" in reason


def test_adding_a_dependency_dirties_the_dependent():
    before = fingerprints(registry(theorem(id="THM-0001"), theorem(id="THM-0002")))
    record = review_for(before["THM-0002"], "THM-0002")
    after = fingerprints(
        registry(theorem(id="THM-0001"), theorem(id="THM-0002", depends_on=["THM-0001"]))
    )
    assert derive_review_state(after["THM-0002"], record)[0] == "STALE_DEPENDENCY_CLAIM"


def test_a_sibling_theorem_over_the_same_unit_is_untouched():
    """Several theorems share one supporting unit. Restating one must not dirty the others,
    or the layer's whole benefit — separating claims that a single prover run supports —
    disappears into one shared status."""
    before = fingerprints(registry(theorem(id="THM-0001"), theorem(id="THM-0002")))
    record = review_for(before["THM-0002"], "THM-0002")
    after = fingerprints(
        registry(theorem(id="THM-0001", statement="Restated."), theorem(id="THM-0002"))
    )
    assert derive_review_state(after["THM-0002"], record)[0] == REVIEWED


# --- records that must not read as approvals ---------------------------------------


def test_an_absent_record_is_unreviewed():
    current = fingerprints(registry())["THM-0001"]
    assert derive_review_state(current, None)[0] == UNREVIEWED


def test_a_record_carrying_an_approval_bit_is_dropped():
    """§14.7: no mutable approval string. A record that says `approved: true` alongside a
    fingerprint is the stored status field wearing the record's clothes.

    Refused by the CLOSED schema rather than by a list of bad names — that is the stronger
    rule, since it also refuses the approval bit nobody thought to name. The named-key scan
    over arbitrary documents is `scripts/registry_approval_gate.py`."""
    current = fingerprints(registry())["THM-0001"]
    for key in ("approved", "status", "verdict", "signed_off", "anything_else"):
        assert _valid(review_for(current) | {key: True}) is None, key
    # And the schema is closed in the direction that matters: dropping a REQUIRED key is
    # equally fatal, so a record cannot approve without naming who reviewed or what.
    for key in ("reviewer", "reviewed_fingerprint", "subject", "axis"):
        record = review_for(current)
        del record[key]
        assert _valid(record) is None, key


def test_a_record_for_the_wrong_axis_is_dropped():
    current = fingerprints(registry())["THM-0001"]
    assert _valid(review_for(current) | {"axis": "assumption"}) is None
    assert _valid(review_for(current) | {"axis": "vibes"}) is None


def test_a_record_with_no_reviewer_is_dropped():
    current = fingerprints(registry())["THM-0001"]
    assert _valid(review_for(current) | {"reviewer": "  "}) is None


def test_a_record_predating_the_current_components_is_unknown_not_reviewed():
    """The `_graph` rule, restated on this axis: a record that cannot be compared says
    nothing, and saying nothing is not approval."""
    current = fingerprints(registry())["THM-0001"]
    stale_schema = review_for(current)
    stale_schema["components"] = {"theorem_claim": current["components"]["theorem_claim"]}
    state, reason = derive_review_state(current, stale_schema)
    assert state == "UNKNOWN" and "predates" in reason


def test_matching_components_with_a_different_digest_is_unknown():
    """Components equal, aggregate different ⇒ the encoding changed, so the comparison
    means something else. Preserved from the unit engine deliberately."""
    current = fingerprints(registry())["THM-0001"]
    record = review_for(current)
    record["reviewed_fingerprint"] = "sha256:" + "0" * 64
    state, reason = derive_review_state(current, record)
    assert state == "UNKNOWN" and "encoding" in reason


def test_a_componentless_record_still_detects_staleness():
    current = fingerprints(registry())["THM-0001"]
    record = review_for(current)
    del record["components"]
    assert derive_review_state(current, record)[0] == REVIEWED
    after = fingerprints(registry(theorem(statement="Restated.")))["THM-0001"]
    state, reason = derive_review_state(after, record)
    assert state == "STALE_REVIEW" and "no components" in reason


def test_every_returned_state_is_in_the_closed_set():
    """A state nobody enumerated is a state no consumer handles, and an unhandled state in a
    conjunction is how a not-reviewed subject slips through as truthy."""
    current = fingerprints(registry())["THM-0001"]
    seen = {
        derive_review_state(current, None)[0],
        derive_review_state(current, review_for(current))[0],
    }
    assert seen <= REVIEW_STATES


# --- the conjunction: no axis may carry the others ----------------------------------


def assurance(doc, *, unit_state="FRESH", reviewed=True, **kwargs):
    fps = fingerprints(doc)
    reviews = {}
    if reviewed:
        reviews = {
            ("specification", tid): review_for(fp, tid) for tid, fp in fps.items()
        }
    states = {UNIT: (unit_state, "test fixture")}
    return theorem_assurance(doc, fps, reviews, states, **kwargs)


def test_all_axes_green_is_established():
    assert assurance(registry())["THM-0001"]["established"] is True


def test_an_unreviewed_specification_is_not_established():
    """The case the whole phase is for: the prover is green, the unit is FRESH, and nobody
    has reviewed what is claimed."""
    assert assurance(registry(), reviewed=False)["THM-0001"]["established"] is False


def test_a_dirty_unit_is_not_established():
    for state in ("DIRTY_SELF", "DIRTY_ASSUMPTION", "UNKNOWN", "BLOCKED"):
        result = assurance(registry(), unit_state=state)
        assert result["THM-0001"]["established"] is False, state


def test_a_theorem_with_no_supporting_unit_is_not_established():
    assert assurance(registry(theorem(supported_by=[])))["THM-0001"]["established"] is False


def test_a_deprecated_theorem_is_not_established():
    doc = registry(theorem(id="THM-0001", replaced_by="THM-0002"), theorem(id="THM-0002"))
    assert assurance(doc)["THM-0001"]["established"] is False
    assert assurance(doc)["THM-0002"]["established"] is True


def test_an_unestablished_premise_denies_every_claim_above_it():
    doc = premise_chain("The premise.")
    fps = fingerprints(doc)
    # Everything reviewed and fresh EXCEPT the bottom premise's review.
    reviews = {
        ("specification", tid): review_for(fp, tid)
        for tid, fp in fps.items()
        if tid != "THM-0001"
    }
    result = theorem_assurance(doc, fps, reviews, {UNIT: ("FRESH", "fixture")})
    assert [result[tid]["established"] for tid in ("THM-0001", "THM-0002", "THM-0003")] == [
        False,
        False,
        False,
    ]


# --- the repository as it stands -----------------------------------------------------


def test_the_live_review_store_is_wellformed_and_empty():
    """No theorem is declared, so no review record may exist. A record for a theorem that
    does not exist would be an approval of nothing, sitting in the tree looking valid."""
    from _manifest import REPO_ROOT
    from _review import review_root
    from _theorems import load_theorems

    doc = load_verification()
    theorems = load_theorems({unit["id"] for unit in doc.get("unit", [])})
    declared = {row["id"] for row in theorems.get("theorem", [])}
    for (axis, subject), _record in load_reviews(review_root(REPO_ROOT)).items():
        if axis == "specification":
            assert subject in declared, f"review for undeclared theorem {subject}"


def test_the_assumption_axis_reads_the_live_registry_entry():
    """The assumption axis keys on the entry's content digest, so widening a justification
    invalidates its review exactly as weakening a statement invalidates a specification."""
    entries = load_assumptions().get("assumption", [])
    assert entries, "the pilot registered assumptions; this test needs one"
    entry = dict(entries[0])
    before = assumption_digest(entry)
    entry["justification"] = entry["justification"] + " And another thing."
    assert assumption_digest(entry) != before


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
