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

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _fingerprint import (  # noqa: E402
    EVIDENCE_UNIT_COMPONENTS,
    SEMANTIC_UNIT_COMPONENTS,
    assumption_digest,
    canonical_digest,
    fingerprint_theorem,
    fingerprint_unit,
    theorem_premises,
    theorem_review_digests,
)
from _manifest import (  # noqa: E402
    load_assumptions,
    load_toolchains,
    load_verification,
)
from _review import (  # noqa: E402
    CAUSE_PRECEDENCE,
    COMPLETE,
    COMPONENT_CAUSE,
    INCOMPLETE,
    REVIEWED,
    REVIEW_STATES,
    NO_SEMANTIC_DIGEST,
    PREMISE_UNREVIEWED,
    STALE_SEMANTICS,
    UNBACKED,
    UNDECLARED,
    UNREVIEWED,
    _valid,
    closure_satisfied,
    derive_review_state,
    _by_precedence,
    load_reviews,
    root_completeness,
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


def registry(*rows, roots: list[str] | None = None) -> dict:
    return {
        "schema_version": 1,
        "root_theorems": list(roots or []),
        "theorem": list(rows or (theorem(),)),
    }


def review_for(current: dict, subject: str = "THM-0001", semantic: dict | None = None) -> dict:
    """The record a reviewer commits after reading the claim as it stands — and, when
    `semantic` is given, the supporting evidence it was read against."""
    record = {
        "axis": "specification",
        "subject": subject,
        "reviewed_fingerprint": current["fingerprint"],
        "components": current["components"],
        "reviewer": "owner@example.com",
    }
    if semantic is not None:
        record["review_digest"] = semantic["fingerprint"]
        record["review_components"] = semantic["components"]
    return record


def unit_fp(**overrides) -> dict:
    """A supporting unit's fingerprint with one value per kind of component: semantic
    (source, test selection, proved symbols) and evidence-only (toolchain, lane identity,
    policy revision)."""
    components = {
        "encoding_version": 10,
        "unit_id": UNIT,
        "class": "V1",
        "source_inputs": {"src/freshness.rs": "sha256:aaa"},
        "test_selection": {"symbols": ["freshness::tests::admits_inside_window"]},
        "proved_symbols": ["check_freshness"],
        "trusted_assumptions": {},
        "governing_boundaries": {},
        "toolchain_identity": {"verus": "0.2026.09.01"},
        "verus_lane_identity": {"tools/verification/verify-verus": "sha256:bbb"},
        "review_policy_revision": "policy-7",
    }
    components.update(overrides)
    return {"unit_id": UNIT, "fingerprint": canonical_digest(components), "components": components}


UNIT_FP = unit_fp()


def semantics(doc: dict, premises: dict, units: dict | None = None) -> dict:
    return theorem_review_digests(
        doc, fingerprints(doc), premises, {UNIT: UNIT_FP} if units is None else units
    )


def fingerprints(doc: dict) -> dict[str, dict]:
    return {row["id"]: fingerprint_theorem(row, doc) for row in doc["theorem"]}


# --- THE control ---------------------------------------------------------------


def test_the_reported_cause_is_a_decision_not_an_alphabet():
    """Several components can move at once, and the reviewer is told ONE cause. Which one
    was `sorted(causes)[0]` — alphabetical order, which happened to put `STALE_CLAIM` first.

    Correct by accident is not correct: the next cause added ranks itself by its spelling,
    and a `STALE_A…` would mask a moved claim behind it. Both halves are asserted here —
    that the ranking holds, and that ALPHABETICAL ORDER IS NOT THE MECHANISM, which is the
    half a green tree cannot show."""
    # The ranking itself, over the real causes.
    assert _by_precedence({"STALE_CLAIM", "STALE_REVIEW_REQUIREMENT"}) == "STALE_CLAIM"
    assert (
        _by_precedence({"STALE_DEPENDENCY_CLAIM", "STALE_REVIEW_REQUIREMENT"})
        == "STALE_DEPENDENCY_CLAIM"
    )
    # A component this schema cannot name leads, mirroring UNKNOWN in `_graph`: the named
    # causes cannot be assumed complete when an unnamed one moved.
    assert _by_precedence({"STALE_CLAIM", "STALE_INPUT"}) == "STALE_INPUT"

    # The falsifier. Under the old rule this returned the alphabetically first name; under
    # the precedence it returns the RANKED one, and the two disagree by construction.
    invented = "STALE_AAA_WOULD_HAVE_WON_ALPHABETICALLY"
    assert sorted({"STALE_CLAIM", invented})[0] == invented
    assert _by_precedence({"STALE_CLAIM", invented}) == "STALE_CLAIM"
    # An unranked cause sorts LAST, so it can never silently outrank a placed one.
    assert _by_precedence({invented}) == invented

    # And the ranking covers exactly the causes a moved COMPONENT can produce, so none
    # reaches the fallback by omission. `STALE_REVIEW` is deliberately outside it: that is
    # what a record carrying no components yields, which is not a statement about which
    # component moved and has no place in an ordering of those.
    producible = set(COMPONENT_CAUSE.values()) | {"STALE_INPUT"}
    assert set(CAUSE_PRECEDENCE) == producible, (
        set(CAUSE_PRECEDENCE) ^ producible
    )
    assert producible <= REVIEW_STATES
    assert "STALE_REVIEW" not in CAUSE_PRECEDENCE


def test_two_components_moving_reports_the_more_fundamental_one():
    """The same property end to end, through `derive_review_state` rather than the helper:
    a theorem whose claim AND whose review requirement both moved is STALE_CLAIM, because
    the claim has to be re-read either way."""
    strong = registry()
    before = fingerprints(strong)["THM-0001"]
    record = review_for(before)
    assert derive_review_state(before, record)[0] == REVIEWED

    moved = registry(
        theorem(
            statement="Every NORMAL admitted request satisfies the skew-widened window "
            "constraints.",
            review_requirement="Owner security-specification review",
        )
    )
    after = fingerprints(moved)["THM-0001"]
    state, reason = derive_review_state(after, record)
    assert state == "STALE_CLAIM", (state, reason)
    assert "theorem_claim" in reason


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


def test_a_source_change_does_not_move_the_claim_fingerprint():
    """The claim fingerprint is the claim surface alone — what the correction chain and the
    claim-surface gate are about. Supporting source reaches the review through the separate
    semantic `review_digest` (tested below), never through this digest: folding it in here
    would make every code edit read as a change to what the theorem SAYS."""
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


#: Every subject backed by the owner-approval ledger: the fixtures below test the other
#: axes, and `test_*premise*`/`test_*ledger*` test this one.
class Backing(dict):
    """A ledger answer for every subject, `default` unless overridden."""

    def __init__(self, default=(True, "fixture ledger signs it"), **overrides):
        super().__init__(overrides)
        self.default = default

    def get(self, key, fallback=None):
        return super().get(key, self.default)


BACKED = Backing()


def no_premises(doc) -> dict:
    return {row["id"]: {} for row in doc["theorem"]}


def assurance(doc, *, unit_state="FRESH", reviewed=True, **kwargs):
    fps = fingerprints(doc)
    digests = semantics(doc, no_premises(doc))
    reviews = {}
    if reviewed:
        reviews = {
            ("specification", tid): review_for(fp, tid, digests[tid]) for tid, fp in fps.items()
        }
    states = {UNIT: (unit_state, "test fixture")}
    return theorem_assurance(
        doc, fps, reviews, states, no_premises(doc), BACKED, digests, **kwargs
    )


def test_all_axes_green_is_established():
    assert assurance(registry())["THM-0001"]["currently_verified"] is True


def test_an_unreviewed_specification_is_not_established():
    """The case the whole phase is for: the prover is green, the unit is FRESH, and nobody
    has reviewed what is claimed."""
    assert assurance(registry(), reviewed=False)["THM-0001"]["currently_verified"] is False


def test_a_dirty_unit_is_not_established():
    for state in ("DIRTY_SELF", "DIRTY_ASSUMPTION", "UNKNOWN", "BLOCKED"):
        result = assurance(registry(), unit_state=state)
        assert result["THM-0001"]["currently_verified"] is False, state


def test_a_theorem_with_no_supporting_unit_is_not_established():
    assert assurance(registry(theorem(supported_by=[])))["THM-0001"]["currently_verified"] is False


def test_a_deprecated_theorem_is_not_established():
    doc = registry(theorem(id="THM-0001", replaced_by="THM-0002"), theorem(id="THM-0002"))
    assert assurance(doc)["THM-0001"]["currently_verified"] is False
    assert assurance(doc)["THM-0002"]["currently_verified"] is True


def test_an_unestablished_premise_denies_every_claim_above_it():
    doc = premise_chain("The premise.")
    fps = fingerprints(doc)
    # Everything reviewed and fresh EXCEPT the bottom premise's review.
    digests = semantics(doc, no_premises(doc))
    reviews = {
        ("specification", tid): review_for(fp, tid, digests[tid])
        for tid, fp in fps.items()
        if tid != "THM-0001"
    }
    result = theorem_assurance(
        doc, fps, reviews, {UNIT: ("FRESH", "fixture")}, no_premises(doc), BACKED, digests
    )
    assert [result[tid]["currently_verified"] for tid in ("THM-0001", "THM-0002", "THM-0003")] == [
        False,
        False,
        False,
    ]


# --- the premise axis: REVIEWED covers the claim AND its premises (Ruling 34 §7 A) ------


ASM = {"id": "ASM-0001", "description": "The clock is monotone.", "scope": [f"unit://{UNIT}"]}


def assumption_review(entry: dict) -> dict:
    digest = assumption_digest(entry)
    return {
        "axis": "assumption",
        "subject": entry["id"],
        "reviewed_fingerprint": digest,
        "components": {"assumption_entry": digest},
        "reviewer": "owner@example.com",
    }


def premise_assurance(*, premise_entry=ASM, record=True, backing=BACKED):
    """The owner reviewed THM-0001 over premise `ASM`; the tree now has `premise_entry`."""
    doc = registry()
    fps = fingerprints(doc)
    read_at = semantics(doc, {"THM-0001": {ASM["id"]: assumption_digest(ASM)}})
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"], semantic=read_at["THM-0001"])}
    if record:
        reviews[("assumption", ASM["id"])] = assumption_review(ASM)
    premises = {"THM-0001": {premise_entry["id"]: assumption_digest(premise_entry)}}
    return theorem_assurance(
        doc, fps, reviews, {UNIT: ("FRESH", "fixture")}, premises, backing,
        semantics(doc, premises),
    )["THM-0001"]


def test_a_reviewed_claim_on_an_unreviewed_premise_is_not_reviewed():
    """The false REVIEWED the closure packet found: THM-0007 and 22 others read REVIEWED
    while an assumption under them changed and nobody signed it. The claim's own record is
    current; the premise has none."""
    state = premise_assurance(record=False)
    assert state["specification_review"][0] == REVIEWED
    assert state["review"][0] == PREMISE_UNREVIEWED, state["review"]
    assert state["currently_verified"] is False


def test_a_premise_reviewed_at_an_earlier_text_is_not_reviewed():
    """The digest is over the whole entry, so a widened premise invalidates its review."""
    widened = {**ASM, "description": ASM["description"] + " Or nearly so."}
    state = premise_assurance(premise_entry=widened)
    assert state["review"][0] == PREMISE_UNREVIEWED, state["review"]
    assert "ASM-0001" in state["review"][1]


def test_a_reviewed_and_backed_premise_lets_the_claim_be_reviewed():
    state = premise_assurance()
    assert state["review"][0] == REVIEWED, state["review"]
    assert state["currently_verified"] is True


def test_an_unknown_premise_closure_is_not_reviewed():
    """A theorem the caller computed no closure for has an UNKNOWN closure, not an empty
    one: no premises to check must not read as every premise checked."""
    doc = registry()
    fps = fingerprints(doc)
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"])}
    state = theorem_assurance(
        doc, fps, reviews, {UNIT: ("FRESH", "fixture")}, {}, BACKED, semantics(doc, {})
    )["THM-0001"]
    assert state["review"][0] != REVIEWED, state["review"]


# --- two axes: REVIEW_CURRENT and EVIDENCE_ESTABLISHED (Ruling 35 §3) -------------------


def two_axis(*, read_units=None, now_units=None, unit_state="FRESH", read_doc=None,
             now_doc=None, read_premises=None, now_premises=None, record=True):
    """The owner reviewed THM-0001 over `read_*`; the tree now has `now_*`. Every premise is
    reviewed and backed, so only the semantic and evidence axes are under test."""
    read_doc = read_doc or registry()
    now_doc = now_doc or read_doc
    read_premises = read_premises if read_premises is not None else no_premises(read_doc)
    now_premises = now_premises if now_premises is not None else read_premises
    read_units = read_units or {UNIT: UNIT_FP}
    now_units = now_units or read_units
    read_at = theorem_review_digests(read_doc, fingerprints(read_doc), read_premises, read_units)
    reviews = {}
    if record:
        reviews[("specification", "THM-0001")] = review_for(
            fingerprints(read_doc)["THM-0001"], semantic=read_at["THM-0001"]
        )
    for asm in (now_premises.get("THM-0001") or {}):
        reviews[("assumption", asm)] = {
            "axis": "assumption",
            "subject": asm,
            "reviewed_fingerprint": now_premises["THM-0001"][asm],
            "components": {"assumption_entry": now_premises["THM-0001"][asm]},
            "reviewer": "owner@example.com",
        }
    now_fps = fingerprints(now_doc)
    return theorem_assurance(
        now_doc,
        now_fps,
        reviews,
        {UNIT: (unit_state, "fixture")},
        now_premises,
        BACKED,
        theorem_review_digests(now_doc, now_fps, now_premises, now_units),
    )["THM-0001"]


def test_both_axes_current_is_currently_verified():
    state = two_axis()
    assert state["review_current"] and state["evidence_established"], state
    assert state["currently_verified"] is True


def test_a_claim_change_is_not_review_current():
    state = two_axis(now_doc=registry(theorem(statement="Some admitted requests are fresh.")))
    assert state["review_current"] is False
    assert state["review"][0] == "STALE_CLAIM", state["review"]
    assert state["currently_verified"] is False


def test_a_premise_change_is_not_review_current():
    """The new premise text is itself reviewed and backed — the THEOREM was still read over
    the old one, so its review is not current."""
    old = {"THM-0001": {"ASM-0001": assumption_digest(ASM)}}
    widened = {**ASM, "description": ASM["description"] + " Or nearly so."}
    new = {"THM-0001": {"ASM-0001": assumption_digest(widened)}}
    state = two_axis(read_premises=old, now_premises=new)
    assert state["premise_review"]["ASM-0001"][0] == REVIEWED
    assert state["review_current"] is False
    assert state["review"][0] == STALE_SEMANTICS, state["review"]
    assert "premise ASM-0001" in state["review"][1]


def test_an_implementation_semantics_change_is_not_review_current():
    """The case Ruling 34 §7 C found: the claim text stands still while the code it is about
    changes. The evidence can be re-run green; the review is still of other code."""
    moved = unit_fp(source_inputs={"src/freshness.rs": "sha256:ccc"})
    state = two_axis(now_units={UNIT: moved})
    assert state["review_current"] is False
    assert state["review"][0] == STALE_SEMANTICS, state["review"]
    assert "source_inputs" in state["review"][1]
    assert state["evidence_established"] is True  # a fresh run over the new code
    assert state["currently_verified"] is False


def test_a_material_test_selection_change_is_not_review_current():
    narrowed = unit_fp(test_selection={"symbols": []})
    state = two_axis(now_units={UNIT: narrowed})
    assert state["review_current"] is False
    assert "test_selection" in state["review"][1]


def test_a_proved_symbol_change_is_not_review_current():
    state = two_axis(now_units={UNIT: unit_fp(proved_symbols=[])})
    assert state["review_current"] is False
    assert "proved_symbols" in state["review"][1]


def _attested(fp: dict):
    from _graph import Attestation

    return {UNIT: Attestation(unit_id=UNIT, fingerprint=fp["fingerprint"], components=fp["components"])}


def test_a_toolchain_change_leaves_review_current_and_evidence_stale():
    """A Verus or Lean version bump with identical semantic inputs: the run must be repeated,
    and the owner has nothing new to read."""
    from _graph import derive_unit_state

    bumped = unit_fp(toolchain_identity={"verus": "0.2026.10.01"})
    unit_state, _ = derive_unit_state(UNIT, bumped, _attested(UNIT_FP))
    assert unit_state == "DIRTY_TOOLCHAIN"
    state = two_axis(now_units={UNIT: bumped}, unit_state=unit_state)
    assert state["review_current"] is True, state["review"]
    assert state["evidence_established"] is False
    assert state["currently_verified"] is False


def test_a_proof_policy_change_stales_evidence_until_re_established():
    from _graph import derive_unit_state

    for moved in (
        unit_fp(review_policy_revision="policy-8"),
        unit_fp(verus_lane_identity={"tools/verification/verify-verus": "sha256:ddd"}),
    ):
        stale, _ = derive_unit_state(UNIT, moved, _attested(UNIT_FP))
        assert stale != "FRESH"
        before = two_axis(now_units={UNIT: moved}, unit_state=stale)
        assert before["review_current"] is True
        assert before["evidence_established"] is False
        # Re-run under the new policy: an attestation at the new full fingerprint.
        fresh, _ = derive_unit_state(UNIT, moved, _attested(moved))
        assert fresh == "FRESH"
        after = two_axis(now_units={UNIT: moved}, unit_state=fresh)
        assert after["currently_verified"] is True


def test_neither_half_alone_is_currently_verified():
    only_review = two_axis(unit_state="UNKNOWN")
    assert only_review["review_current"] and not only_review["evidence_established"]
    assert only_review["currently_verified"] is False
    only_evidence = two_axis(now_units={UNIT: unit_fp(source_inputs={"x.rs": "sha256:1"})})
    assert only_evidence["evidence_established"] and not only_evidence["review_current"]
    assert only_evidence["currently_verified"] is False


def test_a_review_without_a_semantic_digest_is_never_current():
    """Records written before the semantic axis name no supporting evidence. No digest is
    reconstructed for them."""
    doc = registry()
    fps = fingerprints(doc)
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"])}
    state = theorem_assurance(
        doc, fps, reviews, {UNIT: ("FRESH", "fixture")}, no_premises(doc), BACKED,
        semantics(doc, no_premises(doc)),
    )["THM-0001"]
    assert state["specification_review"][0] == REVIEWED
    assert state["review"][0] == NO_SEMANTIC_DIGEST
    assert state["currently_verified"] is False


def test_an_uncomputable_semantic_digest_is_not_current():
    """A supporting unit with no fingerprint gives no digest, and nothing is current against
    no digest."""
    state = two_axis(now_units={"some.other_unit": UNIT_FP})
    assert state["review_current"] is False
    assert state["review"][0] == "UNKNOWN", state["review"]


def test_a_semantic_digest_on_a_non_specification_record_is_dropped():
    record = {
        "axis": "assumption",
        "subject": "ASM-0001",
        "reviewed_fingerprint": "sha256:" + "0" * 64,
        "review_digest": "sha256:" + "0" * 64,
        "reviewer": "owner@example.com",
    }
    assert _valid(record) is None


def test_every_unit_component_is_placed_on_exactly_one_axis():
    """The partition is closed. An unplaced component is treated as semantic, so forgetting
    one costs a re-read rather than a false current review — but it must still be placed,
    and this census over every live unit fingerprint and every component the freshness
    engine classifies is what makes it so."""
    from _graph import COMPONENT_STATE, STRUCTURAL_COMPONENT, UNRESOLVED_COMPONENT

    assert not SEMANTIC_UNIT_COMPONENTS & EVIDENCE_UNIT_COMPONENTS
    placed = SEMANTIC_UNIT_COMPONENTS | EVIDENCE_UNIT_COMPONENTS
    known = set(COMPONENT_STATE) | set(STRUCTURAL_COMPONENT) | set(UNRESOLVED_COMPONENT)
    assert known <= placed, sorted(known - placed)
    doc = load_verification()
    toolchains, assumptions = load_toolchains(), load_assumptions()
    produced = set()
    for unit in doc["unit"]:
        produced |= set(fingerprint_unit(unit, doc, toolchains, assumptions)["components"])
    assert produced <= placed, sorted(produced - placed)
    assert placed <= produced | known, sorted(placed - produced - known)


def test_the_toolchain_is_not_semantic_and_the_source_is():
    """Pins the two placements Ruling 35 §3 names, so a reshuffle of the sets that swapped
    them would fail here even if the census still balanced."""
    for name in ("toolchain_identity", "review_policy_revision", "verus_lane_identity",
                 "lean_lane_identity", "generated_inputs", "build_configuration"):
        assert name in EVIDENCE_UNIT_COMPONENTS, name
    for name in ("source_inputs", "test_selection", "test_sources", "mutation_probes",
                 "proved_symbols", "lean_theorem_sources", "trusted_assumptions"):
        assert name in SEMANTIC_UNIT_COMPONENTS, name


# --- ledger integrity: a record is backed by what the ledger SAYS (Ruling 34 §7 B) ------


def test_a_premise_review_the_ledger_does_not_sign_is_unbacked():
    """A review-axis record is a file anyone can commit. Without an owner signature over the
    entry's current text it does not make the premise reviewed."""
    unsigned = Backing(**{"ASM-0001": (False, "not signed")})
    state = premise_assurance(backing=unsigned)
    assert state["premise_review"]["ASM-0001"][0] == UNBACKED
    assert state["review"][0] == PREMISE_UNREVIEWED


def test_a_specification_review_the_ledger_refutes_is_unbacked():
    refuted = Backing(**{"THM-0001": (False, "signed only at other text")})
    doc = registry()
    fps = fingerprints(doc)
    digests = semantics(doc, no_premises(doc))
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"], semantic=digests["THM-0001"])}
    state = theorem_assurance(
        doc, fps, reviews, {UNIT: ("FRESH", "fixture")}, no_premises(doc), refuted, digests
    )["THM-0001"]
    assert state["specification_review"][0] == UNBACKED
    assert state["currently_verified"] is False


def test_no_ledger_check_is_not_a_pass():
    doc = registry()
    fps = fingerprints(doc)
    digests = semantics(doc, no_premises(doc))
    reviews = {("specification", "THM-0001"): review_for(fps["THM-0001"], semantic=digests["THM-0001"])}
    state = theorem_assurance(
        doc, fps, reviews, {UNIT: ("FRESH", "fixture")}, no_premises(doc), {}, digests
    )["THM-0001"]
    assert state["specification_review"][0] == UNBACKED


def test_the_ledger_signs_entry_text_not_a_subject_name():
    """`ledger_state` against a real-shaped ledger: an entry approval at earlier text does
    not back the entry; at the current text it does; an assumption the ledger only NAMES in
    a ruling's prose is not backed; a theorem with no entry approval keeps its record's
    authority."""
    from _approvals import entry_text, ledger_state, text_digest

    registry_text = (
        '[[assumption]]\nid = "ASM-0001"\ndescription = "now"\n\n'
        "# a comment introducing the next entry\n"
        '[[assumption]]\nid = "ASM-0002"\ndescription = "other"\n'
    )
    current = entry_text(registry_text, "ASM-0001")
    assert current == '[[assumption]]\nid = "ASM-0001"\ndescription = "now"\n'
    old = current.replace("now", "then")
    src = 'verification/policy/assumptions.toml [[assumption]] id = "ASM-0001"'
    stale = [{"source": src, "text": old, "sha256": text_digest(old), "ruling": "r1"}]
    assert ledger_state("ASM-0001", current, stale, allow_ruling=False)[0] is False
    signed = stale + [{"source": src, "text": current, "sha256": text_digest(current),
                       "ruling": "r2"}]
    assert ledger_state("ASM-0001", current, signed, allow_ruling=False)[0] is True
    prose = [{"source": "a ruling", "text": "x", "sha256": text_digest("x"), "ruling": "r",
              "surfaces": ["ASM-0001"]}]
    assert ledger_state("ASM-0001", current, prose, allow_ruling=False)[0] is False
    assert ledger_state("THM-0001", "irrelevant", prose, allow_ruling=True)[0] is True


def test_a_ledger_line_whose_digest_does_not_cover_its_text_is_refused():
    import tempfile

    from _approvals import ApprovalError, load_ledger

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "docs/security").mkdir(parents=True)
        line = {"ruling": "r", "approved_by": "o", "approved": "d", "source": "s",
                "text": "signed", "sha256": "0" * 64}
        (root / "docs/security/owner-approvals-2026-01-01.jsonl").write_text(
            json.dumps(line) + "\n"
        )
        try:
            load_ledger(root)
        except ApprovalError as exc:
            assert "does not cover" in str(exc)
        else:
            raise AssertionError("a forged ledger line was accepted")


def test_the_live_ledger_hashes_and_every_entry_approval_parses():
    from _approvals import entry_subject, load_ledger
    from _manifest import REPO_ROOT

    rows = load_ledger(REPO_ROOT)
    assert rows, "the live ledger is empty — a check over nothing is not a check"
    import tomllib

    for row in rows:
        if entry_subject(row):
            tomllib.loads(row["text"])


# --- root completeness: the second property, ADR-MCPRE-059 §28.8 ---------------------
#
# Freshness and completeness are different questions, and the controls below exist to keep
# them from being answered by one number. The pair that matters is the fourth and fifth: a
# repository whose evidence is entirely honest and current, whose ratified system promise is
# nevertheless open, must stay GREEN in ordinary CI and RED in closure mode. If the first
# half fails, recording a gap costs a red build and people stop recording gaps.


def rooted(*rows, roots, **kwargs):
    """Assurance plus the root-completeness derivation over the same registry."""
    doc = registry(*rows, roots=roots)
    return root_completeness(doc, assurance(doc, **kwargs))


def test_an_undeclared_root_set_is_never_a_pass():
    """The emptiest registry must not be the greenest. Nothing is claimed at the boundary,
    so nothing about the boundary is established — and closure mode refuses it too."""
    result = rooted(theorem(), roots=[])
    assert result["verdict"] == UNDECLARED, result
    assert closure_satisfied(result) is False


def test_a_ratified_root_with_no_support_closure_is_a_gap_not_a_pass():
    """Control 3. The claim is stated, its owner is real, and the evidence does not exist.
    That is the §28.5 GAP terminal, and it is DERIVED — there is no status field to set."""
    result = rooted(theorem(supported_by=[]), roots=["THM-0001"])
    assert result["verdict"] == INCOMPLETE, result
    causes = [row["cause"] for row in result["blocking"]["THM-0001"]]
    assert causes and causes[0].startswith("GAP:"), causes


def test_evidence_stays_pass_while_root_completeness_reports_incomplete():
    """Control 4, the load-bearing one. THM-0001 is established on fresh evidence and a
    current review; the ratified root above it rests on a premise that has none. Ordinary
    verification has nothing to complain about, and the system argument is still open."""
    leaf = theorem(id="THM-0001")
    missing = theorem(id="THM-0002", supported_by=[])
    root = theorem(id="THM-0003", depends_on=["THM-0001", "THM-0002"])
    doc = registry(leaf, missing, root, roots=["THM-0003"])
    states = assurance(doc)
    assert states["THM-0001"]["currently_verified"] is True
    result = root_completeness(doc, states)
    assert result["verdict"] == INCOMPLETE
    blocking = {row["theorem"]: row["cause"] for row in result["blocking"]["THM-0003"]}
    # The report names the node that actually blocks it, not only the root.
    assert blocking["THM-0002"].startswith("GAP:"), blocking
    assert blocking["THM-0003"].startswith("DEPENDENCY:"), blocking
    assert "THM-0001" not in blocking


def test_closure_mode_refuses_exactly_that_case():
    """Control 5. The same tree that ordinary CI passes is what T6 and release assurance
    must fail on."""
    leaf = theorem(id="THM-0001")
    missing = theorem(id="THM-0002", supported_by=[])
    root = theorem(id="THM-0003", depends_on=["THM-0001", "THM-0002"])
    result = rooted(leaf, missing, root, roots=["THM-0003"])
    assert closure_satisfied(result) is False


def test_completeness_becomes_pass_once_the_missing_support_is_established():
    """Control 6, paired with 3-5 so the refusal above is not vacuous: the identical shape
    with the gap closed reports COMPLETE and satisfies closure mode."""
    leaf = theorem(id="THM-0001")
    filled = theorem(id="THM-0002")
    root = theorem(id="THM-0003", depends_on=["THM-0001", "THM-0002"])
    result = rooted(leaf, filled, root, roots=["THM-0003"])
    assert result["verdict"] == COMPLETE, result
    assert result["blocking"] == {}
    assert closure_satisfied(result) is True


def test_a_dirty_unit_under_a_root_is_evidence_not_a_gap():
    """A stale lane and a missing architecture are different findings with different
    remedies. Reporting both as GAP would send a reviewer looking for a component that
    exists."""
    result = rooted(theorem(), roots=["THM-0001"], unit_state="DIRTY_SELF")
    causes = [row["cause"] for row in result["blocking"]["THM-0001"]]
    assert causes[0].startswith("EVIDENCE:"), causes


def test_an_unreviewed_root_is_reported_as_review_not_gap():
    result = rooted(theorem(), roots=["THM-0001"], reviewed=False)
    causes = [row["cause"] for row in result["blocking"]["THM-0001"]]
    assert causes[0].startswith("SPECIFICATION REVIEW UNREVIEWED"), causes


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



# --- the premise-closure rule (r12 defect D) ------------------------------------------


def _closure_fixture(*entries: dict) -> dict:
    """THM-A on unit `a`, THM-B on unit `b`; both cross `boundary.k`, only `a` is named."""
    theorems = {
        "theorem": [
            {"id": "THM-A", "supported_by": ["unit://a"]},
            {"id": "THM-B", "supported_by": ["unit://b"]},
        ]
    }
    registry = {"assumption": list(entries)}
    fps = {}
    for unit in ("a", "b"):
        named = {
            e["id"]: assumption_digest(e)
            for e in entries
            if f"unit://{unit}" in e.get("scope", [])
        }
        fps[unit] = {
            "components": {
                "trusted_assumptions": named,
                "governing_boundaries": {"boundary.k": "sha256:k"},
            }
        }
    return theorem_premises(theorems, fps, registry)


def _premise_entry(asm_id: str, scope: list[str], **extra) -> dict:
    return {"id": asm_id, "scope": scope, "premise_class": "assumed", **extra}


def test_a_unit_scoped_premise_does_not_spread_to_every_unit_crossing_its_boundary():
    """Over-inclusion. The `boundary://` entry of a unit-scoped premise says which boundary
    it discharges FOR the units it names; a second unit crossing the same boundary does not
    thereby rest on it. Spread, a narrowed scope changed no closure."""
    named = _premise_entry("ASM-N", ["unit://a", "boundary://boundary.k"])
    closure = _closure_fixture(named)
    assert set(closure["THM-A"]) == {"ASM-N"}
    assert closure["THM-B"] == {}, closure["THM-B"]


def test_a_boundary_only_premise_attaches_to_every_unit_crossing_its_boundary():
    """Nothing narrower was stated, so every crosser rests on it."""
    wide = _premise_entry("ASM-W", ["boundary://boundary.k"])
    closure = _closure_fixture(wide)
    assert set(closure["THM-A"]) == {"ASM-W"}
    assert set(closure["THM-B"]) == {"ASM-W"}


def test_a_model_registration_is_in_no_closure_and_its_interpreter_is():
    """Ruling 39 §4: trust is attributed to the premise that gives the symbol its meaning."""
    giver = _premise_entry("ASM-G", ["unit://a", "boundary://boundary.k"])
    registration = {
        "id": "ASM-R",
        "scope": ["unit://a", "boundary://boundary.k"],
        "premise_class": "model-registration",
        "interpreted_by": "ASM-G",
    }
    closure = _closure_fixture(giver, registration)
    assert set(closure["THM-A"]) == {"ASM-G"}


def test_the_live_closures_take_the_repaired_premises_and_drop_the_registrations():
    """Under-inclusion is repaired by DATA: a premise names the unit that calls into its
    boundary. Measured on the live registry so a reverted scope is seen here."""
    from _theorems import load_theorems

    verification = load_verification()
    assumptions = load_assumptions()
    theorems = load_theorems(
        {unit["id"] for unit in verification.get("unit", [])},
        [e for e in verification.get("edge", []) if e.get("kind") == "PROOF_DEPENDENCY"],
    )
    toolchains = load_toolchains()
    wanted = {
        "THM-0045": "ASM-0078",
        "THM-0083": "ASM-0083",
        "THM-0108": "ASM-0027",
        "THM-0117": "ASM-0076",
        "THM-0007": "ASM-0037",
    }
    units = {
        str(target).removeprefix("unit://")
        for row in theorems["theorem"]
        if row["id"] in wanted
        for target in row.get("supported_by", [])
    }
    fps = {
        unit["id"]: fingerprint_unit(unit, verification, toolchains, assumptions)
        for unit in verification["unit"]
        if unit["id"] in units
    }
    closures = theorem_premises(
        {"theorem": [r for r in theorems["theorem"] if r["id"] in wanted]}, fps, assumptions
    )
    for theorem_id, premise in wanted.items():
        assert premise in (closures[theorem_id] or {}), (theorem_id, closures[theorem_id])
    assert not any(
        asm in (closure or {}) for closure in closures.values() for asm in ("ASM-0074", "ASM-0075")
    )

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
