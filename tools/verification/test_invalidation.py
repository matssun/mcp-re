# SPDX-License-Identifier: Apache-2.0
"""Invalidation semantics — the Phase 4 test list from ADR-MCPRE-059, plus its controls.

Every test here is a claim about when previously established security evidence stops being
usable. The one they collectively defend:

    There is no path from "I could not establish freshness" to FRESH.

The sealed-edge cases are the two that matter most and are easiest to get half-right. A
seal that never stops propagation is useless; a seal that stops it when the contract
changed is unsound, and unsound in the direction that silently skips security review. Both
directions are tested.

Run: python3 tools/verification/test_invalidation.py
"""

from __future__ import annotations

import pathlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _graph import (  # noqa: E402
    Attestation,
    COMPONENT_STATE,
    context_closure,
    derive_unit_state,
    evaluate,
    STRUCTURAL_COMPONENT,
    UNRESOLVED_COMPONENT,
)
from _manifest import ManifestError, validate_edges  # noqa: E402

COMPONENTS = {
    "source_inputs": {"a.rs": "sha256:aaa"},
    "exported_contracts": ["contract://a/v1"],
    "consumed_contracts": [],
    "test_evidence_definition": ["test://a"],
    "trusted_assumptions": [],
    "toolchain_identity": {"verus": {"release": "1"}},
    "review_policy_revision": "r1",
    "formal_model_revision": "m1",
    "threat_model_revision": "t1",
    "enabled_features": [],
    "build_configuration": "unimplemented",
    "generated_inputs": "unimplemented",
    "proof_dependencies": "unimplemented",
}


def current(overrides=None, fingerprint="sha256:fp"):
    components = dict(COMPONENTS)
    components.update(overrides or {})
    return {"fingerprint": fingerprint, "components": components}


def attestation(unit_id="a", overrides=None, fingerprint="sha256:fp", evidence=None):
    components = dict(COMPONENTS)
    components.update(overrides or {})
    return Attestation(
        unit_id=unit_id,
        fingerprint=fingerprint,
        components=components,
        evidence=evidence or {"verus": "pass"},
    )


def state_of(cur, att):
    return derive_unit_state("a", cur, {"a": att} if att else {})[0]


# --- the ADR's required list --------------------------------------------------


def test_local_source_change_makes_the_unit_dirty_self():
    assert state_of(current({"source_inputs": {"a.rs": "sha256:bbb"}}), attestation()) == "DIRTY_SELF"


def test_contract_change_makes_the_producer_dirty_contract():
    got = state_of(current({"exported_contracts": ["contract://a/v2"]}), attestation())
    assert got == "DIRTY_CONTRACT"


def test_assumption_change_makes_the_trusting_unit_dirty():
    got = state_of(current({"trusted_assumptions": ["ASM-0001"]}), attestation())
    assert got == "DIRTY_ASSUMPTION"


def test_policy_revision_change_invalidates_scoped_evidence():
    assert state_of(current({"review_policy_revision": "r2"}), attestation()) == "DIRTY_POLICY"


def test_toolchain_change_invalidates_formal_evidence():
    got = state_of(current({"toolchain_identity": {"verus": {"release": "2"}}}), attestation())
    assert got == "DIRTY_TOOLCHAIN"


def test_security_test_change_invalidates_its_evidence():
    """Deleting or weakening a test must never make its claim look fresher (§15)."""
    got = state_of(current({"test_evidence_definition": []}), attestation())
    assert got == "DIRTY_EVIDENCE"


def test_feature_or_configuration_change_makes_the_unit_dirty():
    got = state_of(current({"enabled_features": ["redis_replay"]}), attestation())
    assert got == "DIRTY_SELF"


def test_generated_model_drift_invalidates_lean_evidence():
    got = state_of(current({"generated_inputs": "sha256:regenerated"}), attestation())
    assert got == "DIRTY_EVIDENCE"


def test_every_component_the_encoding_produces_has_a_classification():
    """The census, over the REAL manifest — which is the half this suite was missing.

    Every test above states a rule with synthetic components, and a rule stated over
    components nobody produces is a rule that cannot fire. `generated_inputs` was exactly
    that for the whole of Phase 4: its rule was asserted here while no unit had a non-empty
    one.

    So the population is the encoding's own output, and membership is a DEFINITION rather
    than a list someone maintained: a component is classified, structurally incomparable, or
    deliberately unresolved with a reason. A new component in none of the three fails here
    the day it is added, instead of silently reaching `UNKNOWN` for years."""
    import sys as _sys
    from pathlib import Path as _Path

    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
    from _fingerprint import fingerprint_unit, load_trust_boundaries
    from _manifest import (
        load_assumptions,
        load_toolchains,
        load_verification,
    )

    doc = load_verification()
    toolchains = load_toolchains()
    assumptions = load_assumptions()
    boundaries = load_trust_boundaries()
    produced = set()
    for unit in doc["unit"]:
        produced |= set(
            fingerprint_unit(unit, doc, toolchains, assumptions, boundaries)["components"]
        )
    assert len(produced) >= 30, produced

    accounted = set(COMPONENT_STATE) | STRUCTURAL_COMPONENT | set(UNRESOLVED_COMPONENT)
    missing = sorted(produced - accounted)
    assert not missing, (
        f"{missing} reach `derive_unit_state`'s UNKNOWN branch with no recorded reason. "
        "Classify each where the encoding determines it, or record why it does not."
    )
    # And no component is in two places at once, which would make the reason depend on
    # lookup order.
    assert not set(COMPONENT_STATE) & set(UNRESOLVED_COMPONENT)
    assert not set(COMPONENT_STATE) & STRUCTURAL_COMPONENT
    assert not set(UNRESOLVED_COMPONENT) & STRUCTURAL_COMPONENT


def test_each_refinement_derives_the_state_of_what_it_refines():
    """The classifications, exercised rather than declared. Each of these reached UNKNOWN
    before — fail-closed, but silent about which input moved, which is the answer §5 asks
    these states to be."""
    expected = {
        "test_selection": "DIRTY_EVIDENCE",
        "test_sources": "DIRTY_EVIDENCE",
        "test_lane_identity": "DIRTY_EVIDENCE",
        "mutation_probes": "DIRTY_EVIDENCE",
        "mutation_lane_identity": "DIRTY_EVIDENCE",
        "structural_probes": "DIRTY_EVIDENCE",
        "structural_lane_identity": "DIRTY_EVIDENCE",
        "measurements": "DIRTY_EVIDENCE",
        "measured_lane_identity": "DIRTY_EVIDENCE",
        "extracted_symbols": "DIRTY_EVIDENCE",
        "lean_theorems": "DIRTY_EVIDENCE",
        "lean_lane_identity": "DIRTY_EVIDENCE",
        "generated_model_lane_identity": "DIRTY_EVIDENCE",
        "lean_theorem_sources": "DIRTY_EVIDENCE",
        "proved_symbols": "DIRTY_EVIDENCE",
        "governing_boundaries": "DIRTY_ASSUMPTION",
    }
    assert set(expected) | set(COMPONENT_STATE) == set(COMPONENT_STATE)
    for name, want in expected.items():
        got, reason = derive_unit_state(
            "a",
            current({name: {"x": "sha256:after"}}),
            {"a": attestation(overrides={name: {"x": "sha256:before"}})},
        )
        assert got == want, (name, got, want, reason)
        assert name in reason, (name, reason)


def test_an_unresolved_component_still_derives_unknown_and_says_why():
    """The other direction, and the reason the three are left alone.

    A classification is not free: a sealed `CONTRACT_CONSUMES` edge stops propagation for
    `DIRTY_SELF` and `DIRTY_EVIDENCE` and for no other state, so classifying a component can
    REDUCE what an invalidation reaches. UNKNOWN propagates through a seal. Leaving these
    unclassified is therefore the conservative answer, not the lazy one — and the reason is
    reported instead of 'this engine cannot classify it'."""
    assert UNRESOLVED_COMPONENT, "the set is the record; an empty one records nothing"
    for name, why in UNRESOLVED_COMPONENT.items():
        got, reason = derive_unit_state(
            "a",
            current({name: "after"}),
            {"a": attestation(overrides={name: "before"})},
        )
        assert got == "UNKNOWN", (name, got)
        assert why in reason, (name, reason)


def test_an_empty_context_closure_says_WHICH_empty_it_is():
    """`review-frontier` prints "(none)" under Context-only on this machine, and will keep
    printing it however the graph is edited — because with no attestation store every unit
    is dirty, and context closure is the neighbours of the dirty set MINUS the dirty set.
    There is no outside.

    "(none)" reads as "the dirty set reaches no context", which is a different fact. Four
    causes are materially different and the note names which one holds. Measured on the real
    tree: 244 units, all UNKNOWN, context closure 0."""
    from _load_tool import load_tool

    frontier = load_tool("review-frontier", "review_frontier_cli")
    note = frontier.context_note
    edges = [{"kind": "COMPILE_DEPENDENCY"}, {"kind": "REVIEW_CONTEXT"}]

    no_relation = note({"review_closure": ["a"]}, [], 10)
    assert "no edge of any kind is declared" in no_relation

    nothing_dirty = note({"review_closure": []}, edges, 10)
    assert "nothing is dirty" in nothing_dirty

    # The case that actually holds here, and the one "(none)" hid: everything is dirty, so
    # the closure is empty for a reason that is about the evidence store, not the graph.
    all_dirty = note({"review_closure": list("abcdefghij")}, edges, 10)
    assert "all 10 units are dirty" in all_dirty
    assert "not the graph" in all_dirty

    neighbours_dirty = note({"review_closure": ["a", "b"]}, edges, 10)
    assert "is itself dirty" in neighbours_dirty

    assert len({no_relation, nothing_dirty, all_dirty, neighbours_dirty}) == 4


def test_a_failed_proof_blocks_rather_than_dirties():
    """BLOCKED, not dirty: a failed proof is not 'review it again', it is 'no freshness may
    be issued from here, and nothing downstream may inherit any' (§Case C)."""
    got = state_of(current(), attestation(evidence={"verus": "fail"}))
    assert got == "BLOCKED"


def test_a_missing_attestation_is_unknown_not_fresh():
    assert state_of(current(), None) == "UNKNOWN"


def test_an_unchanged_unit_is_fresh():
    """The control without which every test above passes on a function that returns a
    constant."""
    assert state_of(current(), attestation()) == "FRESH"


def test_an_attestation_predating_the_encoding_is_unknown():
    stale = attestation()
    partial = Attestation(
        unit_id="a",
        fingerprint=stale.fingerprint,
        components={"source_inputs": COMPONENTS["source_inputs"]},
        evidence={"verus": "pass"},
    )
    assert state_of(current(), partial) == "UNKNOWN"


def test_matching_components_with_a_different_fingerprint_is_unknown():
    """The encoding changed underneath the comparison, so the comparison means something
    else. Not fresh."""
    assert state_of(current(fingerprint="sha256:other"), attestation()) == "UNKNOWN"


# --- propagation and sealing --------------------------------------------------

UNITS = [{"id": "producer"}, {"id": "consumer"}]


def graph(edge, producer_now, consumer_now=None, producer_att=None, consumer_att=None):
    return evaluate(
        UNITS,
        [edge],
        {"producer": producer_now, "consumer": consumer_now or current()},
        {
            "producer": producer_att or attestation("producer"),
            "consumer": consumer_att or attestation("consumer"),
        },
    )


SEALED = {
    "kind": "CONTRACT_CONSUMES",
    "from": "producer",
    "to": "consumer",
    "sealed": True,
    "contract": "contract://a/v1",
}
UNSEALED = {"kind": "CONTRACT_CONSUMES", "from": "producer", "to": "consumer"}
COMPILE = {"kind": "COMPILE_DEPENDENCY", "from": "producer", "to": "consumer"}
CONTEXT = {"kind": "REVIEW_CONTEXT", "from": "producer", "to": "consumer"}
PROOF = {"kind": "PROOF_DEPENDENCY", "from": "producer", "to": "consumer"}


def test_a_sealed_edge_stops_producer_source_churn():
    """Case A, and the entire point of combining proof with the graph: the implementation
    changed, the contract did not, the proof passed — so the consumer is not re-reviewed."""
    result = graph(SEALED, current({"source_inputs": {"a.rs": "sha256:bbb"}}))
    assert result["states"]["producer"][0] == "DIRTY_SELF"
    assert result["states"]["consumer"][0] == "FRESH"


def test_a_sealed_edge_does_not_stop_a_contract_change():
    """Case B. A seal is a claim about the CONTRACT being the whole of the consumer's
    reasoning; when the contract itself moves, the claim says nothing."""
    result = graph(SEALED, current({"exported_contracts": ["contract://a/v2"]}))
    assert result["states"]["producer"][0] == "DIRTY_CONTRACT"
    assert result["states"]["consumer"][0] == "DIRTY_DEPENDENCY"


def test_a_sealed_edge_does_not_stop_a_failed_proof():
    """Case C. The seal's premise is that the proof still passes. It did not.

    The consumer is BLOCKED, not merely dirty: a seal claims the exported contract is the
    whole of the consumer's reasoning about the producer, and that claim is worthless when
    the proof establishing the contract has failed. Nothing the consumer can re-run repairs
    a prerequisite outside it."""
    result = graph(SEALED, current(), producer_att=attestation("producer", evidence={"verus": "fail"}))
    assert result["states"]["producer"][0] == "BLOCKED"
    assert result["states"]["consumer"][0] == "BLOCKED"


def test_a_sealed_edge_does_not_stop_an_assumption_change():
    """A proof that passes because of a changed assumption is a different proof."""
    result = graph(SEALED, current({"trusted_assumptions": ["ASM-0001"]}))
    assert result["states"]["consumer"][0] == "DIRTY_DEPENDENCY"


def test_a_sealed_edge_does_not_stop_a_toolchain_change():
    result = graph(SEALED, current({"toolchain_identity": {"verus": {"release": "2"}}}))
    assert result["states"]["consumer"][0] == "DIRTY_DEPENDENCY"


def test_an_unsealed_edge_propagates_source_churn():
    """The default. Without a predeclared seal there is no ground to claim the consumer's
    reasoning survived, so conservative propagation stands (§6)."""
    result = graph(UNSEALED, current({"source_inputs": {"a.rs": "sha256:bbb"}}))
    assert result["states"]["consumer"][0] == "DIRTY_DEPENDENCY"


def test_a_compile_dependency_propagates():
    result = graph(COMPILE, current({"source_inputs": {"a.rs": "sha256:bbb"}}))
    assert result["states"]["consumer"][0] == "DIRTY_DEPENDENCY"


def test_a_review_context_edge_never_propagates():
    """Context closure is not review closure (§3)."""
    result = graph(CONTEXT, current({"source_inputs": {"a.rs": "sha256:bbb"}}))
    assert result["states"]["consumer"][0] == "FRESH"


def test_context_closure_holds_the_neighbours_without_invalidating_them():
    result = graph(CONTEXT, current({"source_inputs": {"a.rs": "sha256:bbb"}}))
    assert result["review_closure"] == ["producer"]
    assert result["context_closure"] == ["consumer"]


def test_a_proof_dependency_propagates_forwards_and_not_backwards():
    """The edge-direction control.

    `A --PROOF_DEPENDENCY--> B` means B depends on evidence produced by A, and nothing else.
    A graph that propagated the other way would be internally consistent and would report
    precisely the wrong unit as sound. The first implementation of this edge in
    verification.toml had producer and consumer reversed, which is why the asymmetry is
    pinned here rather than trusted to careful reading.
    """
    broken_producer = graph(PROOF, current({"source_inputs": {"a.rs": "sha256:bbb"}}))
    assert broken_producer["states"]["producer"][0] == "DIRTY_SELF"
    assert broken_producer["states"]["consumer"][0] == "DIRTY_DEPENDENCY"

    broken_consumer = graph(
        PROOF, current(), consumer_now=current({"source_inputs": {"a.rs": "sha256:bbb"}})
    )
    assert broken_consumer["states"]["consumer"][0] == "DIRTY_SELF"
    assert broken_consumer["states"]["producer"][0] == "FRESH", (
        "a consumer's own churn must never reach back to the unit it depends on"
    )


def test_the_composed_claim_lifecycle_through_failure_and_recovery():
    """The whole loop, not just the invalidation half.

    Recovery matters as much as failure: a graph that blocks correctly but never lets go is
    unusable, and one that releases too eagerly is a false green.
    """
    passing = attestation("producer")
    failing = attestation("producer", evidence={"verus": "fail"})

    both_pass = graph(PROOF, current(), producer_att=passing)
    assert both_pass["states"]["producer"][0] == "FRESH"
    assert both_pass["states"]["consumer"][0] == "FRESH"

    a_broken = graph(PROOF, current(), producer_att=failing)
    assert a_broken["states"]["producer"][0] == "BLOCKED"
    assert a_broken["states"]["consumer"][0] == "BLOCKED"

    # Re-attesting the consumer at its own unchanged, still-passing inputs changes nothing.
    still_broken = graph(
        PROOF, current(), producer_att=failing, consumer_att=attestation("consumer")
    )
    assert still_broken["states"]["consumer"][0] == "BLOCKED"

    # The producer is repaired to the SAME inputs its record was taken at, so nothing in
    # the closure has moved and the composed claim is supported again.
    restored = graph(PROOF, current(), producer_att=passing)
    assert restored["states"]["producer"][0] == "FRESH"
    assert restored["states"]["consumer"][0] == "FRESH"

    # Repaired to DIFFERENT source is a different matter: the producer is dirty, and the
    # consumer inherits an ordinary dependency refresh rather than a block.
    repaired_differently = graph(
        PROOF, current({"source_inputs": {"a.rs": "sha256:ccc"}}), producer_att=passing
    )
    assert repaired_differently["states"]["producer"][0] == "DIRTY_SELF"
    assert repaired_differently["states"]["consumer"][0] == "DIRTY_DEPENDENCY"


def test_blocked_escalates_a_consumer_that_was_merely_dirty():
    """BLOCKED is strictly the stronger statement, so it must overwrite DIRTY_*, not lose
    to it because the consumer happened to be stale for a reason of its own."""
    result = graph(
        PROOF,
        current(),
        consumer_now=current({"source_inputs": {"a.rs": "sha256:bbb"}}),
        producer_att=attestation("producer", evidence={"verus": "fail"}),
    )
    assert result["states"]["consumer"][0] == "BLOCKED"


def test_a_failed_lower_proof_does_not_leave_the_composed_claim_green():
    """The composition rule, and the reason the graph exists rather than a list of badges.

    Shape taken from the real pair: `http_profile.continuation_binding` proves that the
    continuation check establishes role separation; `http_profile.continuation_unbypassability`
    proves that check cannot be skipped. Only together do they say anything end to end.

    When the LOWER proof fails, the upper unit's own inputs have not moved at all — its
    fingerprint is identical, its lane would pass again on its own terms, and every earlier
    version of this system would have shown it green beside a red one. It must not be
    fresh, because the claim it participates in no longer holds.
    """
    result = graph(
        PROOF,
        current(),
        producer_att=attestation("producer", evidence={"verus": "fail"}),
    )
    assert result["states"]["producer"][0] == "BLOCKED"
    assert result["states"]["consumer"][0] == "BLOCKED"
    assert result["review_closure"] == ["consumer", "producer"]


def test_a_failed_proof_keeps_propagating_and_cannot_be_re_attested_away():
    """No laundering. Propagation is recomputed from the producer's state on every run, so
    re-attesting the consumer at its own unchanged inputs does not restore its freshness
    while the lower proof is still failing."""
    fresh_consumer = attestation("consumer")
    result = graph(
        PROOF,
        current(),
        producer_att=attestation("producer", evidence={"verus": "fail"}),
        consumer_att=fresh_consumer,
    )
    assert result["states"]["consumer"][0] == "BLOCKED"


def test_context_closure_excludes_the_dirty_set_itself():
    assert context_closure({"a", "b"}, [{"from": "a", "to": "b"}]) == set()


def test_consuming_a_different_contract_is_a_dependency_change():
    """The owner's ruling, applied only now that the value is derived from the edges.

    Three states are plausible and only one is right. It is not `DIRTY_CONTRACT`: that is the
    PRODUCER whose published interface moved, and reusing it here would overload a state the
    propagation rules read. It is not `DIRTY_SELF`: nobody edited this unit. What changed is
    the dependency closure the unit's evidence rests on."""
    got, reason = derive_unit_state(
        "a",
        current({"consumed_contracts": ["contract://b/v2"]}),
        {"a": attestation(overrides={"consumed_contracts": ["contract://b/v1"]})},
    )
    assert got == "DIRTY_DEPENDENCY", (got, reason)
    assert "consumed_contracts" in reason


def test_the_producer_and_consumer_halves_of_a_contract_get_different_states():
    """Two components, one relation, and the distinction is the reason both exist."""
    producer, _ = derive_unit_state(
        "a",
        current({"exported_contracts": ["contract://a/v2"]}),
        {"a": attestation(overrides={"exported_contracts": ["contract://a/v1"]})},
    )
    consumer, _ = derive_unit_state(
        "a",
        current({"consumed_contracts": ["contract://b/v2"]}),
        {"a": attestation(overrides={"consumed_contracts": ["contract://b/v1"]})},
    )
    assert (producer, consumer) == ("DIRTY_CONTRACT", "DIRTY_DEPENDENCY")



# --- what makes an edge a CONTRACT edge -----------------------------------------
#
# `CONTRACT_CONSUMES` claims a relation to the producer's PUBLISHED INTERFACE, which is more
# than "the consumer compiles against the producer". Nine edges carried the kind while naming
# no contract and while none of their producers exported one, so the kind said "contract
# relation" about nine compile-time dependencies — and the admission rule could not notice,
# because it ran only under `sealed` and compared against the union of EVERY unit's exports.
#
# Each control below is a way the rule can be wrong, not a way it can be satisfied.

UNITS_AB = {"producer", "consumer", "elsewhere"}
EXPORTS_AB = {
    "producer": {"contract://producer/v1"},
    "elsewhere": {"contract://elsewhere/v1"},
    "consumer": set(),
}


def edge_refused(edge: dict) -> str:
    """The message admission refused with, or an assertion failure if it accepted."""
    try:
        validate_edges("t", [edge], UNITS_AB, EXPORTS_AB)
    except ManifestError as exc:
        return str(exc)
    raise AssertionError(f"admission accepted an edge it must refuse: {edge}")


def test_a_contract_edge_naming_a_contract_its_producer_exports_is_admitted():
    """The positive case, first, so every refusal below means something."""
    validate_edges("t", [{
        "kind": "CONTRACT_CONSUMES", "from": "producer", "to": "consumer",
        "contract": "contract://producer/v1",
    }], UNITS_AB, EXPORTS_AB)


def test_a_contract_edge_that_names_no_contract_is_refused():
    """The nine. The kind was the only thing asserting a contract relation existed."""
    assert "contract" in edge_refused(
        {"kind": "CONTRACT_CONSUMES", "from": "producer", "to": "consumer"}
    )


def test_a_contract_exported_by_someone_else_does_not_make_a_contract_edge():
    """The check the old one could not make. It compared against the union of every unit's
    exports, so an edge between two units could be justified by a third — a relation whose
    named interface belongs to neither of its endpoints."""
    message = edge_refused({
        "kind": "CONTRACT_CONSUMES", "from": "producer", "to": "consumer",
        "contract": "contract://elsewhere/v1",
    })
    assert "does not export" in message
    assert "COMPILE_DEPENDENCY" in message


def test_a_valid_contract_edge_need_not_be_sealed():
    """`sealed` is an ADDITIONAL property of a valid contract relation — the claim that the
    contract is the whole of the consumer's reasoning — not what makes the relation a
    contract relation. Requiring it would make every honest contract edge inadmissible until
    someone could prove the stronger thing."""
    validate_edges("t", [{
        "kind": "CONTRACT_CONSUMES", "from": "producer", "to": "consumer",
        "contract": "contract://producer/v1",
    }], UNITS_AB, EXPORTS_AB)


def test_a_sealed_edge_still_needs_its_seal_evidence():
    """And sealing keeps its own requirements: who proved it, and why."""
    assert "sealed_by" in edge_refused({
        "kind": "CONTRACT_CONSUMES", "from": "producer", "to": "consumer",
        "contract": "contract://producer/v1", "sealed": True,
    })


def test_only_a_contract_edge_may_be_sealed():
    assert "only a CONTRACT_CONSUMES edge may be sealed" in edge_refused({
        "kind": "COMPILE_DEPENDENCY", "from": "producer", "to": "consumer",
        "sealed": True, "sealed_by": "THM-0001", "rationale": "r",
    })


def test_a_compile_dependency_needs_no_contract():
    """The kind the nine became. It asserts only what it can show: this consumer's code
    depends on that producer's, and any producer dirtiness reaches the consumer."""
    validate_edges("t", [
        {"kind": "COMPILE_DEPENDENCY", "from": "producer", "to": "consumer"},
    ], UNITS_AB, EXPORTS_AB)


def test_the_committed_manifest_declares_no_inadmissible_contract_edge():
    """The census, over the real manifest — the half a synthetic suite cannot state.

    `load_verification` runs `validate_edges`, so this passing means every declared contract
    edge names a contract its own producer exports. It is deliberately not an assertion that
    contract edges EXIST: there are none today, and requiring one would be pressure to invent
    the relation this rule exists to refuse."""
    import _manifest

    doc = _manifest.load_verification()
    exports = {
        unit["id"]: set(unit.get("exported_contracts", [])) for unit in doc["unit"]
    }
    for edge in doc["edge"]:
        if edge["kind"] == "CONTRACT_CONSUMES":
            assert edge["contract"] in exports[edge["from"]], edge


def _while_manifest_has(edge_toml: str, observe):
    """Append one `[[edge]]` block to the REAL manifest, observe, restore.

    The observation happens INSIDE the edit window, because a helper that restores first and
    measures afterwards measures the restored file against itself — this suite's sibling made
    exactly that mistake once. Restoration is byte-for-byte and in a `finally`, and the caller
    below re-loads afterwards so a test cannot leave a tree that no longer parses.
    """
    from _manifest import VERIFICATION_TOML

    path = pathlib.Path(VERIFICATION_TOML)
    original = path.read_bytes()
    try:
        path.write_bytes(original + edge_toml.encode("utf-8"))
        return observe()
    finally:
        path.write_bytes(original)


def test_the_real_loader_refuses_an_inadmissible_contract_edge():
    """Through `load_verification`, which is the function every tool in this directory calls.

    A rule that is only reachable from its own tests is a rule production never applies. This
    control is the one that says the admission check is ON the manifest-loading path: it
    appends an edge to the real registry, asks the public loader for the manifest, and
    requires the refusal — then restores the bytes and requires the loader to succeed again,
    so a green run cannot be a tree this test broke.
    """
    import _manifest

    def observe():
        try:
            _manifest.load_verification()
        except ManifestError as exc:
            return str(exc)
        raise AssertionError("the production loader accepted an edge it must refuse")

    message = _while_manifest_has(
        '''
[[edge]]
kind = "CONTRACT_CONSUMES"
from = "proxy.certificate_identity"
to = "proxy.channel_associated_identity"
contract = "contract://core/time/parse_rfc3339_utc"
''',
        observe,
    )
    assert "does not export" in message, message
    assert "COMPILE_DEPENDENCY" in message, message
    # And the tree is intact: the loader answers again.
    assert _manifest.load_verification()["schema_version"]


def test_the_real_loader_refuses_a_contract_edge_naming_no_contract():
    """The nine, as the loader would have seen them if this rule had existed."""
    import _manifest

    def observe():
        try:
            _manifest.load_verification()
        except ManifestError as exc:
            return str(exc)
        raise AssertionError("the production loader accepted an edge it must refuse")

    message = _while_manifest_has(
        '''
[[edge]]
kind = "CONTRACT_CONSUMES"
from = "core.time_rfc3339"
to = "proxy.certificate_identity"
''',
        observe,
    )
    assert "contract" in message, message
    assert _manifest.load_verification()["schema_version"]


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError:
                failures += 1
                print(f"FAIL {name}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
