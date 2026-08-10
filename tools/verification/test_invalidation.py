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

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _graph import (  # noqa: E402
    Attestation,
    context_closure,
    derive_unit_state,
    evaluate,
)

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
    """Case C. The seal's premise is that the proof still passes. It did not."""
    result = graph(SEALED, current(), producer_att=attestation("producer", evidence={"verus": "fail"}))
    assert result["states"]["producer"][0] == "BLOCKED"
    assert result["states"]["consumer"][0] == "DIRTY_DEPENDENCY"


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


def test_context_closure_excludes_the_dirty_set_itself():
    assert context_closure({"a", "b"}, [{"from": "a", "to": "b"}]) == set()


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
