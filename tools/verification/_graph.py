# SPDX-License-Identifier: Apache-2.0
"""The security evidence graph — ADR-MCPRE-059 §2-§6, Phase 4.

Freshness is DERIVED, never asserted. There is no mutable `clean = true` anywhere: a unit
is fresh only while every input its previous conclusion depended on still hashes the same.

## Why an attestation records components, not one hash

`ReviewFingerprint` is a single digest over every input, and a single digest can only say
"something moved". The states ADR-MCPRE-059 §5 requires — `DIRTY_SELF` versus
`DIRTY_CONTRACT` versus `DIRTY_DEPENDENCY` — are answers to *which* input moved, and a
reviewer needs that answer to know what work the change actually created. So an attestation
stores the components individually and derivation compares them one at a time.

The whole-fingerprint digest is still recorded, and still authoritative for "is this the
same evidence": if the components matched but the fingerprint did not, the encoding itself
changed, and that is `UNKNOWN`.

## Fail-closed everywhere

Missing attestation, unparsable record, unknown edge kind, a component the current schema
does not know how to compute — every one of them is dirty. There is no path in this module
from "I could not establish freshness" to `FRESH`, which is the property the entire design
rests on and the one that would be easiest to lose to a convenience.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

#: Precedence when several inputs moved at once. The reported state is the FIRST match, so
#: a reviewer is told the most fundamental reason rather than an incidental one: a unit
#: whose own source and whose upstream contract both changed is `DIRTY_SELF`, because its
#: own code has to be read either way.
STATE_PRECEDENCE = (
    "BLOCKED",
    "UNKNOWN",
    "DIRTY_POLICY",
    "DIRTY_TOOLCHAIN",
    "DIRTY_ASSUMPTION",
    "DIRTY_SELF",
    "DIRTY_CONTRACT",
    "DIRTY_EVIDENCE",
    "DIRTY_DEPENDENCY",
    "FRESH",
)

#: Which recorded component, when it differs, produces which state.
#:
#: This table was written for Phase 4's twelve components and did not grow with the
#: encoding. Eighteen of the thirty components `fingerprint_unit` produces were in neither
#: it nor any other list, so each of them reached `derive_unit_state`'s last resort —
#: `UNKNOWN`, "this engine cannot classify it". Fail-closed, and there is no path from it to
#: FRESH, so nothing was unsound. What was lost is the thing §5 asks these states to be:
#: `DIRTY_SELF` versus `DIRTY_CONTRACT` versus `DIRTY_EVIDENCE` are answers to WHICH input
#: moved, and a reviewer needs that answer to know what work the change created. "Something
#: this engine cannot classify" is not that answer.
#:
#: Every entry added below is DETERMINED by the encoding's own statement about what the
#: component refines — not chosen for a tidier state. `_fingerprint.py` says of each one
#: which earlier component it makes effective, and the refinement inherits that component's
#: classification. Where the encoding does NOT determine it, the component is in
#: `UNRESOLVED_COMPONENT` and keeps deriving UNKNOWN.
COMPONENT_STATE = {
    # --- Phase 4's original twelve ---------------------------------------------------
    "source_inputs": "DIRTY_SELF",
    "exported_contracts": "DIRTY_CONTRACT",
    # The consumer's half of the same relation, and a different state on purpose.
    # `DIRTY_CONTRACT` is the PRODUCER whose published interface moved; a change to WHICH
    # producer contract this unit consumes is neither that nor consumer implementation
    # churn — it is a change to the dependency closure the unit's evidence rests on. Applied
    # only now, because until the value was derived from the incoming CONTRACT_CONSUMES
    # edges it was an independently authored field, and classifying one of three
    # representations that had never had to agree would have fixed the reading of a
    # disagreement instead of removing it.
    "consumed_contracts": "DIRTY_DEPENDENCY",
    "test_evidence_definition": "DIRTY_EVIDENCE",
    "trusted_assumptions": "DIRTY_ASSUMPTION",
    "toolchain_identity": "DIRTY_TOOLCHAIN",
    "review_policy_revision": "DIRTY_POLICY",
    "formal_model_revision": "DIRTY_POLICY",
    "threat_model_revision": "DIRTY_POLICY",
    "enabled_features": "DIRTY_SELF",
    "build_configuration": "DIRTY_SELF",
    "generated_inputs": "DIRTY_EVIDENCE",
    "proof_dependencies": "DIRTY_EVIDENCE",
    # --- v4: the EFFECTIVE test evidence, not merely its label ------------------------
    # "Encoding v4 measures the EFFECTIVE TEST EVIDENCE" — these three answer "what did the
    # test lane actually measure" for the claim `test_evidence_definition` states. A
    # refinement of a component classified DIRTY_EVIDENCE is DIRTY_EVIDENCE: the battery
    # behind the claim moved, which is the same fact at a finer grain.
    "test_selection": "DIRTY_EVIDENCE",
    "test_sources": "DIRTY_EVIDENCE",
    "test_lane_identity": "DIRTY_EVIDENCE",
    # --- v5: "extends the same rule to the MUTATION evidence" -------------------------
    "mutation_probes": "DIRTY_EVIDENCE",
    "mutation_lane_identity": "DIRTY_EVIDENCE",
    # --- ADR-MCPRE-068 Phase 0D: "the same closure the mutation components give" -------
    "structural_probes": "DIRTY_EVIDENCE",
    "structural_lane_identity": "DIRTY_EVIDENCE",
    "measurements": "DIRTY_EVIDENCE",
    "measured_lane_identity": "DIRTY_EVIDENCE",
    # --- v8: the extracted-model SELECTION, "for the reason v3 added the test selection"
    "extracted_symbols": "DIRTY_EVIDENCE",
    "lean_theorems": "DIRTY_EVIDENCE",
    # --- the PROOF lane's own identity ------------------------------------------------
    # The seventh lane, and the same sentence the other six carry: the code that decides
    # what "a machine-checked proof passed" MEANS is part of that result's identity. A
    # refinement of the formal evidence, so it takes the classification of what it refines.
    "verus_lane_identity": "DIRTY_EVIDENCE",
    # --- the extraction lanes' own identity, and the theorem TEXT ---------------------
    # The same three sentences the four host lane identities already carry, for the two
    # lanes that had none: the code deciding what a `lean://` or generated-model result
    # MEANS is part of that result's identity, and the theorem the prover resolves is the
    # claim rather than its label. All three refine the extraction evidence, so they take
    # the classification of what they refine.
    "lean_lane_identity": "DIRTY_EVIDENCE",
    "generated_model_lane_identity": "DIRTY_EVIDENCE",
    "lean_theorem_sources": "DIRTY_EVIDENCE",
    # The theorems a formal unit claims, by prover-reported name. Same shape as
    # `test_evidence_definition`: it states WHAT is claimed, and deleting one is a reduction
    # in evidence that the source digest would not report.
    "proved_symbols": "DIRTY_EVIDENCE",
    # --- the boundary cap ------------------------------------------------------------
    # `max_class_without_assumption` is what keeps a proof's meaning honest across a
    # declared trust boundary — a premise about what may be trusted beyond it, which is what
    # `trusted_assumptions` already carries. Relaxing the cap relaxes an assumption.
    "governing_boundaries": "DIRTY_ASSUMPTION",
}

#: Components that CANNOT differ between an attestation and the current derivation, because
#: the comparison is keyed on them or short-circuits before reading them. Listed rather than
#: omitted so that the census below can range over every produced component.
STRUCTURAL_COMPONENT = {
    # Skipped explicitly in `derive_unit_state`: a moved encoding is UNKNOWN by fingerprint
    # comparison, which is a stronger statement than any per-component one.
    "encoding_version",
    # Attestations are looked up BY unit id, so a differing one means a corrupt record. It
    # keeps deriving UNKNOWN, which is the right answer to a record that is not about this
    # unit.
    "unit_id",
}

#: Produced, and deliberately NOT classified. Each derives UNKNOWN — fail-closed, and more
#: conservative than any `DIRTY_*` — because the encoding does not determine which state it
#: is, and a classification is not free: a sealed `CONTRACT_CONSUMES` edge stops propagation
#: for `DIRTY_SELF` and `DIRTY_EVIDENCE` and for nothing else, so classifying a component
#: can REDUCE what an invalidation reaches. Zero sealed edges are declared today, which
#: makes the choice unobservable now and load-bearing the moment one is.
#:
#: These three are the owner's, and the value here is the question, not a placeholder.
UNRESOLVED_COMPONENT = {
    "class": (
        "a unit's class decides which lanes are REQUIRED of it, so a reclassification "
        "changes what evidence must exist rather than what any evidence measured. That is "
        "arguably DIRTY_POLICY and arguably DIRTY_EVIDENCE, and the encoding says neither."
    ),
    "gate_controls": (
        "ADR-MCPRE-068 Phase 1 describes these as 'the production carrier of the "
        "proposition it defends' and says softening one is 'a reduction in evidence "
        "exactly as deleting a runtime check is'. The first phrase points at DIRTY_SELF "
        "and the second at DIRTY_EVIDENCE, in one sentence."
    ),
}


@dataclass(frozen=True)
class Attestation:
    """A successful check, as a record of exactly what it was checked against.

    `evidence` carries each lane's result. A `verus: fail` makes the unit BLOCKED rather
    than dirty: a failed proof is not "needs review again", it is "no freshness may be
    issued from here, and nothing downstream may inherit any" (§Case C).
    """

    unit_id: str
    fingerprint: str
    components: dict
    evidence: dict = field(default_factory=dict)

    @staticmethod
    def from_json(raw: dict) -> "Attestation":
        return Attestation(
            unit_id=raw["unit_id"],
            fingerprint=raw["fingerprint"],
            components=raw.get("components", {}),
            evidence=raw.get("evidence", {}),
        )


def load_attestations(store: Path) -> dict[str, Attestation]:
    """Every attestation in `store`, keyed by unit id.

    An unreadable or malformed record is DROPPED rather than repaired. The unit then has no
    attestation, so it derives to `UNKNOWN` — which is what "a cache whose provenance
    cannot be established" must mean (§2).
    """
    out: dict[str, Attestation] = {}
    if not store.exists():
        return out
    for path in sorted(store.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            attestation = Attestation.from_json(raw)
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        out[attestation.unit_id] = attestation
    return out


def _first_by_precedence(states: set[str]) -> str:
    for state in STATE_PRECEDENCE:
        if state in states:
            return state
    return "UNKNOWN"


def derive_unit_state(unit_id: str, current: dict, attestations: dict) -> tuple[str, str]:
    """The state of one unit from its own inputs alone, before any propagation.

    Returns `(state, reason)`. The reason is for the reviewer, and it names the component,
    because "this unit is dirty" without saying which input moved sends someone to re-read
    everything — the outcome this whole system exists to avoid.
    """
    attestation = attestations.get(unit_id)
    if attestation is None:
        return "UNKNOWN", "no attestation: this unit has never been established fresh"

    if attestation.evidence.get("verus") == "fail" or attestation.evidence.get("lean") == "fail":
        return "BLOCKED", "a required proof failed; no freshness may be issued from here"

    recorded = attestation.components
    differing: set[str] = set()
    reasons: list[str] = []
    for name, value in current["components"].items():
        if name == "encoding_version":
            continue
        if name not in recorded:
            return (
                "UNKNOWN",
                f"the attestation records no `{name}`: it predates the current encoding, "
                f"so what it certified cannot be compared",
            )
        if recorded[name] != value:
            state = COMPONENT_STATE.get(name)
            if state is None:
                why = UNRESOLVED_COMPONENT.get(name)
                return "UNKNOWN", (
                    f"`{name}` changed and is deliberately unclassified: {why}"
                    if why
                    else f"`{name}` changed and this engine cannot classify it. It is in "
                    f"neither COMPONENT_STATE nor UNRESOLVED_COMPONENT, which the component "
                    f"census forbids — so the census is not running where this ran."
                )
            differing.add(state)
            reasons.append(name)

    if not differing:
        if attestation.fingerprint != current["fingerprint"]:
            return (
                "UNKNOWN",
                "every recorded component matches but the fingerprint does not: the "
                "encoding itself changed, so the comparison means something different",
            )
        return "FRESH", "every recorded input is unchanged"

    return _first_by_precedence(differing), "changed: " + ", ".join(sorted(reasons))


def propagate(
    states: dict[str, tuple[str, str]],
    edges: list[dict],
    current: dict[str, dict],
    attestations: dict[str, Attestation],
) -> dict[str, tuple[str, str]]:
    """Push invalidation along typed edges until it stops moving.

    Three rules. The first is about what a failure MEANS; the other two are about how far
    ordinary staleness travels, and the difference between them is the value of the formal
    layer:

      * A `BLOCKED` producer blocks its consumers, over every propagating edge kind and
        through any seal. Freshness is a property of the whole declared evidence closure,
        not of a unit's own latest verifier result, so a consumer whose own theorem still
        passes may not issue freshness while a required prerequisite has failed.


      * An UNSEALED `CONTRACT_CONSUMES` or a `COMPILE_DEPENDENCY` propagates ANY producer
        dirtiness. Conservative, and the default: without a proved unchanged contract there
        is no ground to claim the consumer's reasoning survived.
      * A SEALED `CONTRACT_CONSUMES` propagates only when the producer's exported CONTRACT
        changed, or its proof failed, or the assumptions/toolchain under that proof moved.
        Producer source churn alone stops at the producer.

    `REVIEW_CONTEXT` never propagates — that is what makes it context closure rather than
    review closure (§3).
    """
    result = dict(states)
    changed = True
    while changed:
        changed = False
        for edge in edges:
            kind = edge["kind"]
            if kind == "REVIEW_CONTEXT":
                continue
            # Direction is not decorative: `from` PRODUCES the evidence, `to` CONSUMES it,
            # and invalidation flows only that way. A graph that is internally consistent
            # while propagating backwards would report exactly the wrong unit as sound,
            # which is why `test_invalidation` pins the asymmetry.
            producer, consumer = edge["from"], edge["to"]
            producer_state = result.get(producer, ("UNKNOWN", "not declared"))[0]
            consumer_state = result.get(consumer, ("UNKNOWN", "not declared"))[0]
            if producer_state == "FRESH":
                continue

            # A BLOCKED producer is not staleness, and the difference is the whole point of
            # keeping two words. DIRTY_* means "this evidence can be re-derived". BLOCKED
            # means "no valid freshness may be issued until something OUTSIDE this unit is
            # repaired" — and no amount of re-running the consumer repairs a failed
            # prerequisite. So it propagates as BLOCKED, and a seal does not stop it: a seal
            # is a claim about a contract being the whole of the consumer's reasoning, which
            # says nothing when the proof establishing that contract has failed.
            #
            # It also escalates a consumer that is merely dirty, because BLOCKED is strictly
            # the stronger statement about what may be issued.
            if producer_state == "BLOCKED":
                if consumer_state != "BLOCKED":
                    result[consumer] = (
                        "BLOCKED",
                        f"required dependency {producer} is BLOCKED over a {kind} edge; "
                        "re-running this unit cannot repair a failed prerequisite",
                    )
                    changed = True
                continue

            if consumer_state != "FRESH":
                continue

            if kind == "CONTRACT_CONSUMES" and edge.get("sealed"):
                # The sealed edge's promise, and its exact limits.
                stops_here = producer_state in {"DIRTY_SELF", "DIRTY_EVIDENCE"}
                producer_attestation = attestations.get(producer)
                producer_current = current.get(producer)
                if stops_here and producer_attestation and producer_current:
                    recorded = producer_attestation.components.get("exported_contracts")
                    now = producer_current["components"].get("exported_contracts")
                    if recorded == now:
                        # Source moved, contract did not, no proof failure: propagation
                        # stops. This is the ONLY case where dirtiness does not flow.
                        continue
                reason = (
                    f"sealed on {edge.get('contract')}, but the producer is "
                    f"{producer_state}, which a seal does not stop"
                )
            else:
                reason = f"{producer} is {producer_state} over an unsealed {kind} edge"

            result[consumer] = ("DIRTY_DEPENDENCY", reason)
            changed = True
    return result


def context_closure(unit_ids: set[str], edges: list[dict]) -> set[str]:
    """Units a reviewer should READ, which is not the same as units to re-review (§3).

    Every neighbour of a dirty unit, by any edge kind including `REVIEW_CONTEXT`, and
    excluding the dirty set itself. Belonging here carries no invalidation: keeping the two
    apart is what stops the graph from either invalidating the repository for every local
    change, or showing a reviewer only the lines that moved.
    """
    out: set[str] = set()
    for edge in edges:
        if edge["from"] in unit_ids:
            out.add(edge["to"])
        if edge["to"] in unit_ids:
            out.add(edge["from"])
    return out - unit_ids


def evaluate(
    units: list[dict],
    edges: list[dict],
    current: dict[str, dict],
    attestations: dict[str, Attestation],
) -> dict:
    """The full derivation: per-unit states, propagation, frontier, context closure."""
    states = {
        unit["id"]: derive_unit_state(unit["id"], current[unit["id"]], attestations)
        for unit in units
    }
    states = propagate(states, edges, current, attestations)
    dirty = {unit_id for unit_id, (state, _) in states.items() if state != "FRESH"}
    return {
        "states": states,
        "review_closure": sorted(dirty),
        "context_closure": sorted(context_closure(dirty, edges)),
        "fresh": sorted(set(states) - dirty),
    }
