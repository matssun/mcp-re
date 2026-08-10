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
COMPONENT_STATE = {
    "source_inputs": "DIRTY_SELF",
    "exported_contracts": "DIRTY_CONTRACT",
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
    consumed_contracts: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)

    @staticmethod
    def from_json(raw: dict) -> "Attestation":
        return Attestation(
            unit_id=raw["unit_id"],
            fingerprint=raw["fingerprint"],
            components=raw.get("components", {}),
            consumed_contracts=raw.get("consumed_contracts", {}),
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
                return "UNKNOWN", f"`{name}` changed and this engine cannot classify it"
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

    Two rules, and the difference between them is the entire value of the formal layer:

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
            producer, consumer = edge["from"], edge["to"]
            producer_state = result.get(producer, ("UNKNOWN", "not declared"))[0]
            consumer_state = result.get(consumer, ("UNKNOWN", "not declared"))[0]
            if producer_state == "FRESH" or consumer_state != "FRESH":
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
