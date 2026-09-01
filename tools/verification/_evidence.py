# SPDX-License-Identifier: Apache-2.0
"""Machine evidence records, and who may be issued an attestation — ADR-MCPRE-059 §2, §5.

The pipeline has two halves that must not be one program:

    verification lane  ->  machine evidence record  ->  verdict  ->  ISSUER  ->  attestation

A lane MEASURES. The issuer RECORDS what a lane measured. The dangerous implementation is
the one that collapses them — "the prover's output looked green, so stamp the working
tree" — because the thing stamped is then the CURRENT source, while the thing measured was
whatever the source happened to be when the prover ran. Everything in this module exists to
keep those two apart.

An evidence record therefore carries the fingerprint the lane measured AT. Issuance
compares it against the fingerprint of the tree as it is now, and a mismatch is a refusal,
never a fresh stamp on unmeasured source.

Three refusal grounds, and each is a false-green that would otherwise be reachable:

  * `no evidence`      — the unit claims a lane that produced no record. Absence of
                         measurement is not measurement.
  * `stale evidence`   — a record exists but was taken at a different fingerprint.
  * `blocked upstream` — the unit's own lane passed, but a required prerequisite failed.
                         Freshness is a property of the whole declared evidence closure,
                         so a locally green theorem may not issue freshness over a broken
                         one underneath it.

A FAILED lane is not a refusal. It is issued, as a record carrying `fail`, because
"the proof failed at this fingerprint" is itself evidence, and it is exactly the fact the
graph must propagate as BLOCKED. Refusing to write it would leave the previous, passing
attestation in place — the failure would make the unit look fresh.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

#: Edge kinds over which a producer's failure denies the consumer an attestation. The same
#: set `_graph.propagate` treats as carrying invalidation, for the same reason: an edge
#: that transmits staleness after issuance must also block issuance, or the issuer becomes
#: the way around the graph.
PREREQUISITE_KINDS = {"PROOF_DEPENDENCY", "CONTRACT_CONSUMES", "COMPILE_DEPENDENCY"}


@dataclass(frozen=True)
class EvidenceRecord:
    """One lane's result for one unit, bound to the fingerprint it was measured at."""

    unit_id: str
    lane: str
    result: str  # "pass" | "fail"
    fingerprint: str
    detail: str = ""
    prover: dict | None = None

    def to_json(self) -> dict:
        out: dict[str, object] = {
            "unit_id": self.unit_id,
            "lane": self.lane,
            "result": self.result,
            "fingerprint": self.fingerprint,
            "detail": self.detail,
        }
        if self.prover:
            out["prover"] = self.prover
        return out

    @staticmethod
    def from_json(raw: dict) -> "EvidenceRecord":
        return EvidenceRecord(
            unit_id=raw["unit_id"],
            lane=raw["lane"],
            result=raw["result"],
            fingerprint=raw["fingerprint"],
            detail=raw.get("detail", ""),
            prover=raw.get("prover"),
        )


def write_record(store: Path, record: EvidenceRecord) -> Path:
    """Persist one lane result. Deterministic bytes: the same measurement rewrites identically."""
    directory = store / record.lane
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{record.unit_id}.json"
    path.write_text(
        json.dumps(record.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def load_records(store: Path, lane: str) -> dict[str, EvidenceRecord]:
    """Every record for one lane, keyed by unit id. Malformed records are DROPPED.

    Dropped rather than repaired, and dropped rather than raised: a record that cannot be
    parsed is a unit with no evidence, which is a refusal. Repairing it would invent the
    provenance the record was supposed to carry.
    """
    out: dict[str, EvidenceRecord] = {}
    directory = store / lane
    if not directory.exists():
        return out
    for path in sorted(directory.glob("*.json")):
        try:
            out[path.stem] = EvidenceRecord.from_json(
                json.loads(path.read_text(encoding="utf-8"))
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return out


def write_bundle(store: Path, aggregate: str, lanes: dict[str, str], policy_revision: str) -> Path:
    """The run's aggregate verdict, as a record the issuer can consume.

    Phase 3 of the pipeline, and the reason it is a file rather than an exit code: the
    issuer must be able to see WHICH lanes carried the verdict, not merely that some
    process upstream exited 0.

    THE BUNDLE DESCRIBES THE LAST RUN, NOT THE LAST SUCCESSFUL ONE. `attest` reads it as
    "the aggregate verdict of the last verification run", and that reading is only true if
    every exit path from `verify` writes one. It did not: a run that failed manifest
    validation returned before reaching this call, leaving the PREVIOUS run's verdict on
    disk for the issuer to consume — a failed run made the tree look measured, and the
    worse a run failed, the earlier it exited and the more certainly the stale record
    survived. `verify` now writes on every path, which is what makes the file's meaning
    the one the issuer assumes.
    """
    store.mkdir(parents=True, exist_ok=True)
    path = store / "bundle.json"
    path.write_text(
        json.dumps(
            {"aggregate": aggregate, "lanes": lanes, "policy_revision": policy_revision},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def load_bundle(store: Path) -> dict | None:
    """The aggregate verdict record, or None if absent or unreadable — which is a refusal."""
    path = store / "bundle.json"
    if not path.is_file():
        return None
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return bundle if isinstance(bundle, dict) else None


#: The scheme a declaration takes when it is not a URI at all. It resolves to no lane, so
#: it refuses, which is what an unparsable evidence declaration must do.
MALFORMED_LANE = "<malformed-evidence-uri>"


def required_lanes(unit: dict) -> set[str]:
    """The lanes this unit claims, read off its declared evidence URIs.

    EVERY scheme, not a recognised subset. Filtering to the schemes that happen to have an
    implementation is how a unit whose only declared evidence is `test://` ends up claiming
    no lane at all: the issuance loop then has nothing to check, falls through to
    ISSUE_PASS, and stamps an attestation whose evidence map is empty. A declared evidence
    class nothing resolves is unmeasured evidence, and unmeasured evidence refuses.
    """
    lanes = set()
    for entry in unit.get("evidence", []):
        text = str(entry)
        lanes.add(text.split("://", 1)[0] if "://" in text else MALFORMED_LANE)
    return lanes


def decide_issuance(
    units: list[dict],
    edges: list[dict],
    current: dict[str, dict],
    records: dict[str, dict[str, EvidenceRecord]],
    aggregate: str | None = None,
) -> dict[str, tuple[str, dict, str]]:
    """Who may be issued what.

    Returns `{unit_id: (decision, evidence, reason)}` where decision is one of:

        ISSUE_PASS   every claimed lane measured this exact fingerprint and passed
        ISSUE_FAIL   a claimed lane measured this exact fingerprint and FAILED; the
                     attestation is written carrying that failure, so the graph blocks
        REFUSE       no attestation may be written; the previous one, whatever it said,
                     is left alone for the graph to judge

    `records` is keyed by lane, then unit.

    The prerequisite pass runs to a fixpoint, so a refusal propagates down a chain: if the
    bottom theorem is unmeasured, nothing standing on it may be issued either.
    """
    decisions: dict[str, tuple[str, dict, str]] = {}

    for unit in units:
        unit_id = unit["id"]
        wanted = required_lanes(unit)
        evidence: dict[str, str] = {}
        refusal: str | None = None
        failed_lane: str | None = None

        if not wanted:
            # A unit that declares no evidence has had nothing measured about it. Issuing a
            # PASS here is the emptiest false green available: the attestation would carry
            # an empty evidence map and the graph would print the unit FRESH on the
            # strength of a manifest declaration alone.
            decisions[unit_id] = (
                "REFUSE",
                {},
                "the unit declares no evidence, so no lane measured it; absence of "
                "measurement is not measurement",
            )
            continue

        for lane in sorted(wanted):
            record = records.get(lane, {}).get(unit_id)
            if record is None:
                refusal = (
                    f"the unit claims {lane} evidence but no {lane} record exists for it; "
                    "absence of measurement is not measurement"
                )
                break
            if record.fingerprint != current[unit_id]["fingerprint"]:
                refusal = (
                    f"the {lane} record was measured at {record.fingerprint[:23]} but the "
                    f"unit now fingerprints {current[unit_id]['fingerprint'][:23]}; "
                    "evidence inputs do not match current fingerprint"
                )
                break
            evidence[lane] = record.result
            if record.result != "pass":
                failed_lane = lane

        if refusal is not None:
            decisions[unit_id] = ("REFUSE", {}, refusal)
        elif failed_lane is not None:
            decisions[unit_id] = (
                "ISSUE_FAIL",
                evidence,
                f"the {failed_lane} lane failed at this fingerprint; the attestation "
                "records the failure so it propagates as BLOCKED",
            )
        else:
            decisions[unit_id] = ("ISSUE_PASS", evidence, "every claimed lane passed at this fingerprint")

    # Prerequisites. A locally passing theorem may not be issued freshness over a
    # prerequisite that failed or was never measured — that is the issuer-side twin of
    # BLOCKED propagation, and without it the issuer is the way around the graph.
    changed = True
    while changed:
        changed = False
        for edge in edges:
            if edge["kind"] not in PREREQUISITE_KINDS:
                continue
            producer, consumer = edge["from"], edge["to"]
            if consumer not in decisions or producer not in decisions:
                continue
            producer_decision = decisions[producer][0]
            if producer_decision == "ISSUE_PASS":
                continue
            if decisions[consumer][0] != "ISSUE_PASS":
                continue
            cause = "failed" if producer_decision == "ISSUE_FAIL" else "has no issuable evidence"
            decisions[consumer] = (
                "REFUSE",
                {},
                f"required prerequisite {producer} {cause} over a {edge['kind']} edge; "
                "a locally passing theorem may not issue freshness over a broken one",
            )
            changed = True

    # The aggregate verdict, if one was supplied, gates PASS issuance only. A run whose
    # hygiene or Lean lane failed may not stamp freshness anywhere — but a unit whose own
    # proof demonstrably failed at this exact fingerprint still gets its failure recorded,
    # because withholding THAT would leave its last passing attestation standing.
    if aggregate is not None and aggregate != "PASS":
        for unit_id, (decision, _evidence, _reason) in list(decisions.items()):
            if decision == "ISSUE_PASS":
                decisions[unit_id] = (
                    "REFUSE",
                    {},
                    f"the aggregate evidence verdict for this run is {aggregate}, not "
                    "PASS; no freshness may be issued from an incomplete or failed run",
                )

    return decisions
