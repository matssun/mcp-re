# SPDX-License-Identifier: Apache-2.0
"""Composing one verification verdict out of evidence produced in two environments.

# The problem this exists for

The repository's required evidence cannot be produced by one process. Verus and the cargo
matrix run on the macOS host; Charon links the private rustc crates and does not build
there at all, so extraction and the Lean proofs run inside the pinned container. Before a
V2 unit existed the split was invisible — `verify --gate` ran on the host and both
extracted-model lanes reported `NOT_REQUIRED`. Declaring one made them required, and the
host gate became structurally incapable of `PASS`: two lanes it cannot execute, both
correctly reporting `UNAVAILABLE`, holding the aggregate at `INCOMPLETE` forever.

Every verdict there was right. What was wrong was the question: a process was being asked
for an aggregate over lanes it cannot run.

# The change, stated precisely

    from   one process must EXECUTE every required lane
    to     every required lane must have valid EVIDENCE for the current fingerprint

That is a change to what `VERIFICATION: PASS` means, and it is the whole content of this
module. It is not a relaxation. The old rule was unsatisfiable, and the new one is strictly
harder to satisfy by accident: a lane that silently did not run leaves no record, and a
missing record is `INCOMPLETE`.

# What it does NOT license

**A lane may not report PASS by reading somebody else's record.** `verify-lean` on a macOS
host still reports `UNAVAILABLE`, and `check-generated` still reports `UNAVAILABLE` where it
could not have produced a stamp. Lane executors remain the authorities for EXECUTION; only
the central aggregate composes. Letting a lane launder another environment's record into its
own verdict would put the composition inside the thing being composed, where no control can
see it.

**A record is not accepted because it exists.** Every acceptance rule below is a way for a
record to be refused, and the fingerprint is the load-bearing one: it carries the unit's
sources, its build configuration, the whole toolchain identity — including, since the
artifact store landed, `artifact_digest` and `archive_digest`. So a record produced by a
different tree, a different prover, or a *different extraction artifact* cannot be composed
into a verdict about this one.

**A stale directory cannot make a run green.** The store is named by `MCP_RE_EVIDENCE_DIR`
and CI creates a fresh one per invocation, so composition sees this run's records and
nothing else. Fingerprint-bound reuse across runs is a separate question about the evidence
system and is deliberately not what solves this one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from _evidence import EvidenceRecord, load_records
from _fingerprint import fingerprint_unit
from _manifest import aggregate_verdict

#: The lanes that produce per-unit EVIDENCE, mapped to the classes that require them.
#:
#: Derived from the class, never from what a lane happened to report: "this unit is V2" is
#: what makes Lean evidence required, and a lane's own `NOT_REQUIRED` about a V2 unit is a
#: contradiction rather than an excuse. That is why the rule below refuses it outright.
FORMAL_LANES: dict[str, set[str]] = {
    "test": {"V0", "V1", "V2", "V3"},
    "mutation": {"V0", "V1", "V2", "V3"},
    "verus": {"V1", "V3"},
    "lean": {"V2", "V3"},
    "generated-model": {"V2", "V3"},
}

# A LANE MAY NOT DECLARE `NOT_REQUIRED` FOR A CLASS THAT REQUIRES IT, and neither of the
# extracted-model lanes can: `verify-lean` reaches its NOT_REQUIRED branch only when no
# V2/V3 unit exists, and `check-generated` only when no V2/V3 unit declares an extraction.
# So the contradiction — "the manifest requires Lean evidence for this unit" against "Lean
# was not asked for any" — is refused at the executor by construction rather than being
# something the composer detects after the fact. Pinned by a control, because a structural
# impossibility that nothing checks is one refactor away from being possible.

#: Which execution environment each formal lane belongs to. Total over `FORMAL_LANES` by
#: construction — a lane in neither set would be a lane no phase runs and no control
#: notices, which is the failure this whole module is repairing one level up.
HOST_LANES = frozenset({"test", "mutation", "verus"})
EXTRACTION_LANES = frozenset({"lean", "generated-model"})
assert HOST_LANES | EXTRACTION_LANES == set(FORMAL_LANES)
assert not (HOST_LANES & EXTRACTION_LANES)


@dataclass(frozen=True)
class Requirement:
    """One (lane, unit) pair the manifest requires evidence for."""

    lane: str
    unit_id: str
    fingerprint: str


def requirements(doc: dict, toolchains: dict, assumptions: dict) -> list[Requirement]:
    """Every (lane, unit) the manifest requires, with the fingerprint it requires it AT.

    Read from the MANIFEST, not from what any lane reported. A requirement set derived from
    lane output would shrink exactly when a lane stopped running, which is the shape of
    every false green this platform exists to prevent.
    """
    out: list[Requirement] = []
    for unit in doc.get("unit", []):
        fingerprint = fingerprint_unit(unit, doc, toolchains, assumptions)["fingerprint"]
        for lane, classes in sorted(FORMAL_LANES.items()):
            if unit["class"] not in classes:
                continue
            # `test` and `mutation` are declared per unit by evidence URI rather than by
            # class alone: a V0 unit with no battery claims none, and requiring one would
            # make the aggregate demand evidence the manifest never promised.
            if lane == "test" and not _claims(unit, "test://"):
                continue
            if lane == "mutation" and not _claims(unit, "mutation://"):
                continue
            if lane == "lean" and not _claims(unit, "lean://"):
                continue
            out.append(Requirement(lane, unit["id"], fingerprint))
    return out


def contradictions(lane_verdicts: dict[str, str], required: list[Requirement]) -> list[str]:
    """Lanes that declared `NOT_REQUIRED` while the manifest requires them.

    A DIFFERENT DEFECT from an absent record, and it must not be composed around. A missing
    record says a measurement was not taken; this says a lane looked at the manifest, was
    required by it, and reported that nothing asked. One is an environment to fix and the
    other is a lane whose reading of the manifest disagrees with the composer's — and a
    disagreement about what is required is the one thing the aggregate cannot arbitrate,
    because both readings are inputs to it.

    Checked in the EXECUTION phase, where the declared verdict exists. The composer sees
    only records, and a `NOT_REQUIRED` lane leaves none.
    """
    needed = {requirement.lane for requirement in required}
    return [
        f"{lane} declared NOT_REQUIRED, and the manifest requires it for "
        f"{sum(1 for r in required if r.lane == lane)} unit(s). A lane's reading of the "
        "manifest may not disagree with the requirement set composed from it."
        for lane, verdict in sorted(lane_verdicts.items())
        if verdict == "NOT_REQUIRED" and lane in needed
    ]


def _claims(unit: dict, scheme: str) -> bool:
    return any(str(entry).startswith(scheme) for entry in unit.get("evidence", []))


def _duplicates(store: Path, lane: str) -> list[str]:
    """Unit ids for which this lane's directory holds more than one record.

    `load_records` keys by file stem, so a second file for the same unit under a different
    name would be silently dropped or silently win depending on sort order. Neither is
    acceptable: two records asserting different things about one unit is a store that
    cannot be read, and reading it anyway is choosing one claim without saying so.
    """
    directory = store / lane
    if not directory.is_dir():
        return []
    seen: dict[str, list[str]] = {}
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            unit_id = str(raw["unit_id"])
        except (json.JSONDecodeError, OSError, KeyError, TypeError):
            continue
        seen.setdefault(unit_id, []).append(path.name)
    return sorted(unit for unit, files in seen.items() if len(files) > 1)


def _malformed(store: Path, lane: str) -> list[str]:
    """Files in the lane's directory that are not readable records.

    `load_records` DROPS these, which is right for it — a record that cannot be parsed is a
    unit with no evidence. But dropping is only safe if somebody notices: an unreadable
    record in a fresh directory means a lane wrote something this run and the composer
    cannot tell what, and unknown is dirty.
    """
    directory = store / lane
    if not directory.is_dir():
        return []
    bad: list[str] = []
    for path in sorted(directory.glob("*.json")):
        try:
            EvidenceRecord.from_json(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError, KeyError, TypeError):
            bad.append(path.name)
    return bad


def compose(
    store: Path,
    doc: dict,
    toolchains: dict,
    assumptions: dict,
    hygiene: dict[str, str],
) -> tuple[str, dict[str, str], list[str]]:
    """The repository verdict, the per-lane verdicts behind it, and every refusal.

    `hygiene` is the executed hygiene lanes' verdicts — those are whole-repository
    propositions with no per-unit evidence, they are host-capable, and they enter the
    algebra exactly as they always have: able to withhold a pass, never to carry one.
    """
    required = requirements(doc, toolchains, assumptions)
    refusals: list[str] = []
    lane_verdicts: dict[str, str] = {}

    for lane in sorted(FORMAL_LANES):
        wanted = [r for r in required if r.lane == lane]
        unreadable = "PASS"
        for name in _malformed(store, lane):
            refusals.append(
                f"{lane}: {name} is not a readable evidence record. A lane wrote it this "
                "run and the composer cannot tell what it says; unknown is dirty."
            )
            unreadable = "FAIL"
        for unit_id in _duplicates(store, lane):
            refusals.append(
                f"{lane}/{unit_id}: more than one record. Two records about one unit is a "
                "store that cannot be read, and picking one is choosing a claim silently."
            )
            unreadable = "FAIL"
        if not wanted:
            # NOT_REQUIRED, and it must stay distinguishable from a pass: "the manifest
            # asked nothing of this lane" is not evidence about the code. A lane the
            # manifest asks nothing of, whose directory nonetheless holds something
            # unreadable, is still a store that cannot be read.
            lane_verdicts[lane] = "NOT_REQUIRED" if unreadable == "PASS" else "FAIL"
            continue
        records = load_records(store, lane)
        verdict = unreadable
        for requirement in wanted:
            record = records.get(requirement.unit_id)
            if record is None:
                refusals.append(
                    f"{lane}/{requirement.unit_id}: no evidence record. The manifest "
                    f"requires this lane for a {_class_of(doc, requirement.unit_id)} "
                    "unit, and absence of measurement is not measurement."
                )
                verdict = _weaken(verdict, "UNAVAILABLE")
                continue
            severity, problem = _unacceptable(record, requirement, toolchains)
            if problem:
                refusals.append(f"{lane}/{requirement.unit_id}: {problem}")
                verdict = _weaken(verdict, severity)
                continue
            if record.result != "pass":
                refusals.append(
                    f"{lane}/{requirement.unit_id}: recorded {record.result!r} — "
                    f"{record.detail or 'no detail'}"
                )
                verdict = _weaken(verdict, "FAIL")
        lane_verdicts[lane] = verdict

    aggregate = aggregate_verdict(
        list(lane_verdicts.values()), list(hygiene.values())
    )
    return aggregate, {**lane_verdicts, **hygiene}, refusals


def _class_of(doc: dict, unit_id: str) -> str:
    for unit in doc.get("unit", []):
        if unit["id"] == unit_id:
            return str(unit["class"])
    return "?"


def _weaken(current: str, candidate: str) -> str:
    """FAIL outranks UNAVAILABLE outranks PASS — a lane is as strong as its weakest unit."""
    order = {"PASS": 0, "UNAVAILABLE": 1, "FAIL": 2}
    return candidate if order[candidate] > order[current] else current


def _unacceptable(
    record: EvidenceRecord, requirement: Requirement, toolchains: dict
) -> tuple[str, str | None]:
    """Why this record may not stand for this requirement, and how badly.

    Every clause is a way a record that LOOKS right is not about this tree, this lane, or
    this instrument. The severity is not decoration: a STALE record is a measurement that
    has not been taken over this tree — `UNAVAILABLE`, which the algebra turns into
    `INCOMPLETE`, and whose remedy is to run the lane — while a record that MISDESCRIBES
    itself or names the wrong instrument is `FAIL`, because something wrote a claim that is
    not true of what it measured, and re-running is not the remedy for that.
    """
    if record.unit_id != requirement.unit_id:
        return "FAIL", (
            f"the record names unit {record.unit_id!r}; it is filed under "
            f"{requirement.unit_id!r}"
        )
    if record.lane != requirement.lane:
        return "FAIL", (
            f"the record names lane {record.lane!r}; it is filed under "
            f"{requirement.lane!r}"
        )
    if record.result not in {"pass", "fail"}:
        return "FAIL", f"result {record.result!r} is neither 'pass' nor 'fail'"
    if record.fingerprint != requirement.fingerprint:
        return "UNAVAILABLE", (
            f"STALE — measured at {record.fingerprint[:23]}…, and this tree fingerprints "
            f"{requirement.fingerprint[:23]}…. A record is evidence about the tree it was "
            "taken over, and this is not that tree."
        )
    if requirement.lane in EXTRACTION_LANES:
        pinned = str(toolchains.get("extraction_container", {}).get("artifact_digest", ""))
        named = str((record.prover or {}).get("extraction_artifact", ""))
        if not named:
            return "FAIL", (
                "an extraction-lane record that does not name the artifact it ran in. The "
                "instrument is part of what the evidence is about."
            )
        if named != pinned:
            return "FAIL", (
                f"produced in extraction artifact {named[:23]}…, and the lock pins "
                f"{pinned[:23]}…. A different build of the same declared pins is a "
                "different instrument."
            )
    return "PASS", None
