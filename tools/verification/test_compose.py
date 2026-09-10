#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Controls for composing one verdict out of evidence produced in two environments.

The change these exist for moves what `VERIFICATION: PASS` means — from *one process
executed every required lane* to *every required lane has valid evidence for the current
fingerprint*. That is the kind of change which, done carelessly, turns a gate into a
formality: an aggregate that accepts whatever records it finds would report PASS for a run
that measured nothing, which is the failure this whole platform exists to prevent.

So every control below hands the composer a store that LOOKS complete and asks it to
refuse. A composer that only ever passes is indistinguishable from one that reads nothing.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _compose import (  # noqa: E402
    EXTRACTION_LANES,
    FORMAL_LANES,
    HOST_LANES,
    compose,
    contradictions,
    requirements,
)
from _evidence import EvidenceRecord, write_record  # noqa: E402
from _load_tool import load_tool  # noqa: E402

ARTIFACT = f"sha256:{'d' * 64}"


def world() -> tuple[dict, dict, dict]:
    """A minimal manifest world: one V0 unit with a battery, one V2 unit with Lean.

    Synthetic rather than the real manifest, because these controls are about the
    COMPOSITION rule and must keep asking the same question while the repository's units
    change underneath them.
    """
    doc = {
        "policy_revision": "test",
        "unit": [
            {
                "id": "u.v0",
                "class": "V0",
                "description": "",
                "paths": ["tools/verification/_compose.py"],
                "evidence": ["test://u/v0/battery"],
                "tested_symbols": ["lib#a::b"],
            },
            {
                "id": "u.v2",
                "class": "V2",
                "description": "",
                "paths": ["tools/verification/_compose.py"],
                "evidence": ["lean://u/v2/theorem"],
            },
        ],
    }
    toolchains = {
        "schema_version": 1,
        "extraction_container": {
            "state": "resolved",
            "artifact_digest": ARTIFACT,
            "archive_digest": f"sha256:{'e' * 64}",
        },
    }
    return doc, toolchains, {"assumption": []}


def store_for(doc, toolchains, assumptions, *, omit=(), mutate=None) -> Path:
    """A fresh evidence directory holding an acceptable record for every requirement."""
    root = Path(tempfile.mkdtemp(prefix="compose-store-"))
    for requirement in requirements(doc, toolchains, assumptions):
        if (requirement.lane, requirement.unit_id) in omit or requirement.lane in omit:
            continue
        record = EvidenceRecord(
            unit_id=requirement.unit_id,
            lane=requirement.lane,
            result="pass",
            fingerprint=requirement.fingerprint,
            detail="synthetic",
            prover=(
                {"extraction_artifact": ARTIFACT}
                if requirement.lane in EXTRACTION_LANES
                else None
            ),
        )
        if mutate:
            record = mutate(record)
        if record is not None:
            write_record(root, record)
    return root


def verdict(store: Path, doc, toolchains, assumptions, hygiene=None):
    return compose(store, doc, toolchains, assumptions, hygiene or {"assumptions": "PASS"})


# ---------------------------------------------------------------------------
# The positive, first — a control set in which nothing ever passes proves nothing
# ---------------------------------------------------------------------------


def test_a_complete_current_store_composes_to_PASS():
    doc, tc, asm = world()
    aggregate, lanes, refusals = verdict(store_for(doc, tc, asm), doc, tc, asm)
    assert aggregate == "PASS", (aggregate, refusals)
    assert lanes["lean"] == "PASS" and lanes["test"] == "PASS"
    assert refusals == []


def test_the_composer_and_the_ISSUER_require_the_same_lanes():
    """Two authorities read "what does this unit require", and they must read one fact.

    `_evidence.required_lanes` derives it from the declared evidence URIs; the composer's
    requirement set derives it here. They agreed only while every V2/V3 unit happened to
    declare `lean://`, and nothing made it — a unit with `extracted_symbols` and
    `lean_theorems` but no `lean://` entry would have been ISSUED an attestation on its test
    battery alone while claiming extracted-model evidence, because the issuer would have
    seen no lean lane to check. The manifest now requires the entry, and this pins the
    agreement rather than trusting it.
    """
    from _evidence import required_lanes

    doc, tc, asm = world()
    wanted = requirements(doc, tc, asm)
    for unit in doc["unit"]:
        issuer = required_lanes(unit)
        composed = {r.lane for r in wanted if r.unit_id == unit["id"]}
        # `generated-model` has no URI of its own: it is the freshness precondition of
        # `lean://`, so the composer asks for it exactly where the issuer asks for lean.
        assert composed - {"generated-model"} == issuer, (unit["id"], composed, issuer)
        assert ("generated-model" in composed) == ("lean" in issuer), unit["id"]


def _validated(unit: dict):
    """Run the REAL manifest validator over a tree carrying `unit`, and return or raise.

    `_load` is replaced rather than the file, because the validator's refusals are what is
    under test and writing a synthetic TOML would test a parser instead. The rest of the
    document is the repository's own, so the unit is judged in the world it would live in.
    """
    import _manifest

    doc = _manifest.load_verification()
    doc = {**doc, "unit": [*doc.get("unit", []), unit]}
    original = _manifest._load
    try:
        _manifest._load = lambda _path: doc
        return _manifest.load_verification()
    finally:
        _manifest._load = original


def _v2_unit(**overrides) -> dict:
    unit = {
        "id": "synthetic.extracted",
        "class": "V2",
        "description": "a synthetic extracted-model unit",
        "paths": ["tools/verification/_compose.py"],
        "evidence": ["lean://synthetic/theorem"],
        "extracted_symbols": ["crate::item"],
        "lean_theorems": ["Synthetic.theorem"],
    }
    unit.update(overrides)
    return unit


def test_a_V2_unit_that_declares_no_lean_evidence_is_refused_by_the_manifest():
    """THE rule that makes the two authorities agree, asked of the real validator.

    Exercised against the repository's own manifest rather than asserted over its units:
    on a tree with no V2 unit an assertion over the declared ones passes while measuring
    nothing, which is the shape of control this platform exists to refuse.
    """
    from _manifest import ManifestError

    try:
        _validated(_v2_unit(evidence=["test://synthetic/battery"], tested_symbols=["lib#a::b"]))
    except ManifestError as exc:
        assert "no `lean://` evidence entry" in str(exc), exc
    else:
        raise AssertionError("a V2 unit with no lean:// evidence was accepted")


def test_a_V2_unit_that_declares_lean_evidence_is_accepted():
    """The positive half. A control that refuses everything is not a control."""
    _validated(_v2_unit())


def test_the_requirement_set_comes_from_the_manifest_not_from_the_store():
    """A requirement derived from what a lane reported would shrink exactly when a lane
    stopped running — which is the shape of every false green here.

    The V2 unit requires BOTH extracted-model lanes from its class alone, while `test` is
    required only where the unit's own evidence claims a battery: a V0 unit that promises
    none must not have one demanded of it.
    """
    doc, tc, asm = world()
    assert {(r.lane, r.unit_id) for r in requirements(doc, tc, asm)} == {
        ("test", "u.v0"),
        ("lean", "u.v2"),
        ("generated-model", "u.v2"),
    }


# ---------------------------------------------------------------------------
# The six refusals
# ---------------------------------------------------------------------------


def test_removing_the_lean_record_makes_the_aggregate_incomplete():
    doc, tc, asm = world()
    store = store_for(doc, tc, asm, omit=("lean",))
    aggregate, lanes, refusals = verdict(store, doc, tc, asm)
    assert aggregate == "INCOMPLETE", (aggregate, refusals)
    assert lanes["lean"] == "UNAVAILABLE"
    assert any("lean/u.v2: no evidence record" in r for r in refusals), refusals


def test_removing_the_generated_model_record_makes_the_aggregate_incomplete():
    doc, tc, asm = world()
    store = store_for(doc, tc, asm, omit=("generated-model",))
    aggregate, lanes, refusals = verdict(store, doc, tc, asm)
    assert aggregate == "INCOMPLETE", (aggregate, refusals)
    assert lanes["generated-model"] == "UNAVAILABLE"


def test_a_lean_record_at_another_fingerprint_is_refused_as_STALE():
    doc, tc, asm = world()

    def stale(record):
        if record.lane != "lean":
            return record
        return EvidenceRecord(
            record.unit_id, record.lane, record.result,
            f"sha256:{'0' * 64}", record.detail, record.prover,
        )

    aggregate, lanes, refusals = verdict(store_for(doc, tc, asm, mutate=stale), doc, tc, asm)
    assert aggregate == "INCOMPLETE", (aggregate, refusals)
    assert lanes["lean"] == "UNAVAILABLE"
    assert any("STALE" in r for r in refusals), refusals


def test_a_record_from_a_different_extraction_artifact_is_refused():
    """THE reason the artifact is preserved under an identity at all: a record produced in
    a different build of the same declared pins is evidence about a different instrument."""
    doc, tc, asm = world()

    def other_artifact(record):
        if record.lane not in EXTRACTION_LANES:
            return record
        return EvidenceRecord(
            record.unit_id, record.lane, record.result, record.fingerprint,
            record.detail, {"extraction_artifact": f"sha256:{'9' * 64}"},
        )

    aggregate, lanes, refusals = verdict(
        store_for(doc, tc, asm, mutate=other_artifact), doc, tc, asm
    )
    assert aggregate == "FAIL", (aggregate, refusals)
    assert any("different instrument" in r for r in refusals), refusals


def test_an_extraction_record_naming_no_artifact_is_refused():
    doc, tc, asm = world()

    def anonymous(record):
        if record.lane not in EXTRACTION_LANES:
            return record
        return EvidenceRecord(
            record.unit_id, record.lane, record.result, record.fingerprint, record.detail, {}
        )

    aggregate, _lanes, refusals = verdict(
        store_for(doc, tc, asm, mutate=anonymous), doc, tc, asm
    )
    assert aggregate == "FAIL", (aggregate, refusals)
    assert any("does not name the artifact" in r for r in refusals), refusals


def test_a_conflicting_duplicate_record_refuses_the_aggregate():
    """Two records about one unit is a store that cannot be read, and `load_records` keys
    by file stem — so the second would silently win or silently lose."""
    doc, tc, asm = world()
    store = store_for(doc, tc, asm)
    original = json.loads((store / "lean" / "u.v2.json").read_text())
    conflicting = dict(original, result="fail", detail="a second, contradicting claim")
    (store / "lean" / "u.v2-copy.json").write_text(json.dumps(conflicting))
    aggregate, _lanes, refusals = verdict(store, doc, tc, asm)
    assert aggregate == "FAIL", (aggregate, refusals)
    assert any("more than one record" in r for r in refusals), refusals


def test_a_malformed_record_refuses_rather_than_being_dropped():
    """`load_records` drops what it cannot parse, which is right for it. Dropping is only
    safe if somebody notices: a fresh directory containing an unreadable record means a
    lane wrote something this run that the composer cannot read, and unknown is dirty."""
    doc, tc, asm = world()
    store = store_for(doc, tc, asm)
    (store / "lean" / "u.v2.json").write_text("{ not json")
    aggregate, _lanes, refusals = verdict(store, doc, tc, asm)
    assert aggregate in {"FAIL", "INCOMPLETE"}, aggregate
    assert any("not a readable evidence record" in r for r in refusals), refusals


def test_a_recorded_failure_is_a_FAIL_not_a_missing_measurement():
    doc, tc, asm = world()

    def failed(record):
        if record.lane != "lean":
            return record
        return EvidenceRecord(
            record.unit_id, record.lane, "fail", record.fingerprint,
            "the theorem did not stand", record.prover,
        )

    aggregate, lanes, refusals = verdict(store_for(doc, tc, asm, mutate=failed), doc, tc, asm)
    assert aggregate == "FAIL", (aggregate, refusals)
    assert lanes["lean"] == "FAIL"


def test_a_record_filed_under_another_units_name_is_refused():
    doc, tc, asm = world()
    store = store_for(doc, tc, asm)
    raw = json.loads((store / "lean" / "u.v2.json").read_text())
    raw["unit_id"] = "u.somewhere-else"
    (store / "lean" / "u.v2.json").write_text(json.dumps(raw))
    aggregate, _lanes, refusals = verdict(store, doc, tc, asm)
    assert aggregate == "FAIL", (aggregate, refusals)
    assert any("names unit" in r for r in refusals), refusals


# ---------------------------------------------------------------------------
# The rule the executors hold, not the composer
# ---------------------------------------------------------------------------


def test_a_lane_declaring_NOT_REQUIRED_for_a_required_lane_is_a_contradiction():
    """A lane saying "nothing asked me" about a lane the manifest requires is a DIFFERENT
    defect from an absent record, and it must not be composed around.

    A missing record says a measurement was not taken — an environment to fix. This says a
    lane read the manifest, was required by it, and reported that nothing asked: its
    reading disagrees with the requirement set composed from the same file. That is the one
    disagreement the aggregate cannot arbitrate, because both readings are inputs to it, so
    it is refused in the EXECUTION phase where the declared verdict exists."""
    doc, tc, asm = world()
    required = requirements(doc, tc, asm)
    assert contradictions({"lean": "NOT_REQUIRED"}, required), "the contradiction stood"
    assert contradictions({"generated-model": "NOT_REQUIRED"}, required)
    # And a lane the manifest genuinely does not require may say so without complaint.
    assert contradictions({"verus": "NOT_REQUIRED"}, required) == []
    assert contradictions({"lean": "PASS"}, required) == []


def test_a_phase_refuses_a_lane_that_declares_NOT_REQUIRED_for_a_required_lane():
    """The executor holds the rule, so it must actually consult it."""
    verify = load_tool("verify")
    source = (Path(__file__).resolve().parent / "verify").read_text()
    assert "contradictions(" in source, "the phase never asks"
    assert hasattr(verify, "_phase_outcome")


def test_a_hygiene_lane_cannot_carry_the_aggregate():
    """It can withhold a pass by failing; passing it says nothing about the code."""
    doc, tc, asm = world()
    store = store_for(doc, tc, asm, omit=("lean", "generated-model", "test"))
    aggregate, _lanes, _refusals = verdict(store, doc, tc, asm, {"assumptions": "PASS"})
    assert aggregate == "INCOMPLETE", aggregate


def test_a_failing_hygiene_lane_outranks_complete_evidence():
    doc, tc, asm = world()
    aggregate, _lanes, _refusals = verdict(
        store_for(doc, tc, asm), doc, tc, asm, {"assumptions": "FAIL"}
    )
    assert aggregate == "FAIL", aggregate


# ---------------------------------------------------------------------------
# The phase split
# ---------------------------------------------------------------------------


def test_every_formal_lane_belongs_to_exactly_one_phase():
    """A formal lane in no phase is a lane nothing executes; one in both is two authorities
    for a single measurement. `verify` asserts the same over its own table."""
    verify = load_tool("verify")
    formal = {name for name, _script, is_formal in verify.LANES if is_formal}
    assert set().union(*verify.PHASES.values()) == formal
    assert not (verify.PHASES["host"] & verify.PHASES["extraction"])
    # And `_compose` must agree about which environment each one belongs to: two answers
    # would let the composer demand an artifact identity of a lane no container ran.
    assert verify.PHASES["host"] == HOST_LANES
    assert verify.PHASES["extraction"] == EXTRACTION_LANES
    assert HOST_LANES | EXTRACTION_LANES == set(FORMAL_LANES)


def test_the_aggregate_executes_no_formal_lane():
    """The composer must not be able to synthesize the evidence it composes — and the
    hygiene lanes it does execute must be exactly the ones no phase runs."""
    verify = load_tool("verify")
    formal = {name for name, _s, is_formal in verify.LANES if is_formal}
    hygiene = {name for name, _s, is_formal in verify.LANES if not is_formal}
    assert hygiene & formal == set()
    assert hygiene & set().union(*verify.PHASES.values()) == set()
    assert hygiene, "a control over an empty hygiene set proves nothing"


def test_phase_and_aggregate_are_refused_together():
    """They are different authorities: a process that executed lanes and composed the
    result would be the instrument certifying itself."""
    import subprocess

    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "verify"),
         "--phase", "host", "--aggregate"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode != 0
    assert "Run them separately" in completed.stderr, completed.stderr


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
