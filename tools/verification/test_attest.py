# SPDX-License-Identifier: Apache-2.0
"""Issuance semantics — what the attestation issuer must REFUSE to write.

`test_invalidation.py` proves the graph will not launder a broken prerequisite once
attestations exist. These tests prove the ISSUER will not launder one either, which is the
same property one step earlier and the step where it is easier to lose: the graph reasons
over records, so a wrong record poisons it before any of its rules run.

The single claim:

    An attestation is only ever written for evidence measured at the fingerprint the
    attestation is being written against.

The two most dangerous implementations, both pinned here as negative controls:

  * "a lane printed PASS earlier, so stamp the current source" — evidence taken at
    fingerprint X, source now at Y. Must REFUSE.
  * "this unit's own theorem passed, so it is fresh" — with a required prerequisite whose
    proof failed. Must REFUSE.

Run: python3 tools/verification/test_attest.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _evidence import (  # noqa: E402
    EvidenceRecord,
    decide_issuance,
    load_records,
    required_lanes,
    write_record,
)

PROOF_EDGE = {
    "kind": "PROOF_DEPENDENCY",
    "from": "lower",
    "to": "upper",
}


def units(*ids, evidence=("verus://x",)):
    return [{"id": uid, "class": "V1", "evidence": list(evidence)} for uid in ids]


def current(**fingerprints):
    return {uid: {"fingerprint": fp} for uid, fp in fingerprints.items()}


def verus(**results):
    """`unit=(result, fingerprint)` -> a records mapping."""
    return {
        "verus": {
            uid: EvidenceRecord(
                unit_id=uid, lane="verus", result=result, fingerprint=fingerprint
            )
            for uid, (result, fingerprint) in results.items()
        }
    }


def decide(*args, **kwargs):
    return decide_issuance(*args, **kwargs)


# --- the happy path, so the refusals below mean something ---------------------


def test_evidence_at_the_current_fingerprint_is_issued():
    got = decide(units("a"), [], current(a="sha256:X"), verus(a=("pass", "sha256:X")))
    assert got["a"][0] == "ISSUE_PASS"
    assert got["a"][1] == {"verus": "pass"}


def test_a_unit_claiming_no_prover_lane_needs_no_record():
    """A V0 unit's evidence is review and tests, not a proof. It must not be handed a
    `verus` verdict it never earned, and it must not be refused for lacking one."""
    got = decide(
        units("a", evidence=("review://owner",)), [], current(a="sha256:X"), {"verus": {}}
    )
    assert got["a"][0] == "ISSUE_PASS"
    assert got["a"][1] == {}


def test_required_lanes_are_read_off_the_declared_evidence():
    assert required_lanes({"evidence": ["verus://f", "test://t"]}) == {"verus"}
    assert required_lanes({"evidence": ["review://owner"]}) == set()


# --- negative control 1: stale evidence, current source -----------------------


def test_evidence_measured_at_another_fingerprint_is_refused():
    """The most dangerous possible implementation: proof result generated for source
    digest X, source modified to digest Y without re-running the proof, then stamped."""
    got = decide(units("a"), [], current(a="sha256:Y"), verus(a=("pass", "sha256:X")))
    assert got["a"][0] == "REFUSE"
    assert "do not match current fingerprint" in got["a"][2]


def test_a_claimed_lane_with_no_record_is_refused():
    got = decide(units("a"), [], current(a="sha256:X"), {"verus": {}})
    assert got["a"][0] == "REFUSE"
    assert "absence of measurement is not measurement" in got["a"][2]


def test_an_unparsable_record_is_absent_rather_than_repaired():
    with tempfile.TemporaryDirectory() as raw:
        store = Path(raw)
        (store / "verus").mkdir(parents=True)
        (store / "verus" / "a.json").write_text("{not json", encoding="utf-8")
        assert load_records(store, "verus") == {}


def test_a_record_round_trips_through_the_store():
    with tempfile.TemporaryDirectory() as raw:
        store = Path(raw)
        record = EvidenceRecord("a", "verus", "pass", "sha256:X", detail="7 verified")
        write_record(store, record)
        assert load_records(store, "verus")["a"] == record


# --- negative control 2: locally green over a broken prerequisite -------------


def test_a_failed_prerequisite_refuses_the_consumer_whose_own_proof_passed():
    """A proof FAIL/BLOCKED, B local Verus theorem PASS, attest B -> REFUSE."""
    got = decide(
        units("lower", "upper"),
        [PROOF_EDGE],
        current(lower="sha256:L", upper="sha256:U"),
        verus(lower=("fail", "sha256:L"), upper=("pass", "sha256:U")),
    )
    assert got["lower"][0] == "ISSUE_FAIL"
    assert got["upper"][0] == "REFUSE"
    assert "required prerequisite lower failed" in got["upper"][2]


def test_a_prerequisite_with_no_issuable_evidence_refuses_the_consumer():
    got = decide(
        units("lower", "upper"),
        [PROOF_EDGE],
        current(lower="sha256:L", upper="sha256:U"),
        verus(lower=("pass", "sha256:OLD"), upper=("pass", "sha256:U")),
    )
    assert got["upper"][0] == "REFUSE"
    assert "has no issuable evidence" in got["upper"][2]


def test_refusal_propagates_down_a_chain():
    """Refusal reaches a fixpoint, so a unit two edges above an unmeasured theorem is
    refused as well — otherwise the chain launders it one hop at a time."""
    got = decide(
        units("lower", "middle", "top"),
        [
            {"kind": "PROOF_DEPENDENCY", "from": "lower", "to": "middle"},
            {"kind": "PROOF_DEPENDENCY", "from": "middle", "to": "top"},
        ],
        current(lower="sha256:L", middle="sha256:M", top="sha256:T"),
        verus(
            lower=("fail", "sha256:L"),
            middle=("pass", "sha256:M"),
            top=("pass", "sha256:T"),
        ),
    )
    assert [got[u][0] for u in ("lower", "middle", "top")] == [
        "ISSUE_FAIL",
        "REFUSE",
        "REFUSE",
    ]


def test_the_prerequisite_direction_is_not_symmetric():
    """Break the LOWER theorem and the upper one is refused; break the UPPER one and the
    lower is untouched. A graph that is internally consistent while propagating backwards
    would refuse exactly the wrong unit."""
    got = decide(
        units("lower", "upper"),
        [PROOF_EDGE],
        current(lower="sha256:L", upper="sha256:U"),
        verus(lower=("pass", "sha256:L"), upper=("fail", "sha256:U")),
    )
    assert got["lower"][0] == "ISSUE_PASS"
    assert got["upper"][0] == "ISSUE_FAIL"


def test_a_review_context_edge_does_not_gate_issuance():
    got = decide(
        units("lower", "upper"),
        [{"kind": "REVIEW_CONTEXT", "from": "lower", "to": "upper"}],
        current(lower="sha256:L", upper="sha256:U"),
        verus(lower=("fail", "sha256:L"), upper=("pass", "sha256:U")),
    )
    assert got["upper"][0] == "ISSUE_PASS"


# --- issuance is a function of inputs, never of time --------------------------


def test_issuance_is_idempotent():
    """Same inputs, same evidence, same decision — three times. No `last attested at`
    semantics: a record that got fresher by being rewritten would be a mutable clean flag
    with extra steps."""
    args = (units("a"), [], current(a="sha256:X"), verus(a=("pass", "sha256:X")))
    assert decide(*args) == decide(*args) == decide(*args)


def test_a_failed_lane_is_recorded_rather_than_withheld():
    """Withholding the record would leave the previous PASSING attestation in place, and
    the unit would read fresh precisely because its proof broke."""
    got = decide(units("a"), [], current(a="sha256:X"), verus(a=("fail", "sha256:X")))
    assert got["a"][0] == "ISSUE_FAIL"
    assert got["a"][1] == {"verus": "fail"}


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
