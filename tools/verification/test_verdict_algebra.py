# SPDX-License-Identifier: Apache-2.0
"""The aggregate verdict algebra — ADR-MCPRE-059.

The single property under test: **absence can never equal success.** Every other case here
exists to keep that one from being satisfied vacuously.

Run with `python3 -m pytest tools/verification/test_verdict_algebra.py`, or directly.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _load_tool import load_tool  # noqa: E402
from _manifest import LANE_VERDICTS, aggregate_verdict  # noqa: E402

verify_cli = load_tool("verify", "verify_cli")


def test_a_required_formal_lane_that_passed_is_a_pass():
    assert aggregate_verdict(["PASS"], ["PASS"]) == "PASS"
    assert aggregate_verdict(["PASS", "PASS"], []) == "PASS"


def test_a_lane_that_could_not_run_is_never_a_pass():
    """UNAVAILABLE is the whole reason the two-lane split needs an algebra.

    A developer on the Mac cannot run Lean. If that read as success, the split would
    silently convert "I could not check" into "it checks out" — for V2 units, on the
    machine least able to verify them.
    """
    assert aggregate_verdict(["PASS", "UNAVAILABLE"], []) == "INCOMPLETE"


def test_a_deliberately_skipped_required_lane_is_never_a_pass():
    assert aggregate_verdict(["PASS", "SKIPPED"], []) == "INCOMPLETE"


def test_not_required_does_not_hold_the_aggregate_back():
    """A manifest with no V2 unit is not owed Lean evidence.

    This is the case that makes NOT_REQUIRED worth having: without it, a V1-only scope
    could never report PASS, and a verdict nobody can ever reach gets routed around.
    """
    assert aggregate_verdict(["PASS", "NOT_REQUIRED"], []) == "PASS"


def test_not_required_is_not_itself_evidence():
    """The complement, and the more dangerous direction.

    All-NOT_REQUIRED means no proof was asked for and none was produced. Reporting PASS
    there would let an empty manifest — or one whose units were quietly downgraded to V0 —
    read as a verified repository.
    """
    assert aggregate_verdict(["NOT_REQUIRED", "NOT_REQUIRED"], ["PASS"]) == "INCOMPLETE"
    assert aggregate_verdict([], ["PASS"]) == "INCOMPLETE"


def test_hygiene_lanes_cannot_carry_the_aggregate():
    """The assumption/TCB gate is a precondition, not evidence.

    It passing means no unregistered escape hatch was found. That says nothing whatsoever
    about whether any code satisfies any property.
    """
    assert aggregate_verdict(["NOT_REQUIRED"], ["PASS"]) == "INCOMPLETE"


def test_a_failing_hygiene_lane_outranks_passing_evidence():
    """Evidence gathered beside a broken assumption gate is not evidence we may rely on.

    An unregistered `assume` can be exactly what made the proof succeed.
    """
    assert aggregate_verdict(["PASS"], ["FAIL"]) == "FAIL"


def test_any_failure_is_a_failure():
    assert aggregate_verdict(["PASS", "FAIL"], []) == "FAIL"
    assert aggregate_verdict(["FAIL", "UNAVAILABLE"], []) == "FAIL"


def test_an_unrecognized_verdict_is_dirty():
    """Unknown is dirty (§2). A lane emitting a verdict this tool does not know about is a
    lane whose outcome cannot be established, which is not a pass."""
    assert aggregate_verdict(["PASS", "MOSTLY_FINE"], []) == "INCOMPLETE"
    assert aggregate_verdict(["PASS"], ["probably ok"]) == "INCOMPLETE"


def test_the_verdict_set_is_closed():
    assert LANE_VERDICTS == {
        "NOT_REQUIRED",
        "PASS",
        "FAIL",
        "UNAVAILABLE",
        "SKIPPED",
    }


# --- which verdict a lane's own exit status may overturn ---------------------
#
# R9-C114. The algebra above has five verdicts; two of them were UNREACHABLE from any lane
# that reports them by exiting non-zero, because `verify` overwrote the declared verdict with
# FAIL before reading the `VERDICT:` line at all. The Verus lane is such a lane, so
# UNAVAILABLE — "the prover is not installed" — arrived as FAIL, which is "the evidence says
# the tree is broken". They call for opposite actions.


def test_a_lane_that_did_not_complete_may_still_say_which_non_measuring_case_it_is_in():
    """Neither UNAVAILABLE nor SKIPPED claims a measurement, and both are already
    non-passing in the algebra above — so believing the lane about which of them it is in
    cannot turn absence into success."""
    assert verify_cli._lane_verdict(1, "UNAVAILABLE", "")[0] == "UNAVAILABLE"
    assert verify_cli._lane_verdict(1, "SKIPPED", "")[0] == "SKIPPED"
    assert aggregate_verdict(["UNAVAILABLE"], []) != "PASS"
    assert aggregate_verdict(["SKIPPED"], []) != "PASS"


def test_a_lane_that_crashed_may_never_claim_success():
    """The other direction, and the one that must not be given away with it. A non-zero exit
    beside a declared PASS is a contradiction, and it is reported rather than resolved in the
    lane's favour."""
    verdict, output = verify_cli._lane_verdict(1, "PASS", "some output")
    assert verdict == "FAIL"
    assert "exited 1" in output
    assert verify_cli._lane_verdict(1, "INCOMPLETE", "")[0] == "FAIL"


def test_a_lane_that_says_nothing_is_a_failure_whatever_its_exit_status():
    """Unchanged, and it is what keeps the two cases above from being a hole: a lane that
    does not say what it did has unknown provenance, and unknown is dirty."""
    assert verify_cli._lane_verdict(0, None, "")[0] == "FAIL"
    assert verify_cli._lane_verdict(1, None, "")[0] == "FAIL"


def test_a_clean_exit_carries_the_lanes_own_verdict():
    """The positive control. Without it the three above are satisfied by a rule that answers
    FAIL to everything."""
    for declared in ("PASS", "INCOMPLETE", "UNAVAILABLE", "SKIPPED", "NOT_REQUIRED"):
        assert verify_cli._lane_verdict(0, declared, "")[0] == declared


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
