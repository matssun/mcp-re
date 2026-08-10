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

from _manifest import LANE_VERDICTS, aggregate_verdict  # noqa: E402


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
