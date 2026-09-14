# SPDX-License-Identifier: Apache-2.0
"""The aggregate verdict algebra — ADR-MCPRE-059.

The single property under test: **absence can never equal success.** Every other case here
exists to keep that one from being satisfied vacuously.

Run with `python3 -m pytest tools/verification/test_verdict_algebra.py`, or directly.
"""

from __future__ import annotations

import ast
import pathlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _load_tool import load_tool  # noqa: E402
from _manifest import LANE_VERDICTS, aggregate_verdict  # noqa: E402

from _lean_query import external_termination  # noqa: E402

verify_cli = load_tool("verify", "verify_cli")
verify_lean_cli = load_tool("verify-lean", "verify_lean_cli")


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


# ---------------------------------------------------------------------------
# An externally killed prover is absence, not refutation — measured 2026-09-14.
#
# `verify-lean --activation-probe` printed `VERDICT: FAIL` because the colima VM held
# 1.91 GiB and the OOM killer removed Lean at `[1699/1700]`. The theorems were untouched and
# re-established unchanged after the VM was resized, so the FAIL was a statement about the
# host wearing the words of a statement about the proof. These are the controls for that.
# ---------------------------------------------------------------------------


def test_a_killed_child_reported_only_in_lakes_TEXT_is_still_a_termination():
    """The shape that actually happened, and the one a status-only reading cannot see.

    `lake` does not propagate its child's signal: it printed `error: Lean exited with code
    137` and then exited **1** of its own accord. A classifier that looked only at the
    return code would call that an ordinary build failure, which is exactly what happened.
    """
    reason = external_termination(1, "error: Lean exited with code 137\nerror: build failed")
    assert reason is not None
    assert "137" in reason and "SIGKILL" in reason


def test_a_signal_on_our_own_process_is_a_termination_in_both_conventions():
    """POSIX gives `-N` to the parent; a shell in between gives `128 + N`. Both are the
    same event and neither may read as a refuted proof."""
    assert external_termination(-9, "") is not None
    assert external_termination(137, "") is not None
    assert external_termination(-15, "") is not None
    assert external_termination(143, "") is not None


def test_an_ordinary_build_failure_is_STILL_a_failure():
    """The positive control, and the one that stops this whole change from being a way to
    launder red lanes into `UNAVAILABLE`. A build that failed on its own terms says
    something about the theorems, and it must keep saying it."""
    assert external_termination(1, "error: build failed") is None
    assert external_termination(1, "") is None
    assert external_termination(2, "unknown identifier 'civil_from_days'") is None


def test_an_abort_is_the_prover_deciding_and_is_NOT_external():
    """`SIGABRT` (134) is the prover concluding it cannot continue. That is a fact about the
    prover on this input, so it stays in the FAIL direction; only signals imposed from
    outside — the OOM killer, a cancellation, a timeout — move a lane to UNAVAILABLE."""
    assert external_termination(1, "error: Lean exited with code 134") is None
    assert external_termination(134, "") is None


def test_the_lane_has_a_verdict_for_it_and_that_verdict_is_not_a_pass():
    """The two halves that make the classification mean anything.

    `verify-lean` must emit the word the aggregate understands, and `verify` must let a
    lane keep it on a non-zero exit — otherwise the classifier answers correctly into a
    channel that overwrites it, which is the R9-C114 defect one lane over.
    """
    assert verify_lean_cli.unavailable("stopped from outside") == 1
    assert verify_cli._lane_verdict(1, "UNAVAILABLE", "")[0] == "UNAVAILABLE"
    assert aggregate_verdict(["UNAVAILABLE"], []) != "PASS"
    assert "UNAVAILABLE" in LANE_VERDICTS


def test_a_terminated_lane_writes_no_evidence_record():
    """The durable half. A `fail` row is fingerprinted and outlives the run: it asserts that
    these units WERE measured and did not stand. Writing one from a build the OOM killer
    ended would leave that assertion in the store after the host was repaired.

    Read from the syntax tree rather than from the text, so the control is about the branch
    that actually executes and not about where a substring happens to fall.
    """
    tree = ast.parse((pathlib.Path(__file__).parent / "verify-lean").read_text())
    branches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "killed"
    ]
    assert branches, "no `if killed:` branch found — the classifier is not wired in"
    for branch in branches:
        called = {
            n.func.id
            for n in ast.walk(branch)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        assert "record" not in called, (
            "the externally-terminated branch must return before any evidence record"
        )
        assert "unavailable" in called, (
            "the externally-terminated branch must return the UNAVAILABLE verdict"
        )
        assert "refuse" not in called


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
