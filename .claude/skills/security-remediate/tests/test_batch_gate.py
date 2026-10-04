"""Regression: the batch gate runs the verification self-test suites, and says when it cannot.

Two `tools/verification/test_*.py` suites were red while every per-file and batch gate
reported green, because neither gate ran them. `verification_suites` is the batch gate's
answer; these pin that it runs each suite, reports a failing one by name, refuses to read an
empty suite set as green, and does not run a suite STRUCTURAL already runs.

Run:  python3 .claude/skills/security-remediate/tests/test_batch_gate.py
"""
from __future__ import annotations

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)

import batch_gate  # noqa: E402


def _suites(files: dict[str, str]) -> tuple[str, str]:
    root = tempfile.mkdtemp()
    work = tempfile.mkdtemp()
    for name, body in files.items():
        with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    return root, work


def test_every_suite_runs_and_green_suites_are_ok():
    root, work = _suites({"test_a.py": "raise SystemExit(0)\n",
                          "test_b.py": "raise SystemExit(0)\n",
                          "helper.py": "raise SystemExit(1)\n"})
    result = batch_gate.verification_suites(work, root)
    assert result["verdict"] == "ok", result
    assert result["suites"] == 2, "only test_*.py files are suites: %r" % result


def test_control_a_red_suite_is_a_new_failure_named_by_suite():
    root, work = _suites({"test_a.py": "raise SystemExit(0)\n",
                          "test_red.py": "print('FAIL pinned 62, measured 69')\nraise SystemExit(1)\n"})
    result = batch_gate.verification_suites(work, root)
    assert result["verdict"] == "new-failures", result
    assert [f["suite"] for f in result["failed"]] == ["test_red.py"], result
    assert any("measured 69" in line for line in result["failed"][0]["tail"]), result


def test_control_no_suite_is_infra_never_ok():
    root, work = _suites({"helper.py": "raise SystemExit(0)\n"})
    assert batch_gate.verification_suites(work, root)["verdict"] == "infra"
    assert batch_gate.verification_suites(work, os.path.join(root, "absent"))["verdict"] == "infra"


def test_a_suite_structural_already_runs_is_not_run_twice():
    assert "test_mutation_lane.py" in batch_gate._structural_suites()
    root, work = _suites({"test_mutation_lane.py": "raise SystemExit(1)\n",
                          "test_a.py": "raise SystemExit(0)\n"})
    result = batch_gate.verification_suites(work, root, already={"test_mutation_lane.py"})
    assert result["verdict"] == "ok" and result["suites"] == 1, result
    # Control: without the exclusion the same red suite is run and caught.
    assert batch_gate.verification_suites(work, root, already=set())["verdict"] == "new-failures"


def main() -> int:
    tests = [test_every_suite_runs_and_green_suites_are_ok,
             test_control_a_red_suite_is_a_new_failure_named_by_suite,
             test_control_no_suite_is_infra_never_ok,
             test_a_suite_structural_already_runs_is_not_run_twice]
    failed = 0
    for t in tests:
        print("%s ..." % t.__name__)
        try:
            t()
        except AssertionError as exc:
            failed += 1
            print("  FAIL: %s" % exc)
    print("\n%d/%d passed" % (len(tests) - failed, len(tests)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
