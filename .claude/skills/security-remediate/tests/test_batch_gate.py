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


def _workflow(body: str) -> str:
    root = tempfile.mkdtemp()
    path = os.path.join(root, "ci.yml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


def test_ci_gates_reads_bare_flag_invocations_and_leaves_valued_ones_to_the_workflow():
    wf = _workflow(
        "steps:\n"
        "  - run: python3 scripts/a_gate.py\n"
        "  - run: python3 scripts/a_gate.py --selftest\n"
        "  - run: python3 scripts/b_gate.py --base \"$BASE\"\n"
        "  - run: python3 scripts/clippy_ratchet_gate.py --activation-probe\n"
        "  - run: |\n"
        "      python3 tools/verification/check-views\n"
        "      python3 scripts/a_gate.py\n"
        "  - run: tools/verification/rust-targets --check\n"
        "  - run: |\n"
        "      ./tools/verification/check-views --selftest\n"
        "  - run: scripts/run_gate.sh --selftest\n"
    )
    assert batch_gate.ci_gates(wf) == [
        ("scripts/a_gate.py",),
        ("scripts/a_gate.py", "--selftest"),
        ("tools/verification/check-views",),
        ("tools/verification/rust-targets", "--check"),
        ("tools/verification/check-views", "--selftest"),
    ], batch_gate.ci_gates(wf)


def test_control_the_build_graph_table_check_is_on_the_merge_path_the_batch_runs():
    assert ("tools/verification/rust-targets", "--check") in batch_gate.ci_gates(), \
        batch_gate.ci_gates()


def test_control_a_red_merge_path_gate_is_named():
    root = tempfile.mkdtemp()
    for name, rc in (("green.py", 0), ("red.py", 1)):
        with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
            fh.write("print('verdict')\nraise SystemExit(%d)\n" % rc)
    wf = _workflow("  - run: python3 scripts/green.py\n  - run: python3 scripts/red.py\n")
    cwd = os.getcwd()
    os.chdir(root)
    try:
        os.makedirs("scripts")
        os.replace("green.py", "scripts/green.py")
        os.replace("red.py", "scripts/red.py")
        result = batch_gate.merge_path_gates(tempfile.mkdtemp(), wf, already=set())
    finally:
        os.chdir(cwd)
    assert result["verdict"] == "new-failures" and result["gates"] == 2, result
    assert [f["gate"] for f in result["failed"]] == ["scripts/red.py"], result


def test_control_a_workflow_with_no_gate_is_infra_never_ok():
    assert batch_gate.merge_path_gates(tempfile.mkdtemp(), _workflow("steps: []\n"),
                                       already=set())["verdict"] == "infra"
    assert batch_gate.merge_path_gates(tempfile.mkdtemp(), "/nonexistent/ci.yml",
                                       already=set())["verdict"] == "infra"


def main() -> int:
    tests = [test_every_suite_runs_and_green_suites_are_ok,
             test_control_a_red_suite_is_a_new_failure_named_by_suite,
             test_control_no_suite_is_infra_never_ok,
             test_a_suite_structural_already_runs_is_not_run_twice,
             test_ci_gates_reads_bare_flag_invocations_and_leaves_valued_ones_to_the_workflow,
             test_control_a_red_merge_path_gate_is_named,
             test_control_a_workflow_with_no_gate_is_infra_never_ok,
             test_control_the_build_graph_table_check_is_on_the_merge_path_the_batch_runs]
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
