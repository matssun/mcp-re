"""Regression: the bazel gate judges a SET DELTA, never an exit code.

Reproduces the tick-1 false red directly. `scope.py` and
`settings_info.py` were both judged `gate-failed` because
`bazel test //<tree>/...:all` exited 1 — while every real test target in those
trees executed and passed, and the same exit-1 reproduces on an unmodified tree.

The fixtures below are shaped like that run: real test targets PASSED, image and
`*_linux` variants failing analysis, overall exit 1.

Every verdict class has a control, because a gate that can only say `ok` is not a
gate. `new-failures` and `infra` are each provoked explicitly.

Run:  python3 .claude/skills/security-remediate/tests/test_bazel_gate.py
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)

from bazel_gate import compare, parse_output  # noqa: E402

# Shaped after the real tick-1 output: tests pass, image/linux variants do not.
BASELINE_OUTPUT = """
INFO: Analyzed 42 targets.
ERROR: Analysis of target '//components/demo/widgets:image_linux_amd64' failed
//components/demo/widgets:test_scope                          PASSED in 1.2s
//components/demo/widgets:test_widget_container                      PASSED in 0.9s
//components/demo/di:test_scope                      PASSED in 2.1s
//components/demo/di:test_container                  PASSED in 1.7s
//components/demo/widgets:image_linux_amd64                    NO STATUS
//components/demo/widgets:distroless_image                     NO STATUS
Executed 4 out of 4 tests: 4 tests pass.
"""

# Same tree after an in-file docstring change: identical target outcomes.
UNCHANGED_OUTPUT = BASELINE_OUTPUT

# A change that genuinely broke a test.
REGRESSED_OUTPUT = BASELINE_OUTPUT.replace(
    "//components/demo/di:test_scope                      PASSED in 2.1s",
    "//components/demo/di:test_scope                      FAILED in 2.1s")

# Bazel never got far enough to judge anything (crate-universe splice timeout).
INFRA_OUTPUT = """
ERROR: error evaluating module extension @@rules_rust+//crate_universe:extension.bzl%crate
ERROR: Timed out
Elapsed time: 0.1s
"""


REAL_OUTPUT_FIXTURE = os.path.join(HERE, "fixture_bazel_real_output.txt")


def test_golden_real_bazel_output_is_parsed_correctly() -> None:
    """GOLDEN: captured from a live run on this host, 2026-09-22.

    Provenance, stated precisely because a golden fixture's whole value is that
    you know where its bytes came from: this is real `bazel test` output, with
    trailing whitespace on two lines and one trailing blank line removed by the
    repo's pre-commit whitespace hooks, and the absolute repo prefix rewritten to
    `/REPO` for the no-absolute-paths gate. None of the three carries information
    this parser reads — the toolchain line is parsed for its `//label`, not its
    filesystem path — and the assertions below were re-run after each change.

    Every fixture above this line was INVENTED, and an invented fixture nearly
    shipped a blind gate: real output puts `(cached)` between the label and the
    status, and never gives the broken image targets a status line at all. The
    first parser scored this exact tree as `0 passing, 0 failing` while four
    tests passed and seven targets were broken. A test suite made only of
    self-authored fixtures confirms the author's model of the format, not the
    format. This frozen sample is the control against that.
    """
    with open(REAL_OUTPUT_FIXTURE, encoding="utf-8") as fh:
        real = fh.read()
    d = parse_output(real, exit_code=1, tree="//components/demo/widgets/...")

    assert len(d["passing"]) == 4, "cached PASSED lines not parsed: %s" % d["passing"]
    assert "//components/demo/widgets:interfaces_test" in d["passing"]
    assert len(d["failing"]) == 7, d["failing"]
    assert all(":test_image" in t or ":test_layer" in t or ":test_linux" in t
               or "index_json" in t or "load_test_image" in t for t in d["failing"]), \
        "a real test target leaked into the broken set: %s" % d["failing"]
    # A label broken in one configuration and passing in another is recorded,
    # not silently counted as both.
    assert d["analysis_failed_but_passing_in_default_config"] == [
        "//components/demo/widgets:test"], d
    assert not (set(d["passing"]) & set(d["failing"])), "a target is in both sets"
    # executed==0 on a warm cache is "all reused", not "nothing ran".
    assert d["executed"] == 0 and d["total"] == 4, (d["executed"], d["total"])
    assert not d["infra_suspected"], "a warm cache must not read as an infra failure"
    assert d["tests_all_passed_with_build_errors"] is True
    print("  golden: real output -> 4 passing, 7 broken, 1 dual-config, not infra  OK")


def test_golden_real_output_unchanged_is_ok() -> None:
    """The tick-1 verdict, computed from real bytes rather than invented ones."""
    with open(REAL_OUTPUT_FIXTURE, encoding="utf-8") as fh:
        real = fh.read()
    d = parse_output(real, exit_code=1)
    out = compare(d, parse_output(real, exit_code=1))
    assert out["verdict"] == "ok", out
    assert out["post_exit"] == 1, "the run really did exit nonzero"
    print("  golden: unchanged tree, exit 1 both sides, verdict=ok  OK")


def test_baseline_records_the_failing_set_not_the_exit_code() -> None:
    b = parse_output(BASELINE_OUTPUT, exit_code=1)
    assert b["exit_code"] == 1
    assert len(b["passing"]) == 4, b["passing"]
    assert b["failing"] == [
        "//components/demo/widgets:distroless_image",
        "//components/demo/widgets:image_linux_amd64"], b["failing"]
    assert b["executed"] == 4 and b["total"] == 4
    assert not b["infra_suspected"], "target results existed; this is not an infra failure"
    print("  baseline: exit 1 but 4/4 tests passed; 2 known-broken targets recorded  OK")


def test_the_tick1_false_red_is_now_ok() -> None:
    """THE REGRESSION. Exit 1 before and after, no new failure -> verdict ok."""
    b = parse_output(BASELINE_OUTPUT, exit_code=1)
    p = parse_output(UNCHANGED_OUTPUT, exit_code=1)
    out = compare(b, p)
    assert out["verdict"] == "ok", out
    assert out["new_failures"] == [], out
    assert out["baseline_exit"] == 1 and out["post_exit"] == 1, out
    assert len(out["baseline_failures_still_failing"]) == 2, out
    print("  tick-1 case: exit 1 -> exit 1, no new failures, verdict=ok  OK")


def test_control_a_real_new_failure_is_caught() -> None:
    """CONTROL: without this, `ok` could mean the gate detects nothing at all."""
    b = parse_output(BASELINE_OUTPUT, exit_code=1)
    p = parse_output(REGRESSED_OUTPUT, exit_code=1)
    out = compare(b, p)
    assert out["verdict"] == "new-failures", out
    assert out["new_failures"] == [
        "//components/demo/di:test_scope"], out
    print("  control: a genuinely broken test IS caught, and named  OK")


def test_control_identical_exit_codes_do_not_imply_pass() -> None:
    """The verdict must not degenerate to `exit before == exit after`.

    Both runs exit 1 in the control above, yet one is ok and one is not. If the
    gate compared exit codes it would call both the same — which is precisely the
    reduction the ruling forbade.
    """
    b = parse_output(BASELINE_OUTPUT, exit_code=1)
    ok = compare(b, parse_output(UNCHANGED_OUTPUT, exit_code=1))
    bad = compare(b, parse_output(REGRESSED_OUTPUT, exit_code=1))
    assert ok["baseline_exit"] == bad["baseline_exit"] == 1
    assert ok["post_exit"] == bad["post_exit"] == 1
    assert ok["verdict"] != bad["verdict"], (
        "the gate gave the same verdict to a clean change and a broken one — it is "
        "comparing exit codes, not target identities")
    print("  discrimination: same exit codes, different verdicts (%s vs %s)  OK"
          % (ok["verdict"], bad["verdict"]))


def test_control_infra_failure_is_classified_separately() -> None:
    """CONTROL: Bazel failing before any target result is NOT a code verdict."""
    b = parse_output(BASELINE_OUTPUT, exit_code=1)
    p = parse_output(INFRA_OUTPUT, exit_code=1)
    assert p["infra_suspected"], p
    out = compare(b, p)
    assert out["verdict"] == "infra", out
    assert out["infra_errors"], out
    print("  control: analysis abort classified `infra`, not attributed to the change  OK")


def test_a_vanishing_baseline_target_is_reported() -> None:
    """A target that stops being selected narrows the gate silently."""
    b = parse_output(BASELINE_OUTPUT, exit_code=1)
    narrowed = "\n".join(
        line for line in BASELINE_OUTPUT.splitlines()
        if "test_widget_container" not in line)
    p = parse_output(narrowed, exit_code=1)
    out = compare(b, p)
    assert out["baseline_passing_now_absent"] == [
        "//components/demo/widgets:test_widget_container"], out
    print("  narrowing: a target that stopped being selected is reported  OK")


def test_unowned_baseline_debt_is_surfaced() -> None:
    """The known-broken set is tracked debt; with no owning issue, say so."""
    b = parse_output(BASELINE_OUTPUT, exit_code=1)
    out = compare(b, parse_output(UNCHANGED_OUTPUT, exit_code=1))
    assert out["unowned_baseline_failures"], (
        "broken baseline targets with no owning issue must be surfaced, not blessed")
    b["owner"] = "#9999"
    owned = compare(b, parse_output(UNCHANGED_OUTPUT, exit_code=1))
    assert owned["unowned_baseline_failures"] == [], owned
    assert owned["baseline_debt_owner"] == "#9999"
    print("  debt: unowned broken targets surfaced; owned ones attributed  OK")


def main() -> int:
    tests = [test_golden_real_bazel_output_is_parsed_correctly,
             test_golden_real_output_unchanged_is_ok,
             test_baseline_records_the_failing_set_not_the_exit_code,
             test_the_tick1_false_red_is_now_ok,
             test_control_a_real_new_failure_is_caught,
             test_control_identical_exit_codes_do_not_imply_pass,
             test_control_infra_failure_is_classified_separately,
             test_a_vanishing_baseline_target_is_reported,
             test_unowned_baseline_debt_is_surfaced]
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
