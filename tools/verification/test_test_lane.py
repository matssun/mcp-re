# SPDX-License-Identifier: Apache-2.0
"""The test lane's own false-green catalogue — ADR-MCPRE-059 §2, §9.

The single property under test: **a battery reports a pass only when every test it declared
actually ran and actually passed, in the target it declared.**

The lane is thin, and that is what makes it dangerous. It shells out to `cargo test` and
reads libtest's output, and every classic false green in this repository lives in exactly
that gap: a filter that selects nothing exits 0, an `#[ignore]`d test prints a line that is
not `ok`, a feature-gated target compiles to zero tests and reports PASSED, and a run piped
through anything reports the pipe's status. Each case below is one of those.

Run with `python3 -m pytest tools/verification/test_test_lane.py`, or directly.
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The lane is an extensionless script, so it is loaded by path rather than imported.
_LOADER = SourceFileLoader(
    "verify_tests_lane", str(Path(__file__).resolve().parent / "verify-tests")
)
_SPEC = importlib.util.spec_from_loader("verify_tests_lane", _LOADER)
assert _SPEC is not None
lane = importlib.util.module_from_spec(_SPEC)
_LOADER.exec_module(lane)


class FakeProc:
    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode


def run_with(monkey_output: str, returncode: int = 0):
    """Drive `run_selection` against a canned libtest transcript."""
    import subprocess

    original = subprocess.run
    subprocess.run = lambda *a, **k: FakeProc(monkey_output, returncode)  # type: ignore[assignment]
    try:
        return lane.run_selection("crate", "lib", ["a::tests::one", "a::tests::two"])
    finally:
        subprocess.run = original  # type: ignore[assignment]


PASSING = (
    "running 2 tests\n"
    "test a::tests::one ... ok\n"
    "test a::tests::two ... ok\n"
    "\ntest result: ok. 2 passed; 0 failed; 0 ignored\n"
)


def test_a_battery_whose_every_member_passed_is_a_pass():
    ok, detail = run_with(PASSING)
    assert ok, detail
    assert "2 passed" in detail


def test_output_interleaved_into_a_result_line_does_not_hide_the_status():
    """A measured false RED, 2026-08-31.

    libtest writes `test <name> ... ` and the status from the harness thread, but a test
    that spawns a child process — or any code writing to the real fd 2 rather than to the
    capture buffer — lands its bytes BETWEEN them. The lane read the status as `mcp` and
    reported a deterministic two-assert test as not having passed.
    """
    ok, detail = run_with(
        "test a::tests::one ... mcp-re-proxy: WARNING: --key-source env is a dev build ok\n"
        "test a::tests::two ... ok\n"
        "\ntest result: ok. 2 passed; 0 failed; 0 ignored\n"
    )
    assert ok, detail


def test_interleaved_output_cannot_turn_a_failure_into_a_pass():
    """The direction that matters. libtest writes the status LAST, so a stray `ok` inside
    interleaved text cannot outrank the real result."""
    ok, detail = run_with(
        "test a::tests::one ... mcp-re-proxy: everything looks ok so far FAILED\n"
        "test a::tests::two ... ok\n"
        "\ntest result: FAILED. 1 passed; 1 failed; 0 ignored\n"
    )
    assert not ok
    assert "a::tests::one (FAILED)" in detail


def test_an_interleave_carrying_a_newline_reads_as_never_ran():
    """The remaining case, and it fails in the safe direction: the line does not match at
    all, so the member reports as never having run rather than as quietly green."""
    ok, detail = run_with(
        "test a::tests::one ... mcp-re-proxy: a line of its own\nok\n"
        "test a::tests::two ... ok\n"
        "\ntest result: ok. 2 passed; 0 failed; 0 ignored\n"
    )
    assert not ok
    assert "a::tests::one (never ran)" in detail


def test_a_selection_that_matched_nothing_is_not_a_pass():
    """The repository's standing hazard: `--exact` on a renamed test selects nothing,
    libtest prints `running 0 tests` and exits 0, and the lane must not read that as
    evidence."""
    ok, detail = run_with("running 0 tests\n\ntest result: ok. 0 passed; 0 failed\n")
    assert not ok
    assert "never ran" in detail
    assert "2 of 2" in detail


def test_a_partially_selected_battery_is_not_a_pass():
    """Half the battery running is coverage silently halving behind a green unit."""
    ok, detail = run_with(
        "running 1 test\ntest a::tests::one ... ok\n\ntest result: ok. 1 passed\n"
    )
    assert not ok
    assert "a::tests::two (never ran)" in detail


def test_an_ignored_test_is_not_a_passing_test():
    """`#[ignore]` prints a result line, so a lane counting LINES rather than statuses
    would accept it. A test that did not execute establishes nothing."""
    ok, detail = run_with(
        "running 2 tests\n"
        "test a::tests::one ... ok\n"
        "test a::tests::two ... ignored\n"
        "\ntest result: ok. 1 passed; 0 failed; 1 ignored\n"
    )
    assert not ok
    assert "a::tests::two (ignored)" in detail


def test_a_failing_member_fails_the_battery():
    ok, detail = run_with(
        "running 2 tests\n"
        "test a::tests::one ... ok\n"
        "test a::tests::two ... FAILED\n"
        "\ntest result: FAILED. 1 passed; 1 failed\n",
        returncode=101,
    )
    assert not ok
    assert "a::tests::two (FAILED)" in detail


def test_a_nonzero_exit_is_not_a_pass_even_when_every_line_said_ok():
    """A target that printed every expected `ok` and then died — a panic in a later test,
    a linker failure in a second binary — did not complete, so the battery's result is
    unknown, and unknown is dirty."""
    ok, detail = run_with(PASSING, returncode=101)
    assert not ok
    assert "exited 101" in detail


def test_a_symbol_without_a_target_is_malformed_not_defaulted():
    """Defaulting the target would let a test that moved between the lib and an
    integration target keep reporting under the one it left."""
    grouped, malformed = lane.group_by_target(["a::tests::one", "lib#a::tests::two"])
    assert malformed == ["a::tests::one"]
    assert grouped == {"lib": ["a::tests::two"]}


def test_an_unknown_target_form_is_malformed():
    grouped, malformed = lane.group_by_target(["bench#a", "tests/#b", "examples/x#c"])
    assert sorted(malformed) == ["bench#a", "examples/x#c", "tests/#b"]
    assert grouped == {}


def test_a_doctest_item_matches_its_own_doctests_and_nothing_else():
    observed = {
        "src/verified_response.rs - verified_response::VerifiedMcpResponse (line 82) - compile fail": "ok",
        "src/verified_response.rs - verified_response::VerifiedDelegatedMcpResponse (line 114) - compile fail": "ok",
        "src/verified_request.rs - verified_request::VerifiedMcpRequest (line 114) - compile fail": "ok",
    }
    assert lane.doc_matches(observed, "verified_response::VerifiedMcpResponse") == [
        "src/verified_response.rs - verified_response::VerifiedMcpResponse (line 82) - compile fail"
    ]
    # The line number is deliberately not part of the symbol: an edit above the control
    # must not break the declaration, and a rename or deletion must.
    assert lane.doc_matches(observed, "verified_response::Gone") == []


def test_targets_are_selected_by_their_own_cargo_flag():
    assert lane.target_argv("doc") == ["--doc"]
    assert lane.target_argv("lib") == ["--lib"]
    assert lane.target_argv("tests/dispatch_test") == ["--test", "dispatch_test"]
    assert lane.target_argv("tests/a/b") is None
    assert lane.target_argv("") is None


def test_a_battery_spanning_two_targets_is_two_selections():
    """One filter across two targets would let a name that exists in only one of them
    look satisfied by the other."""
    grouped, malformed = lane.group_by_target(
        ["lib#policy::tests::window", "tests/proof_path_test#stale_window_fails_closed"]
    )
    assert not malformed
    assert set(grouped) == {"lib", "tests/proof_path_test"}


def test_a_multi_package_unit_without_test_package_has_no_derivable_crate():
    """The lane must not GUESS. Before `test_package` existed a unit whose source closure
    reached a second crate simply refused to run, which is the safe half; the danger is a
    lane that picks one and reports a pass for a battery it never located."""
    unit = {
        "paths": [
            "mcp-re-http-profile/src/verify.rs",
            "mcp-re-core/src/crypto.rs",
        ]
    }
    assert lane.unit_crate(unit) is None
    unit["test_package"] = "mcp-re-http-profile"
    assert lane.unit_crate(unit) == "mcp-re-http-profile"


def test_test_package_naming_a_crate_outside_the_closure_selects_nothing():
    """A package the unit does not measure would run a battery outside the fingerprinted
    source, so the lane refuses rather than running it. The manifest loader rejects this
    shape first; the lane does not rely on that."""
    unit = {
        "paths": ["mcp-re-http-profile/src/verify.rs", "mcp-re-core/src/crypto.rs"],
        "test_package": "mcp-re-proxy",
    }
    assert lane.unit_crate(unit) is None


def test_test_package_is_refused_where_the_lane_can_derive_it():
    """A restatement of a derived fact is a second place for it to be wrong: the loader
    refuses `test_package` on a single-package unit rather than ignoring it."""
    from _manifest import ManifestError, _validate_test_package

    single = {
        "paths": ["mcp-re-http-profile/src/verify.rs"],
        "test_package": "mcp-re-http-profile",
        "tested_symbols": ["lib#a::b"],
    }
    try:
        _validate_test_package("unit[0]", single)
    except ManifestError:
        pass
    else:
        raise AssertionError("a single-package unit must not carry `test_package`")


def test_a_multi_package_battery_must_name_its_package():
    """The loader fails the manifest rather than leaving the lane to fail later: an
    unrunnable battery is a manifest defect, not a test result."""
    from _manifest import ManifestError, _validate_test_package

    spanning = {
        "paths": ["mcp-re-http-profile/src/verify.rs", "mcp-re-core/src/crypto.rs"],
        "tested_symbols": ["lib#a::b"],
    }
    try:
        _validate_test_package("unit[0]", spanning)
    except ManifestError:
        pass
    else:
        raise AssertionError("a multi-package battery must name `test_package`")

    spanning["test_package"] = "mcp-re-proxy"
    try:
        _validate_test_package("unit[0]", spanning)
    except ManifestError:
        pass
    else:
        raise AssertionError("`test_package` outside the closure must be refused")

    spanning["test_package"] = "mcp-re-core"
    _validate_test_package("unit[0]", spanning)


def test_only_units_claiming_test_evidence_are_in_scope():
    assert lane.claims_test_evidence({"evidence": ["test://a/b/c"]})
    assert lane.claims_test_evidence({"evidence": ["verus://x", "test://a/b/c"]})
    assert not lane.claims_test_evidence({"evidence": ["verus://x"]})
    assert not lane.claims_test_evidence({})


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
