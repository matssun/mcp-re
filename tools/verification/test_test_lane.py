# SPDX-License-Identifier: Apache-2.0
"""The test lane's own false-green catalogue — ADR-MCPRE-059 §2, §9.

The single property under test: **a battery reports a pass only when every test it declared
actually ran and actually passed, in the target it declared.**

The lane is thin, and that is what makes it dangerous. It shells out to `bazel test` and
reads libtest's output, and every classic false green in this repository lives in exactly
that gap: a filter that selects nothing exits 0, an `#[ignore]`d test prints a line that is
not `ok`, a feature-gated target compiles to zero tests and reports PASSED, and a run piped
through anything reports the pipe's status. Each case below is one of those.

Run with `python3 -m pytest tools/verification/test_test_lane.py`, or directly.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _ecosystems import PYTHON
from _ecosystems import RUST
from _ecosystems import TYPESCRIPT
from _ecosystems import parse_results
from _ecosystems import test_argv
from _ecosystems import valid_target
from _ecosystems import ReportUnreadable
from _manifest import ManifestError  # noqa: E402
from _manifest import _UNIT_KEYS  # noqa: E402
from _manifest import _validate_in_crate_selectors  # noqa: E402
from _manifest import _validate_rust_test_packages  # noqa: E402
from _load_tool import load_tool  # noqa: E402
import _rust_targets  # noqa: E402

# The lane is an extensionless script, so it is loaded by path rather than imported.
lane = load_tool("verify-tests", "verify_tests_lane")

#: Real Bazel test targets from the build graph: two flavors of the proxy library's unit
#: tests, one integration target, one doctest target.
UNIT = "//mcp-re-proxy:proxy_unit_test"
UNIT_EXT = "//mcp-re-proxy:proxy_ext_unit_test"
INTEGRATION = "//mcp-re-http-profile:proof_path_test"
DOCTEST = "//mcp-re-http-profile:mcp_re_http_profile_doc_test"


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
        return lane.run_selection(RUST, None, UNIT, ["a::tests::one", "a::tests::two"])
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
        "test a::tests::one ... mcp-re-proxy: WARNING: the system clock reads at/near the Unix epoch ok\n"
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


def test_a_failing_member_records_what_the_runner_said_about_it():
    """The evidence record must carry the cause, not only the verdict: a `FAILED` with no
    panic text is a red nobody can diagnose away from the machine that produced it."""
    ok, detail = run_with(
        "running 2 tests\n"
        "test a::tests::one ... ok\n"
        "test a::tests::two ... FAILED\n"
        "\nfailures:\n\n"
        "---- a::tests::two stdout ----\n"
        "thread 'a::tests::two' panicked at src/a.rs:9:5:\n"
        "the token signature must verify\n"
        "\nfailures:\n    a::tests::two\n"
        "\ntest result: FAILED. 1 passed; 1 failed\n",
        returncode=101,
    )
    assert not ok
    assert "panicked at src/a.rs:9:5" in detail
    assert "the token signature must verify" in detail
    assert "a::tests::one ... ok" not in detail, "only the failing test's block is kept"


def test_a_run_that_died_before_reporting_records_its_tail():
    ok, detail = run_with("Compiling x\nerror: linking with `cc` failed\n", returncode=1)
    assert not ok
    assert "linking with `cc` failed" in detail


def test_a_nonzero_exit_is_not_a_pass_even_when_every_line_said_ok():
    """A target that printed every expected `ok` and then died — a panic in a later test,
    a linker failure in a second binary — did not complete, so the battery's result is
    unknown, and unknown is dirty."""
    ok, detail = run_with(PASSING, returncode=101)
    assert not ok
    assert "exited 101" in detail


def test_a_symbol_without_a_target_is_malformed_not_defaulted():
    """Defaulting the target would let a test that moved between the crate's own tests and
    an integration target keep reporting under the one it left."""
    grouped, malformed = lane.group_by_target(RUST, ["a::tests::one", f"{UNIT}#a::tests::two"])
    assert malformed == ["a::tests::one"]
    assert grouped == {UNIT: ["a::tests::two"]}


def test_a_target_that_is_not_a_bazel_test_target_is_malformed():
    """A library, a binary, a label nothing defines, and the old Cargo target words all
    name no battery, so each is refused rather than dropped."""
    symbols = ["lib#a", "//mcp-re-proxy:mcp_re_proxy#b", "//mcp-re-proxy:no_such_target#c", "tests/x#d"]
    grouped, malformed = lane.group_by_target(RUST, symbols)
    assert sorted(malformed) == sorted(symbols)
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


def test_a_rust_target_is_run_as_its_bazel_label():
    """The label is the whole selection: Bazel resolves it from the workspace root, runs it
    fresh, streams libtest's own lines, and passes each declared name as `--exact`. A
    doctest target runs whole, because a doctest's reported name embeds its line."""
    argv = test_argv(RUST, None, UNIT, ["a::b"])
    assert argv[:3] == ["bazel", "test", UNIT]
    assert "--nocache_test_results" in argv, "a cached result describes an earlier run"
    assert "--test_output=streamed" in argv
    assert argv[-2:] == ["--test_arg=--exact", "--test_arg=a::b"]
    assert not any(a.startswith("--test_arg") for a in test_argv(RUST, None, DOCTEST, ["x"]))
    assert not valid_target(RUST, "")


def test_the_build_configuration_is_the_label_and_not_a_field_beside_it():
    """A control behind `#[cfg(feature = ...)]` exists only in a target compiled with the
    feature, so a unit whose claim is about feature-gated code names that flavor's target.
    Two flavors of one crate share a crate root and differ in features — the build graph
    states both — and there is no unit field left that could restate, or contradict, which
    configuration a battery ran under."""
    plain, ext = _rust_targets.target(UNIT), _rust_targets.target(UNIT_EXT)
    assert plain["root"] == ext["root"] == "mcp-re-proxy/src/lib.rs"
    assert "redis_replay" in ext["features"] and "redis_replay" not in plain["features"]
    assert "test_features" not in _UNIT_KEYS and "test_package" not in _UNIT_KEYS


def test_a_battery_spanning_two_targets_is_two_selections():
    """One filter across two targets would let a name that exists in only one of them
    look satisfied by the other."""
    grouped, malformed = lane.group_by_target(
        RUST, [f"{UNIT}#policy::tests::window", f"{INTEGRATION}#stale_window_fails_closed"]
    )
    assert not malformed
    assert set(grouped) == {UNIT, INTEGRATION}


def test_a_rust_battery_needs_no_derived_project():
    """A Rust selector's label names its package, so a unit whose source closure spans two
    crates has a runnable battery without any field choosing between them."""
    unit = {"paths": ["mcp-re-http-profile/src/verify.rs", "mcp-re-core/src/crypto.rs"]}
    assert lane.unit_crate(unit) is None
    assert lane._cwd(RUST, None) == lane.REPO_ROOT


def test_a_battery_outside_the_measured_closure_is_refused():
    """A target in a package the unit's paths do not name would measure code no component
    of the fingerprint digests. Inside the closure — either of two packages — is legal."""
    spanning = {
        "paths": ["mcp-re-http-profile/src/verify.rs", "mcp-re-core/src/crypto.rs"],
        "tested_symbols": [f"{INTEGRATION}#a", "//mcp-re-core:mcp_re_core_test#b"],
    }
    _validate_rust_test_packages("unit[0]", spanning)
    spanning["tested_symbols"].append(f"{UNIT}#c")
    try:
        _validate_rust_test_packages("unit[0]", spanning)
    except ManifestError as exc:
        assert "mcp-re-proxy" in str(exc), exc
    else:
        raise AssertionError("a battery outside the measured closure must be refused")


def test_an_in_crate_selector_must_name_a_module_the_unit_measures():
    """A selector on a target built from a crate runs code inside that crate's sources, so
    its module must be among the unit's paths; the crate root itself counts, since it holds
    the modules it declares inline."""
    unit = {
        "paths": ["mcp-re-proxy/src/outbound_fetch/mod.rs"],
        "tested_symbols": [f"{UNIT}#outbound_fetch::tests::t"],
    }
    _validate_in_crate_selectors("unit[0]", unit)
    unit["tested_symbols"] = [f"{UNIT}#cli::tests::t"]
    try:
        _validate_in_crate_selectors("unit[0]", unit)
    except ManifestError as exc:
        assert "mcp-re-proxy/src" in str(exc), exc
    else:
        raise AssertionError("a module outside the unit's paths must be refused")
    unit = {"paths": ["mcp-re-proxy/src/lib.rs"], "tested_symbols": [f"{UNIT}#tests::t"]}
    _validate_in_crate_selectors("unit[0]", unit)


def test_only_units_claiming_test_evidence_are_in_scope():
    assert lane.claims_test_evidence({"evidence": ["test://a/b/c"]})
    assert lane.claims_test_evidence({"evidence": ["verus://x", "test://a/b/c"]})
    assert not lane.claims_test_evidence({"evidence": ["verus://x"]})
    assert not lane.claims_test_evidence({})


# --- a result line that could not be READ is re-measured, never assumed ------


def test_a_symbol_with_no_result_line_is_rerun_alone_before_the_lane_concludes():
    """A symbol with NO line at all is the one case that can be a reading failure rather
    than a test failure, and the failure is this lane's own: a child process writing to the
    real fd 2 can land bytes carrying a NEWLINE between the harness's `test <name> ... ` and
    its status, and the result line then does not exist to be read. It has fired on a
    deterministic control twice.

    Re-measuring is not believing it. The symbol is RUN AGAIN, alone, and only a fresh `ok`
    from that run is admitted."""
    calls: list[list[str]] = []

    class Result:
        def __init__(self, code: int, out: str) -> None:
            self.returncode = code
            self.stdout = out

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        name = argv[-1].removeprefix("--test_arg=")
        if name == "a::tests::readable":
            return Result(0, "test a::tests::readable ... ok\n")
        return Result(101, "test a::tests::broken ... FAILED\n")

    original = lane.subprocess.run
    lane.subprocess.run = fake_run
    try:
        recovered = lane._rerun_unread(
            RUST, None, UNIT, ["a::tests::readable", "a::tests::broken"]
        )
    finally:
        lane.subprocess.run = original

    assert recovered == {"a::tests::readable"}, recovered
    assert len(calls) == 2, "each unread symbol is run ALONE, not as a batch"
    assert calls[0][-1] == "--test_arg=a::tests::readable"
    assert "--test_arg=--exact" in calls[0], "the re-run selects exactly the one symbol"


# --- the RUNTIME dimension (issue #746) -------------------------------------------
#
# A Python battery's result is a claim about the interpreter it ran on. Until the `[python]`
# pin existed the lane ran `uv run`, which resolved whatever CPython the machine offered,
# and one interpreter's green was recorded as evidence for a `>=3.10` support claim. Each
# case below is a way that could come back.


def test_a_typescript_battery_names_the_runtime_it_runs_on():
    """The Node half of the same property. `npx vitest` resolved whatever node was on PATH,
    so the battery's result described an unnamed runtime (#747)."""
    try:
        test_argv(TYPESCRIPT, "sdk/typescript", "vitest", ["test/x.test.ts > a"])
    except ValueError as exc:
        assert "runtime" in str(exc), exc
    else:
        raise AssertionError("a TypeScript selection without a runtime must be refused")


def test_the_typescript_command_runs_the_pinned_node_and_not_npx():
    argv = test_argv(
        TYPESCRIPT, "sdk/typescript", "vitest", ["test/x.test.ts > a"], "22.23.2"
    )
    assert argv[0] == ".node-v22/node_modules/node/bin/node", argv
    assert "npx" not in argv, "npx would resolve a node of its own"
    assert argv[1].endswith("vitest.mjs"), argv
    assert "--reporter=json" in argv, "the lane must not read a human-facing rendering"


def test_each_ecosystem_names_its_own_runtime():
    """`cpython-26.8.1` on a Node battery describes a runtime that does not exist, and the
    evidence record carries this label."""
    assert PYTHON.runtime_label == "cpython"
    assert TYPESCRIPT.runtime_label == "node"
    assert RUST.runtime_label is None, "a Rust battery has no runtime dimension to label"


def test_a_runtime_is_asked_its_version_in_every_ecosystem_that_has_one():
    """A directory called `.node-v20` holding Node 22 is the substitution the pin exists to
    refuse, so every ecosystem with a runtime dimension must have a probe."""
    from _ecosystems import RUNTIME_PROBES

    for eco in (PYTHON, TYPESCRIPT):
        assert eco.name in RUNTIME_PROBES, eco.name
        relative, argv = RUNTIME_PROBES[eco.name]
        assert argv, f"{eco.name}: a probe with no command asks nothing"
        assert relative("20.20.2") or relative("3.12.13")
    assert RUST.name not in RUNTIME_PROBES


def test_a_python_battery_names_the_interpreter_it_runs_on():
    """No runtime, no command. A default would reintroduce the unpinned interpreter."""
    try:
        test_argv(PYTHON, "sdk/python", "pytest", ["tests/test_x.py::test_y"])
    except ValueError as exc:
        assert "interpreter" in str(exc), exc
    else:
        raise AssertionError("a Python selection without a runtime must be refused")


def test_the_python_command_runs_the_prepared_environment_for_that_runtime():
    argv = test_argv(
        PYTHON, "sdk/python", "pytest", ["tests/test_x.py::test_y"], "3.11.15"
    )
    assert argv[0] == ".venv-cp311/bin/python", argv
    assert "uv" not in argv, "the lane must not resolve or sync its own environment"
    assert argv[-1] == "tests/test_x.py::test_y"
    assert "no:randomly" in argv, "order must be reproducible from the record"
    assert "--color=no" in argv, (
        "the runner must be told not to colour, or an environment variable decides "
        "whether the lane can read the report"
    )


def test_a_coloured_pytest_report_is_still_read():
    """A measured false RED, 2026-09-06.

    pytest honours `FORCE_COLOR` even when its stdout is a PIPE, so an environment
    variable set by whatever invoked the lane wrapped every status in SGR escapes. The
    reader matches a WORD at a known position; the escape sequence in front of it made
    every line unmatchable while leaving the log perfectly legible to a human. All
    thirty-nine controls of `sdk_python.exchange_path` were reported as `never ran` while
    every one of them had just passed.

    The argv now says `--color=no`, and this is the second half: a report that arrives
    coloured anyway is still read, so the lane does not depend on one runner honouring
    one flag.
    """
    coloured = (
        "collected 2 items\n\n"
        "tests/test_x.py::test_one \x1b[32mPASSED\x1b[0m\x1b[32m [ 50%]\x1b[0m\n"
        "tests/test_x.py::test_two \x1b[31mFAILED\x1b[0m\x1b[31m [100%]\x1b[0m\n"
    )
    observed = parse_results(PYTHON, coloured)
    assert observed == {
        "tests/test_x.py::test_one": "ok",
        "tests/test_x.py::test_two": "FAILED",
    }, observed


def test_a_collected_run_this_lane_cannot_read_is_a_reading_failure_not_absent_tests():
    """The two call for OPPOSITE next actions, so they may not share a verdict.

    `never ran` says the tests are absent and sends a reader to the test files. An
    unreadable report says the LANE is broken and sends a reader here. pytest states how
    many cases it collected, so a run that collected some and yielded no status this
    reader understands is the second, and says so.
    """
    unreadable = "collected 3 items\n\ntests/test_x.py::test_one <<<who knows>>>\n"
    try:
        parse_results(PYTHON, unreadable)
    except ReportUnreadable as exc:
        assert "collected 3" in str(exc), exc
    else:
        raise AssertionError("a collected run with no readable status must not read as absent")


def test_a_run_that_collected_nothing_is_not_called_unreadable():
    """An empty selection IS a battery that never ran, and the lane already says so.

    Turning it into a reading failure would hide the case the `--exact` selection exists
    to catch: a declared symbol that does not exist.
    """
    assert parse_results(PYTHON, "collected 0 items\n\nno tests ran\n") == {}


def test_two_runtimes_are_two_environments():
    """A shared environment would make the second measurement the first one again."""
    first = test_argv(PYTHON, "p", "pytest", ["t::a"], "3.10.20")[0]
    second = test_argv(PYTHON, "p", "pytest", ["t::a"], "3.14.7")[0]
    assert first != second, (first, second)


def test_an_ecosystem_with_no_runtime_pin_is_measured_once():
    runtimes, refusal = lane.pinned_runtimes(RUST, {"schema_version": 1})
    assert refusal is None, refusal
    assert runtimes == [None], runtimes


def test_the_compiler_pin_is_not_a_runtime_pin():
    """`[rust]` pins the COMPILER, and it shares its name with the ecosystem. Read as a
    runtime pin it names no interpreter, and the lane refused every Rust battery as
    measured on an empty runtime set — the first run after the ecosystem was renamed."""
    toolchains = {"rust": {"state": "resolved", "channel": "1.97.1"}}
    runtimes, refusal = lane.pinned_runtimes(RUST, toolchains)
    assert refusal is None, refusal
    assert runtimes == [None], runtimes


def test_an_unresolved_runtime_pin_refuses_rather_than_running():
    runtimes, refusal = lane.pinned_runtimes(PYTHON, {"python": {"state": "unresolved"}})
    assert runtimes == [], runtimes
    assert refusal is not None and "unresolved" in refusal, refusal


def test_a_resolved_pin_naming_no_interpreter_is_not_a_runtime_set():
    """The same failure wearing a resolved label: an empty set selects no environment."""
    runtimes, refusal = lane.pinned_runtimes(
        PYTHON, {"python": {"state": "resolved", "interpreters": []}}
    )
    assert runtimes == [], runtimes
    assert refusal is not None and "empty" in refusal, refusal


def test_every_pinned_interpreter_is_measured():
    runtimes, refusal = lane.pinned_runtimes(
        PYTHON,
        {"python": {"state": "resolved", "interpreters": ["3.12.13", "3.10.20"]}},
    )
    assert refusal is None, refusal
    assert runtimes == ["3.10.20", "3.12.13"], runtimes


def test_a_missing_prepared_environment_fails_rather_than_skipping():
    for eco, project, runtime in (
        (PYTHON, "sdk/python", "3.99.0"),
        (TYPESCRIPT, "sdk/typescript", "99.0.0"),
    ):
        ok, detail = lane.runtime_identity(eco, project, runtime)
        assert not ok, eco.name
        assert "no prepared environment" in detail, detail


def test_an_environment_holding_another_interpreter_is_refused():
    """The pin names an exact patch version, and this is what makes that more than prose."""
    calls = []

    class Result:
        def __init__(self, returncode, stdout):
            self.returncode = returncode
            self.stdout = stdout

    original_run = lane.subprocess.run
    original_isfile = lane.Path.is_file
    lane.subprocess.run = lambda argv, **_k: (calls.append(argv), Result(0, "3.12.13\n"))[1]
    lane.Path.is_file = lambda self: True
    try:
        ok, detail = lane.runtime_identity(PYTHON, "sdk/python", "3.11.15")
    finally:
        lane.subprocess.run = original_run
        lane.Path.is_file = original_isfile

    assert not ok
    assert "3.12.13" in detail and "3.11.15" in detail, detail
    assert calls, "the interpreter must be asked its version, not assumed"


def test_the_matching_interpreter_is_accepted():
    """The positive case: a gate that refuses everything measures nothing."""

    class Result:
        returncode = 0
        stdout = "3.11.15\n"

    original_run = lane.subprocess.run
    original_isfile = lane.Path.is_file
    lane.subprocess.run = lambda argv, **_k: Result()
    lane.Path.is_file = lambda self: True
    try:
        ok, detail = lane.runtime_identity(PYTHON, "sdk/python", "3.11.15")
    finally:
        lane.subprocess.run = original_run
        lane.Path.is_file = original_isfile
    assert ok, detail


def test_an_unrecognised_subset_flag_is_refused_rather_than_dropped():
    """A selector nobody validated is the defect, in EITHER face.

    `main` read no argv at all: `--unti proxy.peer_identity_value` was discarded, the whole
    196-unit lane ran and the run exited 0 printing `PASS`. Measured, not reasoned — the run
    is in this campaign's record. It failed safe that day only because the lane it ran was
    larger than the one asked for; the same typo before a SMALLER selection prints `PASS`
    over something else entirely.

    The edit that turns this red is `parse_known_args` in place of `parse_args`, which is
    the exact shape being refused.
    """
    import argparse

    for bad in (["--unti", "proxy.peer_identity_value"], ["--units", "x"], ["proxy.x"]):
        try:
            lane.parse_args(bad)
        except SystemExit as exit_:
            assert exit_.code != 0, f"{bad} was refused with a zero exit"
        else:
            raise AssertionError(f"{bad} was accepted; an unknown token was dropped")
    assert isinstance(lane.parse_args([]), argparse.Namespace)
    assert lane.parse_args(["--unit", "a", "--unit", "b"]).unit == ["a", "b"]


def test_a_subset_flag_naming_no_declared_unit_fails():
    """A subset that selects nothing must never read as a clean lane.

    This repository has met the zero-selection face three times — a word-splitting error
    reporting `0 passed` for seven units, a probe run whose short ids matched nothing, and
    an `#[ignore]` filter selecting zero tests at exit 0. A `--unit` naming no declared unit
    is the same shape reachable by one typo, so it is a FAIL and not an empty PASS.
    """
    assert lane.main(["--unit", "no.such.unit.exists"]) != 0


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        # Only this module's controls: `test_argv` is an imported adapter helper whose name
        # begins the same way, and calling it would be a runner bug reported as a failure.
        if (
            name.startswith("test_")
            and callable(fn)
            and getattr(fn, "__module__", None) == "__main__"
        ):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
