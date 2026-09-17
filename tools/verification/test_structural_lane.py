# SPDX-License-Identifier: Apache-2.0
"""The structural lane's own false-green catalogue — ADR-MCPRE-068 §12.1, Phase 0B.

This lane's claim is the strongest one in the evidence model: *the representation admits no
illegal inhabitant*. Every way it could report that without having proved it is a case
below, and two of them are compiled for real, because a runner that cannot go red when the
hostile construction COMPILES is measuring nothing:

  * **the construction compiles** — the boundary is OPEN and the claim above it is false.
    The runner must report FAIL, not "no error found";
  * **the refusal is a different error** — the lane watched something else break and cannot
    attribute the refusal to the boundary;
  * **zero execution** — a unit declaring `structural://` with no probe registered, or a
    selection that resolves to nothing, may not report a pass. This is the owner's
    ratification, and it is the `-- --ignored`-selects-zero-tests failure in new clothes;
  * **an unanswered producer path** — a witness that attacks one route while another stands
    open establishes nothing, so `producer_paths` answers for every route including the
    ones that do not apply;
  * **a construction injected at the wrong site** — `tests/` compiles as a separate crate
    and `src/` does not, so the placement decides which proposition was attacked;
  * **an in-crate module nothing declares** — a file rustc never opened produces no error,
    which this lane would otherwise read as an open boundary;
  * **a probe whose documented case has drifted** — the doctest a reader reaches for first
    no longer states what the registry says it does.

Run: python3 tools/verification/test_structural_lane.py
"""

from __future__ import annotations

import io
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _load_tool import load_tool  # noqa: E402
from _manifest import REPO_ROOT, ManifestError, load_verification  # noqa: E402
from _structural import (  # noqa: E402
    KINDS,
    PRODUCER_PATHS,
    adjudicate,
    load_probes,
    marker_line,
    provenance_problem,
)

lane = load_tool("verify-structural", "verify_structural_lane")

REGISTRY = REPO_ROOT / "verification" / "policy" / "structural-probes.toml"
UNITS = {unit["id"]: unit for unit in load_verification().get("unit", [])}

#: A crate with NO dependencies, so a fixture run compiles in about a second. The fixtures
#: below are deliberately not run against a real owner: what they test is the LANE, and a
#: lane fixture that took a minute to compile would be one somebody eventually skips.
FIXTURE_CRATE = "mcp-re-test-paths"
FIXTURE_UNIT = "conformance.verdict_vocabulary_scope"


def _probe(**overrides) -> dict:
    probe = {
        "id": "F01",
        "unit": FIXTURE_UNIT,
        "kind": "in-crate-source-injection",
        "package": FIXTURE_CRATE,
        "invariant": "a fixture invariant, for testing the lane rather than a product claim",
        "insertion_path": f"{FIXTURE_CRATE}/src/structural_probe_fixture.rs",
        "insertion_parent": f"{FIXTURE_CRATE}/src/lib.rs",
        "insertion_declaration": "mod structural_probe_fixture;",
        "construction": "pub fn hostile() -> u8 {\n    7 // SITE\n}\n",
        "marker": "SITE",
        "error_code": "E0451",
        "producer_paths": {route: "answered" for route in PRODUCER_PATHS},
    }
    probe.update(overrides)
    return probe


def _write_registry(directory: Path, probes: list[dict]) -> Path:
    """A fixture registry on disk, written as TOML by hand.

    `tomllib` reads and does not write, and this layer is stdlib-only by rule.
    """
    lines = ["schema_version = 1\n"]
    for probe in probes:
        lines.append("[[probe]]\n")
        for key, value in probe.items():
            if key == "producer_paths":
                continue
            if isinstance(value, list):
                lines.append(f"{key} = {value!r}\n".replace("'", '"'))
            else:
                lines.append(f'{key} = """{value}"""\n')
        lines.append("[probe.producer_paths]\n")
        for route, answer in probe["producer_paths"].items():
            lines.append(f'{route} = """{answer}"""\n')
    path = directory / "fixture-probes.toml"
    path.write_text("".join(lines), encoding="utf-8")
    return path


def _expect_manifest_error(call, why: str) -> None:
    try:
        call()
    except ManifestError:
        return
    raise AssertionError(why)


def _run_lane(registry: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(HERE / "verify-structural"), "--registry", str(registry)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


# --- the two cases that need a compiler ------------------------------------------------


def test_a_hostile_construction_that_COMPILES_is_a_FAIL():
    """THE lane's own falsifier. A runner that cannot go red when the illegal inhabitant
    builds is measuring nothing, and would report PASS over an open boundary for ever."""
    with tempfile.TemporaryDirectory() as tmp:
        registry = _write_registry(Path(tmp), [_probe()])
        status, output = _run_lane(registry)
    assert status != 0, f"a compiling construction must FAIL the lane; got 0\n{output}"
    assert "VERDICT: FAIL" in output, output
    assert "COMPILED" in output, f"the finding must name what happened\n{output}"


def test_a_refusal_by_a_DIFFERENT_error_is_not_evidence():
    """'Does not compile' is satisfied by a typo, a missing import or a broken fixture. The
    probe declares the code and the line its primary span must fall on."""
    construction = "pub fn hostile() -> u8 {\n    no_such_function() // SITE\n}\n"
    with tempfile.TemporaryDirectory() as tmp:
        registry = _write_registry(Path(tmp), [_probe(construction=construction)])
        status, output = _run_lane(registry)
    assert status != 0, f"an unattributable refusal must FAIL the lane\n{output}"
    assert "not by the boundary this probe attacks" in output, output


# --- fail-close on zero execution ------------------------------------------------------


def _main_with(probes, units, argv) -> tuple[int, str]:
    """Run the lane's `main` over a synthetic registry and unit set, capturing its output."""
    original_probes, original_doc, original_argv = lane.load_probes, lane.load_verification, sys.argv
    lane.load_probes = lambda _registry: probes
    lane.load_verification = lambda: {"unit": units, "policy_revision": "fixture"}
    sys.argv = ["verify-structural", *argv]
    buffer = io.StringIO()
    try:
        # BOTH streams: the verdict line goes to stdout and the reason to stderr, and a
        # test that read only one of them would be asserting on half the lane's answer.
        with redirect_stdout(buffer), redirect_stderr(buffer):
            status = lane.main()
    finally:
        lane.load_probes, lane.load_verification, sys.argv = original_probes, original_doc, original_argv
    return status, buffer.getvalue()


def _declaring_unit() -> dict:
    return {
        "id": "fixture.sealed_owner",
        "class": "V0",
        "evidence": ["structural://fixture/sealed_owner"],
        "evidence_class": "structural",
        "direct_consequence_severity": "high",
    }


def test_a_unit_declaring_the_scheme_with_no_probe_FAILS():
    """An orphaned declaration is unmeasured evidence. `_evidence.required_lanes` binds
    every declared scheme, so the alternative is a unit claiming a lane nothing ran."""
    status, output = _main_with([], [_declaring_unit()], [])
    assert status != 0 and "VERDICT: FAIL" in output, output
    assert "no probe is registered" in output, output


def test_a_selection_that_resolves_to_nothing_FAILS_while_a_unit_declares():
    """The ratified rule: the lane fail-closes on ZERO EXECUTION. A run that selected no
    probe measured nothing, whatever its exit status would otherwise have been."""
    probe = _probe(unit="fixture.sealed_owner")
    status, output = _main_with([probe], [_declaring_unit()], ["--probe", "NOT-A-PROBE"])
    assert status != 0 and "VERDICT: FAIL" in output, output
    assert "measured nothing" in output, output


def test_a_selector_that_matches_nothing_is_a_FAIL_even_with_no_declaring_unit():
    """An empty SELECTION and an empty REGISTRY are different facts, and only the second is
    quiet. Found in `verify-mutations`, where `--probe M25` matched nothing — every id there
    is `M25-<what-it-weakens>` — and the lane reported NOT_REQUIRED and exited 0."""
    unit = {"id": FIXTURE_UNIT, "class": "V0", "evidence": ["test://fixture"]}
    status, output = _main_with([_probe()], [unit], ["--probe", "NOT-A-PROBE"])
    assert status != 0 and "selected NO registered probe" in output, output


def test_not_required_only_when_nothing_claims_and_nothing_is_registered():
    """The one honest quiet state, and it is not a pass over an unmeasured claim."""
    status, output = _main_with([], [], [])
    assert status == 0 and "VERDICT: NOT_REQUIRED" in output, output


def test_a_probe_naming_an_unknown_unit_FAILS():
    """A probe attacking no declared proposition witnesses nothing, however green it runs."""
    status, output = _main_with([_probe(unit="fixture.nothing_declares_this")], [], [])
    assert status != 0 and "VERDICT: FAIL" in output, output


# --- adjudication ----------------------------------------------------------------------


def _diagnostic(code: str, path: str, line: int) -> dict:
    return {
        "level": "error",
        "code": {"code": code},
        "spans": [{"is_primary": True, "file_name": path, "line_start": line}],
    }


def test_no_error_at_all_is_the_open_boundary_finding():
    probe = _probe()
    problem = adjudicate(probe, [], probe["insertion_path"])
    assert problem is not None and "COMPILED" in problem
    assert probe["invariant"] in problem, "the finding names the invariant that is not closed"


def test_a_warning_is_not_a_refusal():
    """Only `level == error` refuses. A deny-by-default lint that fires as a warning would
    otherwise let a compiling construction read as a closed boundary."""
    probe = _probe()
    warning = {"level": "warning", "code": {"code": "E0451"}, "spans": []}
    assert "COMPILED" in (adjudicate(probe, [warning], probe["insertion_path"]) or "")


def test_the_right_code_on_the_wrong_line_is_not_evidence():
    probe = _probe()
    path = probe["insertion_path"]
    assert adjudicate(probe, [_diagnostic("E0451", path, 99)], path) is not None
    assert adjudicate(probe, [_diagnostic("E0451", path, marker_line(probe))], path) is None


def test_the_right_code_in_the_wrong_file_is_not_evidence():
    """A crate that fails to build for an unrelated reason produces errors of every code.
    The span must be on the probe's own construction."""
    probe = _probe()
    elsewhere = _diagnostic("E0451", "some/other/file.rs", marker_line(probe))
    assert adjudicate(probe, [elsewhere], probe["insertion_path"]) is not None


def test_the_marker_must_identify_exactly_one_line():
    _expect_manifest_error(
        lambda: load_probes(_two_marker_registry()),
        "a marker on two lines cannot say which line was refused",
    )


def _two_marker_registry() -> Path:
    directory = Path(tempfile.mkdtemp())
    return _write_registry(
        directory, [_probe(construction="// SITE\npub fn hostile() {} // SITE\n")]
    )


# --- registry adequacy -----------------------------------------------------------------


def test_every_producer_path_must_be_answered():
    """The ratification: private fields alone are insufficient, and the witness must account
    for EVERY producer path relevant to the invariant. An unanswered route is
    indistinguishable from an unconsidered one."""
    for route in PRODUCER_PATHS:
        answers = {other: "answered" for other in PRODUCER_PATHS if other != route}
        directory = Path(tempfile.mkdtemp())
        registry = _write_registry(directory, [_probe(producer_paths=answers)])
        _expect_manifest_error(
            lambda registry=registry: load_probes(registry),
            f"a probe that does not answer for {route} must be refused",
        )


def test_an_empty_answer_is_not_an_answer():
    answers = {route: ("" if route == PRODUCER_PATHS[0] else "answered") for route in PRODUCER_PATHS}
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(directory, [_probe(producer_paths=answers)])
    _expect_manifest_error(lambda: load_probes(registry), "an empty route answer must be refused")


def test_a_boundary_probe_may_not_inject_into_src():
    """`tests/` compiles as a separate crate and `src/` does not. A boundary probe under
    `src/` would claim the in-crate seal it never attacked."""
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(
        directory,
        [
            _probe(
                kind=KINDS[0],
                doc_path="mcp-re-http-profile/src/verified_response/bound.rs",
                doc_item="doc#verified_response::bound::VerifiedMcpResponse",
                insertion_path=f"{FIXTURE_CRATE}/src/probe.rs",
                insertion_parent=None,
            )
        ],
    )
    _expect_manifest_error(lambda: load_probes(registry), "a boundary probe under src/ must be refused")


def test_a_vague_expected_refusal_is_refused():
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(directory, [_probe(error_code="does not compile")])
    _expect_manifest_error(lambda: load_probes(registry), "'does not compile' is not an error code")


def test_an_empty_invariant_is_refused():
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(directory, [_probe(invariant="  ")])
    _expect_manifest_error(
        lambda: load_probes(registry),
        "a probe that states no invariant cannot be said to attack the right boundary",
    )


def test_an_unknown_key_is_refused():
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(directory, [_probe(expect_red="a mutation probe's key")])
    _expect_manifest_error(
        lambda: load_probes(registry),
        "a mistyped security declaration must not read as an absent one",
    )


# --- the registered probes, as they stand ----------------------------------------------


def test_the_real_registry_loads_and_every_probe_names_a_real_unit():
    probes = load_probes(REGISTRY)
    assert probes, "Phase 0B registers real probes; an empty registry would make the lane inert"
    for probe in probes:
        assert probe["unit"] in UNITS, f"{probe['id']} names unit {probe['unit']!r}"


def test_every_boundary_probe_still_corresponds_to_its_documented_case():
    """Provenance, checked rather than trusted: the drift is silent in exactly the direction
    that makes the registry look better than the tree."""
    for probe in load_probes(REGISTRY):
        problem = provenance_problem(probe, UNITS[probe["unit"]], REPO_ROOT)
        assert problem is None, f"{probe['id']}: {problem}"


def test_a_drifted_documented_case_is_detected():
    probe = _probe(
        kind=KINDS[0],
        doc_path="mcp-re-http-profile/src/verified_response/bound.rs",
        doc_item="doc#not::a::declared::symbol",
        insertion_path="mcp-re-http-profile/tests/probe.rs",
    )
    del probe["insertion_parent"], probe["insertion_declaration"]
    assert provenance_problem(probe, UNITS[FIXTURE_UNIT], REPO_ROOT) is not None


def test_no_unit_declares_the_scheme_before_phase_0D():
    """Phase 0B builds the lane and changes no unit's class. A `structural://` URI landing
    early would take its unit OUT of the graph, because `decide_issuance` refuses a claimed
    lane with no record — the declaration must follow the reclassification, not lead it."""
    declaring = [uid for uid, unit in UNITS.items() if lane.claims_structural(unit)]
    assert not declaring, f"0D moves these through the class-transition ratchet, not 0B: {declaring}"


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
