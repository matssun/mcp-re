# SPDX-License-Identifier: Apache-2.0
"""The measured lane's own false-green catalogue — ADR-MCPRE-068 §4.1, §12.2, Phase 0B.

A MEASURED proposition owes no mutation falsifier — deleting a production property makes it
a measurement of a different tree, not a false one — and owes instead the demonstration
that its apparatus can still MOVE. Every way this lane could report that without having
seen it is a case below, and all of them execute the runner end to end, because the
registry is empty at Phase 0B and these fixtures are therefore the lane's whole liveness:

  * **a dead apparatus** — the perturbation moved nothing. `APPARATUS-MOVED: 0` is a FAIL,
    and it is the finding, not a lane malfunction;
  * **a silent control** — it exited 0 and stated no count. An exit status of 0 from a
    control that selected nothing is the false green this contract exists to refuse, so a
    missing count is a distinct failure from a zero one;
  * **an empty result** — the protocol produced no line matching its own pattern, so
    nothing was observed and no control could be adjudicated over it;
  * **an irreproducible protocol** — two runs over one tree disagreed, so the apparatus
    reads something its scope does not name;
  * **a protocol that failed to run** — its previous number says nothing about this tree;
  * **zero execution** — a unit declaring `measured://` with nothing registered, or a
    selection resolving to nothing, may not report a pass.

Run: python3 tools/verification/test_measured_lane.py
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
from _measured import apparatus_problem, extract, load_measurements, moved  # noqa: E402

lane = load_tool("verify-measured", "verify_measured_lane")

REGISTRY = REPO_ROOT / "verification" / "policy" / "measurements.toml"
UNITS = {unit["id"]: unit for unit in load_verification().get("unit", [])}

FIXTURE_UNIT = "conformance.verdict_vocabulary_scope"

#: An apparatus that observes something stable, and one that perturbs it and says so.
STABLE = "print('MEASURED: files_deciding_verdict_tokens=2')"
LIVE_CONTROL = "print('APPARATUS-MOVED: 3')"
DEAD_CONTROL = "print('APPARATUS-MOVED: 0')"
SILENT_CONTROL = "print('control ran, and says nothing about whether anything moved')"
DRIFTING = "import time; print('MEASURED:', time.time_ns())"


def _measurement(**overrides) -> dict:
    measurement = {
        "id": "F01",
        "unit": FIXTURE_UNIT,
        "protocol": [sys.executable, "-c", STABLE],
        "scope": "a fixture apparatus, for testing the lane rather than a product claim",
        "artifact": "fixture.txt",
        "artifact_pattern": "^MEASURED: ",
        "control_kind": "sensitivity",
        "control": [sys.executable, "-c", LIVE_CONTROL],
    }
    measurement.update(overrides)
    return {k: v for k, v in measurement.items() if v is not None}


def _write_registry(directory: Path, measurements: list[dict]) -> Path:
    lines = ["schema_version = 1\n"]
    for measurement in measurements:
        lines.append("[[measurement]]\n")
        for key, value in measurement.items():
            if isinstance(value, list):
                members = ", ".join(f'"""{part}"""' for part in value)
                lines.append(f"{key} = [{members}]\n")
            else:
                lines.append(f'{key} = """{value}"""\n')
    path = directory / "fixture-measurements.toml"
    path.write_text("".join(lines), encoding="utf-8")
    return path


def _run_lane(registry: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(HERE / "verify-measured"), "--registry", str(registry)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _lane_over(measurements: list[dict]) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        return _run_lane(_write_registry(Path(tmp), measurements))


def _expect_manifest_error(call, why: str) -> None:
    try:
        call()
    except ManifestError:
        return
    raise AssertionError(why)


# --- the apparatus, executed -----------------------------------------------------------


def test_a_live_sensitivity_apparatus_passes():
    status, output = _lane_over([_measurement()])
    assert status == 0 and "VERDICT: PASS" in output, output
    assert "sensitivity control" in output, output


def test_a_DEAD_apparatus_fails():
    """The perturbation changed no observation, so the number cannot move. A figure that
    cannot move is not a measurement."""
    status, output = _lane_over([_measurement(control=[sys.executable, "-c", DEAD_CONTROL])])
    assert status != 0 and "VERDICT: FAIL" in output, output
    assert "APPARATUS-MOVED: 0" in output and "DEAD" in output, output


def test_a_SILENT_control_fails_differently():
    """Absence of a count and a count of zero are two findings. One is an apparatus that
    cannot move; the other is a control that did not say whether it moved."""
    status, output = _lane_over([_measurement(control=[sys.executable, "-c", SILENT_CONTROL])])
    assert status != 0, output
    assert "printed no `APPARATUS-MOVED" in output, output


def test_an_irreproducible_protocol_fails_its_reproducibility_control():
    status, output = _lane_over(
        [
            _measurement(
                protocol=[sys.executable, "-c", DRIFTING],
                control_kind="reproducibility",
                control=None,
            )
        ]
    )
    assert status != 0, output
    assert "DIFFERENT" in output, output


def test_a_stable_protocol_passes_its_reproducibility_control():
    status, output = _lane_over(
        [_measurement(control_kind="reproducibility", control=None)]
    )
    assert status == 0 and "VERDICT: PASS" in output, output


def test_a_protocol_that_observes_NOTHING_fails():
    """An empty result is refused BEFORE either control is consulted: a control over nothing
    would be adjudicating an absence."""
    status, output = _lane_over([_measurement(protocol=[sys.executable, "-c", "print('quiet')"])])
    assert status != 0, output
    assert "apparatus that did not run" in output, output


def test_a_protocol_that_fails_to_run_is_not_a_measurement():
    status, output = _lane_over(
        [_measurement(protocol=[sys.executable, "-c", "raise SystemExit(3)"])]
    )
    assert status != 0, output
    assert "exited 3" in output, output


# --- fail-close on zero execution ------------------------------------------------------


def _main_with(measurements, units, argv) -> tuple[int, str]:
    original = (lane.load_measurements, lane.load_verification, sys.argv)
    lane.load_measurements = lambda _registry: measurements
    lane.load_verification = lambda: {"unit": units, "policy_revision": "fixture"}
    sys.argv = ["verify-measured", *argv]
    buffer = io.StringIO()
    try:
        with redirect_stdout(buffer), redirect_stderr(buffer):
            status = lane.main()
    finally:
        lane.load_measurements, lane.load_verification, sys.argv = original
    return status, buffer.getvalue()


def _declaring_unit(**overrides) -> dict:
    unit = {
        "id": "fixture.measured_owner",
        "class": "V0",
        "evidence": ["measured://fixture/corpus"],
        "evidence_class": "measured",
        "direct_consequence_severity": "medium",
        "measurement_protocol": "the fixture protocol",
        "measurement_scope": "the fixture corpus",
        "measurement_artifact": "fixture.txt",
        "measurement_control": "the fixture control",
    }
    unit.update(overrides)
    return unit


def test_a_unit_declaring_the_scheme_with_no_measurement_FAILS():
    status, output = _main_with([], [_declaring_unit()], [])
    assert status != 0 and "no measurement is registered" in output, output


def test_a_selection_that_resolves_to_nothing_FAILS_while_a_unit_declares():
    measurement = _measurement(unit="fixture.measured_owner")
    status, output = _main_with([measurement], [_declaring_unit()], ["--measurement", "NOPE"])
    assert status != 0 and "measured nothing" in output, output


def test_an_artifact_the_unit_does_not_claim_is_refused():
    """The unit's `measurement_artifact` and the registry's are ONE fact. Two spellings of
    it would let a unit cite a result no lane produced."""
    measurement = _measurement(unit="fixture.measured_owner", artifact="somewhere-else.txt")
    status, output = _main_with([measurement], [_declaring_unit()], [])
    assert status != 0 and "measurement_artifact" in output, output


def test_a_selector_that_matches_nothing_is_a_FAIL_even_with_no_declaring_unit():
    """The same rule as the structural lane's: a selector matching nothing has measured
    nothing, whatever the registry holds."""
    unit = {"id": FIXTURE_UNIT, "class": "V0", "evidence": ["test://fixture"]}
    status, output = _main_with([_measurement()], [unit], ["--measurement", "NOPE"])
    assert status != 0 and "selected NO registered measurement" in output, output


def test_not_required_only_when_nothing_claims_and_nothing_is_registered():
    status, output = _main_with([], [], [])
    assert status == 0 and "VERDICT: NOT_REQUIRED" in output, output


def test_a_measurement_naming_an_unknown_unit_FAILS():
    """A number with nothing to be about is not a measurement of anything."""
    status, output = _main_with([_measurement(unit="fixture.no_such_unit")], [], [])
    assert status != 0 and "VERDICT: FAIL" in output, output


# --- adjudication and registry adequacy ------------------------------------------------


def test_absence_and_zero_are_different_answers():
    assert moved("APPARATUS-MOVED: 0") == 0
    assert moved("nothing of the sort") is None
    assert moved("APPARATUS-MOVED: 4\nAPPARATUS-MOVED: 1") == 1, "the weakest claim governs"


def test_the_result_is_the_filtered_lines_not_the_whole_output():
    output = "compiling...\nMEASURED: x=2\nfinished in 0.31s\n"
    assert extract("^MEASURED: ", output) == ["MEASURED: x=2"]


def test_an_empty_result_is_refused_before_the_control():
    problem = apparatus_problem(_measurement(), [], None, "APPARATUS-MOVED: 9")
    assert problem is not None and "did not run" in problem


def test_a_sensitivity_measurement_must_carry_a_control():
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(directory, [_measurement(control=None)])
    _expect_manifest_error(lambda: load_measurements(registry), "sensitivity needs a control argv")


def test_a_reproducibility_measurement_may_not_carry_one():
    """Its control IS the second run. A third command would be an apparatus check nothing
    adjudicates — configuration that enforces nothing, one layer in."""
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(directory, [_measurement(control_kind="reproducibility")])
    _expect_manifest_error(lambda: load_measurements(registry), "a reproducibility control takes no argv")


def test_scope_may_not_be_empty():
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(directory, [_measurement(scope="   ")])
    _expect_manifest_error(
        lambda: load_measurements(registry),
        "a number whose corpus is unstated cannot be compared against the next one",
    )


def test_an_unknown_control_kind_is_refused():
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(directory, [_measurement(control_kind="mutation")])
    _expect_manifest_error(
        lambda: load_measurements(registry),
        "a measured proposition does not inherit the mutation falsifier (Ruling 4)",
    )


def test_an_unknown_key_is_refused():
    directory = Path(tempfile.mkdtemp())
    registry = _write_registry(directory, [_measurement(expect_red="a mutation probe's key")])
    _expect_manifest_error(lambda: load_measurements(registry), "unknown keys are failures here")


# --- the registry, as it stands at Phase 0B --------------------------------------------


def test_every_declaring_unit_has_a_measurement_and_every_measurement_a_declaring_unit():
    """Phase 0D. A `measured://` URI with no registered measurement takes its unit OUT of the
    graph — `decide_issuance` refuses a claimed lane with no record — and a measurement whose
    unit does not declare the scheme produces a number no claim rests on."""
    registered = {m["unit"] for m in load_measurements(REGISTRY)}
    declaring = {uid for uid, unit in UNITS.items() if lane.claims_measured(unit)}
    assert declaring, "0D declared the first one; an empty set means the reclassification was lost"
    assert declaring <= registered, sorted(declaring - registered)
    assert registered <= set(UNITS), sorted(registered - set(UNITS))


def test_a_measured_unit_declares_the_four_fields_and_no_battery():
    """Ruling 4's four elements are what a measured proposition owes INSTEAD of a mutation
    falsifier, and the artifact the unit cites is the one its measurement writes — one fact,
    not two spellings of it. The battery goes with the class: a `tested_symbols` list no
    declared lane selects reads as coverage."""
    from _evidence_class import MEASUREMENT_KEYS

    measurements = {m["unit"]: m for m in load_measurements(REGISTRY)}
    for unit_id, unit in UNITS.items():
        if unit.get("evidence_class") != "measured":
            continue
        for key in MEASUREMENT_KEYS:
            assert str(unit.get(key, "")).strip(), f"{unit_id}: {key}"
        assert not unit.get("tested_symbols"), unit_id
        assert not any(str(e).startswith("test://") for e in unit.get("evidence", [])), unit_id
        assert unit["measurement_artifact"] == measurements[unit_id]["artifact"]


def test_the_registered_measurement_runs_and_its_apparatus_moves():
    """The estate's own record, executed. The fixtures above prove the lane can go red; this
    proves the thing it is pointed at is alive — a lane whose only real subject is a fixture
    is configured rather than measuring."""
    status, output = _run_lane(REGISTRY)
    assert status == 0 and "VERDICT: PASS" in output, output
    assert "MSR-0001" in output, output


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
