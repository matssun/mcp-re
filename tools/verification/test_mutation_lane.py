# SPDX-License-Identifier: Apache-2.0
"""The mutation lane's own false-green catalogue.

The lane exists to prove that a claimed conjunct is load-bearing. Every way it could report
that without having proved it is a case below:

  * a probe whose anchor matches zero or two sites has not identified the check it claims
    to have broken;
  * a probe expecting a control the unit does not DECLARE would prove something about a
    test that is not evidence for the theorem;
  * a control that NEVER RAN counted as red in the first version of this lane, so a
    weakening that stopped a test from being reported at all satisfied the probe;
  * a control matched by bare symbol could be satisfied by a same-named test in a target
    the probe never intended to touch;
  * a probe with no expectations at all asserts nothing;
  * a weakened tree that does not compile has measured nothing, and must not read as
    "the controls held".

Run: python3 tools/verification/test_mutation_lane.py
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _load_tool import load_tool  # noqa: E402

lane = load_tool("verify-mutations", "verify_mutations_lane")

from _manifest import ManifestError, load_verification  # noqa: E402

UNITS = {unit["id"]: unit for unit in load_verification().get("unit", [])}


def _probe(**overrides):
    probe = {
        "id": "T-01",
        "unit": "http_profile.request_floor_result",
        "theorem": "THM-0014",
        "conjunct": "a conjunct",
        "path": "mcp-re-http-profile/src/verify.rs",
        "anchor": "x",
        "weakening": "y",
        "expect_red": ["body_tamper_fails_closed"],
    }
    probe.update(overrides)
    return probe


def _expect_manifest_error(fn, message: str):
    try:
        fn()
    except ManifestError:
        return
    raise AssertionError(message)


# --- the registry is validated strictly ---------------------------------------


def test_the_registry_parses_and_every_probe_names_a_real_unit_and_theorem():
    """A probe resolving into nothing would be a self-test of an imaginary battery."""
    import tomllib

    probes = lane.load_probes()
    assert probes, "the registry must not be empty while V0 claims rest on it"
    theorems = {
        t["id"]
        for t in tomllib.load(
            (lane.REPO_ROOT / "verification/policy/theorems.toml").open("rb")
        )["theorem"]
    }
    for probe in probes:
        assert probe["unit"] in UNITS, probe["id"]
        # `theorem` is optional — a unit may have a probe before it has a registered
        # claim — but a theorem that IS named must resolve.
        if "theorem" in probe:
            assert probe["theorem"] in theorems, probe["id"]


def test_every_registered_anchor_matches_exactly_one_site_today():
    """The staleness property, asserted over the real registry: this is the check that
    turns a refactor into a re-adjudication instead of a silent loss of coverage."""
    for probe in lane.load_probes():
        source = (lane.REPO_ROOT / probe["path"]).read_text()
        assert source.count(probe["anchor"]) == 1, f"{probe['id']} is stale"


def test_a_weakening_that_changes_nothing_is_rejected_by_construction():
    """A probe whose weakening equals its anchor would apply no weakening at all and then
    report whatever the battery does normally."""
    for probe in lane.load_probes():
        assert probe["anchor"] != probe["weakening"], probe["id"]


# --- the failure modes --------------------------------------------------------


def test_an_anchor_matching_no_site_is_stale(tmp=None):
    tree = lane.REPO_ROOT
    _expect_manifest_error(
        lambda: lane.apply(tree, _probe(anchor="this text is nowhere in verify.rs"), "p"),
        "a zero-match anchor must be STALE",
    )


def test_an_ambiguous_anchor_is_stale_too():
    """Two matches is as much a failure as none: the lane could not say which check it
    broke, so whatever went red proves nothing about the conjunct named."""
    source = (lane.REPO_ROOT / "mcp-re-http-profile/src/verify/floor/response.rs").read_text()
    repeated = "    reject_content_encoding(&response.headers)?;"
    assert source.count(repeated) > 1, "fixture assumption: this line is not unique"
    _expect_manifest_error(
        lambda: lane.apply(lane.REPO_ROOT, _probe(anchor=repeated), "p"),
        "an ambiguous anchor must be STALE",
    )


def test_the_working_tree_is_never_edited():
    """`apply` writes into whatever tree it is handed; the lane hands it a COPY. A run that
    crashed mid-probe must leave the repository untouched, which is only true if the
    working tree is never the mutation target."""
    import inspect

    body = inspect.getsource(lane.main)
    assert "copy_tracked_tree(tree)" in body
    assert "lane.apply(REPO_ROOT" not in body
    assert "apply(tree, probe" in body


def test_expecting_a_control_the_unit_does_not_declare_is_refused():
    """A red test outside the declared battery is not evidence for the theorem: the unit's
    `tested_symbols` is what the claim rests on."""
    _expect_manifest_error(
        lambda: lane.declared_battery(
            UNITS, _probe(expect_red=["a_test_that_is_not_declared"]), "p"
        ),
        "an undeclared control must be refused",
    )


def test_a_probe_with_no_expectations_is_refused_by_the_loader():
    import tomllib

    doc = tomllib.loads(
        'schema_version = 1\n'
        '[[probe]]\n'
        'id = "T"\nunit = "u"\ntheorem = "THM-0001"\nconjunct = "c"\n'
        'path = "p"\nanchor = "a"\nweakening = "b"\nexpect_red = []\n'
    )
    assert doc["probe"][0]["expect_red"] == []
    # The loader reads the real file, so assert the rule it enforces is present in it.
    import inspect

    assert "`expect_red` is empty" in inspect.getsource(lane.load_probes)


def test_a_tree_that_did_not_compile_is_not_a_result():
    """`run_battery` reports `ran=False` on a compile error, and `main` turns that into a
    FAIL. A weakening that breaks the build has measured nothing; reading it as "the
    controls held" would be the exact false green this lane exists to prevent."""
    import inspect

    assert "did not COMPILE" in inspect.getsource(lane.main)
    assert "return False, results" in inspect.getsource(lane.run_battery)


# --- "never ran" is a measurement failure, not a red result --------------------


def test_a_control_that_never_reported_is_not_red():
    """The defect this lane shipped with. `results.get(name, "never ran") != "ok"` made an
    ABSENT result satisfy the probe, so a weakening that stopped a test from being reported
    at all read as "the control caught it". The lane cannot conclude anything about a check
    from a test it did not watch run."""
    probe = _probe(expect_red=["tests/t#a", "tests/t#b"])
    missing, red = lane.adjudicate(probe, {})
    assert missing == ["tests/t#a", "tests/t#b"]
    assert red == []


def test_a_partially_reported_expectation_is_still_a_measurement_failure():
    """One control failing does not excuse another never executing: the probe named both,
    and the lane must say it could not measure one of them."""
    probe = _probe(expect_red=["tests/t#a", "tests/t#b"])
    missing, red = lane.adjudicate(probe, {"tests/t#a": "FAILED"})
    assert missing == ["tests/t#b"]
    assert red == ["tests/t#a"]


def test_an_ignored_control_is_not_a_red_one():
    """An `#[ignore]`d test printed a line but did not execute. Reading it as red is the
    same false green one level down — the case `verify-tests` already catches."""
    probe = _probe(expect_red=["tests/t#a"])
    missing, red = lane.adjudicate(probe, {"tests/t#a": "ignored"})
    assert missing == []
    assert red == []


def test_a_passing_control_is_not_red():
    probe = _probe(expect_red=["tests/t#a"])
    assert lane.adjudicate(probe, {"tests/t#a": "ok"}) == ([], [])


def test_main_reports_absence_as_measurement_failure_and_not_as_success():
    import inspect

    body = inspect.getsource(lane.main)
    assert "MEASUREMENT FAILURE" in body
    assert "missing, red = adjudicate(probe, results)" in body


# --- test identity is TARGET plus symbol ---------------------------------------


def test_a_same_named_test_in_another_target_does_not_satisfy_a_probe():
    """Test identity here is target + symbol, and this is exactly where flattening bites:
    two integration targets may each hold `body_tamper_fails_closed`, and a probe about the
    request floor must not be satisfied by the response one going red."""
    probe = _probe(expect_red=["tests/proof_path_test#body_tamper_fails_closed"])
    observed = {"tests/other_test#body_tamper_fails_closed": "FAILED"}
    missing, red = lane.adjudicate(probe, observed)
    assert red == []
    assert missing == ["tests/proof_path_test#body_tamper_fails_closed"]


def test_run_battery_keys_results_by_target_and_symbol():
    import inspect

    assert 'results[f"{target}#{name.strip()}"]' in inspect.getsource(lane.run_battery)


def test_every_registered_expectation_carries_its_target():
    """A bare symbol in the registry would be unmatchable against the target-qualified
    results, so this is both an identity rule and a liveness one.

    WHICH TARGETS ARE RUNNABLE IS THE ECOSYSTEM'S ANSWER, asked here rather than kept as a
    list. The literal `("lib#", "tests/", "gate#")` this used to carry was a cargo list, so
    the first `pytest#` expectation registered would have been refused by the lane's own
    test while the lane ran it correctly -- a rule drifting behind the thing it checks.
    `gate#` is not any ecosystem's target: it is this lane's own control form, resolved by
    `run_gates` rather than by a test runner, so it is named beside them.
    """
    from _ecosystems import ECOSYSTEMS, valid_target

    for probe in lane.load_probes():
        for name in probe["expect_red"]:
            assert "#" in name, (probe["id"], name)
            target, _, symbol = name.partition("#")
            assert symbol, (probe["id"], name)
            runnable = name.startswith("gate#") or any(
                valid_target(eco, target) for eco in ECOSYSTEMS
            )
            assert runnable, (probe["id"], name)


def test_a_doctest_control_may_not_be_expected_to_go_red():
    """`doc#` members are compile-fail controls; no runtime weakening moves one, so a probe
    naming it could never be satisfied honestly."""
    _expect_manifest_error(
        lambda: lane.declared_battery(
            UNITS,
            _probe(expect_red=["doc#verified_response::bound::VerifiedMcpResponse"]),
            "p",
        ),
        "a doctest control must be refused",
    )


# --- gate controls: a control that is a SCRIPT, not a test symbol ---------------
#
# ADR-MCPRE-068 Phase 1. The lane gained a second kind of control, so it gained the same
# catalogue of ways to report a green it did not measure — and one that is new: a gate is
# started by the lane rather than compiled into a battery, so "it did not start" and "it
# ran and held" are two facts a naive runner would collapse into one.


def test_expecting_a_gate_the_unit_does_not_declare_is_refused():
    """The same rule as a test symbol, and for the same reason: a gate outside the declared
    battery is not evidence for the theorem however red it goes."""
    _expect_manifest_error(
        lambda: lane.declared_battery(
            UNITS, _probe(expect_red=["gate#scripts/module_size_gate.py"]), "p"
        ),
        "a gate the unit does not declare must be refused",
    )


def test_a_declared_gate_control_resolves_as_a_battery_member():
    probe = _probe(
        unit="proxy.dispatch_commitment",
        expect_red=["gate#scripts/authorization_provenance_gate.py"],
    )
    _package, _grouped, _features, gates, _eco = lane.declared_battery(UNITS, probe, "p")
    assert "scripts/authorization_provenance_gate.py" in gates, gates


def test_a_gate_that_cannot_start_is_ABSENT_rather_than_RED():
    """The false RED this kind of control makes possible, which is the sharper one.

    A missing script is not a refusal. `python3 nothing.py` exits non-zero, so the obvious
    runner records `FAILED` — and a probe whose weakening DELETED or renamed the gate would
    then be satisfied by the control's disappearance. That is the mirror of the false green
    the adjudicator was already built to refuse: absence must never be a verdict, in either
    direction. MEASURED 2026-09-18 — the first version of this runner did exactly that, and
    this test is why it does not.
    """
    results = lane.run_gates(lane.REPO_ROOT, ["scripts/there_is_no_such_gate.py"])
    assert results == {}, results
    probe = _probe(expect_red=["gate#scripts/there_is_no_such_gate.py"])
    missing, red = lane.adjudicate(probe, results)
    assert missing == ["gate#scripts/there_is_no_such_gate.py"], missing
    assert red == [], red


def test_a_gate_that_CRASHED_is_absent_rather_than_red():
    """A non-zero exit is a refusal only when the gate reached a verdict.

    A weakening that breaks the gate's own parse exits non-zero exactly as a real finding
    does, and reading that as red would let a probe be satisfied by breaking the control
    instead of the check. The discriminator is the traceback, because that is the one thing
    a gate that reached a verdict never prints.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as raw:
        tree = Path(raw)
        (tree / "scripts").mkdir()
        (tree / "scripts/crasher.py").write_text("raise RuntimeError('broken gate')\n")
        assert lane.run_gates(tree, ["scripts/crasher.py"]) == {}
        # And a gate that refuses in the ordinary way IS red, so the rule above is a
        # discriminator rather than a blanket excuse.
        (tree / "scripts/refuser.py").write_text(
            "import sys\nprint('a finding')\nsys.exit(1)\n"
        )
        assert lane.run_gates(tree, ["scripts/refuser.py"]) == {
            "gate#scripts/refuser.py": "FAILED"
        }


def test_a_gate_reports_in_the_same_vocabulary_as_a_libtest_line():
    """The adjudicator asks one question of every control and must not learn where it came
    from, so a gate's exit status is translated at the boundary rather than special-cased
    downstream."""
    import subprocess

    ok = lane.run_gates(lane.REPO_ROOT, ["scripts/serving_product_provenance_gate.py"])
    assert ok == {"gate#scripts/serving_product_provenance_gate.py": "ok"}, ok
    # And the red half, measured rather than asserted: the gate's own selftest exits 0, so
    # a non-zero exit has to come from a real refusal. `--selftest` is used here only to
    # confirm the gate is the kind of thing that can refuse at all.
    proc = subprocess.run(
        [sys.executable, "scripts/serving_product_provenance_gate.py", "--selftest"],
        cwd=lane.REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr


def test_a_declared_gate_control_must_exist_in_the_tree():
    """A control the lane cannot run is not evidence, however it is described."""
    from _manifest import _validate_gate_controls

    _expect_manifest_error(
        lambda: _validate_gate_controls(
            "u", {"gate_controls": ["scripts/there_is_no_such_gate.py"]}
        ),
        "a gate control that is not a file must be refused",
    )
    # The registered ones pass, so the refusal above is about the missing file and not
    # about the check being unsatisfiable.
    _validate_gate_controls("u", UNITS["proxy.dispatch_commitment"])


def test_gate_controls_enter_the_unit_fingerprint():
    """Softening a rule is a reduction in evidence, so it must invalidate the attestation.

    The scripts cannot go in `paths` — a `.py` entry collapses a cargo unit's ecosystem —
    so the component is what carries them, and a unit that declares none must not gain an
    empty key: that would move all 156 fingerprints to record an absence.
    """
    import _fingerprint

    unit = UNITS["proxy.dispatch_commitment"]
    assert unit.get("gate_controls"), "the fixture unit must declare gate controls"
    source = inspect.getsource(_fingerprint)
    assert 'if unit.get("gate_controls"):' in source
    assert 'components["gate_controls"] = _digest_paths' in source


# --- the lane is inside the attestation closure --------------------------------


def test_the_unit_declares_mutation_evidence_so_attestation_depends_on_it():
    """Without the `mutation://` URI the probe suite is decoration: `attest` would issue
    `http_profile.request_floor_result` from the ordinary test evidence alone, and the CI job
    could be deleted with no unit ever deriving DIRTY."""
    from _evidence import required_lanes

    unit = UNITS["http_profile.request_floor_result"]
    assert lane.claims_mutation_evidence(unit)
    assert "mutation" in required_lanes(unit)


def test_attest_reads_the_mutation_lane():
    """A lane `attest` does not load refuses forever — a refusal no measurement can
    satisfy, which reads as a defect in the unit rather than an absent reader."""
    text = (lane.REPO_ROOT / "tools/verification/attest").read_text()
    assert '"test", "verus", "lean", "mutation"' in text


def test_a_partial_run_writes_no_evidence_record():
    """`--probe` measures part of the battery. A record from it would let "three probes
    passed" stand in for "the suite passed"."""
    import inspect

    assert "if not args.probe:" in inspect.getsource(lane.main)


def test_the_probe_set_participates_in_the_units_fingerprint():
    """A closure over a suite that can silently shrink proves as little as the v3 test
    component did: deleting a probe must invalidate the standing mutation PASS."""
    from _fingerprint import fingerprint_unit
    from _manifest import load_assumptions, load_toolchains, load_verification

    doc = load_verification()
    toolchains, assumptions = load_toolchains(), load_assumptions()
    unit = UNITS["http_profile.request_floor_result"]
    components = fingerprint_unit(unit, doc, toolchains, assumptions)["components"]
    scoped = [p for p in lane.load_probes() if p["unit"] == unit["id"]]
    assert len(components["mutation_probes"]) == len(scoped)
    assert components["mutation_lane_identity"], "the lane binary must be measured"

    # And SCOPED: another unit's probes must not enter this unit's fingerprint, or every
    # unit would be dirtied by every other unit's probe edits.
    other = UNITS["proxy.epoch_bound_session_store"]
    other_probes = fingerprint_unit(other, doc, toolchains, assumptions)["components"][
        "mutation_probes"
    ]
    assert set(other_probes).isdisjoint(components["mutation_probes"])
    assert other_probes


def test_a_selector_that_matches_nothing_is_a_FAIL():
    """`--probe M25` selects nothing, because every id is `M25-<what-it-weakens>`. That
    reported NOT_REQUIRED and exited 0, so a mistyped selector was indistinguishable from a
    tree with no probes to apply. An empty SELECTION and an empty REGISTRY are two facts."""
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(HERE / "verify-mutations"), "--probe", "M25"],
        cwd=lane.REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0, "a selector matching nothing must not exit 0"
    assert "VERDICT: FAIL" in proc.stdout, proc.stdout
    assert "selected NO registered probe" in proc.stderr, proc.stderr


def test_the_documented_matrix_count_is_checked_against_the_registry():
    """Prose is a claim. The blueprint's count drifted from 26 to 27 the first time this
    matrix was written by hand."""
    probes = lane.load_probes()
    assert lane.check_matrix_count(probes) is None
    documented = [p for p in probes if p["unit"] in lane.MATRIX_UNITS]
    assert lane.check_matrix_count(documented[:3]) is not None
    # Another unit's probes are not part of that section's count, so adding one must not
    # make the document look stale.
    assert lane.check_matrix_count(probes + [{"unit": "proxy.epoch_bound_session_store"}]) is None


# --- ADR-MCPRE-068 Phase 2: the lane reaches the two SDK roots -----------------
#
# Every case here is a way the extension could report redness it had not measured. The
# lane's rule does not change per ecosystem -- a control that did not run is not red --
# so each Rust case above has a counterpart the moment a second runner can be selected.


def _sdk_unit(prefix: str) -> tuple[str, dict]:
    """A real registered unit of that ecosystem, with a symbol of it, or skip the case.

    Read from the registry rather than invented: a fixture unit would prove the lane can
    run a shape nothing declares, which is the opposite of the property.
    """
    for uid, unit in sorted(UNITS.items()):
        if uid.startswith(prefix) and unit.get("tested_symbols"):
            return uid, unit
    raise AssertionError(f"no registered {prefix} unit with controls")


def test_a_python_unit_resolves_its_project_and_carries_its_ecosystem():
    """Resolution was never the blocker, and this pins that so the next reader does not
    re-remove a refusal that does not exist: `test_package_for` is ecosystem-aware and
    answers `sdk/python` here. What the battery needs from `declared_battery` is the
    ECOSYSTEM, because that is what decides how the selection is run."""
    from _manifest import test_package_for

    uid, unit = _sdk_unit("sdk_python.")
    assert test_package_for(unit), "the manifest resolves a project for an SDK unit"
    probe = _probe(unit=uid, expect_red=[unit["tested_symbols"][0]])
    package, grouped, _features, _gates, eco = lane.declared_battery(UNITS, probe, "p")
    assert package, "a python unit must resolve a project"
    assert eco is lane.PYTHON
    assert "pytest" in grouped, grouped


def test_a_typescript_unit_resolves_a_project_too():
    uid, unit = _sdk_unit("sdk_typescript.")
    probe = _probe(unit=uid, expect_red=[unit["tested_symbols"][0]])
    package, grouped, _features, _gates, eco = lane.declared_battery(UNITS, probe, "p")
    assert package, "a typescript unit must resolve a project"
    assert eco is lane.TYPESCRIPT
    assert "vitest" in grouped, grouped


def test_an_undeclared_control_is_still_refused_on_an_sdk_unit():
    """The declared-battery rule is the lane's, not cargo's. It must not have been lost
    with the ecosystem dispatch."""
    uid, _unit = _sdk_unit("sdk_python.")
    _expect_manifest_error(
        lambda: lane.declared_battery(
            UNITS, _probe(unit=uid, expect_red=["pytest#tests/nope.py::not_declared"]), "p"
        ),
        "an undeclared control must be refused whatever the ecosystem",
    )


def test_every_ecosystem_can_say_the_tree_did_not_build():
    """A weakening routinely breaks the build. If no marker matched for an ecosystem, that
    state would parse as zero results and then as controls that never ran -- which the
    adjudicator reports as a MEASUREMENT FAILURE, so it is not a false green, but it makes
    every probe over that ecosystem permanently unmeasurable."""
    for eco in (lane.CARGO, lane.PYTHON, lane.TYPESCRIPT):
        assert lane._DID_NOT_BUILD.get(eco), f"{eco.name} names no did-not-build marker"


def test_a_tree_that_did_not_build_is_not_red_in_any_ecosystem():
    """The false green this guards. If a broken tree read as `FAILED` for every control, a
    probe would be satisfied by BREAKING the tree rather than by weakening the property,
    and the redness would measure the compiler instead of the claim. Same rule, same
    reason, as a gate control that the weakening DELETED."""
    for eco, marker in (
        (lane.CARGO, "error[E0432]: unresolved import"),
        (lane.PYTHON, "ERROR collecting tests/test_mtls.py"),
        (lane.TYPESCRIPT, "Failed to load url ./transport"),
    ):
        assert lane._did_not_build(eco, marker), eco.name
        assert not lane._did_not_build(eco, "everything is fine"), eco.name


def test_an_unreadable_report_is_not_red():
    """`parse_results` raises when the runner collected cases and the reader understood
    none of them. That is the lane's own blindness; presenting it as a red battery would
    satisfy the probe with a parsing bug."""
    body = inspect.getsource(lane.run_battery)
    assert "except ReportUnreadable" in body
    assert body.index("except ReportUnreadable") < body.index("return True, results")


def test_the_battery_runs_through_the_same_seam_as_the_test_lane():
    """A control green in the test lane and unrunnable in this one would be two answers
    about one declared symbol. Both resolve the command and the report through
    `_ecosystems`, so there is one answer per ecosystem rather than one per tool."""
    body = inspect.getsource(lane.run_battery)
    assert "test_argv(eco," in body
    assert "parse_results(eco," in body


def test_a_non_cargo_battery_runs_inside_its_own_project():
    """pytest and vitest selections are relative to the project that holds their
    configuration; cargo is driven from the workspace root with `-p`. Running a pytest
    selection from the tree root would select nothing and report a green battery."""
    body = inspect.getsource(lane.run_battery)
    assert "cwd = tree / package" in body
    assert "cwd = tree\n" in body or "cwd = tree" in body


def test_an_absent_matrix_and_a_stale_artefact_are_different_refusals():
    """`prepare_scratch` returns a typed cause, and only one of them is skippable.

    An absent SDK matrix is an ENVIRONMENT fact -- the lean lane is reported the same way
    outside the extraction image. A probe that would weaken a source the carried binary was
    compiled from is a PROBE DEFECT: the battery would run old native code against a new
    declaration, and no flag may wave that through. Sharing one signal would make
    `--skip-unprepared` silently skip the defect too.
    """
    assert lane.UNPREPARED != lane.STALE
    body = inspect.getsource(lane.main)
    assert "cause == lane.UNPREPARED" in body or "cause == UNPREPARED" in body
    # The skip is conditioned on BOTH the cause and the flag, never on the flag alone.
    assert "args.skip_unprepared" in body
    guard = body[body.index("args.skip_unprepared") - 120 : body.index("args.skip_unprepared")]
    assert "UNPREPARED" in guard


def test_a_needed_artefact_is_looked_for_where_each_preparation_leaves_it():
    """The Python native module has TWO spellings, and the lane refused CI over knowing one.

    `maturin develop` leaves `_core.abi3.so` beside the package in the source tree;
    `prepare_python_matrix.sh` -- the form the verification workflow runs, and the one that
    pins an environment per supported interpreter -- builds a WHEEL and installs it, so the
    tree has no `.so` at all. A lane that knew only the first spelling reported a correctly
    prepared runner as an unbuilt environment and failed every Python probe on it.

    Asked over the declared candidates rather than by running a probe, so it states the rule
    instead of re-measuring one environment: the tree spelling is FIRST (a developer's own
    build wins over an installed one), and an installed spelling follows it.
    """
    candidates = lane._SCRATCH_NEEDS[lane.PYTHON]["python/mcp_re_sdk/_core.abi3.so"]
    assert candidates[0] == "python/mcp_re_sdk/_core.abi3.so", candidates
    assert any("site-packages" in spelling for spelling in candidates[1:]), candidates
    # And whichever is found, the battery imports it from the tree layout: the INSTALL path
    # is the first spelling, so a probe measures one layout in both environments.
    found = lane._first_present(
        lane.REPO_ROOT / "sdk/python",
        "python/mcp_re_sdk/_core.abi3.so",
        ("does/not/exist", *candidates),
    )
    assert found, "neither spelling is present in this workspace"
    for _source, relative in found:
        assert relative == "python/mcp_re_sdk/_core.abi3.so", relative


def test_an_unavailable_probe_is_named_in_the_verdict_line():
    """A skipped probe that did not appear in the verdict would let this job's green be
    read as "every registered probe was applied", which is the false green the whole lane
    exists to refuse -- one level up."""
    body = inspect.getsource(lane.main)
    assert "UNAVAILABLE in this environment" in body
    assert "unavailable.append" in body


def test_the_fast_job_declares_what_it_skips():
    """The workflow step was called "Apply every registered probe". With the flag that
    sentence is false, and a step name is what a reader takes the job to have measured."""
    workflow = (lane.REPO_ROOT / ".github/workflows/mutation-probe.yml").read_text()
    assert "--skip-unprepared" in workflow
    assert "Apply every registered probe" not in workflow


def test_skipping_every_probe_is_not_a_pass():
    """`--skip-unprepared` reintroduced the exact shape this lane set is ratified against:
    every probe skipped, nothing weakened, nothing observed, and a green verdict. Measured
    by hiding `node_modules` and running the flag -- it printed `PASS -- 0 probe(s)`."""
    body = inspect.getsource(lane.main)
    assert "measured == 0" in body
    assert "VERDICT: UNAVAILABLE" in body
    # And the pass branch is reached only after that check.
    assert body.index("measured == 0") < body.index("verify-mutations: PASS")


def test_the_refusal_names_a_script_that_exists():
    """The message derived the filename from the ecosystem name, so TypeScript's refusal
    told a reader to run `prepare_typescript_matrix.sh`. There is no such file -- the Node
    matrix is built by `prepare_node_matrix.sh` -- and a confident pointer to a file that
    does not exist is worse than none."""
    for eco, script in lane._MATRIX_SCRIPT.items():
        assert (lane.REPO_ROOT / script).is_file(), (eco.name, script)


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
