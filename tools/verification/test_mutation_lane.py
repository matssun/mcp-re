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
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

_LOADER = SourceFileLoader("verify_mutations_lane", str(HERE / "verify-mutations"))
_SPEC = importlib.util.spec_from_loader("verify_mutations_lane", _LOADER)
assert _SPEC is not None
lane = importlib.util.module_from_spec(_SPEC)
_LOADER.exec_module(lane)

from _manifest import ManifestError, load_verification  # noqa: E402

UNITS = {unit["id"]: unit for unit in load_verification().get("unit", [])}


def _probe(**overrides):
    probe = {
        "id": "T-01",
        "unit": "http_profile.verifier_results",
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
    source = (lane.REPO_ROOT / "mcp-re-http-profile/src/verify.rs").read_text()
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
    assert "copy_tree(tree)" in body
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
    results, so this is both an identity rule and a liveness one."""
    for probe in lane.load_probes():
        for name in probe["expect_red"]:
            assert name.startswith(("lib#", "tests/")), (probe["id"], name)
            assert "#" in name, (probe["id"], name)


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


# --- the lane is inside the attestation closure --------------------------------


def test_the_unit_declares_mutation_evidence_so_attestation_depends_on_it():
    """Without the `mutation://` URI the probe suite is decoration: `attest` would issue
    `http_profile.verifier_results` from the ordinary test evidence alone, and the CI job
    could be deleted with no unit ever deriving DIRTY."""
    from _evidence import required_lanes

    unit = UNITS["http_profile.verifier_results"]
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
    unit = UNITS["http_profile.verifier_results"]
    components = fingerprint_unit(unit, doc, toolchains, assumptions)["components"]
    assert len(components["mutation_probes"]) == len(lane.load_probes())
    assert components["mutation_lane_identity"], "the lane binary must be measured"


def test_the_documented_matrix_count_is_checked_against_the_registry():
    """Prose is a claim. The blueprint's count drifted from 26 to 27 the first time this
    matrix was written by hand."""
    assert lane.check_matrix_count(lane.load_probes()) is None
    assert lane.check_matrix_count(lane.load_probes()[:3]) is not None


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
