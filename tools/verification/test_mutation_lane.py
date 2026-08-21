# SPDX-License-Identifier: Apache-2.0
"""The mutation lane's own false-green catalogue.

The lane exists to prove that a claimed conjunct is load-bearing. Every way it could report
that without having proved it is a case below:

  * a probe whose anchor matches zero or two sites has not identified the check it claims
    to have broken;
  * a probe expecting a control the unit does not DECLARE would prove something about a
    test that is not evidence for the theorem;
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
