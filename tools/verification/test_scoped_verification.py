# SPDX-License-Identifier: Apache-2.0
"""Scoped verification — a pull request measures the units it affects, and says so.

`select-units` decides the scope; `verify --units-file` confines the scoped lanes and the
composer to it; every scoped lane takes `--unit` with one semantics (`_unit_selection`).
The properties pinned here, each with the control that shows it can fail:

  * the selection is exactly the moved units plus their prerequisite consumers — and
    empty when nothing moved, which is a stated result rather than a quiet one;
  * a change to the platform itself selects a FULL run, never a scope;
  * a scoped run can never leave a bundle that reads as a repository PASS, so `attest`
    cannot issue from a pull-request check;
  * a `--unit` that names nothing, or a unit the lane owes nothing, is FAIL in every lane.

Run: python3 tools/verification/test_scoped_verification.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _compose import Requirement, within  # noqa: E402
from _evidence import decide_issuance, load_bundle, write_bundle  # noqa: E402
from _load_tool import load_tool  # noqa: E402
from _unit_selection import selection_error  # noqa: E402

select_units = load_tool("select-units")
verify = load_tool("verify")

EDGES = [
    {"kind": "PROOF_DEPENDENCY", "from": "a", "to": "b"},
    {"kind": "COMPILE_DEPENDENCY", "from": "b", "to": "c"},
    # REVIEW_CONTEXT never propagates invalidation, so it must not widen the scope.
    {"kind": "REVIEW_CONTEXT", "from": "a", "to": "z"},
]


# --- the selection ---------------------------------------------------------------------


def test_a_moved_fingerprint_is_selected_and_an_unmoved_one_is_not():
    moved = select_units.moved({"a": "1", "b": "2"}, {"a": "1", "b": "X"})
    assert moved == {"b"}, moved


def test_a_unit_new_at_head_is_selected():
    assert select_units.moved({"a": "1"}, {"a": "1", "n": "9"}) == {"n"}


def test_consumers_are_selected_transitively_over_prerequisite_edges():
    assert select_units.consumer_closure({"a"}, EDGES) == {"a", "b", "c"}


def test_review_context_does_not_widen_the_scope():
    closure = select_units.consumer_closure({"a"}, EDGES)
    assert "z" not in closure, closure
    # Control: the same unit IS reached when the edge propagates.
    propagating = [{"kind": "PROOF_DEPENDENCY", "from": "a", "to": "z"}]
    assert "z" in select_units.consumer_closure({"a"}, propagating)


def test_a_change_to_the_platform_forces_a_full_run():
    for path in (
        "tools/verification/verify",
        "tools/verification/select-units",
        ".github/workflows/verification.yml",
        ".github/workflows/mutation-probe.yml",
    ):
        assert select_units.full_run_reason([path]), path
    # Control: an ordinary source change is scoped, not full.
    assert select_units.full_run_reason(["mcp-re-core/src/lib.rs"]) is None


def test_lane_narrowing_keeps_exactly_the_units_the_lane_is_required_for():
    from _manifest import load_verification

    doc = load_verification()
    every = {unit["id"] for unit in doc["unit"]}
    verus = {unit["id"] for unit in doc["unit"] if unit["class"] in {"V1", "V3"}}
    assert select_units.required_of("verus", every) == verus
    assert verus, "a control over an empty Verus set proves nothing"
    # Narrowing never adds a unit that was not affected.
    one = sorted(verus)[0]
    assert select_units.required_of("verus", {one}) == {one}
    assert select_units.required_of("verus", set()) == set()


def test_an_uncomputable_scope_is_a_full_run_never_an_empty_one():
    mode, units, why = select_units.select("no-such-revision-anywhere")
    assert mode == "full" and not units, (mode, units)
    assert "could not be computed" in why, why


def test_the_real_tree_against_itself_selects_nothing_and_says_so():
    with tempfile.TemporaryDirectory() as scratch:
        out = Path(scratch) / "units"
        completed = subprocess.run(
            [sys.executable, str(HERE / "select-units"), "--base", "HEAD", "--out", str(out)],
            capture_output=True, text=True, check=False,
        )
        assert completed.returncode == 0, completed.stderr
        # Only a clean checkout is "itself"; with local edits to lane code, every unit whose
        # fingerprint carries that lane moves, which is the property working as designed.
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "."],
            capture_output=True, text=True, check=True, cwd=HERE.parents[1],
        ).stdout.strip()
        if not dirty:
            assert out.read_text(encoding="utf-8") == "", out.read_text(encoding="utf-8")
            assert "0 of" in completed.stdout, completed.stdout


# --- the composer and the bundle ------------------------------------------------------


def test_a_scope_narrows_requirements_to_its_units_and_only_those():
    required = [Requirement("test", "a", "f1"), Requirement("test", "b", "f2")]
    assert within(required, frozenset({"a"})) == [required[0]]
    assert within(required, frozenset()) == []
    # Control: no scope is the whole manifest.
    assert within(required, None) == required


def test_a_scoped_run_never_bundles_a_pass():
    scoped = verify.RunOutcome(0, "PASS", {"test": "PASS"}, ("a",))
    assert scoped.bundle_aggregate() == "INCOMPLETE"
    # Control: the same PASS from a full run is bundled as PASS.
    full = verify.RunOutcome(0, "PASS", {"test": "PASS"})
    assert full.bundle_aggregate() == "PASS"


def test_the_scoped_bundle_records_its_scope_and_the_full_one_does_not():
    with tempfile.TemporaryDirectory() as scratch:
        store = Path(scratch)
        write_bundle(store, "INCOMPLETE", {}, "rev", scope=("a", "b"))
        assert load_bundle(store)["scope"] == ["a", "b"]
        write_bundle(store, "PASS", {}, "rev")
        assert "scope" not in load_bundle(store)


def test_attest_issues_nothing_from_what_a_scoped_run_bundles():
    unit = [{"id": "a", "class": "V1", "evidence": ["verus://x"]}]
    current = {"a": {"fingerprint": "fp"}}
    from _evidence import EvidenceRecord

    records = {"verus": {"a": EvidenceRecord("a", "verus", "pass", "fp")}}
    scoped = verify.RunOutcome(0, "PASS", {"verus": "PASS"}, ("a",)).bundle_aggregate()
    decision = decide_issuance(unit, [], current, records, scoped)["a"][0]
    assert decision != "ISSUE_PASS", decision
    # Control: the identical evidence under a full run's PASS IS issued, so the refusal
    # above is the scope's doing and not a defect in the fixture.
    assert decide_issuance(unit, [], current, records, "PASS")["a"][0] == "ISSUE_PASS"


# --- the lanes' shared --unit semantics ------------------------------------------------


def test_an_undeclared_unit_is_refused():
    assert "no declared unit" in selection_error(["nope"], {"a"}, {"a"}, "x")


def test_a_unit_owing_the_lane_nothing_is_refused():
    assert "owing no" in selection_error(["a"], {"a", "b"}, {"b"}, "x")
    # Control: a unit the lane does measure is accepted.
    assert selection_error(["b"], {"a", "b"}, {"b"}, "x") is None


def _lane(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HERE / script), *args],
        capture_output=True, text=True, check=False,
    )


def test_every_scoped_lane_refuses_an_undeclared_unit_as_fail():
    for script in ("verify-mutations", "verify-structural", "verify-measured", "verify-verus"):
        completed = _lane(script, "--unit", "no.such.unit")
        assert completed.returncode != 0, (script, completed.stdout)
        assert "VERDICT: FAIL" in completed.stdout, (script, completed.stdout, completed.stderr)
        assert "no declared unit" in completed.stderr, (script, completed.stderr)


def test_the_scopable_lanes_are_exactly_the_lanes_that_take_unit():
    for name, script, _formal in verify.LANES:
        help_text = _lane(script, "--help").stdout
        assert ("--unit" in help_text) == (name in verify.SCOPABLE_LANES), (name, script)


def test_units_file_is_refused_on_the_full_sweep():
    with tempfile.TemporaryDirectory() as scratch:
        units = Path(scratch) / "units"
        units.write_text("", encoding="utf-8")
        completed = _lane("verify", "--units-file", str(units))
        assert completed.returncode != 0
        assert "--units-file scopes" in completed.stderr, completed.stderr


def test_units_file_naming_an_undeclared_unit_is_refused():
    with tempfile.TemporaryDirectory() as scratch:
        units = Path(scratch) / "units"
        units.write_text("no.such.unit\n", encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(HERE / "verify"), "--aggregate", "--units-file", str(units)],
            capture_output=True, text=True, check=False,
            env={**__import__("os").environ, "MCP_RE_EVIDENCE_DIR": scratch},
        )
        assert completed.returncode != 0
        assert "undeclared unit" in completed.stderr, completed.stderr
        # The refusal still leaves a bundle, and it is not a pass.
        assert json.loads((Path(scratch) / "bundle.json").read_text())["aggregate"] == "FAIL"


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
