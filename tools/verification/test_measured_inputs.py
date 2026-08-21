# SPDX-License-Identifier: Apache-2.0
"""What the platform claims to have measured, and what it actually compared.

Three separate places the platform reported an established property over inputs nothing
had looked at:

  * the ReviewFingerprint recorded constant sentinels for whole components, so the
    freshness derivation compared them, found them equal, and answered FRESH over inputs it
    had never seen;
  * the fingerprint covered a unit's DECLARED paths while the Verus lane verified the whole
    crate, so source inside the proof cone could change without moving any component;
  * `verify --gate` exited 0 on INCOMPLETE, so the only gating CI step passed for a run in
    which no required lane produced formal evidence;
  * `max_class_without_assumption` was validated as a string and enforced nowhere, so a
    unit could claim V1 over a boundary capped at V0.

Run: python3 tools/verification/test_measured_inputs.py
"""

from __future__ import annotations

import importlib.util
import re
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _fingerprint import fingerprint_unit  # noqa: E402
from _manifest import (  # noqa: E402
    boundary_class_violations,
    load_assumptions,
    load_toolchains,
    load_trust_boundaries,
    load_verification,
)

_loader = SourceFileLoader("verify_cli", str(HERE / "verify"))
_spec = importlib.util.spec_from_loader("verify_cli", _loader)
verify_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(verify_cli)

DOC = load_verification()
TOOLCHAINS = load_toolchains()
ASSUMPTIONS = load_assumptions()
UNITS = {unit["id"]: unit for unit in DOC.get("unit", [])}


def components(unit_id: str) -> dict:
    return fingerprint_unit(UNITS[unit_id], DOC, TOOLCHAINS, ASSUMPTIONS)["components"]


# --- no component is a constant -----------------------------------------------


def test_no_component_is_a_sentinel():
    """A constant compares equal on every run. Three components were recorded as the
    literal string "unimplemented" while the module documented them as read UNKNOWN and
    therefore dirty — two whole fail-closed inputs that were inert."""
    for unit_id in UNITS:
        for name, value in components(unit_id).items():
            assert value != "unimplemented", f"{unit_id}.{name}"


def test_the_build_configuration_is_measured_and_names_the_lockfile():
    """A dependency swap, a lockfile bump or a toolchain channel change alters what a
    theorem is about without touching the source a unit declares."""
    build = components("http_profile.freshness_window")["build_configuration"]
    assert "Cargo.lock" in build
    assert "rust-toolchain.toml" in build
    assert "mcp-re-http-profile/Cargo.toml" in build
    assert all(digest.startswith("sha256:") for digest in build.values())


# --- the fingerprint covers the cone the LANE measures ------------------------


def test_a_formal_units_fingerprint_covers_the_whole_verified_crate():
    """`cargo verus verify -p <crate>` verifies the crate, not the four files the unit
    lists. `check_params` quantifies over `SignatureParams`, defined in sigbase.rs, which no
    unit declares: editing it changed what the theorem says while every component stayed
    identical and the graph answered FRESH."""
    source = components("http_profile.freshness_window")["source_inputs"]
    assert "mcp-re-http-profile/src/sigbase.rs" in source
    assert "mcp-re-http-profile/src/verify.rs" in source


def test_a_formal_units_proof_dependencies_reach_the_verified_dependency_closure():
    """The `verify` feature travels down the path-dependency closure, so the prover checks
    mcp-re-core as part of the run an http-profile unit claims."""
    deps = components("http_profile.freshness_window")["proof_dependencies"]
    assert "mcp-re-core/src/time.rs" in deps
    assert not any(path.startswith("mcp-re-http-profile/") for path in deps)


def test_an_ordinary_unit_is_not_given_a_whole_crate_cone():
    """A V0 unit's evidence is not a whole-crate prover run, so its fingerprint must not
    claim one — that would report the unit dirty for unrelated crate churn."""
    source = components("proxy.runtime_lifecycle")["source_inputs"]
    assert list(source) == ["mcp-re-proxy/src/runtime_state.rs"]


def test_the_effective_test_selection_is_measured_not_only_its_uri():
    """A `test://` URI is a LABEL. Until encoding v4 it was the only test component, so a
    battery could fall from 67 declared controls to 5 — or move to another Cargo package —
    with the URI, and therefore the fingerprint, unchanged."""
    selection = components("http_profile.verifier_results")["test_selection"]
    assert selection["package"] == "mcp-re-http-profile"
    assert len(selection["symbols"]) > 50
    assert (
        "tests/full_profile_test#a_target_uri_disagreeing_with_the_audience_tuple_fails"
        in selection["symbols"]
    )


def test_dropping_a_declared_control_moves_the_fingerprint():
    """The property the previous encoding did not have. Shrinking the battery must be
    visible, or a unit can lose its negative controls and stay FRESH."""
    unit = dict(UNITS["http_profile.verifier_results"])
    before = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS)["fingerprint"]
    unit["tested_symbols"] = unit["tested_symbols"][:5]
    after = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS)["fingerprint"]
    assert before != after


def test_moving_the_battery_to_another_package_moves_the_fingerprint():
    """`test_package` selects which package the lane runs in, so it decides what was
    measured; a fingerprint blind to it would let the measurement move under a standing
    attestation."""
    unit = dict(UNITS["http_profile.verifier_results"])
    before = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS)["fingerprint"]
    unit["test_package"] = "mcp-re-core"
    after = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS)["fingerprint"]
    assert before != after


def test_the_integration_test_sources_are_measured_not_only_their_names():
    """A control can keep its declared name and lose its body: the selector still resolves,
    the lane still reports a pass. The name is the label; the file is the evidence."""
    sources = components("http_profile.verifier_results")["test_sources"]
    assert "mcp-re-http-profile/tests/delegation_e2e_test.rs" in sources
    assert "mcp-re-http-profile/tests/proof_path_test.rs" in sources
    assert "mcp-re-http-profile/tests/full_profile_test.rs" in sources
    assert "mcp-re-http-profile/tests/algorithm_confusion_test.rs" in sources
    assert all(digest.startswith("sha256:") for digest in sources.values())
    # A target the unit does not select is not measured: the component is the unit's
    # evidence, not the package's test directory.
    assert "mcp-re-http-profile/tests/rfc9421_kat.rs" not in sources


def test_in_crate_selectors_are_covered_by_the_units_own_paths():
    """`lib#`/`doc#` selectors are deliberately absent from `test_sources` because they
    execute inside files `source_inputs` already digests. That is only safe because the
    manifest loader REFUSES a selector whose module the unit does not declare."""
    from _manifest import ManifestError, _validate_in_crate_selectors

    unit = {
        "paths": ["mcp-re-http-profile/src/verify.rs"],
        "tested_symbols": ["lib#rejection::tests::unbound_rejection_verifies"],
    }
    try:
        _validate_in_crate_selectors("unit[0]", unit)
    except ManifestError:
        pass
    else:
        raise AssertionError("an undeclared in-crate module must be refused")

    unit["paths"].append("mcp-re-http-profile/src/rejection.rs")
    _validate_in_crate_selectors("unit[0]", unit)

    # A module DIRECTORY resolves through any prefix of the selector's path.
    nested = {
        "paths": ["mcp-re-http-profile/src/verified_response/bound.rs"],
        "tested_symbols": ["doc#verified_response::bound::VerifiedMcpResponse"],
    }
    _validate_in_crate_selectors("unit[0]", nested)


def test_the_test_lane_instrument_is_part_of_the_evidence_identity():
    """The meaning of a `doc#` selector, and of `test_package`, is decided by the lane's
    own code. Evidence whose measuring instrument changed is evidence whose meaning
    changed — the same argument that puts the toolchain in the fingerprint."""
    lane = components("http_profile.verifier_results")["test_lane_identity"]
    assert set(lane) == {
        "tools/verification/verify-tests",
        "tools/verification/_manifest.py",
    }
    assert all(digest.startswith("sha256:") for digest in lane.values())


def test_the_probe_set_is_measured_so_the_suite_cannot_silently_shrink():
    """`mutation://` puts the probe suite inside the attestation closure, but a closure
    over a suite that can shrink proves as little as the v3 test component did. Each probe
    entry is digested WHOLE, so softening a weakening or widening an `expect_red` moves the
    fingerprint and invalidates the standing mutation PASS."""
    probes = components("http_profile.verifier_results")["mutation_probes"]
    assert len(probes) > 20
    assert all(digest.startswith("sha256:") for digest in probes.values())
    lane = components("http_profile.verifier_results")["mutation_lane_identity"]
    assert set(lane) == {"tools/verification/verify-mutations"}


def test_a_unit_without_mutation_evidence_measures_no_mutation_components():
    """Empty, and measured as empty: a unit with no probe suite must not be dirtied by
    another unit's probes, and the component must not become a sentinel."""
    c = components("http_profile.keyid")
    assert c["mutation_probes"] == {}
    assert c["mutation_lane_identity"] == {}


def test_a_unit_without_test_evidence_measures_no_test_components():
    """Empty, and measured as empty — a Verus-only unit must not be dirtied by test-lane
    churn, and the component must not silently become a sentinel either."""
    unit = {
        "id": "x",
        "class": "V0",
        "paths": ["mcp-re-core/src/time.rs"],
        "evidence": ["verus://core/time/x"],
    }
    c = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS)["components"]
    assert c["test_selection"] == {}
    assert c["test_sources"] == {}
    assert c["test_lane_identity"] == {}


def test_an_assumptions_content_participates_not_only_its_id():
    """Recording ids alone let an assumption be rewritten — its description widened, its
    mechanism swapped — without any unit deriving DIRTY_ASSUMPTION."""
    trusted = components("core.time_rfc3339")["trusted_assumptions"]
    assert set(trusted) == {"ASM-0001", "ASM-0002", "ASM-0003", "ASM-0004"}
    assert all(digest.startswith("sha256:") for digest in trusted.values())

    widened = {
        "assumption": [
            dict(entry, description="anything at all")
            for entry in ASSUMPTIONS.get("assumption", [])
        ]
    }
    after = fingerprint_unit(UNITS["core.time_rfc3339"], DOC, TOOLCHAINS, widened)
    assert after["components"]["trusted_assumptions"] != trusted


# --- the exit code CI reads ----------------------------------------------------


def test_only_pass_exits_zero_under_gate():
    """FV-01 at the exit-code boundary: a SKIPPED or NOT_REQUIRED lane must never count
    toward a pass, and INCOMPLETE is exactly the aggregate those produce."""
    assert verify_cli.gate_exit_code("PASS", True) == 0
    assert verify_cli.gate_exit_code("FAIL", True) == 1
    assert verify_cli.gate_exit_code("INCOMPLETE", True) == 1


def test_report_only_mode_never_fails_the_build():
    for aggregate in ("PASS", "FAIL", "INCOMPLETE"):
        assert verify_cli.gate_exit_code(aggregate, False) == 0


# --- the boundary a unit's paths cross -----------------------------------------


BOUNDARIES = {
    "boundary": [
        {
            "id": "boundary.clock",
            "description": "d",
            "kind": "environment",
            "paths": ["mcp-re-core/src/time.rs"],
            "beyond": "b",
            "max_class_without_assumption": "V0",
        }
    ]
}

CROSSING_UNIT = {
    "unit": [
        {"id": "u", "class": "V1", "paths": ["mcp-re-core/src/time.rs"]},
    ]
}


def scoped(*targets):
    return {"assumption": [{"id": "ASM-X", "scope": list(targets)}]}


def test_a_unit_promoted_past_a_crossed_boundarys_cap_is_a_violation():
    violations = boundary_class_violations(CROSSING_UNIT, BOUNDARIES, scoped())
    assert len(violations) == 1
    assert "boundary.clock" in violations[0]


def test_scoping_an_assumption_to_the_unit_alone_does_not_cover_the_crossing():
    """The ordinary unit scope says nothing about which boundary the assumption discharges,
    so accepting it would make the cap unenforceable the moment a unit had any assumption."""
    violations = boundary_class_violations(
        CROSSING_UNIT, BOUNDARIES, scoped("unit://u")
    )
    assert len(violations) == 1


def test_an_assumption_naming_both_the_unit_and_the_boundary_covers_it():
    violations = boundary_class_violations(
        CROSSING_UNIT, BOUNDARIES, scoped("unit://u", "boundary://boundary.clock")
    )
    assert violations == []


def test_a_unit_at_or_below_the_cap_is_not_a_violation():
    below = {"unit": [{"id": "u", "class": "V0", "paths": ["mcp-re-core/src/time.rs"]}]}
    assert boundary_class_violations(below, BOUNDARIES, scoped()) == []


def test_a_unit_whose_paths_do_not_cross_the_boundary_is_untouched():
    elsewhere = {
        "unit": [{"id": "u", "class": "V1", "paths": ["mcp-re-core/src/hash.rs"]}]
    }
    assert boundary_class_violations(elsewhere, BOUNDARIES, scoped()) == []


# --- boundary.clock models the authority, not a snapshot of the manifest -------
#
# The synthetic cases above prove the CAP is enforced. These prove the DECLARATION is
# true of the source tree — the half that was wrong for as long as the cap was inert:
# boundary.clock named mcp-re-core/src/time.rs, which holds no clock authority, and named
# none of the sixteen production sites that do. Fixing the manifest alone would leave the
# relationship untested and free to drift back on the next file that reads a clock.

REPO = HERE.parent.parent
BOUNDARIES_REAL = load_trust_boundaries()

# Acquisition is `SystemTime::now()` — the call that asks the OS what time it is.
# UNIX_EPOCH alone is NOT the signal: it also appears where an already-supplied
# SystemTime is converted (mcp-re-proxy/src/ocsp.rs), which is transformation.
ACQUIRES = "SystemTime::now()"


def _clock_boundary() -> dict:
    for boundary in BOUNDARIES_REAL["boundary"]:
        if boundary["id"] == "boundary.clock":
            return boundary
    raise AssertionError("boundary.clock is not declared")


def _production_source(path) -> str:
    """A file's source with every `#[cfg(test)]`-attributed item removed.

    A test module reading the clock is not a production clock authority, and counting one
    would make the boundary grow on test code.

    Removing items INDIVIDUALLY is the whole correctness argument. Truncating at the first
    `#[cfg(test)]` looks equivalent and is not: an inline `#[cfg(test)]` on a helper
    appears at ocsp.rs:248, and truncating there discards the production
    `SystemTime::now()` at ocsp.rs:322 -- so the boundary silently lost a real clock
    acquisition site while this test reported agreement. Fifteen files in the workspace
    carry such an early attribute.
    """
    lines = path.read_text(errors="replace").split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        if not lines[i].strip().startswith("#[cfg(test)]"):
            out.append(lines[i])
            i += 1
            continue
        j = i + 1
        while j < len(lines) and "{" not in lines[j] and not lines[j].rstrip().endswith(";"):
            j += 1
        if j < len(lines) and "{" not in lines[j] and lines[j].rstrip().endswith(";"):
            i = j + 1  # an attributed `use ...;` / one-line item
            continue
        depth, seen = 0, False
        while j < len(lines):
            stripped = re.sub(r'"(?:\\.|[^"\\])*"', '""', lines[j])
            stripped = re.sub(r"//.*", "", stripped)
            for ch in stripped:
                if ch == "{":
                    depth += 1
                    seen = True
                elif ch == "}":
                    depth -= 1
            if seen and depth <= 0:
                break
            j += 1
        i = j + 1
    return "\n".join(out)


def _acquisition_sites() -> set[str]:
    found = set()
    for path in sorted(REPO.glob("mcp-re-*/src/**/*.rs")):
        if ACQUIRES in _production_source(path):
            found.add(str(path.relative_to(REPO)))
    return found


def test_the_clock_boundary_names_every_acquisition_site():
    """Every production `SystemTime::now()` site is declared, and nothing else is.

    This is the test that makes the boundary model the AUTHORITY rather than the three
    grep hits that happened to be obvious on the day it was written. A new file that
    reads the OS clock fails here until it is declared."""
    declared = set(_clock_boundary()["paths"])
    actual = _acquisition_sites()
    assert not (actual - declared), (
        f"undeclared wall-clock acquisition site(s): {sorted(actual - declared)}"
    )
    assert not (declared - actual), (
        f"declared but acquires no wall-clock time: {sorted(declared - actual)}"
    )


def test_timestamp_transformation_is_outside_the_clock_boundary():
    """The original defect, pinned. mcp-re-core/src/time.rs converts RFC 3339 text to
    Unix seconds and holds no clock authority — ADR-MCPS-006 pushes timestamps to
    callers, and ADR-MCPS-011/012 purity means the crate cannot read a clock at all."""
    assert "mcp-re-core/src/time.rs" not in _clock_boundary()["paths"]
    core = (REPO / "mcp-re-core" / "src" / "time.rs").read_text()
    assert ACQUIRES not in core
    assert "UNIX_EPOCH" not in core


def test_a_known_acquisition_site_is_classified_as_crossing():
    """The positive control. mcp-re-host/src/clock.rs IS the injected wall-clock seam, so
    a V1 unit over it must be refused — the same verdict time.rs used to get wrongly."""
    unit = {
        "unit": [
            {"id": "u", "class": "V1", "paths": ["mcp-re-host/src/clock.rs"]},
        ]
    }
    violations = boundary_class_violations(unit, BOUNDARIES_REAL, scoped())
    assert len(violations) == 1, violations
    assert "boundary.clock" in violations[0]


def test_the_preserved_unit_is_still_v1_and_assumes_nothing_about_a_clock():
    """core.time_rfc3339 keeps its class and gains no fictitious assumption. Repairing the
    boundary must not have been paid for out of the unit's evidence."""
    unit = UNITS["core.time_rfc3339"]
    assert unit["class"] == "V1"
    assert boundary_class_violations({"unit": [unit]}, BOUNDARIES_REAL, ASSUMPTIONS) == []
    for entry in ASSUMPTIONS.get("assumption", []):
        scope = [str(target) for target in entry.get("scope", [])]
        if "unit://core.time_rfc3339" in scope:
            assert "boundary://boundary.clock" not in scope, entry["id"]


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
