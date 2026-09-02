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
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _load_tool import load_tool  # noqa: E402

from _fingerprint import fingerprint_unit  # noqa: E402
from _manifest import (  # noqa: E402
    assumption_scope_defects,
    boundary_class_violations,
    load_assumptions,
    load_toolchains,
    load_trust_boundaries,
    load_verification,
    unit_assumptions,
)

verify_cli = load_tool('verify', 'verify_cli')

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
    assert "mcp-re-http-profile/src/verify/floor/params.rs" in source


def test_the_proof_dependency_closures_manifests_are_measured_too():
    """R9-C039 / R9-C040. `proof_dependencies` digests the SOURCE of the crates the prover
    compiles alongside this one, and nothing digested their manifests — so the `verify`
    feature could stop travelling down the closure, or a dependency of a dependency could be
    swapped, and the unit still derived FRESH over a prover run that had checked something
    else. The source of a crate and the manifest that decides what that crate IS are the
    same input to this question."""
    build = components("http_profile.freshness_window")["build_configuration"]
    assert "mcp-re-core/Cargo.toml" in build, build
    assert "mcp-re-http-profile/Cargo.toml" in build
    # And a V0 unit is not given the closure: its evidence is not a prover run, so a
    # dependency manifest it never compiles against must not dirty it.
    assert "mcp-re-core/Cargo.toml" not in components("proxy.runtime_lifecycle")["build_configuration"]


def test_a_formal_units_proof_dependencies_reach_the_verified_dependency_closure():
    """The `verify` feature travels down the path-dependency closure, so the prover checks
    mcp-re-core as part of the run an http-profile unit claims."""
    deps = components("http_profile.freshness_window")["proof_dependencies"]
    assert "mcp-re-core/src/time/mod.rs" in deps
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


def test_dropping_a_test_feature_moves_the_fingerprint():
    """A feature-gated control does not fail without its feature — it does not EXIST. So a
    unit that drops a feature loses every control behind it while the symbol list, the
    package and the source digests all stand still. Encoding v7 puts the feature set in
    `test_selection` for the same reason v4 put the symbols there: the battery must not be
    able to shrink to whatever the default crate still contains."""
    unit = dict(UNITS["proxy.outbound_destination"])
    assert unit["test_features"], "this unit's claim is measured under named features"
    before = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS)["fingerprint"]
    unit["test_features"] = [f for f in unit["test_features"] if f != "online_ocsp"]
    after = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS)["fingerprint"]
    assert before != after
    assert "online_ocsp" not in components("proxy.kms_endpoint_authority")["test_selection"]["features"]


def test_a_credential_egress_claim_is_measured_in_the_crate_that_compiles_it():
    """The evidence-closure repair behind THM-0090. The redirect control and the
    capability's single addressing surface are behind the features that link an HTTP
    client, and the single-producer control is behind the two backends. A unit citing a
    conjunct whose control cannot compile in its own lane would be a theorem established
    through evidence one lane away from it."""
    destination = components("proxy.outbound_destination")["test_selection"]
    assert destination["features"] == [
        "aws_kms_keysource",
        "gcp_kms_keysource",
        "online_ocsp",
    ]
    assert any("binding::tests::an_agent_does_not_follow_a_redirect" in s for s in destination["symbols"])
    assert any("credential_egress::tests::" in s for s in destination["symbols"])
    endpoint = components("proxy.kms_endpoint_authority")["test_selection"]
    assert endpoint["features"] == ["aws_kms_keysource", "gcp_kms_keysource"]
    assert any(
        "endpoint::tests::an_endpoint_the_rule_refuses_yields_no_egress" in s
        for s in endpoint["symbols"]
    )


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
    """The meaning of a `doc#` selector, of `test_package`, and of which ecosystem runs the
    battery at all is decided by the lane's own code. Evidence whose measuring instrument
    changed is evidence whose meaning changed — the same argument that puts the toolchain in
    the fingerprint, and the reason #745's adapter registry joined the set rather than
    sitting beside it unmeasured."""
    lane = components("http_profile.verifier_results")["test_lane_identity"]
    assert set(lane) == {
        "tools/verification/verify-tests",
        "tools/verification/_manifest.py",
        "tools/verification/_ecosystems.py",
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
        "paths": ["mcp-re-core/src/time/mod.rs"],
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


# --- the boundary cap a claim's honesty rests on -------------------------------


def test_widening_a_boundarys_cap_dirties_the_units_it_binds():
    """R9-C005 / R9-C041. `trust-boundaries.toml` was a gate in NO fingerprint.

    `max_class_without_assumption` is what keeps a proof's meaning honest across a trust
    boundary — a theorem about code on this side says nothing about the other side. It
    participated in no `ReviewFingerprint`, so widening the cap relaxed the rule and
    invalidated nothing: every claim above it kept deriving FRESH while the argument
    beneath it had changed.
    """
    unit = UNITS["proxy.tls_listener_state"]
    before = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS, BOUNDARIES_REAL)
    widened = {
        "boundary": [
            dict(entry, max_class_without_assumption="V3")
            for entry in BOUNDARIES_REAL.get("boundary", [])
        ]
    }
    after = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS, widened)
    assert before["fingerprint"] != after["fingerprint"]


def test_narrowing_a_boundarys_paths_dirties_the_unit_it_stops_covering():
    """The other way a cap is relaxed, and the one a cap-only digest would miss.

    `paths` decides WHICH units the cap binds. A boundary narrowed until it no longer
    covers a unit has stopped bounding that unit's class, which is the same relaxation
    reached by a different field.
    """
    unit = UNITS["proxy.tls_listener_state"]
    before = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS, BOUNDARIES_REAL)
    emptied = {
        "boundary": [
            dict(entry, paths=["verification/policy/*.toml"])
            for entry in BOUNDARIES_REAL.get("boundary", [])
        ]
    }
    after = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS, emptied)
    assert before["fingerprint"] != after["fingerprint"]


def test_a_boundary_a_unit_does_not_cross_does_not_dirty_it():
    """Without this the component is "every boundary", and one edit dirties the tree.

    A fingerprint that moves for a change the unit's argument does not rest on trains
    reviewers to re-approve without reading, which is the failure a too-wide blast radius
    produces.
    """
    unit = UNITS["core.time_rfc3339"]
    crossed = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS, BOUNDARIES_REAL)[
        "components"
    ]["governing_boundaries"]
    unrelated = {
        "boundary": [
            dict(entry, beyond="something else entirely")
            if entry["id"] not in crossed
            else entry
            for entry in BOUNDARIES_REAL.get("boundary", [])
        ]
    }
    before = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS, BOUNDARIES_REAL)
    after = fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS, unrelated)
    assert before["fingerprint"] == after["fingerprint"]


# --- the exit code CI reads ----------------------------------------------------


def test_only_pass_exits_zero_under_gate():
    """FV-01 at the exit-code boundary: a SKIPPED or NOT_REQUIRED lane must never count
    toward a pass, and INCOMPLETE is exactly the aggregate those produce."""
    assert verify_cli.gate_exit_code("PASS", True) == 0
    assert verify_cli.gate_exit_code("FAIL", True) == 1
    assert verify_cli.gate_exit_code("INCOMPLETE", True) == 1


def test_report_only_mode_does_not_fail_an_unresolved_state():
    """What report mode withholds, and it is not the same as what it used to withhold.

    The claim this protects is that an honestly unresolved state must not fail ordinary
    development — the same reason `review --root-completeness` is report-only. INCOMPLETE
    is that state: no required lane produced formal evidence, which is a legitimate place
    to be while working and is not a place to merge from.
    """
    assert verify_cli.gate_exit_code("PASS", False) == 0
    assert verify_cli.gate_exit_code("INCOMPLETE", False) == 0


def test_report_only_mode_still_reports_a_measured_failure():
    """The half the claim above was over-broad about.

    This asserted that report mode never fails the build, for ANY aggregate. "Not
    authoritative" is a statement about what a PASS is worth, not a licence to report a
    failure as success — and a FAIL is not an unresolved state, it is a measured one.
    Anything reading the status rather than the verdict line read a failed lane as a pass,
    and something did.
    """
    assert verify_cli.gate_exit_code("FAIL", False) == 1


# --- the boundary a unit's paths cross -----------------------------------------


BOUNDARIES = {
    "boundary": [
        {
            "id": "boundary.clock",
            "description": "d",
            "kind": "environment",
            "paths": ["mcp-re-core/src/time/mod.rs"],
            "beyond": "b",
            "max_class_without_assumption": "V0",
        }
    ]
}

CROSSING_UNIT = {
    "unit": [
        {"id": "u", "class": "V1", "paths": ["mcp-re-core/src/time/mod.rs"]},
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
    below = {"unit": [{"id": "u", "class": "V0", "paths": ["mcp-re-core/src/time/mod.rs"]}]}
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
# boundary.clock named mcp-re-core/src/time.rs, which held no clock authority, and named
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
    """The original defect, pinned. `mcp-re-core/src/time/` converts RFC 3339 text to
    Unix seconds and holds no clock authority — ADR-MCPS-006 pushes timestamps to
    callers, and ADR-MCPS-011/012 purity means the crate cannot read a clock at all.

    Read over the whole subtree rather than one file: MCPRE-176 split the formatting
    inverse into `format.rs`, and a control that kept naming `time.rs` would have gone on
    passing while measuring a file that no longer exists."""
    members = sorted((REPO / "mcp-re-core" / "src" / "time").rglob("*.rs"))
    assert members, "the time module has no source to measure"
    for path in members:
        rel = str(path.relative_to(REPO))
        assert rel not in _clock_boundary()["paths"]
        text = path.read_text(encoding="utf-8")
        assert ACQUIRES not in text
        assert "UNIX_EPOCH" not in text


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


# --- the assumption relation has ONE authoritative direction -------------------------
#
# It used to have two. A unit named its premises in `[[unit]].assumptions` and an
# assumption named its units in `scope`, nothing compared them, and the two halves fed
# different machinery: `scope` reached the fingerprint and `check-assumptions`, the unit
# field reached `review-packet` and the generated views. Nine pairs diverged on main —
# ASM-0037 was scoped to `http_profile.keyid` while `http_profile.keyid_selector` declared
# it, so the selector unit's fingerprint carried no `trusted_assumptions` entry at all and
# THM-0050 read as fresh across any rewrite of the premise it stands on.
#
# ADR-MCPRE-059 §8 now names `scope` as the source. These tests hold the two properties
# that replaced the comparison: the inverse is DERIVED, and a unit-side declaration is
# UNREPRESENTABLE rather than merely policed.


def test_a_unit_trusts_exactly_what_scope_names():
    assumptions = {
        "assumption": [
            {"id": "ASM-B", "scope": ["unit://u", "boundary://boundary.clock"]},
            {"id": "ASM-A", "scope": ["unit://u"]},
            {"id": "ASM-C", "scope": ["unit://other"]},
        ]
    }
    assert unit_assumptions("u", assumptions) == ["ASM-A", "ASM-B"]
    assert unit_assumptions("other", assumptions) == ["ASM-C"]


def test_a_unit_no_scope_names_trusts_nothing():
    """Not an error. A unit whose claims rest on no registered premise is the ordinary
    case, and a withdrawn or reserved entry — ASM-0015, ASM-0016, ASM-0017, ASM-0022 —
    reaches nothing at all."""
    assert unit_assumptions("u", {"assumption": [{"id": "ASM-A", "scope": []}]}) == []


def test_a_boundary_scope_is_not_a_unit_scope():
    """`scope` carries both kinds, and only the `unit://` entries name a consumer unit —
    otherwise every claim would inherit a boundary premise no unit rests on."""
    assumptions = {"assumption": [{"id": "ASM-A", "scope": ["boundary://boundary.clock"]}]}
    assert unit_assumptions("boundary.clock", assumptions) == []


def test_a_unit_may_not_declare_its_own_assumptions():
    """The schema is what makes divergence unrepresentable. A migration gate comparing two
    sources would leave both sources in place, and the second one is the defect."""
    import _manifest

    assert "assumptions" not in _manifest._UNIT_KEYS
    try:
        _manifest._reject_unknown("unit u", {"assumptions": ["ASM-A"]}, _manifest._UNIT_KEYS)
    except _manifest.ManifestError as refused:
        assert "assumptions" in str(refused)
    else:
        raise AssertionError("an authored unit-side declaration was accepted")


def test_a_scope_naming_no_such_unit_is_reported():
    verification = {"unit": [{"id": "u", "class": "V0", "paths": []}]}
    assumptions = {"assumption": [{"id": "ASM-X", "scope": ["unit://nope"]}]}
    defects = assumption_scope_defects(verification, assumptions)
    assert len(defects) == 1
    assert "which no [[unit]] declares" in defects[0]


def test_a_scope_naming_a_declared_unit_is_not_a_defect():
    verification = {"unit": [{"id": "u", "class": "V0", "paths": []}]}
    assumptions = {"assumption": [{"id": "ASM-X", "scope": ["unit://u"]}]}
    assert assumption_scope_defects(verification, assumptions) == []


def test_the_shipped_scopes_all_name_declared_units():
    assert assumption_scope_defects(DOC, ASSUMPTIONS) == []


def test_no_shipped_unit_declares_assumptions():
    """The migration is complete, not merely intended."""
    assert [unit["id"] for unit in DOC["unit"] if "assumptions" in unit] == []


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
