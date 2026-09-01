# SPDX-License-Identifier: Apache-2.0
"""The review-unit abstraction is not Cargo — ADR-MCPRE-059 §2, issue #745.

A `[[unit]]` is *the smallest semantic authority whose source, assumptions, evidence and
review can be fingerprinted*, and the implementation had that concept welded to one build
system: the project was the first path segment holding a `Cargo.toml`, the test package was
a Cargo package, and the build configuration was the Rust workspace's manifests. No unit
could own `sdk/python/python/mcp_re_sdk/` or `sdk/typescript/src/`, so the SDK roots were
unevidenceable — and an unevidenceable root reads as coverage while being none.

These are the controls for the seam that fixes it. Each one is a property the platform must
have for a NON-Rust unit and already had for a Rust one, and every one of them is stated so
it fails if the neutrality is bolted on rather than built in.

Run: python3 tools/verification/test_ecosystems.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _ecosystems import (  # noqa: E402
    CARGO,
    PYTHON,
    TYPESCRIPT,
    build_configuration_patterns,
    ecosystem_for_path,
    formal_source_patterns,
    parse_results,
    project_of,
    test_argv,
    test_project_for,
    unit_ecosystem,
    unit_projects,
    valid_target,
)
from _fingerprint import fingerprint_unit  # noqa: E402
from _manifest import (  # noqa: E402
    load_assumptions,
    load_toolchains,
    load_verification,
)

DOC = load_verification()
TOOLCHAINS = load_toolchains()
ASSUMPTIONS = load_assumptions()

#: A unit over Python source that exists in this repository. Not registered in
#: `verification.toml` — #746 is where a claim over it is made — because these controls are
#: about the PLATFORM's ability to measure such a unit, which must be demonstrable before
#: any root rests on it.
PY_UNIT = {
    "id": "test.python_probe",
    "class": "V0",
    "description": "probe",
    "paths": [
        "sdk/python/python/mcp_re_sdk/transport.py",
        "sdk/python/python/mcp_re_sdk/correlation.py",
    ],
    "exported_contracts": [],
    "evidence": ["test://sdk/python/probe"],
    "tested_symbols": ["pytest#tests/test_correlation.py::test_probe"],
}

TS_UNIT = {
    "id": "test.typescript_probe",
    "class": "V0",
    "description": "probe",
    "paths": ["sdk/typescript/src/correlation.ts"],
    "exported_contracts": [],
    "evidence": ["test://sdk/typescript/probe"],
    "tested_symbols": ["vitest#test/correlation.test.ts > a probe"],
}


def fingerprint(unit: dict) -> dict:
    return fingerprint_unit(unit, DOC, TOOLCHAINS, ASSUMPTIONS)


def moved(unit: dict, mutate) -> bool:
    before = fingerprint(unit)["fingerprint"]
    after = fingerprint(mutate(dict(unit)))["fingerprint"]
    return before != after


# --- the ecosystem is derived, and no unit declares one -----------------------


def test_no_unit_names_a_language():
    """The bolt-on this exists to refuse. A `kind = "python"` field would turn an
    architectural concept into a list of exceptions, and the next ecosystem would be a
    schema change rather than a registry entry."""
    from _manifest import _UNIT_KEYS

    for key in _UNIT_KEYS:
        for language in ("python", "typescript", "rust", "cargo", "language", "kind"):
            assert language not in key, f"the unit schema names a language: {key}"


def test_the_file_decides_the_ecosystem_not_the_directory():
    """`sdk/python` holds a `Cargo.toml` AND a `pyproject.toml` — the wheel is a Rust
    extension module — so no directory-level rule can say which project a file belongs to.
    The suffix can, and does."""
    assert ecosystem_for_path("sdk/python/src/lib.rs") is CARGO
    assert ecosystem_for_path("sdk/python/python/mcp_re_sdk/transport.py") is PYTHON
    assert ecosystem_for_path("sdk/typescript/src/correlation.ts") is TYPESCRIPT
    # And a path no ecosystem claims is not an error: it is measured source that names no
    # lane.
    assert ecosystem_for_path("config/ports.toml") is None


def test_a_project_is_the_nearest_manifest_not_the_first_path_segment():
    """The rule the old implementation could not express: `sdk/python` is a project and
    `sdk` is not, so reading the first segment answers with a directory that holds no
    manifest at all."""
    assert project_of("sdk/python/python/mcp_re_sdk/transport.py", PYTHON) == "sdk/python"
    assert project_of("sdk/typescript/src/correlation.ts", TYPESCRIPT) == "sdk/typescript"
    assert project_of("mcp-re-proxy/src/lib.rs", CARGO) == "mcp-re-proxy"
    assert unit_projects(PY_UNIT) == ["sdk/python"]
    assert test_project_for(PY_UNIT) == "sdk/python"


# --- dirtiness: the same properties a Rust unit already had -------------------


def test_changing_owned_python_source_dirties_the_unit():
    """The first thing a review unit must do. A unit whose source can change under a
    standing attestation is a unit whose evidence is about a tree that is no longer
    there."""
    source = fingerprint(PY_UNIT)["components"]["source_inputs"]
    assert "sdk/python/python/mcp_re_sdk/transport.py" in source
    assert "sdk/python/python/mcp_re_sdk/correlation.py" in source
    assert all(digest.startswith("sha256:") for digest in source.values())
    assert moved(PY_UNIT, lambda u: u.update(paths=u["paths"][:1]) or u)


def test_the_dependency_manifest_and_the_lockfile_are_measured():
    """A dependency swap or a lockfile bump alters what a claim is about without touching a
    declared source line. `package.json` and `package-lock.json` bear exactly the weight the
    Rust unit's `Cargo.toml` and the workspace `Cargo.lock` bear.

    MEASURED, and it is a finding for whoever declares a Python root: `sdk/python/uv.lock`
    is `.gitignore`d as "auto-generated by the maturin import hook; not our chosen
    workflow", so the Python SDK commits no lockfile and `pyproject.toml` pins RANGES. The
    fingerprint therefore covers what the project declares and cannot cover what it
    resolved — which is a fact about that project, not a gap in this seam, and a root over
    it must either commit a lockfile or register the looseness as a premise.
    """
    ts_build = fingerprint(TS_UNIT)["components"]["build_configuration"]
    assert "sdk/typescript/package.json" in ts_build
    assert "sdk/typescript/package-lock.json" in ts_build
    assert "sdk/typescript/tsconfig.json" in ts_build
    assert all(digest.startswith("sha256:") for digest in ts_build.values())

    py_build = fingerprint(PY_UNIT)["components"]["build_configuration"]
    assert "sdk/python/pyproject.toml" in py_build
    assert not any(path.endswith(".lock") for path in py_build), (
        "the Python SDK commits no lockfile; if that changes, this control should assert "
        "it is measured rather than assert its absence"
    )


def test_an_absent_lockfile_alternative_contributes_nothing_rather_than_failing():
    """`uv.lock` and `poetry.lock` are alternatives. Naming both is how the platform stays
    neutral about which one a project uses without asking the unit to say — and the one that
    is not there must not appear as a measured input with an empty digest."""
    patterns = build_configuration_patterns(PY_UNIT)
    assert "sdk/python/uv.lock" in patterns
    assert "sdk/python/poetry.lock" in patterns
    build = fingerprint(PY_UNIT)["components"]["build_configuration"]
    assert "sdk/python/poetry.lock" not in build


def test_the_rust_build_configuration_is_unchanged_by_the_seam():
    """The neutrality must not be paid for by moving every existing Rust fingerprint's
    meaning. A crate's inputs are still the workspace manifests plus its own."""
    unit = next(u for u in DOC["unit"] if u["id"] == "http_profile.replay_key")
    build = fingerprint(unit)["components"]["build_configuration"]
    assert set(build) == {
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "mcp-re-http-profile/Cargo.toml",
    }


# --- fail closed ---------------------------------------------------------------


def test_a_closure_spanning_two_ecosystems_has_no_test_project():
    """No single lane covers the source, and answering with either would name a project
    that does not cover it. The same answer the platform already gives a path outside every
    Cargo package: no project, so no battery, so no evidence."""
    mixed = dict(PY_UNIT)
    mixed["paths"] = PY_UNIT["paths"] + ["mcp-re-proxy/src/lib.rs"]
    assert unit_ecosystem(mixed) is None
    assert test_project_for(mixed) is None
    assert unit_projects(mixed) == []
    assert build_configuration_patterns(mixed) == []


def test_a_source_path_outside_every_project_of_its_ecosystem_fails_closed():
    """A `.py` file with no `pyproject.toml` above it has no project whose dependency
    inputs could be measured, so it must not borrow another project's."""
    orphan = dict(PY_UNIT)
    orphan["paths"] = ["scripts/module_size_gate.py"]
    assert unit_ecosystem(orphan) is None
    assert test_project_for(orphan) is None


def test_an_unknown_target_is_malformed_rather_than_skipped():
    """A selector nothing executes is a declared control that establishes nothing. The lane
    refuses in both directions, so an unrunnable target must be refused rather than dropped
    from the selection."""
    assert valid_target(CARGO, "lib")
    assert valid_target(CARGO, "tests/full_profile_test")
    assert not valid_target(CARGO, "pytest")
    assert valid_target(PYTHON, "pytest")
    assert not valid_target(PYTHON, "lib")
    assert valid_target(TYPESCRIPT, "vitest")
    assert not valid_target(TYPESCRIPT, "pytest")


def test_a_formal_class_over_a_prover_less_ecosystem_measures_no_whole_project_cone():
    """V1/V3 evidence is a whole-project prover run. Python and TypeScript have no prover
    lane, so a fingerprint that digested their whole project would claim a measurement that
    never happened."""
    assert formal_source_patterns(PY_UNIT) == []
    assert formal_source_patterns(TS_UNIT) == []
    rust = next(u for u in DOC["unit"] if u["id"] == "http_profile.freshness_window")
    assert formal_source_patterns(rust) == ["mcp-re-http-profile/src/**/*.rs"]


# --- the lane runs it, and reads the answer in one vocabulary -----------------


def test_each_ecosystem_selects_exactly_the_declared_symbols():
    """Exact selection is the property, not a convenience: a runner matching by substring
    would let a battery grow silently, and one running the whole suite would report a pass
    for symbols nobody declared."""
    assert test_argv(CARGO, "mcp-re-proxy", "lib", ["a::b"]) == [
        "cargo", "test", "-p", "mcp-re-proxy", "--lib", "--", "--exact", "a::b",
    ]
    assert test_argv(CARGO, "p", "tests/x", ["a"]) == [
        "cargo", "test", "-p", "p", "--test", "x", "--", "--exact", "a",
    ]
    # pytest selects by exact node id. `uv run` rather than a bare interpreter, because the
    # environment a battery ran in is part of what the record describes.
    py = test_argv(PYTHON, "sdk/python", "pytest", ["tests/test_correlation.py::test_probe"])
    assert py[:4] == ["uv", "run", "--quiet", "python"]
    assert py[-1] == "tests/test_correlation.py::test_probe"

    # vitest selects by FILE — `-t` matches a name by substring, which is not selection — so
    # the files are named here and the exact names are compared by the lane, which is where
    # the both-directions rule already lives.
    ts = test_argv(
        TYPESCRIPT,
        "sdk/typescript",
        "vitest",
        ["test/x.test.ts > a probe", "test/x.test.ts > another", "test/y.test.ts > third"],
    )
    assert ts[:4] == ["npx", "vitest", "run", "--reporter=verbose"]
    assert ts[4:] == ["test/x.test.ts", "test/y.test.ts"]


def test_every_runners_report_is_read_in_one_vocabulary():
    """The lane's rule is ONE rule — a declared symbol that did not report success is a
    failure, whether it failed, was skipped, or never ran — so each runner's own words are
    translated where the adapter is, not where the rule is applied."""
    assert parse_results(CARGO, "test a::b ... ok\ntest c::d ... FAILED\ntest e ... ignored") == {
        "a::b": "ok",
        "c::d": "FAILED",
        "e": "ignored",
    }
    # The measured false RED: a child process writing to the real fd 2 lands its bytes
    # between the name and the status, and the status is still read from the end.
    assert parse_results(CARGO, "test a::b ... mcp-re-proxy: noise ok") == {"a::b": "ok"}

    pytest_out = (
        "tests/test_correlation.py::test_probe PASSED\n"
        "tests/test_mtls.py::test_other FAILED\n"
        "tests/test_smoke.py::test_skipped SKIPPED\n"
    )
    assert parse_results(PYTHON, pytest_out) == {
        "tests/test_correlation.py::test_probe": "ok",
        "tests/test_mtls.py::test_other": "FAILED",
        "tests/test_smoke.py::test_skipped": "ignored",
    }

    vitest_out = " ✓ test/correlation.test.ts > a probe 3ms\n × test/mtls.test.ts > another\n"
    assert parse_results(TYPESCRIPT, vitest_out) == {
        "test/correlation.test.ts > a probe": "ok",
        "test/mtls.test.ts > another": "FAILED",
    }


def test_a_skipped_test_is_not_evidence_in_any_ecosystem():
    """A test that did not execute establishes nothing a test which did not exist would not
    also establish. The lane's rule already says so; this pins that no adapter launders a
    skip into a pass on the way to it."""
    for eco, text in (
        (CARGO, "test a ... ignored"),
        (PYTHON, "tests/t.py::a SKIPPED"),
        (TYPESCRIPT, " ↓ test/t.test.ts > a"),
    ):
        statuses = set(parse_results(eco, text).values())
        assert statuses == {"ignored"}, f"{eco.name}: {statuses}"


# --- the derived views do not care which ecosystem ----------------------------


def test_owner_dependency_and_assumption_views_derive_for_a_non_rust_unit():
    """A non-Rust member must be a member, not a special case: the same components, the
    same shape, and an assumption scoped to it reaches it the same way."""
    components = fingerprint(PY_UNIT)["components"]
    rust = fingerprint(next(u for u in DOC["unit"] if u["id"] == "http_profile.replay_key"))
    assert set(components) == set(rust["components"])
    assert components["test_selection"]["package"] == "sdk/python"
    assert components["test_selection"]["symbols"] == PY_UNIT["tested_symbols"]
    assert components["trusted_assumptions"] == {}
    assert components["mutation_probes"] == {}


def test_a_non_rust_unit_with_no_executed_evidence_cannot_be_established():
    """The reason this slice gates the SDK roots. `attest` refuses a unit without a record
    at its exact fingerprint, and that refusal must apply to a non-Rust unit identically —
    otherwise a root reads as covered because nobody could measure it."""
    from _evidence import required_lanes

    lanes = required_lanes(PY_UNIT)
    assert "test" in lanes, "a test:// URI must require the test lane whatever the language"


def test_stale_evidence_cannot_establish_a_non_rust_unit():
    """A record is a measurement OF A FINGERPRINT. An evidence record taken over one tree
    cannot establish a claim about another, and that must hold for a Python unit exactly as
    it does for a Rust one — otherwise the SDK roots are established by whatever was last
    measured rather than by what is there."""
    from _evidence import EvidenceRecord, decide_issuance

    at = fingerprint(PY_UNIT)["fingerprint"]
    stale = EvidenceRecord(
        unit_id=PY_UNIT["id"],
        lane="test",
        result="pass",
        fingerprint="sha256:" + "0" * 64,
        detail="measured over some other tree",
    )
    decision, _, reason = decide_issuance(
        [PY_UNIT], [], {PY_UNIT["id"]: {"fingerprint": at}}, {"test": {PY_UNIT["id"]: stale}}
    )[PY_UNIT["id"]]
    assert decision == "REFUSE", reason


def test_an_unknown_evidence_provider_fails_closed_for_a_non_rust_unit():
    """A declared evidence class nothing resolves is unmeasured evidence. Filtering to the
    schemes that happen to have an implementation is how a unit ends up claiming no lane and
    being issued a PASS with an empty evidence map."""
    from _evidence import MALFORMED_LANE, decide_issuance, required_lanes

    unknown = dict(PY_UNIT)
    unknown["evidence"] = ["hypothesis://sdk/python/probe"]
    assert required_lanes(unknown) == {"hypothesis"}
    at = fingerprint(unknown)["fingerprint"]
    decision, _, reason = decide_issuance(
        [unknown], [], {unknown["id"]: {"fingerprint": at}}, {}
    )[unknown["id"]]
    assert decision == "REFUSE", reason

    malformed = dict(PY_UNIT)
    malformed["evidence"] = ["not-a-uri"]
    assert required_lanes(malformed) == {MALFORMED_LANE}


def test_no_untracked_file_can_enter_a_fingerprint():
    """The hazard the glob-driven inputs introduce, and the reason they are filtered.

    `sdk/python/uv.lock` is `.gitignore`d as a maturin by-product, so a developer who has
    run the import hook has a file on disk that a CI checkout does not. Digesting it would
    make the SAME COMMIT fingerprint two ways depending on whose machine looked — not a
    stricter measurement, a measurement of something nobody reviewed. This is what caught
    it: the control was written asserting the lockfile was measured, and it passed locally
    and failed on CI.
    """
    from _fingerprint import _tracked_files

    tracked = _tracked_files()
    assert "sdk/typescript/package-lock.json" in tracked
    assert "sdk/python/uv.lock" not in tracked

    for unit in (PY_UNIT, TS_UNIT, *DOC["unit"]):
        for path in fingerprint(unit)["components"]["build_configuration"]:
            assert path in tracked, f"{unit['id']}: untracked build input {path}"


def test_root_completeness_treats_a_non_rust_member_as_a_member():
    """Support closure resolves by unit ID and by nothing else, so a root standing on a
    Python or TypeScript unit is structurally supported exactly as one standing on a Rust
    unit. That is the property #746 needs: an SDK root that could not be a member would
    read as coverage while being none."""
    from _theorems import structurally_supported_theorems, validate_theorems

    doc = {
        "schema_version": 1,
        "root_theorems": ["THM-9001"],
        "theorem": [
            {
                "id": "THM-9001",
                "title": "probe",
                "statement": "s",
                "security_consequence": "c",
                "scope": "p",
                "owner": PY_UNIT["id"],
                "review_requirement": "Owner security-specification review",
                "supported_by": [f"unit://{PY_UNIT['id']}"],
                "depends_on": [],
            }
        ],
    }
    validate_theorems(doc, {PY_UNIT["id"]})
    assert structurally_supported_theorems(doc) == {"THM-9001"}


def main() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        # Only this module's controls: `test_argv` and `test_project_for` are imported
        # helpers whose names begin the same way, and calling them would be a runner bug
        # reported as a failing control.
        if not name.startswith("test_") or not callable(fn):
            continue
        if getattr(fn, "__module__", None) != "__main__":
            continue
        try:
            fn()
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            failures += 1
        else:
            print(f"ok   {name}")
    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
