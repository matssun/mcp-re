# SPDX-License-Identifier: Apache-2.0
"""The ADR-MCPRE-069 census's own false-green catalogue.

A census reporting `0 unclaimed` is worth exactly as much as its ability to SEE. ADR-069's
first measurement could not see doctests at all, and reported a clean sweep over a
population missing a whole control kind; that is the failure this file exists to make
impossible to repeat.

Two families of control, and they refuse different lies:

  * **positive scope** — for every ecosystem this repository actually has, a NAMED control
    that must appear in the enumeration. Not "at least one" — a specific one, by identity,
    chosen so that the assertion goes red when that ecosystem stops being discoverable
    rather than when the repository merely shrinks;
  * **sensitivity** — removing a known claimed control's registration must make the census
    report it as unclaimed, and removing the control from the tree must make its selector
    stale. A census that answered the same whatever the registry said would be measuring
    nothing, and would be green on the day the registry was emptied.

Run: python3 tools/verification/test_controls.py
"""

from __future__ import annotations

import importlib.machinery
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import _census  # noqa: E402
import _controls  # noqa: E402

CONTROLS = _controls.all_controls()
INDEX = {(control.project, control.identity): control for control in CONTROLS}
REPORT = _census.census(CONTROLS)


# ---------------------------------------------------------------------------
# Positive scope — one named control per supported ecosystem
# ---------------------------------------------------------------------------

#: Each entry is `(project, identity)` of a control that exists on main and a note saying
#: what its absence would mean. Named rather than counted: a count survives the loss of a
#: whole discovery path as long as some other path grew.
SCOPE: dict[str, tuple[str, str]] = {
    "rust-test (lib target)": (
        "mcp-re-proxy",
        "lib#runtime_state::tests::the_relation_has_exactly_ten_legal_transitions",
    ),
    "rust-test (integration target)": (
        "mcp-re-proxy",
        "tests/integration#client_verifier_posture_test::"
        "the_builder_enforces_expiration_and_admits_no_posture_argument",
    ),
    "rust-test (binary target)": (
        "mcp-re-client",
        "bin/mcp-re-client#startup::tests::"
        "the_serving_path_starts_the_anchor_refresher_and_anchors_are_withdrawn_on_expiry",
    ),
    "rust-doctest (compile_fail)": (
        "mcp-re-client-core",
        "doc#delegated_trust::DelegatedResponseTrust",
    ),
    "pytest (sdk project)": (
        "sdk/python",
        "pytest#tests/test_nonce_floor.py::test_a_sub_floor_override_is_refused_at_sign_time",
    ),
    "pytest (repository tooling)": (
        ".",
        "pytest#tools/verification/test_controls.py::"
        "test_every_supported_ecosystem_has_a_discovered_control",
    ),
    "vitest": (
        "sdk/typescript",
        "vitest#test/nonce_floor.test.ts > sign-time nonce floor > "
        "a sub-floor override is refused at sign time: %s",
    ),
    "structural probe": ("", "structural#S01"),
    "mutation probe": ("", "mutation#M01-request-signature"),
    "gate": ("", "gate#scripts/module_size_gate.py"),
}


#: A gate a unit CLAIMS, through `gate_controls` rather than through `tested_symbols`.
#: ADR-MCPRE-068 Phase 1 registered four of these as the production carriers of theorems a
#: type could not establish; a census reading only `tested_symbols` would report all four as
#: unclaimed and invite a `not-evidence` reason about the carrier of a `critical` claim.
CLAIMED_GATE = ("", "gate#scripts/serving_identity_provenance_gate.py")


def test_every_supported_ecosystem_has_a_discovered_control():
    """Each named control is found, so no discovery path has gone dark."""
    missing = [name for name, key in SCOPE.items() if key not in INDEX]
    assert not missing, f"the census cannot see: {missing}"


def test_a_gate_a_unit_declares_is_claimed():
    """`gate_controls` is a claim, and the census must read it as one."""
    assert CLAIMED_GATE in INDEX, "the claimed gate moved; retarget this control"
    assert CLAIMED_GATE in REPORT.claimed
    claimed_gates = {
        (c.control.project, c.control.identity)
        for c in REPORT.claims
        if c.control.kind == "gate"
    }
    assert len(claimed_gates) >= 4, sorted(claimed_gates)


def test_a_measurements_own_argv_claims_its_controls():
    """A `measured` unit declares no battery, and its protocol still selects controls.

    ADR-MCPRE-068 §4.1 gives a measured unit a protocol and an apparatus control instead of
    `tested_symbols`. A census reading only `tested_symbols` reports the controls the
    measurement RUNS as claimed by nothing — and would invite a `not-evidence` reason to be
    written about a measurement's own apparatus.
    """
    selected = {
        claim.control.identity
        for claim in REPORT.claims
        if claim.selector.startswith("measured-argv:")
    }
    assert selected, "no measurement argv resolved to a control; the join went dark"
    assert any("the_measurement_moves_when_the_scanned_set_shrinks" in s for s in selected)


def test_every_control_kind_is_non_empty():
    """A kind declared in `KINDS` and enumerated as zero is a discovery path that broke.

    The kinds are the census's own vocabulary; one of them reporting nothing over a tree
    that holds thousands of controls is the ADR-069 §2.1 defect returning under a new name.
    """
    counts = REPORT.by_kind(CONTROLS)
    empty = sorted(kind for kind, count in counts.items() if count == 0)
    assert not empty, f"kind(s) enumerated as zero: {empty}"


def test_the_measurement_is_project_scoped():
    """Two crates may hold the same selector, so identity alone cannot be the join key.

    Asserted on the SHAPE — every control carries a project, and a registry-carried one
    carries the empty project deliberately — rather than on a pair that happens to collide
    today, which would stop testing anything the moment one of them was renamed.
    """
    assert all(isinstance(control.project, str) for control in CONTROLS)
    carried = {control.kind for control in CONTROLS if control.project == ""}
    assert carried == {"structural", "mutation", "measurement", "gate"}, carried


# ---------------------------------------------------------------------------
# Join correctness
# ---------------------------------------------------------------------------


def test_no_registered_selector_names_a_control_that_does_not_exist():
    """A `tested_symbols` entry resolving to nothing is a stale identity.

    It is also the census's sharpest self-check: the lane selects with `--exact`, so a
    selector naming nothing would fail the lane — and an enumerator that had LOST a control
    kind would report every selector of that kind as stale. Zero is therefore evidence in
    both directions, which is why it is asserted rather than reported.
    """
    assert not REPORT.stale, REPORT.stale[:10]


def test_a_parametrised_family_is_one_control_claimed_by_its_cases():
    """pytest's `[case]` ids and vitest's `%s` titles resolve back to the source control."""
    pytest_family = (
        "sdk/python",
        "pytest#tests/test_nonce_floor.py::test_a_sub_floor_override_is_refused_at_sign_time",
    )
    claims = [
        claim
        for claim in REPORT.claims
        if (claim.control.project, claim.control.identity) == pytest_family
    ]
    assert len(claims) >= 2, "the four parametrised cases should all resolve to one control"
    assert all(claim.selector.endswith("]") for claim in claims), [c.selector for c in claims]


def test_a_control_is_claimed_by_selection_and_never_by_path_proximity():
    """A unit's `paths` do not claim the controls inside them.

    The worked instance is ADR-069 §3: `continuation_store/mod.rs` is in
    `proxy.continuation_correlation_store`'s paths, two of its controls are registered and
    the rest are not. If proximity claimed, the unclaimed ones would vanish — and the
    defect ADR-069 exists to measure would be unmeasurable.
    """
    claimed = REPORT.claimed
    in_file = [
        control
        for control in CONTROLS
        if control.carrier == "mcp-re-proxy/src/continuation_store/mod.rs"
    ]
    assert in_file, "the worked instance's carrier moved; retarget this control"
    assert any((c.project, c.identity) in claimed for c in in_file)
    assert any((c.project, c.identity) not in claimed for c in in_file)


# ---------------------------------------------------------------------------
# Sensitivity — the census must answer differently when its inputs change
# ---------------------------------------------------------------------------


def _first_claim():
    for claim in REPORT.claims:
        if claim.control.kind == "rust-test":
            return claim
    raise AssertionError("no rust-test claim to perturb")


def test_removing_a_registration_makes_its_control_unclaimed():
    """Delete one symbol from the registry and the census must report it.

    Performed against a COPY of the loaded registry rather than the file, so the control
    proves the join is sensitive without a test that edits committed policy.
    """
    claim = _first_claim()
    kept = [c for c in REPORT.claims if c is not claim]
    perturbed = _census.Census(controls=CONTROLS, claims=kept, stale=[], dispositions=[])
    key = (claim.control.project, claim.control.identity)
    assert key in REPORT.claimed
    assert key not in perturbed.claimed
    assert key in {(c.project, c.identity) for c in perturbed.unclaimed}


def test_a_disposition_removes_a_control_from_the_residue_and_nothing_else_does():
    """The residue is unclaimed MINUS dispositioned, and a row moves exactly one control."""
    unclaimed = REPORT.unclaimed
    assert unclaimed, "nothing unclaimed; retarget this control"
    target = unclaimed[0]
    row = _census.Disposition(
        id="ND-TEST",
        project=target.project,
        control=target.identity,
        decision="not-evidence",
        reason_family="ND-TEST",
        recorded="2026-09-19",
        proposition=None,
    )
    perturbed = _census.Census(
        controls=CONTROLS, claims=REPORT.claims, stale=[], dispositions=[row]
    )
    assert len(perturbed.residue) == len(unclaimed) - 1
    assert (target.project, target.identity) not in {
        (c.project, c.identity) for c in perturbed.residue
    }


def test_a_disposition_for_a_claimed_control_is_an_orphan():
    """ADR-069 D4: a registered control leaves the census, so a row about one is refused."""
    claim = _first_claim()
    row = _census.Disposition(
        id="ND-TEST",
        project=claim.control.project,
        control=claim.control.identity,
        decision="not-evidence",
        reason_family="ND-TEST",
        recorded="2026-09-19",
        proposition=None,
    )
    perturbed = _census.Census(
        controls=CONTROLS, claims=REPORT.claims, stale=[], dispositions=[row]
    )
    assert [r.id for r in perturbed.orphan_dispositions] == ["ND-TEST"]


def test_a_disposition_for_a_control_that_vanished_is_an_orphan():
    """A control deleted from the tree leaves its row describing nothing."""
    row = _census.Disposition(
        id="ND-GONE",
        project="mcp-re-proxy",
        control="lib#a_module_that_does_not_exist::tests::gone",
        decision="not-evidence",
        reason_family="ND-TEST",
        recorded="2026-09-19",
        proposition=None,
    )
    perturbed = _census.Census(
        controls=CONTROLS, claims=REPORT.claims, stale=[], dispositions=[row]
    )
    assert [r.id for r in perturbed.orphan_dispositions] == ["ND-GONE"]


def test_a_selector_naming_a_deleted_control_is_reported_stale():
    """Remove a control from the enumeration and its registration must go stale."""
    claim = _first_claim()
    thinner = [c for c in CONTROLS if c is not claim.control]
    _, stale = _census.join(thinner)
    assert claim.selector in {selector for _, _, selector in stale}


def test_the_enumerator_is_deterministic():
    """Two runs over one tree produce the same list, so a report can be diffed."""
    again = _controls.all_controls()
    assert [c.identity for c in again] == [c.identity for c in CONTROLS]


def test_a_modified_describe_block_still_names_its_suite():
    """`describe.runIf(expr)("title", …)` nests its cases, and the census must see it.

    A suite the scanner misses does not remove its cases — they are enumerated under the
    WRONG reported name, which is worse than losing them: the identity joins to nothing, and
    a registration written against it would select a case vitest never reports. The live
    instance is the TypeScript end-to-end suite, whose cases ADR-069 dispositions.
    """
    live = (
        "sdk/typescript",
        "vitest#test/transport_e2e.test.ts > McpReHttpTransport (live) > "
        "fails closed on an unsigned response",
    )
    assert live in INDEX, "the live e2e suite moved; retarget this control"


def test_the_register_and_the_registry_agree_in_both_directions():
    """Every declaration has a record, and every record is declared.

    The gate checks both. This control checks that the live pair actually agrees, so the
    assertion goes red on a dead record as well as on a missing one — *a dead row hides the
    next live one* is a defect this repository has already met in another register.
    """
    import re
    import tomllib

    from _controls import POLICY, REPO_ROOT

    register = REPO_ROOT / "docs" / "architecture" / "control-dispositions.md"
    raw = tomllib.loads((POLICY / "control-dispositions.toml").read_text())
    declared = {entry["id"] for entry in raw.get("proposition", [])} | {
        row["reason_family"] for row in raw.get("disposition", []) if row.get("reason_family")
    }
    found = set(re.findall(r"^## (NP-\d+|ND-\d+)", register.read_text(), re.M))
    assert declared, "nothing declared; the registry went dark"
    assert found - declared == set(), sorted(found - declared)
    assert declared - found == set(), sorted(declared - found)


def test_an_unknown_key_in_the_registry_is_refused():
    """The registry's header promises it, so something has to keep the promise.

    Until this check existed the loader ignored an unknown key, so a typo in `reason_family`
    read as an ABSENT reason and a `not-evidence` row passed the ADR-069 D3 check with
    nothing behind it. Perturbed rather than asserted: a schema check that has never seen a
    bad key is a schema check nobody has run.
    """
    censor = _load_census_tool()
    clean = {"disposition": [{"id": "CD-X", "decision": "not-evidence"}], "proposition": []}
    assert censor._schema_failures(clean) == []
    typo = {"disposition": [{"id": "CD-X", "decision": "not-evidence", "reson_family": "ND-001"}]}
    assert any("reson_family" in problem for problem in censor._schema_failures(typo))


def test_a_severity_outside_the_vocabulary_is_refused():
    """ADR-MCPRE-068 §4.1's words, because a consequence is compared across records."""
    censor = _load_census_tool()
    entries = _census.propositions()
    assert entries, "no propositions; the registry went dark"
    assert all(e.get("consequence") in ("medium", "high", "critical") for e in entries)
    bad = {"proposition": [{"id": "NP-X", "consequence": "severe"}], "disposition": []}
    assert any("severe" in problem for problem in censor._schema_failures(bad))


def _load_census_tool():
    """The `control-census` executable as a module — it has no `.py` suffix."""
    import importlib.util

    spec = importlib.util.spec_from_loader(
        "control_census",
        importlib.machinery.SourceFileLoader("control_census", str(HERE / "control-census")),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_doctest_carries_its_fence_mode():
    """ADR-MCPRE-068 §4.1: a compile refusal is not behavioural evidence.

    The census records the mode so that a registration campaign cannot register a
    `compile_fail` example as `tested` evidence without the report saying what it is.
    """
    doctests = [c for c in CONTROLS if c.kind == "rust-doctest"]
    assert doctests
    assert all(control.note for control in doctests)
    assert any("compile-fail" in control.note for control in doctests)


def run() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
        except AssertionError as failure:
            failures += 1
            print(f"FAIL {name}: {failure}")
        else:
            print(f"ok   {name}")
    print(f"control census self-test: {'PASS' if not failures else f'FAIL ({failures})'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
