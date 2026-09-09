# SPDX-License-Identifier: Apache-2.0
"""The Lean lane's axiom accounting, and the false greens it must refuse — issue #541.

The single property under test: **a theorem counts as evidence only when every axiom the
prover reports for it is either the declared kernel baseline or a premise registered
against that unit** — and `sorry` is neither, at any scope, under any registration.

Every case is a way the accounting could report a clean result over an unclean proof.
They are tests rather than a paragraph in the ADR because "the lane checks the axioms" is
the kind of sentence that stays true in a document long after it has stopped being true in
the code.

Run with `python3 tools/verification/test_lean_axioms.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lean_axioms import (  # noqa: E402
    AxiomReport,
    classify,
    parse_print_axioms,
    print_axioms_source,
    registered_axioms,
    sorry_registrations,
    unused_registrations,
)

from _manifest import load_toolchains  # noqa: E402

#: Read from the lock, never restated. The tests measure the baseline the lane will actually
#: use; a copy here would pass while the declared one said something else.
BASELINE = frozenset(load_toolchains()["lean"]["kernel_axioms"])
UNIT = "core.time_civil_from_days"


def test_the_declared_baseline_is_the_three_kernel_axioms_and_not_sorry():
    """What the lock declares, asserted rather than assumed.

    Every test below is relative to this set, so a lock that quietly grew a fourth name
    would make all of them pass over a proof resting on it.
    """
    assert BASELINE == {"Classical.choice", "Quot.sound", "propext"}


def registry(*entries: dict) -> dict:
    """The registry DOCUMENT, in the shape `load_assumptions()` returns.

    The tests build what the lane passes, not what the function would like to receive. The
    two diverged once — the lane handed a document to a function written for a list, and
    every test here passed while the live call iterated dict keys.
    """
    return {"schema_version": 1, "assumption": list(entries)}


def asm(
    identifier: str,
    mechanism: str,
    scope: list[str] | None = None,
) -> dict:
    """One assumption row, in the shape `assumptions.toml` loads."""
    return {
        "id": identifier,
        "description": "x",
        "justification": "x",
        "scope": [f"unit://{UNIT}"] if scope is None else scope,
        "owner": "x",
        "introduced_by": "x",
        "review_requirement": "x",
        "affected_contracts": [],
        "tool_specific_mechanism": mechanism,
    }


# ---------------------------------------------------------------------------
# Reading what the prover said
# ---------------------------------------------------------------------------


def test_the_two_forms_print_axioms_emits_are_both_read():
    """Both lines are verbatim from the pinned Lean, for `Classical.em` and `Nat.add_comm`."""
    output = (
        "'Thm.a' depends on axioms: [propext, Classical.choice, Quot.sound]\n"
        "'Thm.b' does not depend on any axioms\n"
    )
    assert parse_print_axioms(output) == {
        "Thm.a": ("Classical.choice", "Quot.sound", "propext"),
        "Thm.b": (),
    }


def test_a_wrapped_axiom_list_is_read_whole():
    """Lean wraps a long list across lines, and a per-line regex would truncate it.

    Truncation is the dangerous direction: the axioms that fall off the end are the ones
    the lane would have refused, so a partial read reports a cleaner closure than the
    prover found.
    """
    output = (
        "'Thm.wide' depends on axioms: [propext,\n"
        " Classical.choice,\n"
        " Quot.sound,\n"
        " core.num.I64.div_euclid]\n"
    )
    assert parse_print_axioms(output)["Thm.wide"] == (
        "Classical.choice",
        "Quot.sound",
        "core.num.I64.div_euclid",
        "propext",
    )


def test_an_unresolvable_theorem_is_absent_not_axiom_free():
    """The control that keeps a typo from reading as a clean proof.

    `#print axioms` says nothing at all about a constant it cannot resolve. Reporting that
    as an empty axiom set would make a misspelled theorem name the cleanest evidence in
    the repository.
    """
    # The message the pinned Lean actually emits, measured rather than imagined — a control
    # written against a message no prover produces is a control that measures nothing.
    output = (
        "/tmp/q.lean:4:14: error(lean.unknownIdentifier): Unknown constant "
        "`Thm.missing`\n"
    )
    assert parse_print_axioms(output) == {}


def test_the_query_file_asks_about_exactly_the_declared_theorems():
    source = print_axioms_source(["Generated.Model", "Theorems.Time"], ["A.one", "A.two"])
    assert source.splitlines() == [
        "import Generated.Model",
        "import Theorems.Time",
        "#print axioms A.one",
        "#print axioms A.two",
    ]


# ---------------------------------------------------------------------------
# What may stand, and what may not
# ---------------------------------------------------------------------------


def test_the_kernel_baseline_alone_is_clean():
    report = AxiomReport("Thm.a", ("Classical.choice", "Quot.sound", "propext"))
    assert classify(report, BASELINE, {}) == []


def test_an_unregistered_axiom_is_refused():
    report = AxiomReport("Thm.a", ("core.num.I64.div_euclid", "propext"))
    defects = classify(report, BASELINE, {})
    assert len(defects) == 1
    assert "core.num.I64.div_euclid" in defects[0]


def test_a_registered_axiom_scoped_to_this_unit_may_stand():
    registered = registered_axioms(
        registry(asm("ASM-0100", "lean:axiom:core.num.I64.div_euclid")), UNIT
    )
    assert registered == {"core.num.I64.div_euclid": "ASM-0100"}
    report = AxiomReport("Thm.a", ("core.num.I64.div_euclid",))
    assert classify(report, BASELINE, registered) == []


def test_a_registration_scoped_to_another_unit_licenses_nothing_here():
    """Scope is the whole content of an assumption.

    An `ASM` is an argument for why trusting a premise is acceptable *where it is
    trusted*. Reading the mechanism without the scope would turn one unit's ratified
    premise into a repository-wide allowance for every future site the axiom appears in.
    """
    entry = asm(
        "ASM-0100", "lean:axiom:core.num.I64.div_euclid", scope=["unit://other.unit"]
    )
    assert registered_axioms(registry(entry), UNIT) == {}
    assert classify(AxiomReport("Thm.a", ("core.num.I64.div_euclid",)), BASELINE, {})


def test_an_assumption_of_a_different_mechanism_kind_licenses_no_axiom():
    """`lean:external-model` and `verus:external_body` are different trusted things.

    Only `lean:axiom:<name>` binds an assumption to an axiom the prover reported. A row
    that merely mentions Lean does not.
    """
    entries = [
        asm("ASM-0101", "lean:external-model"),
        asm("ASM-0102", "verus:external_body"),
    ]
    assert registered_axioms(registry(*entries), UNIT) == {}


# ---------------------------------------------------------------------------
# `sorry` fails closed
# ---------------------------------------------------------------------------


def test_sorry_fails_closed():
    defects = classify(AxiomReport("Thm.a", ("sorryAx",)), BASELINE, {})
    assert len(defects) == 1
    assert "incomplete" in defects[0]


def test_sorry_is_not_registrable_even_when_someone_registers_it():
    """The one axiom a registration cannot rescue.

    Registering `sorryAx` would convert "nobody has proved this" into "we have decided to
    trust it". Those are different statements, and the registry may only make the second.
    """
    registered = registered_axioms(registry(asm("ASM-0103", "lean:axiom:sorryAx")), UNIT)
    assert registered == {"sorryAx": "ASM-0103"}
    defects = classify(AxiomReport("Thm.a", ("sorryAx",)), BASELINE, registered)
    assert len(defects) == 1
    assert "never registrable" in defects[0]


def test_a_qualified_sorry_axiom_is_caught_too():
    defects = classify(AxiomReport("Thm.a", ("Lean.sorryAx",)), BASELINE, {})
    assert len(defects) == 1
    assert "incomplete" in defects[0]


def test_the_registry_itself_reports_a_sorry_row():
    """Found over the whole registry, whatever its scope.

    The defect is that a row exists asserting an unproved goal is trusted. That is wrong
    before any lane consults it, so it is not conditioned on a unit asking.
    """
    entries = [
        asm("ASM-0103", "lean:axiom:sorryAx", scope=["unit://somewhere.else"]),
        asm("ASM-0104", "lean:axiom:propext"),
    ]
    assert sorry_registrations(registry(*entries)) == ["ASM-0103"]


# ---------------------------------------------------------------------------
# The registry may overstate, and says so
# ---------------------------------------------------------------------------


def test_an_unused_registration_is_reported_and_not_fatal():
    """A premise nothing depends on overstates the trusted computing base.

    It is reported rather than failed: a lane that went red on it would make discharging
    an assumption more expensive than leaving it in place, which is the one incentive this
    registry cannot afford.
    """
    registered = {"core.num.I64.div_euclid": "ASM-0100"}
    reports = [AxiomReport("Thm.a", ("propext",))]
    assert classify(reports[0], BASELINE, registered) == []
    stale = unused_registrations(reports, registered)
    assert len(stale) == 1
    assert "ASM-0100" in stale[0]


# ---------------------------------------------------------------------------
# The shape the LANE passes, not the shape the function would prefer
# ---------------------------------------------------------------------------


def test_the_live_registry_is_the_shape_these_functions_take():
    """The seam that broke once, asserted against the real loader.

    Every case above builds its own registry, so all of them passed while the lane handed
    these functions the loaded DOCUMENT and they iterated its string keys — a crash that
    could only appear once a unit actually asked the lane for evidence, which is the last
    moment anyone wants to discover a caller mismatch. Calling the real loader is what ties
    the tests to the caller.
    """
    from _manifest import load_assumptions

    live = load_assumptions()
    assert isinstance(live, dict) and "assumption" in live
    # Neither call may raise, and the live registry registers no Lean axiom and no `sorry`.
    assert registered_axioms(live, UNIT) == {}
    assert sorry_registrations(live) == []


# ---------------------------------------------------------------------------
# The activation probe — is the refusal still firing?
# ---------------------------------------------------------------------------
#
# The probe's own value depends on it FAILING when the mechanism breaks, so these cases
# feed it the prover output a broken mechanism would produce. Its behaviour against the
# real prover is measured by `verify-lean --activation-probe` in the extraction lane; what
# is measured here is that it reports rather than shrugs.


def _probe_with(output: str) -> list[str]:
    import _lean_probe

    real = _lean_probe.elaborate
    _lean_probe.elaborate = lambda source, what: (0, output)
    try:
        return _lean_probe.run(["McpReCore"], BASELINE)
    finally:
        _lean_probe.elaborate = real


def _probe_output(sorry_axioms: str, premise_axioms: str) -> str:
    import _lean_probe

    ns = _lean_probe.NAMESPACE
    return (
        f"'{ns}.proved_by_sorry' depends on axioms: [{sorry_axioms}]\n"
        f"'{ns}.rests_on_unregistered_premise' depends on axioms: [{premise_axioms}]\n"
    )


def test_the_probe_passes_when_both_refusals_fire():
    import _lean_probe

    ns = _lean_probe.NAMESPACE
    assert _probe_with(
        _probe_output("sorryAx", f"{ns}.unregistered_premise")
    ) == []


def test_the_probe_fails_when_the_prover_reports_nothing():
    """A parser that silently matches nothing looks exactly like a clean axiom closure."""
    defects = _probe_with("")
    assert len(defects) == 2
    assert all("never reached" in defect for defect in defects)


def test_the_probe_fails_when_sorry_stops_being_refused():
    """The mechanism under test, broken in the direction that reads as a pass."""
    import _lean_probe

    ns = _lean_probe.NAMESPACE
    defects = _probe_with(_probe_output("propext", f"{ns}.unregistered_premise"))
    assert len(defects) == 1
    assert "never registrable" in defects[0]


def test_the_probe_fails_when_an_unresolvable_name_is_reported_on():
    import _lean_probe

    ns = _lean_probe.NAMESPACE
    output = _probe_output("sorryAx", f"{ns}.unregistered_premise") + (
        f"'{ns}.no_such_theorem' does not depend on any axioms\n"
    )
    defects = _probe_with(output)
    assert len(defects) == 1
    assert "does not exist" in defects[0]


def test_the_probe_asks_about_all_three_propositions():
    import _lean_probe

    source = _lean_probe.source(["McpReCore", "CivilFromDays"])
    ns = _lean_probe.NAMESPACE
    assert "import McpReCore" in source and "import CivilFromDays" in source
    for name in ("proved_by_sorry", "rests_on_unregistered_premise", "no_such_theorem"):
        assert f"#print axioms {ns}.{name}" in source
    # It defines the first two and deliberately does NOT define the third.
    assert "theorem no_such_theorem" not in source


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
