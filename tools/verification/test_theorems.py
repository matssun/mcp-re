# SPDX-License-Identifier: Apache-2.0
"""The theorem registry's false-green catalogue — ADR-MCPRE-059 §6.3, §16.1.

The single property under test: **a claim that resolves to nothing is refused, never
satisfied vacuously.**

Every case below is a way a registry could hold a security claim that reads as governed
while its support closure resolves to nothing:

  * a support edge pointing at a unit that does not exist, which derives an empty evidence
    closure — and an empty closure is satisfied by everything;
  * a dependency, replacement, or owner that resolves nowhere;
  * a cycle, where each claim is supported by the next and none by a unit;
  * a mistyped key, which would drop a declaration while looking like one;
  * a key restating a fact `verification.toml` owns, which is how two authorities come to
    disagree;
  * a live claim resting on a withdrawn one.

Each negative control is paired with the positive case it must not reject, because a gate
that refuses everything measures as little as one that refuses nothing.

Run: python3 tools/verification/test_theorems.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _manifest import ManifestError, load_verification  # noqa: E402
from _theorems import (  # noqa: E402
    structurally_supported_theorems,
    load_theorems,
    root_theorems,
    unsupported_theorems,
    validate_theorems,
)

UNITS = {"http_profile.freshness_window", "core.time_rfc3339"}


def theorem(**overrides) -> dict:
    entry = {
        "id": "THM-0001",
        "title": "Freshness admission implies the accepted window is current",
        "statement": "Any admitted request satisfies the skew-widened window constraints.",
        "security_consequence": "A request cannot be admitted on stale freshness evidence.",
        "scope": "Freshness admission only; not signature validity or replay uniqueness.",
        "owner": "http_profile.freshness_window",
        "review_requirement": "Owner security-specification review",
        "supported_by": ["unit://http_profile.freshness_window"],
        "depends_on": [],
    }
    entry.update(overrides)
    return {key: value for key, value in entry.items() if value is not None}


def doc(*theorems, roots: list[str] | None = None) -> dict:
    return {
        "schema_version": 1,
        "root_theorems": list(roots or []),
        "theorem": list(theorems),
    }


def refused(*theorems) -> str:
    """The message validation refused with, or an assertion failure if it accepted."""
    try:
        validate_theorems(doc(*theorems), UNITS)
    except ManifestError as exc:
        return str(exc)
    raise AssertionError("validation accepted a registry it must refuse")


def refused_registry(registry: dict) -> str:
    """As `refused`, for a case whose defect is in the registry's top level."""
    try:
        validate_theorems(registry, UNITS)
    except ManifestError as exc:
        return str(exc)
    raise AssertionError("validation accepted a registry it must refuse")


# --- the positive case, so the controls below mean something ------------------


def test_a_well_formed_registry_validates():
    validate_theorems(doc(theorem()), UNITS)


def test_an_empty_registry_validates():
    """The honest state before any claim is written. It must not need a placeholder row."""
    validate_theorems(doc(), UNITS)
    assert structurally_supported_theorems(doc()) == set()


# --- identity ------------------------------------------------------------------


def test_a_duplicate_id_is_refused():
    assert "duplicate theorem id" in refused(theorem(), theorem(title="Another claim"))


def test_a_malformed_id_is_refused():
    for bad in ("THM-1", "THM-00001", "MCPRE-0001", "thm-0001", "THM-000A", 1):
        assert "THM-NNNN" in refused(theorem(id=bad))


# --- support edges: the vacuity control ---------------------------------------


def test_a_support_edge_to_no_unit_fails_closed():
    """THE control. A dangling `supported_by` contributes nothing to the evidence closure,
    and a closure with nothing in it is satisfied by everything — the theorem would read as
    supported by evidence that does not exist."""
    message = refused(theorem(supported_by=["unit://http_profile.nonexistent"]))
    assert "does not resolve" in message and "vacuously" in message


def test_a_support_edge_of_the_wrong_scheme_is_refused():
    """`test://` and `verus://` name evidence, which the UNIT owns. A theorem that could
    name a lane directly would select evidence by provider rather than by target."""
    assert "does not resolve" in refused(
        theorem(supported_by=["test://http_profile/verify/freshness_window_vectors"])
    )
    assert "does not resolve" in refused(
        theorem(supported_by=["http_profile.freshness_window"])
    )


def test_a_theorem_with_no_supporting_unit_has_no_support_closure():
    """Allowed to be declared — a claim may be stated before it is supported — but its
    support closure must not resolve. That distinction is what this layer is for."""
    registry = doc(theorem(supported_by=[]))
    validate_theorems(registry, UNITS)
    assert structurally_supported_theorems(registry) == set()
    assert unsupported_theorems(registry) == ["THM-0001"]


def test_a_composed_theorem_is_no_stronger_than_what_it_rests_on():
    """A supported claim depending on an unsupported one has no support closure of its own.
    Otherwise a composition launders an unsupported premise into a supported conclusion."""
    registry = doc(
        theorem(id="THM-0001", supported_by=[]),
        theorem(id="THM-0002", depends_on=["THM-0001"]),
    )
    validate_theorems(registry, UNITS)
    assert structurally_supported_theorems(registry) == set()


def test_a_supported_composition_over_supported_premises_resolves():
    registry = doc(
        theorem(id="THM-0001"),
        theorem(id="THM-0002", depends_on=["THM-0001"]),
    )
    validate_theorems(registry, UNITS)
    assert structurally_supported_theorems(registry) == {"THM-0001", "THM-0002"}
    assert unsupported_theorems(registry) == []


# --- dependency edges ----------------------------------------------------------


def test_a_dependency_on_no_theorem_is_refused():
    assert "not a declared theorem" in refused(theorem(depends_on=["THM-9999"]))


def test_a_self_dependency_is_refused():
    assert "names itself" in refused(theorem(depends_on=["THM-0001"]))


def test_a_cycle_is_refused():
    """Each claim supported by the next, none by a unit."""
    message = refused(
        theorem(id="THM-0001", depends_on=["THM-0002"]),
        theorem(id="THM-0002", depends_on=["THM-0003"]),
        theorem(id="THM-0003", depends_on=["THM-0001"]),
    )
    assert "cycle in depends_on" in message


# --- ownership -----------------------------------------------------------------


def test_an_owner_that_is_not_a_declared_unit_is_refused():
    assert "not a [[unit]] declared" in refused(theorem(owner="someone@example.com"))


# --- strictness ----------------------------------------------------------------


def test_an_unknown_key_is_refused():
    assert "unknown key" in refused(theorem(sceope="typo"))


def test_a_missing_required_key_is_refused():
    assert "missing required key" in refused(theorem(security_consequence=None))


def test_an_empty_claim_is_refused():
    """A registered theorem whose statement is blank asserts nothing while occupying an
    ID that the review history will refer to."""
    assert "non-empty string" in refused(theorem(statement="   "))


def test_a_key_that_restates_a_unit_fact_is_refused_by_name():
    """Not merely as an unknown key: two authorities over one fact is how they come to
    disagree, and the message must say which file owns it."""
    for key, owner in (
        ("paths", "[[unit]].paths"),
        ("assumptions", "[[unit]].assumptions"),
        ("evidence", "[[unit]].evidence"),
        ("proved_symbols", "[[unit]].proved_symbols"),
    ):
        assert owner in refused(theorem(**{key: []}))


def test_a_stored_approval_is_refused():
    """§14.7. An approval is evidence ABOUT a fingerprint; a status string here would not
    say which proposition was approved, and would make self-approval a one-file edit."""
    for key in ("review", "review_status", "approved", "status"):
        assert "reviewed_fingerprint" in refused(theorem(**{key: "approved"}))


def test_a_stored_reverse_edge_is_refused():
    for key in ("consumed_by", "dependents", "guarantees"):
        assert "reverse edge is never stored" in refused(theorem(**{key: []}))


def test_a_schema_version_this_tooling_does_not_implement_is_refused():
    registry = doc(theorem())
    registry["schema_version"] = 2
    try:
        validate_theorems(registry, UNITS)
    except ManifestError as exc:
        assert "schema_version" in str(exc)
    else:
        raise AssertionError("a future schema version was tolerated")


# --- deprecation ---------------------------------------------------------------


def test_a_deprecated_theorem_stays_resolvable_and_links_its_replacement():
    registry = doc(
        theorem(id="THM-0001", replaced_by="THM-0002", supported_by=[]),
        theorem(id="THM-0002"),
    )
    validate_theorems(registry, UNITS)
    # Present, so historical evidence resolves — and supporting nothing, so it cannot
    # carry a live closure.
    assert structurally_supported_theorems(registry) == {"THM-0002"}
    assert unsupported_theorems(registry) == []


def test_a_replacement_link_to_nothing_is_refused():
    assert "not another declared theorem" in refused(theorem(replaced_by="THM-9999"))
    assert "not another declared theorem" in refused(theorem(replaced_by="THM-0001"))


def test_a_replacement_chain_to_a_deprecated_theorem_is_refused():
    message = refused(
        theorem(id="THM-0001", replaced_by="THM-0002"),
        theorem(id="THM-0002", replaced_by="THM-0003"),
        theorem(id="THM-0003"),
    )
    assert "itself deprecated" in message


def test_a_live_claim_may_not_rest_on_a_withdrawn_one():
    message = refused(
        theorem(id="THM-0001", replaced_by="THM-0003"),
        theorem(id="THM-0002", depends_on=["THM-0001"]),
        theorem(id="THM-0003"),
    )
    assert "may not rest on a withdrawn one" in message


# --- the repository's own registry ---------------------------------------------


def test_the_live_registry_validates_against_the_live_units():
    """Not a unit test of the mechanism but of the repository: the registry as committed
    resolves against the units as committed."""
    units = {unit["id"] for unit in load_verification().get("unit", [])}
    registry = load_theorems(units)
    assert registry["schema_version"] == 1
    # Every live theorem is either structurally supported or reported as not — no third
    # state, and neither reading is assurance on its own.
    declared = {entry["id"] for entry in registry.get("theorem", [])}
    live = {
        entry["id"]
        for entry in registry.get("theorem", [])
        if not entry.get("replaced_by")
    }
    assert structurally_supported_theorems(registry) | set(unsupported_theorems(registry)) == live
    assert structurally_supported_theorems(registry) <= declared


def test_a_depends_on_against_the_declared_proof_dependency_is_refused():
    """The theorem edge and the unit edge are not a duplicated authority — one is about
    evidence dirtiness, the other about which claim is a premise. But where both exist over
    the same owners they state one relation twice and may not disagree.

    This is a real error, not a hypothetical: it was drafted backwards from the prose
    during T4 and caught only by reading `verification.toml`. `depends_on` runs consumer to
    premise; the unit edge runs premise to consumer.
    """
    edges = [
        {
            "kind": "PROOF_DEPENDENCY",
            "from": "core.time_rfc3339",
            "to": "http_profile.freshness_window",
        }
    ]
    premise = theorem(id="THM-0001", owner="core.time_rfc3339")
    consumer = theorem(
        id="THM-0002",
        owner="http_profile.freshness_window",
        supported_by=["unit://http_profile.freshness_window"],
        depends_on=["THM-0001"],
    )
    # The declared direction: the consumer rests on the premise. Accepted.
    validate_theorems(doc(premise, consumer), UNITS, edges)

    # The inversion: the premise's own claim rests on its consumer's.
    inverted_premise = theorem(id="THM-0001", owner="core.time_rfc3339", depends_on=["THM-0002"])
    inverted_consumer = theorem(
        id="THM-0002",
        owner="http_profile.freshness_window",
        supported_by=["unit://http_profile.freshness_window"],
    )
    try:
        validate_theorems(doc(inverted_premise, inverted_consumer), UNITS, edges)
    except ManifestError as exc:
        assert "runs against the declared PROOF_DEPENDENCY" in str(exc), exc
    else:
        raise AssertionError("validation accepted an inverted dependency edge")


def test_the_direction_check_is_off_when_no_edges_are_supplied():
    """A caller that has not loaded the unit catalogue's edges must not silently appear to
    have run the stronger validation. Omitting them skips the check rather than passing it.
    """
    inverted = theorem(id="THM-0001", owner="core.time_rfc3339", depends_on=["THM-0002"])
    other = theorem(
        id="THM-0002",
        owner="http_profile.freshness_window",
        supported_by=["unit://http_profile.freshness_window"],
    )
    validate_theorems(doc(inverted, other), UNITS)


# --- the system root set, ADR-MCPRE-059 §28.1 --------------------------------


def test_a_root_naming_an_unknown_theorem_is_refused():
    """Fail closed. A root that resolves to nothing would make proof-tree completeness
    quantify over a claim that does not exist — and an empty quantifier is satisfied.
    """
    message = refused_registry(doc(theorem(), roots=["THM-9999"]))
    assert "not a declared theorem" in message, message


def test_a_deprecated_theorem_may_not_be_a_root():
    """A withdrawn claim carries no system promise. Naming one as a root would let the
    registry report a promise as closed while the proposition behind it has been retired.
    """
    live = theorem(id="THM-0002", owner="core.time_rfc3339")
    dead = theorem(id="THM-0001", replaced_by="THM-0002")
    message = refused_registry(doc(dead, live, roots=["THM-0001"]))
    assert "is deprecated" in message, message


def test_a_duplicate_root_is_refused():
    message = refused_registry(doc(theorem(), roots=["THM-0001", "THM-0001"]))
    assert "duplicate root" in message, message


def test_root_theorems_must_be_declared():
    """Absence is not "no roots are needed". The key is required so that a registry which
    has never been asked the question cannot read as one that answered it with "none".
    """
    registry = {"schema_version": 1, "theorem": [theorem()]}
    message = refused_registry(registry)
    assert "root_theorems" in message, message


def test_root_theorems_must_be_a_list_of_strings():
    registry = doc(theorem())
    registry["root_theorems"] = "THM-0001"
    message = refused_registry(registry)
    assert "list of THM-NNNN strings" in message, message


def test_a_root_is_declared_and_never_inferred_from_graph_shape():
    """The control for the inference nobody may implement.

    THM-0001 has no dependents: nothing rests on it. Under a "roots are the theorems with
    no dependents" rule it would be a system promise, and the registry would report itself
    complete the moment it held leaves. It is not a root, because it was not declared one.
    """
    isolated = theorem(id="THM-0001")
    consumer = theorem(
        id="THM-0002", owner="core.time_rfc3339", depends_on=[], supported_by=[
            "unit://core.time_rfc3339"
        ]
    )
    registry = doc(isolated, consumer)
    validate_theorems(registry, UNITS)
    assert root_theorems(registry) == [], root_theorems(registry)
    # And the declaration is what makes one:
    declared = doc(isolated, consumer, roots=["THM-0001"])
    validate_theorems(declared, UNITS)
    assert root_theorems(declared) == ["THM-0001"]


def test_root_membership_may_not_be_restated_on_a_theorem():
    """One authority for one fact (§8.2). A per-theorem `root = true` beside the top-level
    set is how the two come to disagree about what the system promises.
    """
    message = refused_registry(doc(theorem(root=True)))
    assert "root_theorems" in message, message


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
