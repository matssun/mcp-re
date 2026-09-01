# SPDX-License-Identifier: Apache-2.0
"""The escape-hatch gate's own false-green catalogue — ADR-MCPRE-059 §13, Case D.

The single property under test: **the gate refuses a proof whose obligations were moved
into the trusted computing base without the registry saying so, at the place they were
moved.**

Every case is a way the gate previously printed `VERDICT: PASS` over a theorem nobody had:

  * registration by mechanism NAME, so one assumption's `verus:external_body` whitelisted
    every `external_body` in the repository, present and future;
  * an escape hatch on the very function a unit claims to have proved, which makes the
    claimed theorem vacuous while the prover still lists the symbol as verified;
  * a deleted specification, which changes neither the function, nor the crate's verified
    count, nor the prover's symbol list;
  * mechanisms the production pattern set never looked for at all.

Run: python3 tools/verification/test_escape_hatches.py
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _load_tool import load_tool  # noqa: E402

gate = load_tool('check-assumptions', 'check_assumptions')


# --- registration is per unit, not per mechanism name -------------------------


REGISTRY = {"core.time_rfc3339": {"external_body"}}


def test_a_mechanism_is_registered_inside_the_unit_that_registered_it():
    assert gate.is_registered("external_body", {"core.time_rfc3339"}, REGISTRY)


def test_a_mechanism_registered_in_one_unit_does_not_cover_another():
    """THE control. `verus:external_body` trusted for the time parser said nothing about a
    new `external_body` in the admission path, and the gate passed it anyway."""
    assert not gate.is_registered(
        "external_body", {"http_profile.admission_currency"}, REGISTRY
    )


def test_a_file_no_unit_declares_can_register_nothing():
    assert not gate.is_registered("external_body", frozenset(), REGISTRY)


def test_a_file_shared_by_units_is_covered_by_any_of_their_registrations():
    """A trusted-specs file belongs to every unit that declares it, so a registration by
    one of them is a registration for that file — the crossing is visible in the listing."""
    assert gate.is_registered(
        "external_body", {"other.unit", "core.time_rfc3339"}, REGISTRY
    )


# --- the mechanisms the production scan looks for -----------------------------


def matched(line: str) -> set[str]:
    return {
        name
        for name, pattern in gate.PRODUCTION_MECHANISMS.items()
        if re.search(pattern, line)
    }


def test_removing_a_function_from_verification_is_a_mechanism():
    """`#[verifier::external]` is a STRONGER escape than external_body — the function is
    not verified at all — and the production pattern set did not contain it."""
    assert "external" in matched("    #[verifier::external]")
    assert "external" in matched('#[cfg_attr(feature = "verify", verus_verify(external))]')


def test_external_body_is_not_reported_as_external():
    """The word-boundary trap: `external_body` and `external_type_specification` are their
    own mechanisms and must not be collapsed into the broader one."""
    assert matched("#[verifier::external_body]") == {"external_body"}
    assert matched("#[verifier::external_type_specification]") == {
        "external_type_specification"
    }


def test_an_uninterpreted_spec_function_is_a_mechanism():
    """An uninterpreted spec function is a trusted seam by construction: every theorem
    mentioning it says nothing about what it computes."""
    assert "uninterp" in matched("pub uninterp spec fn labeled_digest(b: Seq<u8>) -> int;")


def test_opaque_axiom_and_sorry_are_mechanisms():
    assert "opaque" in matched("#[verifier::opaque]")
    assert "axiom" in matched("broadcast axiom fn lemma() {}")
    assert "sorry" in matched("  sorry")


def test_ordinary_english_still_does_not_trip_the_production_scan():
    """The limit the code forms exist to protect: a gate that fired on prose would be
    ignored within a week."""
    assert matched("// admit only the closed set of registry types") == set()
    assert matched("let external_id = header.external_reference();") == set()


def test_a_method_named_admit_is_not_a_proof_escape_hatch():
    """`inner_async.admit()` asks the inner plane whether it will accept a request. Verus'
    `admit()` deletes a proof obligation. A gate that fired on the first would be ignored
    by the time it mattered for the second."""
    assert matched("match self.inner_async.admit() {") == set()
    assert matched("if index.assume(peer) {") == set()
    # Path-qualified is still the mechanism: `::` is not `.`.
    assert "admit" in matched("vstd::pervasive::admit();")
    assert "assume" in matched("assume(x < 10);")


def test_a_method_named_admit_is_not_a_hatch_where_it_is_defined_either():
    """The other half of the same confusion, and it arrived separately.

    `inner_plane.rs` DEFINES `fn admit(&self)` — the inner plane's own question about
    whether it will accept a request. The call site stopped tripping the gate when the
    caller entered a unit's paths; the definition started tripping it when the definition
    did. A definition deletes no proof obligation.
    """
    assert matched("pub(super) fn admit(&self) -> Result<Established<()>, Refusal> {") == set()
    assert matched("fn assume(x: u8) -> u8 { x }") == set()
    # A definition is not a hatch; a CALL through a path still is.
    assert "admit" in matched("vstd::pervasive::admit();")


def test_the_production_scan_reads_the_shipped_half_only():
    """A region that ships in no binary cannot weaken a proof about one.

    `replay.rs` has a test helper `fn admit(..)`; Verus' `admit()` deletes a proof
    obligation. Scanning the whole file reports the first as the second.
    """
    lines = gate.production_lines(
        "fn ship() {}\n"
        "#[cfg(test)]\nmod tests {\n    fn admit(x: u8) -> u8 { x }\n}\n"
        "fn late() {}\n"
    )
    kept = [text for _, text in lines]
    assert "fn ship() {}" in kept
    assert "fn late() {}" in kept, "production below a test module is still production"
    assert not any("admit" in text for text in kept)
    assert [n for n, text in lines if text == "fn late() {}"] == [6], (
        "line numbers must stay absolute, or a report points at the wrong line"
    )


# --- a claimed theorem the prover was told not to check -----------------------


PROVED = """
/// Doc comment.
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures
        out matches Ok(v) ==> v < 10,
))]
pub fn check_params(x: u64) -> Result<u64, E> {
    Ok(x)
}
"""

VACUOUS = """
#[cfg_attr(feature = "verify", verus_verify(external_body))]
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures
        out matches Ok(v) ==> v < 10,
))]
pub fn check_params(x: u64) -> Result<u64, E> {
    Ok(x)
}
"""

SPECIFICATION_DELETED = """
/// Doc comment.
#[inline]
pub fn check_params(x: u64) -> Result<u64, E> {
    Ok(x)
}
"""


def block_for(source: str) -> str:
    sites = gate._definition_sites(
        source.splitlines(), gate._definition("check_params")
    )
    assert len(sites) == 1, sites
    return sites[0][1]


def with_line_before(source: str, comment: str) -> str:
    """`source` with `comment` on its own line directly above the `check_params` item."""
    out = []
    for line in source.splitlines():
        if "fn check_params" in line:
            out.append(comment)
        out.append(line)
    return "\n".join(out)


def hatched(block: str) -> set[str]:
    return {
        name
        for name, pattern in gate.VACUITY_AT_PROVED_SYMBOL.items()
        if re.search(pattern, block)
    }


def test_a_real_specification_reads_as_one():
    block = block_for(PROVED)
    assert gate.SPECIFICATION_TEXT.search(block)
    assert hatched(block) == set()


def test_an_escape_hatch_on_the_proved_symbol_is_seen():
    """The critical case: annotate the proved function `external_body` and the theorem it
    advertises becomes an axiom. Verus still reports the symbol verified, the crate still
    verifies, and every earlier version of this gate still printed PASS."""
    assert "external_body" in hatched(block_for(VACUOUS))


def test_a_deleted_specification_leaves_a_function_with_no_contract():
    """A Verus specification is a detachable attribute. Deleting it removes the theorem
    and nothing else — not the function, not the verified count, not the symbol list."""
    block = block_for(SPECIFICATION_DELETED)
    assert not gate.SPECIFICATION_TEXT.search(block)


def test_prose_about_a_specification_is_not_a_specification():
    """R9-C002 / R9-C038, and it is the only control for a deleted specification.

    Comment lines were accumulated into the block the gate searched, so the words
    `requires` or `ensures` in the DOC COMMENT above a function satisfied
    `SPECIFICATION_TEXT`. The attribute could be deleted while the prose describing it
    stayed — the function, the crate's verified count and the prover's symbol list all
    unchanged — and the gate reported the theorem present.

    A doc comment says what a function is supposed to do. The attribute is what makes the
    prover check it, and only the second is evidence.
    """
    described = with_line_before(
        SPECIFICATION_DELETED,
        "/// Ensures the parameter set is admissible, and requires a validated policy.",
    )
    block = block_for(described)
    assert not gate.SPECIFICATION_TEXT.search(block), (
        "prose describing a specification read as the specification"
    )


def test_a_comment_cannot_supply_an_escape_hatch_either():
    """The same walk, the other direction: a false positive rather than a false green.

    `external_body` written in a comment is a word about the code, not an instruction to
    the prover, and a gate that cannot tell them apart is wrong in both directions.
    """
    mentioned = with_line_before(
        PROVED, "// Deliberately NOT external_body: the prover checks this one."
    )
    assert hatched(block_for(mentioned)) == set()


def test_a_doc_comment_between_the_attribute_and_the_item_does_not_orphan_it():
    """Comments are not part of the block; they must still not RESET it.

    Rust permits a doc comment between an attribute and the item it decorates, and an
    attribute separated that way is still that item's. Dropping the block at a comment
    would report every such specification as deleted.
    """
    separated = with_line_before(PROVED, "/// What this function does, in prose.")
    assert gate.SPECIFICATION_TEXT.search(block_for(separated))


def test_the_block_walker_does_not_reach_the_previous_item():
    """Otherwise a neighbouring function's `ensures` answers for this one, and the deleted
    specification above reads as present."""
    two = PROVED + SPECIFICATION_DELETED.replace("check_params", "other_fn")
    sites = gate._definition_sites(two.splitlines(), gate._definition("other_fn"))
    assert len(sites) == 1
    assert not gate.SPECIFICATION_TEXT.search(sites[0][1])


# --- the repository's own state ------------------------------------------------


def test_every_declared_theorem_is_established_in_the_tree_as_it_stands():
    """Not a unit test of the mechanism but of the repository: no unit currently advertises
    a theorem whose function is missing, excused, or unspecified."""
    assert gate.proved_symbol_defects() == []


# --- the FAIL text must name a remedy that EXISTS ----------------------------


def test_a_site_no_unit_declares_is_told_to_declare_the_file_first():
    """R9-C120. `scope` names units, so a site in a file no `[[unit]]` declares cannot be
    registered at all — and the gate used to tell its author to add an assumption scoped to
    "this unit", which is a step that does not exist for them. The two remedies are
    different and the gate must not offer one for both."""
    import io
    from contextlib import redirect_stderr

    source = Path(gate.__file__).read_text(encoding="utf-8")
    assert "no unit declares this file" in source, (
        "the FAIL path must distinguish a site with an owning unit from one without"
    )
    assert "Declare the file " in source and "`[[unit]]` whose" in source, (
        "the remedy for an unowned site is to declare the file, not to register a scope "
        "that cannot name it"
    )
    # And the two branches are selected by the owner set, which is what `is_registered`
    # already answers `False` for.
    assert not gate.is_registered("external_body", frozenset(), {"u": {"external_body"}})


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
