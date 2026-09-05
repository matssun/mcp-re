# SPDX-License-Identifier: Apache-2.0
"""The generated views' drift controls — ADR-MCPRE-059 §9, §15, Phase T3.

The single property under test: **a generated view can never say something the catalogues
do not.** Every case is a way a document could drift away from its source while still
looking authoritative:

  * a hand edit, which survives review by looking like ordinary Markdown;
  * a catalogue change with no regeneration, which leaves yesterday's reading in the tree;
  * a file in the generated directory that no generator produces, so nothing can ever
    establish that it is current;
  * a render that is not reproducible, which would make the gate fire on noise and be
    switched off within a week.

And the one that is about honesty rather than drift: a view must show its whole input or
say what it bounded, because silent truncation reads as coverage.

Run: python3 tools/verification/test_views.py
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _load_tool import load_tool  # noqa: E402

from _manifest import (  # noqa: E402
    load_assumptions,
    load_trust_boundaries,
    load_verification,
)
from _theorems import load_theorems  # noqa: E402
from _views import GENERATED_ROOT, render_all  # noqa: E402

generator = load_tool('generate-views', 'generate_views')

UNIT = "http_profile.freshness_window"


def catalogues(
    *theorem_rows, roots: list[str] | None = None
) -> tuple[dict, dict, dict, dict]:
    doc = load_verification()
    theorems = {
        "schema_version": 1,
        "root_theorems": list(roots or []),
        "theorem": list(theorem_rows),
    }
    return theorems, doc, load_assumptions(), load_trust_boundaries()


def theorem(**overrides) -> dict:
    entry = {
        "id": "THM-0001",
        "title": "Freshness admission implies the accepted window is current",
        "statement": "Every admitted request satisfies the skew-widened window constraints.",
        "security_consequence": "A request cannot be admitted on stale freshness evidence.",
        "scope": "Freshness admission only.",
        "owner": UNIT,
        "review_requirement": "Owner security-specification review",
        "supported_by": [f"unit://{UNIT}"],
        "depends_on": [],
    }
    entry.update(overrides)
    return entry


def write_into(root: Path, views: dict[str, str]) -> None:
    for relative, content in views.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def drift_against(root: Path, views: dict[str, str]) -> list[str]:
    """`generate-views --check` semantics, against a temporary tree."""
    original = generator.REPO_ROOT
    generator.REPO_ROOT = root
    try:
        return generator.differences(views)
    finally:
        generator.REPO_ROOT = original


# --- reproducibility ------------------------------------------------------------


def test_rendering_twice_is_byte_identical():
    """No timestamp, no run id, no host detail. A view that differed between two runs
    would make the drift gate fire on noise, and a noisy gate gets switched off."""
    first = render_all(*catalogues(theorem()))
    second = render_all(*catalogues(theorem()))
    assert first == second


def test_the_committed_views_match_the_live_catalogues():
    """The repository as it stands: what is checked in is what the catalogues render."""
    doc = load_verification()
    theorems = load_theorems({unit["id"] for unit in doc.get("unit", [])})
    assert (
        generator.differences(
            render_all(theorems, doc, load_assumptions(), load_trust_boundaries())
        )
        == []
    )


# --- drift ----------------------------------------------------------------------


def test_a_hand_edited_view_fails_the_gate():
    """THE control. A hand edit looks like ordinary Markdown to a reviewer and is caught
    only by not surviving regeneration."""
    views = render_all(*catalogues(theorem()))
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_into(root, views)
        target = root / f"{GENERATED_ROOT}/theorem-index.md"
        target.write_text(
            target.read_text(encoding="utf-8").replace(
                "Freshness admission only.", "Everything about admission."
            ),
            encoding="utf-8",
        )
        drift = drift_against(root, views)
    assert any("theorem-index.md" in entry and "differs" in entry for entry in drift), drift


def test_a_catalogue_change_without_regeneration_fails_the_gate():
    """The other direction, and the more likely one: the source moved and the reading in
    the tree is yesterday's."""
    committed = render_all(*catalogues(theorem()))
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_into(root, committed)
        moved = render_all(*catalogues(theorem(statement="A weaker claim.")))
        drift = drift_against(root, moved)
    assert any("theorem-index.md" in entry for entry in drift), drift


def test_a_missing_view_fails_the_gate():
    views = render_all(*catalogues(theorem()))
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_into(root, views)
        (root / f"{GENERATED_ROOT}/owners.md").unlink()
        drift = drift_against(root, views)
    assert any("owners.md" in entry and "missing" in entry for entry in drift), drift


def test_a_file_no_generator_produces_fails_the_gate():
    """A file in a directory whose whole promise is that everything in it is derived, and
    which nothing can regenerate — so nothing can ever establish that it is current."""
    views = render_all(*catalogues(theorem()))
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_into(root, views)
        (root / f"{GENERATED_ROOT}/hand-written-summary.md").write_text("trust me\n")
        drift = drift_against(root, views)
    assert any("hand-written-summary.md" in entry for entry in drift), drift


# --- what the views must and must not contain --------------------------------------


def test_the_reverse_edges_are_computed_not_stored():
    """An assumption's consumers appear in the view but in no catalogue. Changing a
    THEOREM's `supported_by` changes what the assumption view says, without anyone editing
    assumptions.toml — which is what makes it derived rather than a second authority."""
    without = render_all(*catalogues(theorem(supported_by=[])))
    with_support = render_all(*catalogues(theorem()))
    key = f"{GENERATED_ROOT}/assumption-consumers.md"
    assert "THM-0001" not in without[key]
    assert "THM-0001" in with_support[key]

    # And no catalogue DECLARES the reverse direction. Checked as TOML keys, not as
    # substrings: theorems.toml names `consumed_by` in its header precisely to forbid it,
    # and a test that could not tell a prohibition from a declaration would fire on the
    # documentation while missing a key smuggled into a nested table.
    for path in ("verification/policy/assumptions.toml", "verification/policy/theorems.toml"):
        with open(path, "rb") as handle:
            doc = tomllib.load(handle)
        for table in [doc] + [row for rows in doc.values() if isinstance(rows, list) for row in rows if isinstance(row, dict)]:
            for reverse in ("consumed_by", "dependents", "guarantees"):
                assert reverse not in table, (path, reverse)


def test_every_view_carries_a_do_not_edit_marker_and_its_sources():
    for relative, content in render_all(*catalogues(theorem())).items():
        assert "GENERATED FILE — DO NOT EDIT" in content, relative
        assert "verification/policy/theorems.toml" in content, relative
        assert "tools/verification/generate-views" in content, relative


def test_no_view_truncates_what_it_shows():
    """Silent truncation reads as coverage. Nothing here bounds its input, so the longest
    declared assumption description must appear in full."""
    _theorems, _doc, assumptions, _boundaries = catalogues(theorem())
    longest = max(
        (entry["description"] for entry in assumptions.get("assumption", [])),
        key=len,
        default="",
    )
    view = render_all(*catalogues(theorem()))[f"{GENERATED_ROOT}/assumption-consumers.md"]
    assert " ".join(longest.split()) in view


def test_the_dependency_graph_splits_into_focused_components():
    """One diagram per connected component. A single global diagram is unreadable at
    exactly the size where a reader needs it."""
    view = render_all(
        *catalogues(
            theorem(id="THM-0001"),
            theorem(id="THM-0002", depends_on=["THM-0001"]),
            theorem(id="THM-0003"),
        )
    )[f"{GENERATED_ROOT}/theorem-dependencies.md"]
    assert view.count("```mermaid") == 2
    assert "THM_0001 --> THM_0002" in view


def test_an_empty_registry_says_so_rather_than_rendering_a_blank_page():
    """"No claim is made" and "every claim holds" must never look alike."""
    views = render_all(*catalogues())
    index = views[f"{GENERATED_ROOT}/theorem-index.md"]
    assert "declares no theorem" in index
    assert "no claim is made, so no claim is established" in index


def test_the_index_never_asserts_that_a_THEOREM_is_established():
    """The view cannot see the attestations, so it may not report the conjunction — but it
    must SAY that, rather than leaving a reader to assume the table is assurance.

    So the property has two halves: the disclaimer is present, and the marker `review`
    prints for an established claim never appears here."""
    index = render_all(*catalogues(theorem()))[f"{GENERATED_ROOT}/theorem-index.md"]
    assert "Support is STRUCTURAL" in index
    assert "this view cannot see the attestations" in index
    assert "ESTABLISHED" not in index


def test_the_theorem_only_views_do_not_read_the_other_catalogues():
    """The module split claims an invalidation boundary — `_theorem_views` is a function of
    the registry alone — so the claim is checked rather than asserted in a comment.

    If it ever stopped holding, the two views would silently start depending on catalogues
    their own fingerprint axis does not cover, which is the collapse §14.7 exists to
    prevent."""
    doc = load_verification()
    theorems, _doc, assumptions, _boundaries = catalogues(theorem())
    baseline = render_all(theorems, doc, assumptions, _boundaries)
    mutated = dict(doc, unit=[dict(unit, **{"class": "V9"}) for unit in doc["unit"]])
    moved = render_all(theorems, mutated, assumptions, _boundaries)

    for name in ("theorem-index.md", "theorem-dependencies.md"):
        key = f"{GENERATED_ROOT}/{name}"
        assert baseline[key] == moved[key], name

    # The control, and it is the half that makes the assertions above mean something: a
    # view that DOES cross the catalogues must move under the same mutation. Without it,
    # a mutation too weak to reach any renderer would pass as a boundary proof.
    owners = f"{GENERATED_ROOT}/owners.md"
    assert baseline[owners] != moved[owners]


def test_the_root_set_is_rendered_from_the_declaration_not_from_graph_shape():
    """ADR-MCPRE-059 §28.1, in the view layer. THM-0001 has no dependents in either case;
    only the declaration decides whether it is drawn as a system root, so a reader can never
    learn a root set from this page that the owner did not ratify."""
    index = f"{GENERATED_ROOT}/theorem-index.md"
    graph = f"{GENERATED_ROOT}/theorem-dependencies.md"

    undeclared = render_all(*catalogues(theorem()))
    assert "_No system root is declared._" in undeclared[index]
    assert "never a pass" in undeclared[index]
    assert "ROOT — THM-0001" not in undeclared[graph]

    declared = render_all(*catalogues(theorem(), roots=["THM-0001"]))
    assert "## System roots" in declared[index]
    assert "| THM-0001 |" in declared[index]
    assert "ROOT — THM-0001" in declared[graph]


def test_declaring_a_root_moves_the_registry_views_and_nothing_else():
    """The root set lives in `theorems.toml`, so it may only reach views derived from it."""
    baseline = render_all(*catalogues(theorem()))
    rooted = render_all(*catalogues(theorem(), roots=["THM-0001"]))
    for name in ("theorem-index.md", "theorem-dependencies.md"):
        key = f"{GENERATED_ROOT}/{name}"
        assert baseline[key] != rooted[key], name
    for name in ("owners.md", "assumption-consumers.md", "blast-radius.md"):
        key = f"{GENERATED_ROOT}/{name}"
        assert baseline[key] == rooted[key], name


def test_the_root_views_are_reproducible():
    """Same catalogues, same bytes — the property the drift gate rests on."""
    once = render_all(*catalogues(theorem(), roots=["THM-0001"]))
    twice = render_all(*catalogues(theorem(), roots=["THM-0001"]))
    assert once == twice


def test_the_structural_blast_radius_does_not_claim_to_be_live():
    view = render_all(*catalogues(theorem()))[f"{GENERATED_ROOT}/blast-radius.md"]
    assert "never what IS dirty" in view
    assert "review-frontier" in view


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
