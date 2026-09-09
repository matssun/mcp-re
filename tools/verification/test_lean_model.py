# SPDX-License-Identifier: Apache-2.0
"""The generated Lean model's freshness controls — issue #541.

The single property under test: **a model counts as the pinned pipeline's output for this
tree only when a regeneration actually produced it, from these sources, under this
toolchain, and nothing has touched it since.**

Each case below is one of the ways a lane could report a clean model over an unclean one,
and the ADR names four of them by name: stale, missing, zero-selection, and a hand-edited
generated artifact. A fifth — a model extracted by a pipeline the lock no longer pins — is
the same failure one level up, and it is the one that already happened once in this
repository under a valid-looking pin.

Run with `python3 tools/verification/test_lean_model.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _lean_model  # noqa: E402
from _lean_model import Stamp, stamp_defects  # noqa: E402

TOOLCHAINS = {
    "charon": {"state": "resolved", "commit": "c" * 40},
    "aeneas": {"state": "resolved", "commit": "a" * 40},
    "lean": {"state": "resolved", "toolchain": "leanprover/lean4:v4.31.0"},
    "aeneas_lean_backend": {
        "state": "resolved",
        "package_revision": "a" * 40,
        "mathlib_revision": "m" * 40,
    },
    "extraction_container": {
        "state": "resolved",
        "digest": "sha256:" + "d" * 64,
        "definition_digest": "f" * 64,
    },
}

SELECTION = {
    "core.time_civil_from_days": {
        "crate": "mcp-re-core",
        "start_from": ["mcp_re_core::time::format::civil_from_days"],
    }
}


class Tree:
    """A repository and a generated model, on disk, with the module pointed at them.

    The module reads two globals — the repository root and the generated directory — and
    the tests move both. Patching the functions instead would test a different function
    than the lane calls.
    """

    def __init__(self, tmp: Path) -> None:
        self.root = tmp
        self.generated = tmp / "verification" / "lean" / "generated"
        self.generated.mkdir(parents=True)
        (tmp / "mcp-re-core" / "src").mkdir(parents=True)
        self.source = tmp / "mcp-re-core" / "src" / "format.rs"
        self.source.write_text("fn civil_from_days() {}\n", encoding="utf-8")
        self.model = self.generated / "McpReCore.lean"
        self.model.write_text("theorem t : True := trivial\n", encoding="utf-8")
        self._saved = (_lean_model.REPO_ROOT, _lean_model.GENERATED)
        _lean_model.REPO_ROOT = tmp
        _lean_model.GENERATED = self.generated

    def stamp(self) -> Stamp:
        """The stamp a regeneration over this tree would have written."""
        return Stamp(
            identity=_lean_model.extraction_identity(TOOLCHAINS),
            selection=dict(SELECTION),
            sources={"mcp-re-core/src/format.rs": _lean_model.digest(self.source)},
            written=_lean_model.current_written(),
        )

    def restore(self) -> None:
        _lean_model.REPO_ROOT, _lean_model.GENERATED = self._saved


def tree(fn):
    """Run `fn` against a fresh on-disk tree, and put the module's globals back."""
    import tempfile

    def wrapper():
        with tempfile.TemporaryDirectory() as tmp:
            subject = Tree(Path(tmp))
            try:
                fn(subject)
            finally:
                subject.restore()

    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ---------------------------------------------------------------------------
# The clean case, so the failures below mean something
# ---------------------------------------------------------------------------


@tree
def test_a_freshly_regenerated_model_has_no_defects(subject: Tree):
    assert stamp_defects(subject.stamp(), TOOLCHAINS, SELECTION) == []


# ---------------------------------------------------------------------------
# Missing
# ---------------------------------------------------------------------------


@tree
def test_no_stamp_is_a_refusal_not_a_clean_tree(subject: Tree):
    """The green that measures nothing.

    With no regeneration, a drift check compares the checked-in model against itself and
    passes for every model, including one written by hand.
    """
    defects = stamp_defects(None, TOOLCHAINS, SELECTION)
    assert len(defects) == 1
    assert "nothing regenerated" in defects[0]


# ---------------------------------------------------------------------------
# Stale
# ---------------------------------------------------------------------------


@tree
def test_a_source_edited_after_extraction_is_stale(subject: Tree):
    stamp = subject.stamp()
    subject.source.write_text("fn civil_from_days() { /* changed */ }\n", encoding="utf-8")
    defects = stamp_defects(stamp, TOOLCHAINS, SELECTION)
    assert len(defects) == 1
    assert "stale" in defects[0] and "format.rs" in defects[0]


@tree
def test_a_deleted_source_is_stale_too(subject: Tree):
    """Absence is a change. A model extracted from a file that is gone describes nothing."""
    stamp = subject.stamp()
    subject.source.unlink()
    assert any("stale" in defect for defect in stamp_defects(stamp, TOOLCHAINS, SELECTION))


# ---------------------------------------------------------------------------
# Hand-edited
# ---------------------------------------------------------------------------


@tree
def test_an_edited_model_is_caught_by_its_own_digest(subject: Tree):
    """Operational Rule 6: a hand-edit that makes a proof pass is a forged artifact.

    The edit survives review by looking like ordinary Lean. It does not survive being
    compared against what the machine reported writing.
    """
    stamp = subject.stamp()
    subject.model.write_text("theorem t : False := by sorry\n", encoding="utf-8")
    defects = stamp_defects(stamp, TOOLCHAINS, SELECTION)
    assert len(defects) == 1
    assert "modified after extraction" in defects[0]


@tree
def test_a_model_file_added_after_extraction_is_caught(subject: Tree):
    """An extra module is an edit even though every extracted file is untouched."""
    stamp = subject.stamp()
    (subject.generated / "Extra.lean").write_text("axiom cheat : False\n", encoding="utf-8")
    assert any(
        "modified after extraction" in defect
        for defect in stamp_defects(stamp, TOOLCHAINS, SELECTION)
    )


@tree
def test_a_model_file_removed_after_extraction_is_caught(subject: Tree):
    stamp = subject.stamp()
    subject.model.unlink()
    assert any(
        "modified after extraction" in defect
        for defect in stamp_defects(stamp, TOOLCHAINS, SELECTION)
    )


# ---------------------------------------------------------------------------
# Zero selection, and a selection that moved
# ---------------------------------------------------------------------------


@tree
def test_a_manifest_selection_that_moved_invalidates_the_model(subject: Tree):
    """The model covers what was extracted, not what the units now claim."""
    stamp = subject.stamp()
    widened = {
        **SELECTION,
        "core.time_rfc3339": {"crate": "mcp-re-core", "start_from": ["x"]},
    }
    defects = stamp_defects(stamp, TOOLCHAINS, widened)
    assert len(defects) == 1
    assert "selection has changed" in defects[0]


@tree
def test_a_changed_start_from_set_invalidates_the_model(subject: Tree):
    stamp = subject.stamp()
    narrowed = {
        "core.time_civil_from_days": {"crate": "mcp-re-core", "start_from": ["other"]}
    }
    assert any(
        "selection has changed" in defect
        for defect in stamp_defects(stamp, TOOLCHAINS, narrowed)
    )


# ---------------------------------------------------------------------------
# An undeclared instrument
# ---------------------------------------------------------------------------


@tree
def test_a_model_from_a_different_pipeline_is_refused(subject: Tree):
    """The failure this repository has already had, under a pin that looked valid.

    The pinned image went on naming a build of a Dockerfile that had changed three times.
    Every prover commit was unchanged, so every check that read commits kept passing.
    """
    stamp = subject.stamp()
    moved = {
        **TOOLCHAINS,
        "extraction_container": {
            **TOOLCHAINS["extraction_container"],
            "digest": "sha256:" + "e" * 64,
        },
    }
    defects = stamp_defects(stamp, moved, SELECTION)
    assert len(defects) == 1
    assert "different pipeline" in defects[0]
    assert "extraction_container.digest" in defects[0]


@tree
def test_a_moved_aeneas_commit_is_refused(subject: Tree):
    """Not only the image. A different Aeneas produces a different model of the same Rust."""
    stamp = subject.stamp()
    moved = {**TOOLCHAINS, "aeneas": {"state": "resolved", "commit": "b" * 40}}
    assert any(
        "different pipeline" in defect for defect in stamp_defects(stamp, moved, SELECTION)
    )


# ---------------------------------------------------------------------------
# An unreadable record is a missing one
# ---------------------------------------------------------------------------


@tree
def test_an_unparsable_stamp_reads_as_no_stamp(subject: Tree):
    """A record nothing can read does not record anything."""
    stamp_path = subject.root / "stamp.json"
    stamp_path.write_text("{not json", encoding="utf-8")
    saved = _lean_model.STAMP
    _lean_model.STAMP = stamp_path
    try:
        assert _lean_model.read_stamp() is None
    finally:
        _lean_model.STAMP = saved


@tree
def test_a_stamp_of_another_schema_reads_as_no_stamp(subject: Tree):
    """A schema change alters what the fields mean; reading them anyway invents a claim."""
    stamp_path = subject.root / "stamp.json"
    stamp_path.write_text(
        '{"schema_version": 2, "identity": {}, "selection": {}, "sources": {}, '
        '"written": {}}',
        encoding="utf-8",
    )
    saved = _lean_model.STAMP
    _lean_model.STAMP = stamp_path
    try:
        assert _lean_model.read_stamp() is None
    finally:
        _lean_model.STAMP = saved


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
