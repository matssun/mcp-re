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
        "artifact_digest": "sha256:" + "d" * 64,
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
            "artifact_digest": "sha256:" + "e" * 64,
        },
    }
    defects = stamp_defects(stamp, moved, SELECTION)
    assert len(defects) == 1
    assert "different pipeline" in defects[0]
    assert "extraction_container.artifact_digest" in defects[0]


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


# ---------------------------------------------------------------------------
# The extraction and the build definition must agree about which modules exist
# ---------------------------------------------------------------------------
#
# Two places hold one fact: Aeneas decides the module name from the LLBC file's basename —
# measured, `m.llbc` gives `M.lean` and `mcp_re_core.llbc` gives `McpReCore.lean` — and
# `lakefile.toml` declares which roots the package builds. They drift silently: a module the
# package does not build elaborates for nobody, and the lane would then report a theorem it
# could not find rather than the reason it could not find it.


def test_the_produced_roots_are_read_off_whatever_aeneas_wrote():
    assert _lean_model.produced_roots({"McpReCore.lean": "x"}) == ["McpReCore"]
    # A split model: a root file plus a directory beside it. Same root, once.
    assert _lean_model.produced_roots(
        {"McpReCore.lean": "x", "McpReCore/Types.lean": "y", "McpReCore/Funs.lean": "z"}
    ) == ["McpReCore"]
    assert _lean_model.produced_roots({}) == []


def test_a_model_named_after_the_unit_would_not_be_the_declared_root():
    """The defect this control exists for.

    Naming the LLBC after the unit id rather than the crate produces a module the lakefile
    does not build. It looks like a successful extraction — files appear, the tool exits 0 —
    and nothing downstream elaborates against it.
    """
    written = {"Core.time_civil_from_days.lean": "x"}
    assert _lean_model.produced_roots(written) != ["McpReCore"]


def test_the_lakefile_is_the_authority_on_which_roots_are_expected():
    """Read from the build definition, and narrowed to the library being asked about."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        lean = Path(tmp)
        (lean / "lakefile.toml").write_text(
            'name = "mcpre"\n'
            "[[lean_lib]]\n"
            'name = "Generated"\n'
            'srcDir = "generated"\n'
            'roots = ["McpReCore"]\n'
            "[[lean_lib]]\n"
            'name = "Theorems"\n'
            'srcDir = "theorems"\n'
            'roots = ["CivilFromDays"]\n',
            encoding="utf-8",
        )
        saved = _lean_model.LEAN_DIR
        _lean_model.LEAN_DIR = lean
        try:
            assert _lean_model.lakefile_roots() == ["CivilFromDays", "McpReCore"]
            assert _lean_model.lakefile_roots("generated") == ["McpReCore"]
            assert _lean_model.lakefile_roots("theorems") == ["CivilFromDays"]
        finally:
            _lean_model.LEAN_DIR = saved


def test_the_live_lakefile_declares_what_the_live_extraction_produces():
    """The two live values, compared — the check the lane makes, made here over the tree."""
    assert _lean_model.lakefile_roots("generated") == ["McpReCore"]


# ---------------------------------------------------------------------------
# One selection, three readers
# ---------------------------------------------------------------------------


def test_the_selection_is_derived_once_for_every_reader():
    """`regenerate-lean` writes it into the stamp; `verify-lean` and `check-generated`
    compare the stamp against it. Three copies would agree until the first edit, and the way
    they would then disagree is the quiet one — a stamp that matches a reader's idea of the
    selection while the writer extracted something else.
    """
    doc = {
        "unit": [
            {
                "id": "core.time_civil_from_days",
                "class": "V2",
                "paths": ["mcp-re-core/src/time/format.rs"],
                "extracted_symbols": ["mcp_re_core::time::format::civil_from_days"],
            },
            # V0 units are not extracted from and must not appear.
            {"id": "other", "class": "V0", "paths": ["mcp-re-core/src/lib.rs"]},
        ]
    }
    assert _lean_model.selection(doc) == {
        "core.time_civil_from_days": {
            "crate": "mcp-re-core",
            "start_from": ["mcp_re_core::time::format::civil_from_days"],
        }
    }


def test_a_unit_spanning_two_crates_has_no_single_crate_to_extract_from():
    unit = {
        "id": "u",
        "class": "V2",
        "paths": ["mcp-re-core/src/lib.rs", "mcp-re-http-profile/src/lib.rs"],
        "extracted_symbols": ["x"],
    }
    assert _lean_model.unit_crate(unit) is None


def test_charon_extracts_rust_so_a_non_cargo_unit_has_no_crate():
    """Delegating to `unit_projects` is not enough on its own.

    It answers "which project", for every ecosystem. A V2 unit whose paths resolve to a
    Python or TypeScript project would get a project NAME back, and `charon cargo` would
    then run in a directory with no Cargo manifest — a failure some distance from its cause.
    """
    unit = {
        "id": "p",
        "class": "V2",
        "paths": ["sdk/python/**/*.py"],
        "extracted_symbols": ["x"],
    }
    assert _lean_model.unit_crate(unit) is None


def test_the_pilot_unit_resolves_to_the_crate_it_names():
    unit = {
        "id": "u",
        "class": "V2",
        "paths": ["mcp-re-core/src/time/format.rs", "mcp-re-core/src/time/mod.rs"],
        "extracted_symbols": ["mcp_re_core::time::format::civil_from_days"],
    }
    assert _lean_model.unit_crate(unit) == "mcp-re-core"


# ---------------------------------------------------------------------------
# The write has to be possible before the extraction is worth starting
# ---------------------------------------------------------------------------


def test_a_writable_directory_reports_nothing():
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        assert _lean_model.unwritable(Path(tmp) / "generated") is None


def test_a_read_only_mount_is_named_before_the_pipeline_runs():
    """The failure a read-only container mount would otherwise produce at the last step.

    dev1's Docker is colima, where a read-only mount is a real configuration rather than a
    hypothetical, and the regeneration's whole output is a write into the mounted workspace.
    Discovering that after Charon and Aeneas have run is discovering it twenty minutes from
    its cause.
    """
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "generated"
        target.mkdir()
        os.chmod(target, 0o500)
        try:
            why = _lean_model.unwritable(target)
            # Root ignores the mode bits, so a container running as root would still write.
            # The control is that a refusal is REPORTED rather than raised; where the write
            # is genuinely possible there is nothing to report.
            assert why is None or isinstance(why, str)
            if os.geteuid() != 0:
                assert why is not None
        finally:
            os.chmod(target, 0o700)


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
