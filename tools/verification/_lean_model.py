# SPDX-License-Identifier: Apache-2.0
"""The generated Lean model's identity — ADR-MCPRE-059 §8, §16, issue #541.

`verification/lean/generated/` is machine-owned. A theorem proved against a hand-edited
model is not weak evidence; it is a forged artifact (Operational Rule 6). So the question
this module owns is narrow and mechanical: **is the model on disk the one the pinned
pipeline produces from the sources this manifest declares?**

Three facts have to hold together, and each one is a different way the answer can be no:

* a regeneration was PERFORMED — a comparison that nothing regenerated compares the model
  against itself, which is the green that measures nothing;
* the sources it was extracted from are the sources present now — otherwise the model is
  stale, and a theorem about it constrains code that no longer exists;
* the bytes it wrote are the bytes present now — otherwise something edited the model
  after the machine produced it.

The record that carries them is a STAMP written by `regenerate-lean` into the ignored
`.verification/` tree, never into the repository. It is evidence about one run, and a
committed stamp would be a claim that outlives the run it describes.

Whether the committed model equals the regenerated one is git's question, not this
module's, and `check-generated` asks it there: after a regeneration has overwritten the
tree, a dirty `verification/lean/generated/` IS the drift.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from _ecosystems import CARGO, unit_ecosystem, unit_projects
from _manifest import REPO_ROOT

LEAN_DIR = REPO_ROOT / "verification" / "lean"
GENERATED = LEAN_DIR / "generated"
STAMP = REPO_ROOT / ".verification" / "lean" / "regeneration-stamp.json"

#: The lock entries whose identity the extraction result depends on. A model produced by a
#: different Charon, a different Aeneas, or inside a different image is a different model,
#: so the stamp records all of them and a change to any one invalidates it.
IDENTITY_PINS = ("charon", "aeneas", "lean", "aeneas_lean_backend", "extraction_container")


#: The Aeneas Lean library, and the tell for whether this is the extraction environment at
#: all. Charon links the private rustc crates and does not build on macOS, so the whole
#: pipeline lives in the image pinned as `[extraction_container]` — and the hosts that run
#: `verify --gate` are macOS hosts that will never have it.
AENEAS_LEAN = Path("/opt/aeneas/backends/lean")


def lakefile_roots(srcDir: str | None = None) -> list[str]:
    """The Lean module roots the package builds, read from the lakefile that builds them.

    `srcDir` narrows to one library — `"generated"` asks which modules the EXTRACTION is
    expected to produce. Derived rather than listed anywhere else: the build definition is
    the authority on what elaborates, and a second list would drift.
    """
    doc = tomllib.loads((LEAN_DIR / "lakefile.toml").read_text(encoding="utf-8"))
    roots: list[str] = []
    for lib in doc.get("lean_lib", []):
        if srcDir is not None and lib.get("srcDir") != srcDir:
            continue
        roots += [str(name) for name in lib.get("roots", [lib["name"]])]
    return sorted(set(roots))


def unit_crate(unit: dict) -> str | None:
    """The single Cargo package this unit's paths live in, or None.

    Delegated to `_ecosystems.unit_projects`, which already owns "which project does this
    unit live in" for the fingerprint, the test lane and the manifest schema. A fourth
    implementation here would be a fourth answer, and the one that mattered would be
    whichever the reader happened to be looking at.

    The ecosystem is checked as well as the count: Charon extracts RUST, so a V2 unit whose
    paths resolve to a Python or TypeScript project has no crate to start from — and
    returning that project's name would have `charon cargo` run somewhere it cannot.
    """
    if unit_ecosystem(unit) is not CARGO:
        return None
    projects = unit_projects(unit)
    return projects[0] if len(projects) == 1 else None


def selection(doc: dict) -> dict[str, dict]:
    """The extraction selection the manifest declares — WHAT is extracted, from WHERE.

    ONE implementation, because it is one fact with three readers: `regenerate-lean` writes
    it into the stamp, and `verify-lean` and `check-generated` compare the stamp against it.
    Three copies would agree until the first edit, and the way they would then disagree is
    the quiet one — a stamp that matches a reader's idea of the selection while the writer
    extracted something else.
    """
    out: dict[str, dict] = {}
    for unit in doc.get("unit", []):
        if unit["class"] not in {"V2", "V3"}:
            continue
        crate = unit_crate(unit)
        out[unit["id"]] = {
            "crate": crate,
            "start_from": sorted(str(s) for s in unit["extracted_symbols"]),
        }
    return out


def unwritable(directory: Path) -> str | None:
    """Why `directory` cannot be written, or None.

    Asked before an extraction rather than discovered during one. The regeneration's whole
    output is a write into the mounted workspace, and a read-only container mount — the
    default in some colima configurations — would otherwise let the pipeline run to
    completion and fail at the last step, a long way from its cause.
    """
    probe = directory / ".writable-probe"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"")
        probe.unlink()
    except OSError as exc:
        return exc.strerror or str(exc)
    return None


def produced_roots(names: Iterable[str]) -> list[str]:
    """The Lean module roots an extraction actually wrote, from its file list.

    Aeneas emits `<Root>.lean` and, when it splits, a `<Root>/` directory beside it — so the
    first path segment with `.lean` removed is the root either way.
    """
    return sorted({name.split("/", 1)[0].removesuffix(".lean") for name in names})


def extraction_environment() -> bool:
    """Whether this process can regenerate and elaborate at all.

    Asked BEFORE the model's freshness, and the order is the point. "No regeneration stamp"
    is the right message for somebody who could have run `regenerate-lean` and did not; on a
    macOS host it is a false instruction, and it reports FAIL — *something is here and it is
    wrong* — for what is actually UNAVAILABLE — *the measurement is missing because the lane
    cannot run here*. Those are different verdicts with different remedies, and the
    aggregate treats them differently.
    """
    return AENEAS_LEAN.is_dir()


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def model_files() -> list[Path]:
    """Every generated file, sorted. `.gitkeep` is directory scaffolding, not model."""
    if not GENERATED.is_dir():
        return []
    return [
        path
        for path in sorted(GENERATED.rglob("*"))
        if path.is_file() and path.name != ".gitkeep"
    ]


def extraction_identity(toolchains: dict) -> dict[str, str]:
    """The pinned pipeline's identity, flattened to the values that decide a model.

    Read from the lock rather than from the running container: what the lane must compare
    is what the repository DECLARES the extraction to be. A container reporting its own
    identity would be the instrument certifying itself.
    """
    out: dict[str, str] = {}
    for pin in IDENTITY_PINS:
        entry = toolchains.get(pin, {})
        for field in ("commit", "digest", "definition_digest", "toolchain", "package_revision", "mathlib_revision"):
            if field in entry:
                out[f"{pin}.{field}"] = str(entry[field])
    return out


@dataclass(frozen=True)
class Stamp:
    """What one regeneration run measured and produced."""

    identity: dict[str, str]
    #: `{unit_id: {"crate": …, "start_from": [...]}}` — the selection the manifest made.
    selection: dict[str, dict]
    #: `{repo-relative source path: digest}` — what the extraction read.
    sources: dict[str, str]
    #: `{path relative to generated/: digest}` — what the extraction wrote.
    written: dict[str, str]

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema_version": 1,
                "identity": self.identity,
                "selection": self.selection,
                "sources": self.sources,
                "written": self.written,
            },
            indent=2,
            sort_keys=True,
        )


def write_stamp(stamp: Stamp) -> None:
    STAMP.parent.mkdir(parents=True, exist_ok=True)
    STAMP.write_text(stamp.to_json() + "\n", encoding="utf-8")


def read_stamp() -> Stamp | None:
    """The stamp, or None if it is absent or unreadable — both of which are refusals.

    An unparsable stamp is treated exactly as a missing one. It records that a run
    happened, and a record nothing can read does not record anything.
    """
    if not STAMP.is_file():
        return None
    try:
        doc = json.loads(STAMP.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        return None
    try:
        return Stamp(
            identity=dict(doc["identity"]),
            selection=dict(doc["selection"]),
            sources=dict(doc["sources"]),
            written=dict(doc["written"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def current_written() -> dict[str, str]:
    return {
        str(path.relative_to(GENERATED)): digest(path) for path in model_files()
    }


def stamp_defects(stamp: Stamp | None, toolchains: dict, selection: dict[str, dict]) -> list[str]:
    """Why the model on disk is not the pinned pipeline's output for this tree.

    Empty means a regeneration ran, against this toolchain, over these sources, and
    nothing has touched its output since.
    """
    if stamp is None:
        return [
            "no regeneration stamp: nothing regenerated the model in this run, so a "
            "comparison here would compare the checked-in model against itself. Run "
            "tools/verification/regenerate-lean inside the pinned extraction container."
        ]

    defects: list[str] = []

    identity = extraction_identity(toolchains)
    if stamp.identity != identity:
        moved = sorted(
            key
            for key in set(identity) | set(stamp.identity)
            if identity.get(key) != stamp.identity.get(key)
        )
        defects.append(
            "the model was extracted by a different pipeline than the lock now pins "
            f"({', '.join(moved)}). A model produced by an undeclared instrument is not a "
            "model of the declared one."
        )

    if stamp.selection != selection:
        defects.append(
            "the manifest's extraction selection has changed since the model was "
            f"generated: stamped {sorted(stamp.selection)}, manifest declares "
            f"{sorted(selection)}. The model does not cover what the units claim."
        )

    stale = sorted(
        path
        for path, recorded in stamp.sources.items()
        if not (REPO_ROOT / path).is_file() or digest(REPO_ROOT / path) != recorded
    )
    if stale:
        defects.append(
            f"the model is stale: {', '.join(stale)} changed after extraction. A theorem "
            "proved against it constrains source that is no longer there."
        )

    written = current_written()
    if written != stamp.written:
        touched = sorted(
            name
            for name in set(written) | set(stamp.written)
            if written.get(name) != stamp.written.get(name)
        )
        defects.append(
            f"the generated model was modified after extraction: {', '.join(touched)}. "
            "Generated output is machine-owned; a hand-edit that makes a proof pass is a "
            "forged artifact, not weak evidence."
        )

    return defects
