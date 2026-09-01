# SPDX-License-Identifier: Apache-2.0
"""Which build system governs a unit's source — ADR-MCPRE-059 §2, issue #745.

A `[[unit]]` is *the smallest semantic authority whose source, assumptions, evidence and
review can be fingerprinted*. **That concept is not Cargo.** The implementation was: the
project directory was the first path segment holding a `Cargo.toml`, the test package named
a Cargo package, selectors were Rust test paths, and the build configuration was the Rust
workspace's manifests. No unit could own `sdk/python/python/mcp_re_sdk/` or
`sdk/typescript/src/`, and an unevidenceable root reads as coverage while being none.

This module is the seam. The abstraction above it — owned source closure, dependency and
configuration inputs, typed evidence providers, registered assumptions, review fingerprint
— is unchanged; Rust becomes ONE adapter beneath it rather than the shape of it.

# The ecosystem is DERIVED, never declared

There is no `kind = "python"` field, and adding one is the move this exists to avoid: a
language name in the unit schema turns an architectural concept into a list of exceptions,
and the next ecosystem is then a schema change rather than an entry here.

It is derived from the source itself, in two steps that are each a fact rather than a
convention:

  1. the FILE decides the ecosystem, by suffix — `.rs` is Rust, `.py` is Python, `.ts` is
     TypeScript. This is what makes `sdk/python` answerable at all: the directory holds a
     `Cargo.toml` AND a `pyproject.toml`, because the wheel is a Rust extension module, so
     no directory-level rule can decide which project `.../transport.py` belongs to.
  2. the PROJECT is the nearest ancestor directory holding that ecosystem's manifest, which
     is where every one of these tools already looks for dependency and lockfile inputs.

# Fail closed on a mixed closure

A unit whose declared paths span two ecosystems has no single answer to "which lane
measures this", and answering with either would name a project that does not cover its
source. `unit_ecosystem` returns `None` there, and every caller treats that the way it
already treats a path outside every Cargo package: no test project, so no battery, so no
evidence — never a battery run in the wrong place.

# What an adapter must supply

Only what the platform genuinely varies over, and each entry is a measurement input rather
than a preference:

  * `source_suffixes` — how a path names this ecosystem.
  * `project_manifests` — how a project's root is recognised.
  * `workspace_inputs` — repo-root files that decide what any project in this ecosystem IS.
  * `project_inputs` — per-project manifests and lockfiles. A dependency swap or a lockfile
    bump alters what a claim is about without touching a declared source line, which is why
    they are fingerprint inputs and not merely build detail.
  * `test_argv` — the command that runs a selected battery, and
  * `parse_results` — how that command's output reports which selected test did what.

The last two are what `verify-tests` needs to stop being a cargo script; they are supplied
here so that "where do these tests live" and "how are they run" have ONE answer per
ecosystem rather than one per tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Ecosystem:
    """One build system, as the assurance platform needs to see it."""

    name: str
    source_suffixes: frozenset[str]
    project_manifests: tuple[str, ...]
    workspace_inputs: tuple[str, ...]
    project_inputs: tuple[str, ...]
    #: Whether a whole-project source digest is available for formal (V1/V3) units. Only
    #: Rust has a prover lane, and a class the ecosystem cannot carry is refused rather
    #: than silently measured as if it could.
    formal_source_glob: str | None = None
    #: Selector targets this ecosystem understands, as they appear before the `#` in a
    #: `tested_symbols` entry. `None` means any target is accepted (Rust's `tests/<name>`
    #: family is open-ended).
    selector_targets: frozenset[str] | None = field(default=None)


#: `lib#` and `doc#` execute code inside the crate's own sources; `tests/<name>#` names an
#: integration-test target. Kept as data rather than as a condition in three files.
CARGO = Ecosystem(
    name="cargo",
    source_suffixes=frozenset({".rs"}),
    project_manifests=("Cargo.toml",),
    workspace_inputs=("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"),
    project_inputs=("Cargo.toml", "Cargo.lock"),
    formal_source_glob="src/**/*.rs",
)

PYTHON = Ecosystem(
    name="python",
    source_suffixes=frozenset({".py"}),
    project_manifests=("pyproject.toml",),
    # No repo-root Python manifest governs these projects: each SDK is self-contained, and
    # naming a root file that does not exist would put an empty digest in every fingerprint
    # and read as "measured, and nothing there".
    workspace_inputs=(),
    project_inputs=("pyproject.toml", "uv.lock", "poetry.lock", "requirements.txt"),
    selector_targets=frozenset({"pytest"}),
)

TYPESCRIPT = Ecosystem(
    name="typescript",
    source_suffixes=frozenset({".ts", ".tsx", ".mts", ".cts"}),
    project_manifests=("package.json",),
    workspace_inputs=(),
    project_inputs=(
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "tsconfig.json",
    ),
    selector_targets=frozenset({"vitest"}),
)

#: Ordered, and the order is not significant — the suffix sets are disjoint, which is what
#: makes the derivation a fact rather than a precedence rule.
ECOSYSTEMS: tuple[Ecosystem, ...] = (CARGO, PYTHON, TYPESCRIPT)


def ecosystem_for_path(path: str) -> Ecosystem | None:
    """The ecosystem a declared path belongs to, by its suffix.

    `None` for a path no ecosystem claims — a `.toml`, a generated `.lean`, a fixture —
    which is not an error: such a path is source the unit measures without naming a lane.
    """
    suffix = Path(path).suffix
    for eco in ECOSYSTEMS:
        if suffix in eco.source_suffixes:
            return eco
    return None


def project_of(path: str, eco: Ecosystem) -> str | None:
    """The nearest ancestor directory of `path` holding one of `eco`'s manifests.

    Walking UP rather than reading the first segment is what lets a project live anywhere in
    the tree: `sdk/python` and `mcp-re-proxy` are both projects, and only one of them is a
    top-level directory.
    """
    current = (REPO_ROOT / path).parent
    while True:
        try:
            rel = current.relative_to(REPO_ROOT)
        except ValueError:
            return None
        if any((current / manifest).is_file() for manifest in eco.project_manifests):
            return rel.as_posix()
        if current == REPO_ROOT:
            return None
        current = current.parent


def unit_ecosystem(unit: dict) -> Ecosystem | None:
    """The one ecosystem this unit's source belongs to, or `None`.

    `None` means one of three things, and all three are the same answer to the caller —
    there is no lane that measures this unit's battery:

      * no declared path names any ecosystem;
      * the paths span two, so no single lane covers the source;
      * a path names an ecosystem but sits outside every project of it, so there is no
        project whose dependency inputs could be measured.
    """
    seen: set[str] = set()
    chosen: Ecosystem | None = None
    for path in unit["paths"]:
        eco = ecosystem_for_path(path)
        if eco is None:
            continue
        if project_of(path, eco) is None:
            return None
        seen.add(eco.name)
        chosen = eco
    if len(seen) != 1:
        return None
    return chosen


def unit_projects(unit: dict) -> list[str]:
    """The projects this unit's declared paths live in, sorted.

    Empty when the unit has no single ecosystem, for the reason above: a project list drawn
    from a mixed closure would name projects that do not cover the source.
    """
    eco = unit_ecosystem(unit)
    if eco is None:
        return []
    projects = {
        project
        for path in unit["paths"]
        if ecosystem_for_path(path) is eco
        for project in [project_of(path, eco)]
        if project is not None
    }
    return sorted(projects)


def test_project_for(unit: dict) -> str | None:
    """The single project this unit's battery runs in, or `None` if there is none.

    One answer, shared by the lane (which runs the battery) and the fingerprint (which
    records what was measured). Two implementations of "where do these tests live" would let
    the recorded project and the executed project disagree.

    Fail-closed on a path inside the ecosystem but outside every project of it, and on a
    closure spanning several projects with no `test_package` naming one of them.
    """
    eco = unit_ecosystem(unit)
    if eco is None:
        return None
    for path in unit["paths"]:
        if ecosystem_for_path(path) is eco and project_of(path, eco) is None:
            return None
    projects = unit_projects(unit)
    if len(projects) == 1:
        return projects[0]
    declared = unit.get("test_package")
    return declared if declared in projects else None


def build_configuration_patterns(unit: dict) -> list[str]:
    """The dependency and configuration inputs that decide what this unit's source IS.

    The ecosystem's repo-root inputs plus each project's own manifests and lockfiles. A
    lockfile that is not present contributes nothing rather than an error: `uv.lock` and
    `poetry.lock` are alternatives, and naming both is how the platform stays neutral about
    which one a project uses without asking the unit to say.
    """
    eco = unit_ecosystem(unit)
    if eco is None:
        return []
    patterns = list(eco.workspace_inputs)
    for project in unit_projects(unit):
        patterns.extend(f"{project}/{name}" for name in eco.project_inputs)
    return patterns


def formal_source_patterns(unit: dict) -> list[str]:
    """Whole-project sources, for a unit whose evidence comes from a prover run.

    `[]` where the ecosystem has no prover lane, which is what makes a V1/V3 declaration
    over Python or TypeScript source refuse rather than derive a fingerprint that pretends
    a whole-project measurement happened.
    """
    eco = unit_ecosystem(unit)
    if eco is None or eco.formal_source_glob is None:
        return []
    return [f"{project}/{eco.formal_source_glob}" for project in unit_projects(unit)]


# ---------------------------------------------------------------------------
# Running a selected battery
# ---------------------------------------------------------------------------
#
# `verify-tests` selects EXACTLY the declared symbols and compares what reported success
# against what was declared, in both directions. That contract is the lane's; what varies
# per ecosystem is the command that performs the selection and the syntax of the report.



def valid_target(eco: Ecosystem, target: str) -> bool:
    """Whether `target` is a runnable target NAME in this ecosystem.

    The target is the half of a `tested_symbols` entry before the `#`, and what it may say
    is the ecosystem's business: Cargo has an open-ended `tests/<name>` family beside `lib`
    and `doc`, while a pytest or vitest battery is selected by file-and-name and needs only
    the one target that says which runner reads the selector.
    """
    if eco is CARGO:
        if target in ("lib", "doc"):
            return True
        return target.startswith("tests/") and target.count("/") == 1 and bool(target[6:])
    return eco.selector_targets is not None and target in eco.selector_targets


def test_argv(eco: Ecosystem, project: str, target: str, selectors: list[str]) -> list[str]:
    """The command that runs exactly `selectors` of `target` in `project`.

    Exact selection is the property, not a convenience: a runner that matched by substring
    would let a battery grow silently, and one that ran the whole suite would report a pass
    for symbols nobody declared.
    """
    if eco is CARGO:
        if target == "doc":
            # Doctests are selected by substring rather than `--exact`: a doctest's reported
            # name embeds the LINE it starts on, so an exact selector would break on any
            # edit above it — churn that says nothing about the property. The lane's
            # containment check is what makes this selection precise.
            return ["cargo", "test", "-p", project, "--doc", "--", *selectors]
        target_argv = ["--lib"] if target == "lib" else ["--test", target[6:]]
        return ["cargo", "test", "-p", project, *target_argv, "--", "--exact", *selectors]
    if eco is PYTHON:
        # `-p no:randomly` is deliberate: a battery whose order varies is a battery whose
        # result is not reproducible from the fingerprint that recorded it.
        return [
            "python3",
            "-m",
            "pytest",
            "-p",
            "no:randomly",
            "--no-header",
            "-q",
            *selectors,
        ]
    if eco is TYPESCRIPT:
        return ["npx", "vitest", "run", "--reporter=verbose", *selectors]
    raise ValueError(f"no test command for ecosystem {eco.name!r}")


#: The statuses libtest reports. Closed, because everything else on a result line is
#: somebody ELSE's output — see below.
_CARGO_STATUSES = ("ok", "FAILED", "ignored")

#: libtest's per-test result line: `test block::tests::round_trips ... ok`.
#:
#: The status is taken from the END of the line rather than from the first word after the
#: ellipsis, and the reason is a measured false RED. libtest writes `test <name> ... ` and
#: the status from the harness thread, but a test that spawns a child process — or any code
#: writing to the real fd 2 rather than to the capture buffer — lands its bytes BETWEEN
#: them. On 2026-08-31 that produced
#:
#:     test audit_sink::tests::the_collector_preserves_emission_order ... mcp-re-proxy: ...ok
#:
#: and the old pattern read the status as `mcp`, reporting a deterministic two-assert test
#: as not having passed. Anchoring to the end of the line is safe in the direction that
#: matters: libtest writes the status LAST, so interleaved text containing the word `ok`
#: cannot outrank a real `FAILED` — and if the interleave carries a newline the line does
#: not match at all, which reads as `never ran` and fails loudly rather than quietly green.
_CARGO_RESULT = re.compile(
    r"^test (?P<name>\S+) \.\.\. .*?(?P<status>" + "|".join(_CARGO_STATUSES) + r")$"
)

#: pytest's verbose line: `tests/test_x.py::test_name PASSED`.
_PYTEST_RESULT = re.compile(
    r"^(?P<name>\S+::\S+)\s+(?P<status>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\b"
)

#: vitest's verbose reporter: a mark, the file, and the test name after `>`.
_VITEST_RESULT = re.compile(r"^\s*(?P<mark>[x×✓↓·])\s+(?P<name>\S+ > .+?)(?:\s+\d+ms)?$")

_VITEST_STATUS = {"✓": "ok", "x": "FAILED", "×": "FAILED", "↓": "ignored", "·": "ignored"}


def parse_results(eco: Ecosystem, stdout: str) -> dict[str, str]:
    """Selected test name → one of `ok`, `FAILED`, `ignored`.

    Normalised to one vocabulary because the LANE's rule is one rule: a declared symbol that
    did not run is a failure, and a symbol that ran but was skipped establishes nothing a
    test which did not exist would not also establish. Both must be expressible for every
    ecosystem, so an ecosystem's own words are translated here rather than special-cased
    where the rule is applied.
    """
    out: dict[str, str] = {}
    if eco is CARGO:
        for line in stdout.splitlines():
            match = _CARGO_RESULT.match(line.strip())
            if match:
                out[match.group("name")] = match.group("status")
        return out
    if eco is PYTHON:
        for line in stdout.splitlines():
            match = _PYTEST_RESULT.match(line.strip())
            if match:
                status = match.group("status")
                out[match.group("name")] = (
                    "ok" if status == "PASSED" else "ignored" if status == "SKIPPED" else "FAILED"
                )
        return out
    if eco is TYPESCRIPT:
        for line in stdout.splitlines():
            match = _VITEST_RESULT.match(line.rstrip())
            if match:
                out[match.group("name").strip()] = _VITEST_STATUS[match.group("mark")]
        return out
    raise ValueError(f"no result parser for ecosystem {eco.name!r}")
