#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit-closure gate — a file adjacent in the module tree to a measured one is answered for.

`verification/policy/verification.toml` declares assurance units. A unit's `paths` list is
the source closure its ReviewFingerprint is taken over: change a file inside it and every
claim resting on that unit goes dirty. A security-bearing file in NO unit's `paths` can be
rewritten without moving any fingerprint, so the graph keeps answering FRESH over code it
never measured.

THE FAILURE CLASS, which is why this file exists rather than any single instance:

    A security-bearing file used by a declared unit must not silently leave that unit's
    measured closure.

The escape has two shapes, and in both the unit keeps a `paths` entry that still resolves,
keeps deriving a fingerprint, and keeps answering FRESH — over less code than before, with
nothing reporting the difference:

  * the file is MOVED or RENAMED;
  * code is SPLIT OUT of it into a new sibling.

The second is what happened to `mcp-re-proxy/src/signing_plane/`: `rotation.rs`,
`mint_successor.rs` and `trust_epoch_advance.rs` were carved out of a `mod.rs` that
`proxy.signing_credential_provenance` declares, and the unit went on fingerprinting the
`mod.rs` alone. It happened twice more during the r11 campaign — `async_replay/
budget_report.rs` and `audit_sink/writer.rs` — while this gate was being specified.

# Why neither neighbouring gate covers it

`scripts/bazel_srcs_gate.py` walks the same module tree, but its subject is one BUILD
file's hand-listed `srcs`. It fired on the `signing_plane` split and was satisfied the
moment the new files joined the Bazel list — which says nothing about `verification.toml`.

`tools/verification/_manifest.py` raises when a declared path matches nothing, so a
DELETED path is caught. That check is one-directional: declared ⇒ exists. A file that
quietly appears NEXT TO a declared one is invisible, because nothing walks from the file
system back toward the declarations. This gate is the other direction:

    exists ⇒ answered for.

# The rules

UC-1 (child)   For every declared `paths` entry that resolves to a Rust module file, every
               `mod <name>;` it declares in code must resolve to a file that is itself in
               some unit's expanded `paths`, or registered in
               `config/unit-closure-exclusions.toml`.

UC-2 (parent)  The module file that DECLARES a declared path must satisfy the same
               requirement — but only when that parent declares at least one item of its
               own (`fn`/`struct`/`enum`/`trait`/`impl`/`const`/`static`/`type`/`union`)
               outside a test region. A parent whose whole body is `mod` and `pub use` is a
               namespace and is exempt by construction: without that clause
               `config_state/mod.rs`, `authorization/mod.rs` and their kind would be dragged
               into twenty units apiece, coupling every one of those fingerprints to a
               re-export list.

UC-3 (diff)    A flagged path that is NEW since `origin/main` may not be answered with a
               register entry at all. New drift is fixed, never registered.

# What this gate does NOT claim

It cannot decide semantic ownership, and pretending it can is how a coverage gate becomes a
form to fill in. It detects an UNANSWERED question, never a wrong answer: an entry with a
plausible reason passes, and that is correct — the review is the control, the gate only
makes the review unavoidable.

It is also silent on a file with no declared neighbour at all. `admission_enforcer/` is in
no unit and neither is its parent, so no `mod` edge crosses a closure boundary. That is a
COVERAGE gap, not a drift, and no gate can close it: it needs a unit to exist first. The
gate stops the uncovered set from growing; it does not shrink it.

And it says nothing about the evidence half — a path can be declared while contributing no
`tested_symbols`. That is a different rule with a different debt shape, deliberately not
bundled here, because one red line that means two things is worth less than either.

# The register

Three states, borrowed verbatim from `config/module-size-debt.toml`, because investigation
status and disposition are separate facts:

    unreviewed              outside every closure, and nobody has looked
    reviewed-attached       looked at; belongs in a named unit; the `paths` edit is open work
    reviewed-out-of-cone    looked at; genuinely outside every unit's claim, reason written down

It is a debt register, not an exception mechanism. It may only shrink, nothing returns to
`unreviewed`, each reviewed state names a record in `docs/architecture/review-dispositions.md`,
and an entry the rules no longer flag is an error rather than a shrug.

Run:  python3 scripts/unit_closure_gate.py
      python3 scripts/unit_closure_gate.py --selftest
      python3 scripts/unit_closure_gate.py --emit-register
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

REPO = Path(__file__).resolve().parent.parent
REGISTER = REPO / "config" / "unit-closure-exclusions.toml"

sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tools" / "verification"))

# The module walk is IMPORTED, not re-written. `declared_mods` reads `mod` declarations from
# code only — a `mod` inside a comment or a string literal compiles nothing — and a second
# copy of that walk would be a second opinion about what a module is.
from bazel_srcs_gate import declared_mods, strip_noncode  # noqa: E402
from module_size_gate import production_source  # noqa: E402

#: A Rust item declared at the start of a line, after any visibility and any of the
#: modifiers that may precede one. `use` and `mod` are absent on purpose: a file whose whole
#: body is those two is a namespace, which is what UC-2's item test exists to recognise.
ITEM = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:default[ \t]+)?(?:unsafe[ \t]+)?"
    r"(?:async[ \t]+)?(?:const[ \t]+)?(?:extern[ \t]+(?:\"[^\"]*\"[ \t]+)?)?"
    r"(?:fn|struct|enum|trait|impl|const|static|type|union|macro_rules!)\b",
    re.M,
)

#: The three dispositions. See the module docstring: a completed census whose disposition is
#: "attach it" must stay distinguishable from one nobody has performed.
STATUSES = {"unreviewed", "reviewed-attached", "reviewed-out-of-cone"}
REVIEWED = {"reviewed-attached", "reviewed-out-of-cone"}

#: Anything else in an `[[exclusion]]` table is a typo or a stale field name, and both fail.
#: `rule` is here rather than in a comment because it is DERIVED: a reader needs to know why
#: a path is registered, and a derived sentence nothing checks is exactly the kind of prose
#: that rots into a claim about a tree that has moved. As a field the gate re-derives it and
#: refuses a mismatch, so it can be read as a fact.
ENTRY_FIELDS = {"path", "rule", "baseline_sha", "status", "reason", "review_ref"}

#: Every permitted move either preserves or increases what is known. None returns an entry
#: to "nobody has investigated this", because that would tell the next reader to redo the
#: work. A reviewed entry may change its mind in either direction: a re-review that finds a
#: home for an out-of-cone file, or one that decides an attachment was wrong, are both
#: reviews.
PERMITTED_TRANSITIONS = {
    ("unreviewed", "unreviewed"),
    ("unreviewed", "reviewed-attached"),
    ("unreviewed", "reviewed-out-of-cone"),
    ("reviewed-attached", "reviewed-attached"),
    ("reviewed-attached", "reviewed-out-of-cone"),
    ("reviewed-out-of-cone", "reviewed-out-of-cone"),
    ("reviewed-out-of-cone", "reviewed-attached"),
}


# --------------------------------------------------------------------------------------
# the module tree


def expand(root: Path, patterns) -> set[str]:
    """The repo-relative files a `paths` list names, with its globs expanded.

    Mirrors `tools/verification/_manifest.py::expand_paths`, which is not reused directly
    because it resolves against a module-level `REPO_ROOT` and this gate must run against a
    synthetic tree. The two are held to the same answer by `expansion_disagreements`, which
    runs on every real invocation — a mirror checked by measurement rather than by promise.
    """
    out: set[str] = set()
    for pattern in patterns:
        for path in root.glob(pattern):
            if path.is_file():
                out.add(path.relative_to(root).as_posix())
    return out


def closure(root: Path, units) -> dict[str, list[str]]:
    """Every file inside some unit's expanded `paths`, with the units that measure it."""
    covered: dict[str, list[str]] = {}
    for unit in units:
        for rel in sorted(expand(root, unit["paths"])):
            covered.setdefault(rel, []).append(unit["id"])
    return covered


def _child_dir(rel: str) -> str:
    """The directory a module file's children live in, as rustc looks for them."""
    path = Path(rel)
    if path.name in ("mod.rs", "lib.rs", "main.rs"):
        return path.parent.as_posix()
    return (path.parent / path.stem).as_posix()


def module_children(root: Path, rel: str) -> list[tuple[str, str]]:
    """`(module name, file)` for every `mod <name>;` in `rel` that resolves on disk.

    A declaration that resolves to neither form is not this gate's finding: cargo cannot
    compile it either, and `bazel_srcs_gate.py` is the control that says so.
    """
    out: list[tuple[str, str]] = []
    base = _child_dir(rel)
    for name in declared_mods(root / rel):
        for candidate in (f"{base}/{name}.rs", f"{base}/{name}/mod.rs"):
            if (root / candidate).is_file():
                out.append((name, candidate))
                break
    return out


def parent_module(root: Path, rel: str) -> str | None:
    """The module file that declares `rel`, or None when nothing does.

    Resolution is rustc's, then CONFIRMED by reading the candidate's own `mod`
    declarations. Confirming matters where a crate has both `lib.rs` and `main.rs`: which
    of the two declares a given top-level module is a fact in the source, not one the
    directory layout reveals, and a gate that guessed would flag a parent that declares
    nothing.
    """
    path = Path(rel)
    if path.name in ("lib.rs", "main.rs"):
        return None  # a crate root is declared by no module
    container = path.parent.parent if path.name == "mod.rs" else path.parent
    if container.name == "bin":
        return None  # `src/bin/*.rs` are crate roots of their own
    name = path.parent.name if path.name == "mod.rs" else path.stem

    if container.name == "src":
        candidates = [container / "lib.rs", container / "main.rs"]
    else:
        candidates = [container / "mod.rs", container.parent / f"{container.name}.rs"]

    for candidate in candidates:
        if not candidate.is_absolute():
            candidate = root / candidate
        if candidate.is_file() and name in declared_mods(candidate):
            return candidate.relative_to(root).as_posix()
    return None


def declares_items(root: Path, rel: str) -> bool:
    """Whether `rel` declares an item of its own outside a test region.

    False for a namespace — a file whose whole body is `mod` and `pub use`. The test region
    is excluded through `module_size_gate.production_source` so that the two gates cannot
    disagree about where one ends, and comments and string literals are blanked so that an
    item named in prose is not an item.
    """
    text = (root / rel).read_text(errors="replace")
    return bool(ITEM.search(strip_noncode("\n".join(production_source(text)))))


# --------------------------------------------------------------------------------------
# the rules


def flag(root: Path, units) -> tuple[dict[str, str], int]:
    """`{path: why}` for every unmeasured neighbour of a measured file, and files walked.

    The walk starts and stays at the closure boundary: it steps out of files that ARE in a
    unit, never out of registered ones. Walking out of a registered file was tried and is
    wrong — `config_state/mod.rs` is itself outside every closure, so demanding that its
    nineteen children be measured is a demand for COVERAGE, not a report of DRIFT, and this
    gate is explicitly not the instrument for coverage (see the module docstring). Moving
    code between two unmeasured files moves no fingerprint and hides nothing.

    The consequence is worth stating, because it looks like the register growing: when a
    registered parent later joins a unit, its children become neighbours of a measured file
    for the first time and are flagged then. That is a newly VISIBLE question, not new debt
    — the question existed and nothing could see it — and answering it is part of the work
    that attached the parent.

    Findings are what the rules flag, NOT what is left unanswered: a registered path is
    still a finding, and `check_register` is the one place an answer silences one. Keeping
    the two apart is what lets the ratchet see an entry whose path nothing flags any more.
    """
    covered = closure(root, units)
    walked: set[str] = set()
    findings: dict[str, str] = {}

    frontier = sorted(covered)
    while frontier:
        rel = frontier.pop()
        if rel in walked or not rel.endswith(".rs") or not (root / rel).is_file():
            continue
        walked.add(rel)

        for name, child in module_children(root, rel):
            if child in covered:
                continue
            findings.setdefault(
                child,
                f"UC-1: `mod {name};` in {rel} ({covered[rel][0]}) resolves here, and "
                f"this file is in no unit's paths — the unit keeps fingerprinting {rel} "
                f"alone",
            )

        parent = parent_module(root, rel)
        if parent is None or parent in covered or not declares_items(root, parent):
            continue  # a namespace parent decides nothing; see UC-2
        findings.setdefault(
            parent,
            f"UC-2: declares {rel} ({covered[rel][0]}) and holds items of its own, and is "
            f"in no unit's paths — its decisions change with no fingerprint moving",
        )

    return findings, len(walked)


def expansion_disagreements(root: Path, units) -> list[str]:
    """Paths where this gate's glob expansion differs from the manifest loader's.

    The gate carries its own `expand` so it can run against a synthetic tree. That is a
    mirror, and an unchecked mirror drifts. Run only against the real repository, where
    `_manifest.expand_paths` resolves against the same root.
    """
    from _manifest import expand_paths  # noqa: PLC0415 - real-run only

    problems = []
    for unit in units:
        mine = expand(root, unit["paths"])
        theirs = expand_paths(unit["paths"])
        if mine != theirs:
            problems.append(
                f"{unit['id']}: this gate expands `paths` to {sorted(mine ^ theirs)} "
                f"differently from tools/verification/_manifest.py — the two must agree "
                f"about what a unit measures"
            )
    return problems


# --------------------------------------------------------------------------------------
# the register


def load_register(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text())
    return {entry["path"]: entry for entry in data.get("exclusion", [])}


def referenced_documents(review_ref: str) -> list[str]:
    """The repo-relative document paths a `review_ref` names."""
    return re.findall(r"\S+\.md", review_ref)


def permitted_transition(old: str, new: str) -> bool:
    """Whether a disposition may move from `old` to `new`. Total, so the selftest can
    assert the relation rather than re-implement it."""
    return (old, new) in PERMITTED_TRANSITIONS


def validate_register(register: dict[str, dict], root: Path | None = None) -> list[str]:
    problems: list[str] = []
    for rel, entry in sorted(register.items()):
        for field in ("path", "rule", "baseline_sha", "status"):
            if field not in entry:
                problems.append(f"{rel}: exclusion entry is missing `{field}`")
        status = entry.get("status")
        if status is not None and status not in STATUSES:
            problems.append(f"{rel}: status `{status}` is not one of {sorted(STATUSES)}")
        if status in REVIEWED and not entry.get("review_ref"):
            problems.append(
                f"{rel}: status is `{status}` but no `review_ref` names the record that "
                f"adjudicated it"
            )
        if status == "reviewed-out-of-cone" and not entry.get("reason"):
            problems.append(
                f"{rel}: `reviewed-out-of-cone` without a `reason` — the whole content of "
                f"that disposition is why no unit's claim reaches this file"
            )
        unknown = sorted(set(entry) - ENTRY_FIELDS)
        if unknown:
            problems.append(f"{rel}: unknown exclusion field(s) {unknown}")
        ref = entry.get("review_ref")
        if ref and root is not None:
            named = referenced_documents(ref)
            if not named:
                problems.append(
                    f"{rel}: `review_ref` names no document — cite the record's file so the "
                    f"claim can be read"
                )
            for doc in named:
                if not (root / doc).exists():
                    problems.append(
                        f"{rel}: `review_ref` names {doc}, which does not exist — a "
                        f"completed review must point at a record, not at a memory of one"
                    )
    return problems


def check_register(findings: dict[str, str], register: dict[str, dict]) -> list[str]:
    """The ratchet: every flagged path answered, every answer still needed, each for its
    stated reason."""
    problems = []
    for rel, why in sorted(findings.items()):
        entry = register.get(rel)
        if entry is None:
            problems.append(
                f"{rel}: {why}. Add it to a unit's `paths`, or record it in "
                f"config/unit-closure-exclusions.toml with a disposition"
            )
        elif entry.get("rule") and entry["rule"] != why.split(":", 1)[0]:
            problems.append(
                f"{rel}: registered under `{entry['rule']}` but now {why} — the register "
                f"records a different escape from the one the tree has"
            )
    for rel in sorted(register):
        if rel not in findings:
            problems.append(
                f"{rel}: registered as outside every unit's closure, but nothing flags it "
                f"any more — a resolved entry must be removed, not left standing"
            )
    return problems


def check_transitions(previous: dict[str, dict], current: dict[str, dict]) -> list[str]:
    problems = []
    for rel, entry in sorted(current.items()):
        before = previous.get(rel)
        if before is None:
            continue
        old, new = before.get("status"), entry.get("status")
        if old not in STATUSES or new not in STATUSES:
            continue
        if not permitted_transition(old, new):
            problems.append(
                f"{rel}: disposition moved `{old}` -> `{new}`, which the lifecycle does not "
                f"permit — a completed census may not be returned to `unreviewed`, because "
                f"that tells the next reader nobody has looked"
            )
    return problems


def check_new_debt(register: dict[str, dict], new_paths: set[str]) -> list[str]:
    """UC-3. A path this change introduced may not be answered with a register entry."""
    return [
        f"{rel}: new since origin/main and registered as an exclusion — UC-3 admits no new "
        f"debt. A file added or moved by this change must join a unit's `paths`"
        for rel in sorted(register)
        if rel in new_paths
    ]


def introduced_paths(ref: str = "origin/main") -> tuple[set[str] | None, str]:
    """Rust files this branch ADDS relative to `ref`, and a sentence naming the comparison.

    A rename carries its answer with it only when the old path had one; otherwise the new
    name is as new as an addition, and UC-3 treats it that way. Returns `(None, why)` when
    the ref cannot be read: a check that quietly no-ops when it cannot find its baseline is
    the "green that measured nothing" failure applied to this gate, so the caller PRINTS
    the sentence.
    """
    try:
        out = subprocess.run(
            ["git", "diff", "--name-status", "-M", f"{ref}...HEAD"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout
    except Exception as exc:  # noqa: BLE001 - any git failure is the same answer here
        return None, f"not evaluated: no baseline at {ref} ({type(exc).__name__})"

    previous, _ = previous_register(ref)
    known = set(previous or {})
    added: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if parts[0].startswith("A") and len(parts) == 2:
            added.add(parts[1])
        elif parts[0].startswith("R") and len(parts) == 3 and parts[1] not in known:
            added.add(parts[2])
    return added, f"against {ref}"


def previous_register(ref: str = "origin/main") -> tuple[dict[str, dict] | None, str]:
    """The register as of `ref`, and a sentence saying which it is."""
    try:
        out = subprocess.run(
            ["git", "show", f"{ref}:config/unit-closure-exclusions.toml"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout
    except Exception as exc:  # noqa: BLE001
        return None, f"no baseline register at {ref} ({type(exc).__name__})"
    return (
        {entry["path"]: entry for entry in tomllib.loads(out).get("exclusion", [])},
        f"against {ref}",
    )


def empty_scope_is_failure(units: int, walked: int) -> bool:
    """A gate whose subject list can become empty reports success by measuring nothing.

    Deleting the `[[unit]]` table does not raise in the manifest loader — probed, it returns
    a document with zero units — so the refusal has to live here. Named so the selftest can
    assert the contract rather than re-implement it.
    """
    return units == 0 or walked == 0


# --------------------------------------------------------------------------------------
# selftest


def _unit(uid: str, *paths: str) -> dict:
    return {"id": uid, "paths": list(paths)}


def _tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def _run(files: dict[str, str], units, register: dict[str, dict]) -> tuple[list[str], int, int]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _tree(root, files)
        findings, walked = flag(root, units)
        problems = validate_register(register, root) + check_register(findings, register)
        return problems, walked, len(units)


def selftest() -> int:  # noqa: C901 - a control per property, each one named
    ok = True

    def case(name: str, problems: list[str], expect: str | None) -> None:
        """`expect` is a substring one problem must contain, or None for "no problem"."""
        nonlocal ok
        if expect is None:
            if problems:
                print(f"SELFTEST FAILED [{name}]: expected nothing, got {problems}")
                ok = False
            return
        if not any(expect in p for p in problems):
            print(f"SELFTEST FAILED [{name}]: expected a problem containing {expect!r}, "
                  f"got {problems}")
            ok = False

    NS = "mod child;\npub use child::*;\n"

    # P1 — the split escape, the shape that shipped three times.
    p, _, _ = _run(
        {
            "c/src/lib.rs": "pub mod sp;\n",
            "c/src/sp/mod.rs": "mod rotation;\npub fn advance() {}\n",
            "c/src/sp/rotation.rs": "pub fn rotate() {}\n",
        },
        [_unit("u.sp", "c/src/sp/mod.rs")],
        {},
    )
    case("P1 split escape", p, "c/src/sp/rotation.rs")
    case("P1 names the unit", p, "u.sp")

    # P2 — the rename escape: the `paths` entry was updated, the extraction was not.
    p, _, _ = _run(
        {
            "c/src/lib.rs": "pub mod a;\n",
            "c/src/a/mod.rs": "mod new;\n",
            "c/src/a/new.rs": "mod extracted;\npub fn decide() {}\n",
            "c/src/a/new/extracted.rs": "pub fn also_decides() {}\n",
        },
        [_unit("u.a", "c/src/a/mod.rs", "c/src/a/new.rs")],
        {},
    )
    case("P2 rename escape", p, "c/src/a/new/extracted.rs")

    # P3 — the parent escape: a deciding parent outside every closure.
    DECIDER = {
        "c/src/lib.rs": "pub mod b;\n",
        "c/src/b/mod.rs": "mod child;\npub fn decide() -> bool { true }\n",
        "c/src/b/child.rs": "pub fn helper() {}\n",
    }
    p, _, _ = _run(DECIDER, [_unit("u.b", "c/src/b/child.rs")], {})
    case("P3 parent escape", p, "UC-2")
    case("P3 names the parent", p, "c/src/b/mod.rs")

    # P4 — a namespace parent is not an escape.
    p, _, _ = _run(
        {"c/src/lib.rs": "pub mod b;\n", "c/src/b/mod.rs": NS, "c/src/b/child.rs": ""},
        [_unit("u.b", "c/src/b/child.rs")],
        {},
    )
    case("P4 namespace exemption", p, None)

    # P5 — an entry silences its own path and nothing else.
    SPLIT = {
        "c/src/lib.rs": "pub mod sp;\n",
        "c/src/sp/mod.rs": "mod rotation;\npub fn advance() {}\n",
        "c/src/sp/rotation.rs": "",
    }
    entry = {
        "c/src/sp/rotation.rs": {
            "path": "c/src/sp/rotation.rs",
            "rule": "UC-1",
            "baseline_sha": "0000000",
            "status": "reviewed-out-of-cone",
            "reason": "measured elsewhere",
            "review_ref": "REV-1 in docs/d.md",
        }
    }
    p, _, _ = _run({**SPLIT, "docs/d.md": "REV-1"}, [_unit("u.sp", "c/src/sp/mod.rs")], entry)
    case("P5 entry silences its own path", p, None)
    p, _, _ = _run(
        {
            **SPLIT,
            "docs/d.md": "REV-1",
            "c/src/sp/mod.rs": "mod rotation;\nmod mint;\npub fn advance() {}\n",
            "c/src/sp/mint.rs": "",
        },
        [_unit("u.sp", "c/src/sp/mod.rs")],
        entry,
    )
    case("P5 a second escape is still red", p, "c/src/sp/mint.rs")

    # P6 — the register may not outlive what it answers.
    p, _, _ = _run(
        {**SPLIT, "docs/d.md": "REV-1"},
        [_unit("u.sp", "c/src/sp/mod.rs", "c/src/sp/rotation.rs")],
        entry,
    )
    case("P6 resolved entry must be removed", p, "must be removed, not left standing")

    # P7 — a reviewed entry must point at a record that exists.
    p, _, _ = _run(SPLIT, [_unit("u.sp", "c/src/sp/mod.rs")], entry)
    case("P7 review_ref must resolve", p, "does not exist")

    # P8 — nothing returns to `unreviewed`.
    for old, new, want in (
        ("reviewed-attached", "unreviewed", False),
        ("reviewed-out-of-cone", "unreviewed", False),
        ("unreviewed", "reviewed-attached", True),
        ("reviewed-attached", "reviewed-out-of-cone", True),
    ):
        if permitted_transition(old, new) is not want:
            print(f"SELFTEST FAILED [P8]: `{old}` -> `{new}` should be {want}")
            ok = False
    moved = {
        "x.rs": {"path": "x.rs", "rule": "UC-1", "baseline_sha": "0", "status": "unreviewed"},
    }
    before = {
        "x.rs": {"path": "x.rs", "rule": "UC-1", "baseline_sha": "0",
                 "status": "reviewed-attached"},
    }
    case("P8 transition refused", check_transitions(before, moved), "does not permit")

    # P9 — UC-3 admits no new debt.
    case(
        "P9 new drift may not be registered",
        check_new_debt(entry, {"c/src/sp/rotation.rs"}),
        "UC-3 admits no new debt",
    )
    case("P9 an old path may be registered", check_new_debt(entry, {"other.rs"}), None)

    # P10 — a `mod` in a comment or a string is not a declaration.
    p, _, _ = _run(
        {
            "c/src/lib.rs": "pub mod b;\n",
            "c/src/b/mod.rs": '// mod ghost;\nfn f() { let s = "mod ghost;"; }\nmod child;\n',
            "c/src/b/child.rs": "",
        },
        [_unit("u.b", "c/src/b/mod.rs", "c/src/b/child.rs")],
        {},
    )
    case("P10 non-code mod is not a declaration", p, None)

    # P11 — both module forms resolve.
    for shape, files in (
        ("file form", {"c/src/x/a.rs": ""}),
        ("directory form", {"c/src/x/a/mod.rs": ""}),
    ):
        p, _, _ = _run(
            {"c/src/lib.rs": "pub mod x;\n", "c/src/x/mod.rs": "mod a;\n", **files},
            [_unit("u.x", "c/src/x/mod.rs")],
            {},
        )
        case(f"P11 {shape}", p, "UC-1")

    # P12 — the gate is not self-satisfying.
    if not empty_scope_is_failure(0, 12):
        print("SELFTEST FAILED [P12]: zero units must not be a pass")
        ok = False
    if not empty_scope_is_failure(114, 0):
        print("SELFTEST FAILED [P12]: zero walked files must not be a pass")
        ok = False
    if empty_scope_is_failure(1, 1):
        print("SELFTEST FAILED [P12]: a real run must not be refused")
        ok = False
    _, walked, units = _run(SPLIT, [], {})
    if (units, walked) != (0, 0):
        print(f"SELFTEST FAILED [P12]: an empty unit table walked {walked} files in {units}")
        ok = False

    # P13 — the in-tree probe. The synthetic cases prove the RULE; this one proves the gate
    # is wired to this repository's actual documents. The historical escape is replayed by
    # removing the three `signing_plane` submodules from whatever answers for them today.
    ok &= _in_tree_probe()

    if not ok:
        return 1
    print(
        "unit-closure gate selftest: PASS (the split and rename escapes, the deciding "
        "parent and the namespace exemption, an entry's scope, the ratchet, review_ref "
        "resolution, the disposition lifecycle, UC-3, non-code `mod`, both module forms, "
        "the empty-scope refusal, and the signing_plane escape replayed in-tree)"
    )
    return 0


def _in_tree_probe() -> bool:
    """Replay the `signing_plane` split against the live manifest and register."""
    from _manifest import load_verification  # noqa: PLC0415 - real-run only

    escaped = [
        "mcp-re-proxy/src/signing_plane/rotation.rs",
        "mcp-re-proxy/src/signing_plane/mint_successor.rs",
        "mcp-re-proxy/src/signing_plane/trust_epoch_advance.rs",
    ]
    units = [
        {"id": u["id"], "paths": [p for p in u["paths"] if p not in escaped]}
        for u in load_verification()["unit"]
    ]
    register = {k: v for k, v in load_register(REGISTER).items() if k not in escaped}
    findings, walked = flag(REPO, units)
    problems = check_register(findings, register)
    missing = [rel for rel in escaped if not any(rel in p for p in problems)]
    if missing:
        print(
            f"SELFTEST FAILED [P13 in-tree probe]: removing {missing} from every unit and "
            f"from the register left the gate green. It is not wired to this repository."
        )
        return False
    if walked == 0:
        print("SELFTEST FAILED [P13 in-tree probe]: walked no files")
        return False
    return True


# --------------------------------------------------------------------------------------


def emit_register() -> int:
    """Print a register for the current tree, carrying existing dispositions forward."""
    from _manifest import load_verification  # noqa: PLC0415

    sha = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.strip()
    existing = load_register(REGISTER)
    findings, _ = flag(REPO, load_verification()["unit"])
    print(
        f"# Unit-closure exclusions — files the module tree reaches from a measured unit\n"
        f"# that no unit's `paths` answer for. Emitted at {sha}: {len(findings)} entries.\n"
        f"#\n"
        f"# A debt register, not an exception mechanism. It may only shrink; see\n"
        f"# scripts/unit_closure_gate.py."
    )
    for rel, why in sorted(findings.items()):
        prior = existing.get(rel, {})
        print("\n[[exclusion]]")
        print(f'path = "{rel}"')
        print(f'rule = "{why.split(":", 1)[0]}"')
        print(f'baseline_sha = "{prior.get("baseline_sha") or sha}"')
        print(f'status = "{prior.get("status", "unreviewed")}"')
        if prior.get("reason"):
            print(f'reason = "{prior["reason"]}"')
        if prior.get("review_ref"):
            print(f'review_ref = "{prior["review_ref"]}"')
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--emit-register" in sys.argv:
        return emit_register()

    from _manifest import ManifestError, load_verification  # noqa: PLC0415

    try:
        units = load_verification()["unit"]
    except ManifestError as exc:
        print(f"unit-closure gate: FAIL — {exc}", file=sys.stderr)
        return 1

    register = load_register(REGISTER)
    findings, walked = flag(REPO, units)

    if empty_scope_is_failure(len(units), walked):
        print(
            f"unit-closure gate: FAIL — {len(units)} unit(s), {walked} file(s) walked. A "
            f"gate whose subject list is empty reports success by measuring nothing.",
            file=sys.stderr,
        )
        return 1

    new_paths, uc3_note = introduced_paths()
    previous, baseline_note = previous_register()
    problems = (
        expansion_disagreements(REPO, units)
        + validate_register(register, REPO)
        + check_register(findings, register)
        + (check_transitions(previous, register) if previous is not None else [])
        + (check_new_debt(register, new_paths) if new_paths is not None else [])
    )

    if problems:
        print(f"unit-closure gate: FAIL — {len(problems)} problem(s)", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nUC-1: a `mod` declared by a measured file must itself be measured. "
            "UC-2: so must the parent that declares a measured file, when it holds items "
            "of its own. UC-3: a path this change introduced joins a unit, never the "
            "register.",
            file=sys.stderr,
        )
        return 1

    def with_status(name: str) -> int:
        return sum(1 for e in register.values() if e.get("status") == name)

    print(
        f"unit-closure gate: OK — {len(units)} unit(s), {walked} file(s) walked through "
        f"their `mod` declarations. Register: {len(register)} path(s) outside every "
        f"closure — {with_status('unreviewed')} unreviewed, "
        f"{with_status('reviewed-attached')} reviewed-attached, "
        f"{with_status('reviewed-out-of-cone')} reviewed-out-of-cone. No unanswered "
        f"neighbour. Dispositions checked {baseline_note}; UC-3 {uc3_note}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
