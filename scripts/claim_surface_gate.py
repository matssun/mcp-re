#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Claim-surface gate — the published claims and the declared roots are one fact.

THE FAILURE CLASS, which is why this file exists rather than any single instance:

    Two documents that independently decide what the system promises will disagree, and
    the disagreement is invisible because each reads as authoritative on its own.

It had already happened. `verification/policy/theorems.toml` declared TWELVE
`root_theorems`; `docs/spec/security-boundary.md` §2 — the ratified positive-claim
surface, whose own text says "a claim with no root in this table is not a claim this
document makes" — carried NINE rows. THM-0091, THM-0094 and THM-0095 were established and
owner-reviewed while §4 still listed them as *in scope and not yet established*, §5
reported "Root completeness: 7 of 9" against a tree reporting 12 of 12, and §7.1 — the
moves ledger that exists so no amendment is absorbed silently — had a row for none of it.
Nothing failed. Nothing could: no control related the two surfaces.

WHAT THIS GATE DOES NOT DO, deliberately. It does not generate the claim prose. A security
consequence written for a human reader is not derivable from a theorem statement, and a §2
built by templating theorem titles would be a worse document that happened to be
consistent. The split is:

    theorem registry     root IDENTITY and MEMBERSHIP — which claims are system promises
    review records       whether the owner has reviewed the CURRENT statement of each
    boundary spec §2     the human security consequence, one per root, deliberately written
    this gate            the mapping between them, mechanically, with no third opinion

So the registry may not gain a root without the boundary gaining a claim, the boundary may
not claim what no root supports, and neither may drift while the other stands still.

WHAT IT PROVES, from SOURCE alone:

  * TOTAL       every declared root has exactly one §2 claim row.
  * SOUND       every §2 row names a declared root.
  * UNIQUE      no root is claimed twice — two rows for one root are two authorities.
  * DISJOINT    no theorem is both claimed (§2) and disclaimed (§4). A document cannot
                make and withhold the same claim.
  * NOT STALE   every claimed root's specification review covers its CURRENT fingerprint,
                OR a RECORDED ADR-MCPRE-068 Phase-1 claim correction carries it there from
                the fingerprint the owner did review. A published claim whose statement has
                moved for no recorded reason is a claim nobody has approved in its present
                form. See `tools/verification/_claim_corrections.py` for what a record must
                assert and why the chain starts at the owner's review; in short, a
                correction is a recorded DELTA on a reviewed claim, it is one-shot, and it
                does NOT make the specification-review axis fresh — release-mode
                establishment still asks for the human.
  * §4 SHAPE    the open-gap table names no declared root, and no area twice. A root that
                is a system promise is not simultaneously an unclosed gap, and a duplicated
                area row gives a reader a different answer depending which one they reach.
  * NOT MOVED   every theorem the OWNER HAS REVIEWED whose claim this branch moves is
                carried by a review at the new claim or by a recorded correction — not only
                the twelve published roots. See THE REACH below.

THE REACH, and why it is derived rather than listed. Until 2026-09-21 the staleness rule
above ranged over `declared` — the twelve §2-published roots — so a theorem was enforced if
it was published, or if it was already enforced. Nothing pulled a theorem into the enforced
set BECAUSE ITS CLAIM MOVED. Measured on one branch: a single sentence removed from
THM-0023's scope moved NINE theorems' fingerprints, five of them `critical`, and this gate
named ONE. THM-0105's own claim text moved in the same push, held by no other theorem's
closure and published as no root, and nothing in the repository would have reported it.

The published roots are still held hardest — a root with no §2 row, or a §2 row whose review
went stale, fails whether its claim moved or not. What is added is the second, derived
population: compare each theorem's claim components against the MERGE BASE with
`origin/main` and enforce over what actually moved. That set costs one `git show` of
`verification/policy/theorems.toml`, because a theorem fingerprint reads that file and
nothing else.

Three decisions inside it, each of which the obvious implementation gets wrong:

  * THE MERGE BASE, not `origin/main`'s tip. The question is *what did THIS branch move*.
    Against the tip, a claim corrected on `main` after this branch forked reads as this
    branch's movement, and the gate would demand a record from the wrong author.
  * CLAIM COMPONENTS, not the composite fingerprint. `encoding_version` participates in the
    fingerprint and is excluded here: bumping how a claim is ENCODED changes every digest
    while changing nothing a reviewer approved, and a gate that demanded 128 records for it
    would be routed around within the hour.
  * ONLY WHAT THE OWNER REVIEWED. A theorem with no specification review record has no
    approval to invalidate, so moving it breaks nothing this gate is about. Introducing an
    unreviewed theorem is release-mode establishment's question, and it asks for the human.

WHAT THE MOVEMENT HALF DOES NOT COVER, stated because a derived population reads as wider
than it is: a theorem ADDED on the branch (no prior claim to have moved) and one DELETED by
it (no current claim) are both outside it — the registry's own loader and the §2 mapping
above judge those. And when the merge base cannot be read the half is SKIPPED and the skip
is PRINTED, on `module_size_gate.py`'s precedent: a comparison that quietly no-ops when it
cannot find its baseline is this platform's own "green that measured nothing".

WHAT IT DOES NOT PROVE: that a claim's prose is *accurate*, that the evidence behind a root
is fresh, or that the argument composes. Evidence freshness is `tools/verification/review`
and it reads the attestation store, which is machine-local and gitignored — a merge-path
control cannot see it, and a gate that pretended to would be reporting one machine's state
as a property of the commit. This gate is the mapping, and says so.

Run:  python3 scripts/claim_surface_gate.py
      python3 scripts/claim_surface_gate.py --selftest
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BOUNDARY = REPO / "docs" / "spec" / "security-boundary.md"

sys.path.insert(0, str(REPO / "tools" / "verification"))

from _fingerprint import fingerprint_theorem  # noqa: E402
from _manifest import ManifestError, load_verification  # noqa: E402
from _claim_corrections import (  # noqa: E402
    CorrectionError,
    chain,
    corrections_root,
    load_corrections,
)
from _review import REVIEWED, derive_review_state, load_reviews, review_root  # noqa: E402
from _theorems import load_theorems  # noqa: E402

#: A theorem reference anywhere in the document.
THM = re.compile(r"THM-\d{4}")

#: The heading that opens each section this gate reads. Matched on the NUMBER, not the
#: title: the titles are prose the owner may reword, and a gate that broke on a reworded
#: heading would be a gate people route around.
SECTION = re.compile(r"^## (\d+)\. ")
SUBSECTION = re.compile(r"^### (\d+)\.(\d+) ")


def sections(text: str) -> dict[str, list[str]]:
    """The document split by top-level numbered section, subsections included with their parent.

    Subsections stay with the parent because §4.1 and §4.2 are amendments TO §4 and a
    theorem named in one is named in §4. Splitting them out would let a claim hide in an
    amendment.
    """
    found: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        heading = SECTION.match(line) or SUBSECTION.match(line)
        if heading:
            current = str(heading.group(1))
            found.setdefault(current, [])
            continue
        if current is not None:
            found[current].append(line)
    return found


def table_rows(lines: list[str]) -> list[list[str]]:
    """The cells of every markdown table row in a section, header and rule excluded."""
    rows: list[list[str]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if all(set(cell) <= {"-", ":"} and cell for cell in cells):
            continue
        rows.append(cells)
    return rows


def claim_rows(section2: list[str]) -> list[tuple[str, list[str]]]:
    """`(claim prose, theorems named)` per §2 row, header dropped.

    The header is dropped by CONTENT rather than by position: a row whose second cell is
    literally the word `root` is the header, and a document that gained a leading note
    line would otherwise silently lose its first real claim from the gate's view.
    """
    rows = []
    for cells in table_rows(section2):
        if len(cells) < 2 or cells[1].lower() == "root":
            continue
        rows.append((cells[0], THM.findall(cells[1])))
    return rows


#: The header a §4 table must carry to be read as one kind or the other. A table DECLARES
#: which it is; the gate never infers it from the prose in a disposition cell. Inference was
#: tried and is wrong twice over: it makes the gate fire on a correctly-worded settled row,
#: and it lets a badly-worded open gap escape by not containing whatever word the matcher
#: happened to look for. A header is a structural statement the author must make on purpose.
GAP_HEADER = ("area", "disposition", "placement")
SETTLED_HEADER = ("area", "settled as", "route")


def split_section4(section4: list[str]) -> tuple[list[list[str]], list[list[str]], list[str]]:
    """§4's tables, separated by declared kind: `(open gaps, settled record, unrecognized)`.

    The third return value is the reason this returns three things. A table in §4 whose
    header matches neither known shape is not "no gaps found" — it is a table this gate
    cannot classify, and an unclassifiable claim surface must fail rather than read as an
    agreeing one. That is the same rule the rest of this platform applies to a lane that
    exits 0 without declaring a verdict.
    """
    gaps: list[list[str]] = []
    settled: list[list[str]] = []
    unknown: list[str] = []
    target: list[list[str]] | None = None
    for cells in table_rows(section4):
        header = tuple(cell.strip().lower().strip("*") for cell in cells)
        if header == GAP_HEADER:
            target = gaps
            continue
        if header == SETTLED_HEADER:
            target = settled
            continue
        if cells[0].strip().lower() == "area":
            target = None
            unknown.append(" | ".join(cells))
            continue
        if target is not None:
            target.append(cells)
    return gaps, settled, unknown


def gap_rows(section4: list[str]) -> list[tuple[str, list[str]]]:
    """`(area, theorems the row is ABOUT)` per §4 OPEN-gap row.

    Two cells are read and the third deliberately is not. `area | disposition | placement`:
    the disposition names the area's OWN theorems and their state, and the placement names
    the root the area composes UNDER. A row saying "under THM-0077" is stating where an
    open gap attaches, not withholding THM-0077 — reading the placement cell as a
    disclaimer would make every correctly-placed gap row a contradiction, and a gate that
    fires on correct prose is a gate the next author routes around.

    Rows whose disposition places the area outside the runtime roots are not open gaps at
    all: "deployment rendering" and "the assurance platform" say where a concern is owned,
    and §0 governs them.
    """
    rows = []
    for cells in split_section4(section4)[0]:
        if len(cells) < 2:
            continue
        disposition = cells[1]
        if "outside" in disposition.lower():
            continue
        rows.append((cells[0], THM.findall(f"{cells[0]} {disposition}")))
    return rows


def settled_rows(section4: list[str]) -> list[tuple[str, list[str]]]:
    """`(area, theorems named)` per §4 SETTLED row — an area the ruling closed."""
    return [
        (cells[0], THM.findall(" ".join(cells)))
        for cells in split_section4(section4)[1]
        if len(cells) >= 2
    ]


def mapping_defects(
    roots: list[str],
    claims: list[tuple[str, list[str]]],
    gaps: list[tuple[str, list[str]]],
    review_states: dict[str, tuple[str, str]],
    settled: list[tuple[str, list[str]]] | None = None,
    unknown_tables: list[str] | None = None,
    corrected: dict[str, tuple[bool, str]] | None = None,
) -> list[str]:
    """Every way the two surfaces can disagree. One function so the rules are one place."""
    defects: list[str] = []
    declared = set(roots)

    claimed: dict[str, int] = {}
    for prose, named in claims:
        if not named:
            defects.append(
                f"§2 row names no theorem: {prose[:70]!r}. A claim with no root is a claim "
                f"this document is not entitled to make."
            )
            continue
        for theorem in named:
            claimed[theorem] = claimed.get(theorem, 0) + 1

    for theorem in sorted(declared - set(claimed)):
        defects.append(
            f"{theorem} is a declared system root with no §2 claim row. A promise the "
            f"registry makes and the boundary does not publish is a claim no reader can "
            f"find, and the reader is who §2 is for."
        )
    for theorem in sorted(set(claimed) - declared):
        defects.append(
            f"§2 claims {theorem}, which `root_theorems` does not declare. Either the root "
            f"set is missing it or the claim is not one this document may make; the gate "
            f"will not guess which."
        )
    for theorem, count in sorted(claimed.items()):
        if count > 1:
            defects.append(
                f"{theorem} appears in {count} §2 rows. One root, one human claim: two "
                f"rows are two authorities over one promise, which is the condition this "
                f"gate exists to refuse."
            )

    for area, named in gaps:
        for theorem in named:
            if theorem in declared:
                defects.append(
                    f"§4 lists {theorem} under {area!r} as an unclosed gap, but it is a "
                    f"declared system root. A root is a promise the owner ratified; it "
                    f"cannot also be an area in which this document makes no claim."
                )
            if theorem in claimed:
                defects.append(
                    f"{theorem} is claimed in §2 and disclaimed in §4 under {area!r}. A "
                    f"reader gets opposite answers depending which section they reach."
                )
    seen: set[str] = set()
    for area, _ in gaps:
        key = area.strip().lower().strip("*")
        if key in seen:
            defects.append(
                f"§4 lists the area {area!r} more than once. The duplicate rows carried "
                f"different dispositions, so the answer a reader got depended on which row "
                f"they reached first."
            )
        seen.add(key)

    for theorem in sorted(claimed):
        if theorem not in declared:
            continue
        state, reason = review_states.get(theorem, ("MISSING", "no review record"))
        if state == REVIEWED:
            continue
        accepted, why = (corrected or {}).get(theorem, (False, "no correction record"))
        if accepted:
            continue
        defects.append(
            f"§2 claims {theorem}, whose specification review is {state}: {reason}. A "
            f"published claim must be one the owner reviewed in its present form, or one a "
            f"RECORDED ADR-MCPRE-068 Phase-1 correction carries there from the fingerprint "
            f"they did review — and neither holds: {why}."
        )

    # A SETTLED row is the one place this gate cannot judge the prose: whether an area was
    # really closed is a review act. What it can judge is whether the row's own references
    # hold up — a settled row naming a root that §2 does not publish would be recording a
    # closure that did not happen, which is the failure this section was restructured out of.
    for area, named in settled or []:
        for theorem in named:
            if theorem in declared and theorem not in claimed:
                defects.append(
                    f"§4 records {area!r} as settled by {theorem}, a declared root that §2 "
                    f"does not publish. An area closed by a promise no reader can find is "
                    f"not closed."
                )
            if theorem not in review_states:
                defects.append(
                    f"§4 records {area!r} as settled by {theorem}, which the registry does "
                    f"not declare. A closure resting on a theorem that does not exist is "
                    f"the stalest kind of green."
                )

    for header in unknown_tables or []:
        defects.append(
            f"§4 carries a table this gate cannot classify: {header!r}. A §4 table must "
            f"declare its kind in its header — {' | '.join(GAP_HEADER)} for open areas, "
            f"{' | '.join(SETTLED_HEADER)} for closed ones. An unclassifiable claim surface "
            f"must fail rather than read as an agreeing one."
        )
    return defects


#: The branch this gate measures claim movement against. Named once so the selftest and the
#: prose agree with the code about which ref is the baseline.
MOVEMENT_REF = "origin/main"


def merge_base(ref: str = MOVEMENT_REF) -> str | None:
    """The commit this branch forked from `ref`, or `None` when it cannot be determined.

    Deliberately not `ref` itself. A claim corrected on `main` after this branch forked is
    not this branch's movement, and a gate that attributed it here would demand a record
    from an author who changed nothing.
    """
    try:
        out = subprocess.run(
            ["git", "merge-base", "HEAD", ref],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 - any git failure is the same answer here
        return None
    return out or None


def theorems_at(commit: str) -> dict | None:
    """`theorems.toml` as of `commit`, parsed and NOT validated.

    Validation is deliberately skipped. `load_theorems` enforces TODAY's schema, and the
    baseline is a tree that was legal under whatever schema it shipped with; running the
    current validator over it would turn a legitimate schema change into a gate failure
    about a commit nobody can now edit. What is needed here is only what the claim digests
    read, and those are fields, not invariants.
    """
    try:
        out = subprocess.run(
            ["git", "show", f"{commit}:verification/policy/theorems.toml"],
            cwd=REPO, capture_output=True, check=True,
        ).stdout
    except Exception:  # noqa: BLE001
        return None
    try:
        return tomllib.loads(out.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


def claim_components(doc: dict) -> tuple[dict[str, dict], list[str]]:
    """`(per-theorem claim components, ids that could not be measured)`.

    `encoding_version` is dropped: it certifies how a claim is encoded, not what it says.
    A row this code cannot fingerprint is RETURNED as unmeasurable rather than skipped —
    a theorem silently absent from one side of a comparison is a theorem the comparison
    reports as unmoved, which is the failure this whole gate is named after.
    """
    measured: dict[str, dict] = {}
    unmeasurable: list[str] = []
    for row in doc.get("theorem", []):
        theorem = row.get("id")
        if not theorem:
            continue
        try:
            components = dict(fingerprint_theorem(row, doc)["components"])
        except Exception:  # noqa: BLE001 - a row missing a claim field is unmeasurable, not equal
            unmeasurable.append(theorem)
            continue
        components.pop("encoding_version", None)
        components.pop("theorem_id", None)
        measured[theorem] = components
    return measured, sorted(unmeasurable)


def moved_claims(before: dict[str, dict], after: dict[str, dict]) -> list[tuple[str, list[str]]]:
    """`(theorem, which components moved)` for every theorem present on BOTH sides.

    Present on both, because the two asymmetric cases are other controls' propositions and
    answering them here would be this gate holding a second opinion: a theorem added on the
    branch has no prior claim to have moved, and one deleted by it has no current claim for
    a review to be about.
    """
    moved = []
    for theorem in sorted(set(before) & set(after)):
        which = sorted(k for k in set(before[theorem]) | set(after[theorem])
                       if before[theorem].get(k) != after[theorem].get(k))
        if which:
            moved.append((theorem, which))
    return moved


#: How each moved-claim component reads to someone who has to act on the defect.
COMPONENT_PROSE = {
    "theorem_claim": "its own statement, security consequence or scope",
    "theorem_dependencies": "a premise beneath it",
    "theorem_review_requirement": "who must review it",
}


def movement_defects(
    moved: list[tuple[str, list[str]]],
    review_states: dict[str, tuple[str, str]],
    corrected: dict[str, tuple[bool, str]],
    reviewed_subjects: set[str],
    unmeasurable: list[str] | None = None,
) -> list[str]:
    """Every moved claim the owner had reviewed and nothing carries to where it now stands."""
    defects: list[str] = []
    for theorem, which in moved:
        if theorem not in reviewed_subjects:
            # No approval exists, so none was invalidated. Establishing an unreviewed
            # theorem is release mode's question and it asks for the human.
            continue
        state, reason = review_states.get(theorem, ("MISSING", "no review record"))
        if state == REVIEWED:
            continue
        accepted, why = corrected.get(theorem, (False, "no correction record"))
        if accepted:
            continue
        parts = ", ".join(COMPONENT_PROSE.get(k, k) for k in which)
        defects.append(
            f"{theorem}'s claim moved on this branch ({parts}) and its specification "
            f"review is {state}: {reason}. The owner approved a different claim, and "
            f"nothing carries the approval to this one: {why}. This theorem is not a "
            f"published root — it is enforced because its claim MOVED, which is the "
            f"population a silent cascade hides in."
        )
    for theorem in unmeasurable or []:
        defects.append(
            f"{theorem} could not be fingerprinted on one side of the comparison, so this "
            f"gate cannot tell whether its claim moved. An unmeasurable claim must not "
            f"read as an unchanged one."
        )
    return defects


def read_surfaces():
    """`(claims, open gaps, settled record, unclassifiable tables)` from the boundary spec."""
    parts = sections(BOUNDARY.read_text(encoding="utf-8"))
    if "2" not in parts or "4" not in parts:
        raise SystemExit(
            f"FAIL: {BOUNDARY} has no §2 or no §4. The gate reads those sections by "
            f"number; a renumbered document must update this gate rather than silently "
            f"measure nothing."
        )
    return (
        claim_rows(parts["2"]),
        gap_rows(parts["4"]),
        settled_rows(parts["4"]),
        split_section4(parts["4"])[2],
    )


def selftest() -> int:
    """A gate whose only evidence is that a clean tree passes has never been shown to fail."""
    reviewed = {t: (REVIEWED, "reviewed") for t in ("THM-0001", "THM-0002", "THM-0003")}
    cases: list[tuple[list, list, list, dict, str | None, str]] = [
        (
            ["THM-0001"],
            [("a claim", ["THM-0001"])],
            [],
            reviewed,
            None,
            "a root with exactly one claim",
        ),
        (
            ["THM-0001", "THM-0002"],
            [("a claim", ["THM-0001"])],
            [],
            reviewed,
            "THM-0002 is a declared system root with no §2 claim row",
            "a root the boundary does not publish",
        ),
        (
            ["THM-0001"],
            [("a claim", ["THM-0001"]), ("another", ["THM-0002"])],
            [],
            reviewed,
            "which `root_theorems` does not declare",
            "a claim with no root",
        ),
        (
            ["THM-0001"],
            [("a claim", ["THM-0001"]), ("said twice", ["THM-0001"])],
            [],
            reviewed,
            "appears in 2 §2 rows",
            "one root claimed twice",
        ),
        (
            ["THM-0001"],
            [("a claim", ["THM-0001"])],
            [("some area", ["THM-0001"])],
            reviewed,
            "declared system root",
            "a root listed as an open gap",
        ),
        (
            ["THM-0001"],
            [("a claim", ["THM-0001"])],
            [("dup", []), ("Dup", [])],
            reviewed,
            "more than once",
            "a duplicated §4 area",
        ),
        (
            ["THM-0001"],
            [("a claim", ["THM-0001"])],
            [],
            {"THM-0001": ("STALE_CLAIM", "the statement moved")},
            "specification review is STALE_CLAIM",
            "a claim whose review went stale",
        ),
        (
            ["THM-0001"],
            [("a claim", [])],
            [],
            reviewed,
            "names no theorem",
            "a §2 row naming nothing",
        ),
    ]
    for roots, claims, gaps, reviews, needle, label in cases:
        found = mapping_defects(roots, claims, gaps, reviews)
        if needle is None:
            if found:
                print(f"SELFTEST FAIL: refused {label}: {found}", file=sys.stderr)
                return 1
            continue
        if not any(needle in entry for entry in found):
            print(f"SELFTEST FAIL: accepted {label}: {found}", file=sys.stderr)
            return 1

    # The parsers are half the gate. A table reader that stopped matching would report an
    # empty surface as a consistent one, which is "exits 0 having measured nothing" wearing
    # this gate's name.
    doc = "## 2. Claims\n\n| claim | root |\n|---|---|\n| prose here | **THM-0074** — x |\n"
    parsed = claim_rows(sections(doc)["2"])
    if parsed != [("prose here", ["THM-0074"])]:
        print(f"SELFTEST FAIL: the §2 reader parsed {parsed!r}", file=sys.stderr)
        return 1
    doc4 = (
        "## 4. Gaps\n\n| area | disposition | placement |\n|---|---|---|\n"
        "| Replay | in scope — THM-0086 | under THM-0077 |\n"
        "| Rendering | **outside** the runtime roots | release gates |\n"
        "\n### 4.3 Settled\n\n| area | settled as | route |\n|---|---|---|\n"
        "| Sidecar | **§2 claim** — THM-0091 | established and reviewed |\n"
    )
    parsed4 = gap_rows(sections(doc4)["4"])
    # THM-0077 is in the PLACEMENT cell — where the gap attaches, not what it withholds.
    # THM-0091 is in the SETTLED table, which is a different kind of row entirely. A reader
    # of this test should see both omissions as the point of it.
    if parsed4 != [("Replay", ["THM-0086"])]:
        print(f"SELFTEST FAIL: the §4 reader parsed {parsed4!r}", file=sys.stderr)
        return 1
    parsed_settled = settled_rows(sections(doc4)["4"])
    if parsed_settled != [("Sidecar", ["THM-0091"])]:
        print(f"SELFTEST FAIL: the settled reader parsed {parsed_settled!r}", file=sys.stderr)
        return 1
    # A settled row naming a root §2 does not publish records a closure that did not happen.
    orphan = mapping_defects(
        ["THM-0001", "THM-0091"],
        [("a claim", ["THM-0001"])],
        [],
        {**reviewed, "THM-0091": (REVIEWED, "reviewed")},
        settled=[("Sidecar", ["THM-0091"])],
    )
    if not any("does not publish" in entry for entry in orphan):
        print("SELFTEST FAIL: accepted a settled row closing on an unpublished root", file=sys.stderr)
        return 1
    # A §4 table declaring neither kind must fail, not read as an empty gap list.
    strange = "## 4. Gaps\n\n| area | something else |\n|---|---|\n| X | Y |\n"
    if not split_section4(sections(strange)["4"])[2]:
        print("SELFTEST FAIL: an unclassifiable §4 table read as no gaps", file=sys.stderr)
        return 1
    # A subsection's theorems belong to its parent section, or a claim could hide in an
    # amendment where the gate does not look.
    nested = "## 4. Gaps\n\n### 4.1 Amendment\n\n| area | in scope — THM-0091 |\n|---|---|\n"
    if "4" not in sections(nested) or "THM-0091" not in " ".join(sections(nested)["4"]):
        print("SELFTEST FAIL: a §4.1 amendment did not fold into §4", file=sys.stderr)
        return 1
    # ---- the derived half: the reach SF-009 measured as 1-of-9 -------------------------
    def thm(tid, statement="s", consequence="c", scope="sc", depends=(), req="owner"):
        return {
            "id": tid, "statement": statement, "security_consequence": consequence,
            "scope": scope, "depends_on": list(depends), "review_requirement": req,
        }

    base_doc = {"theorem": [thm("THM-0001"), thm("THM-0002", depends=["THM-0001"])]}
    base_components, base_bad = claim_components(base_doc)
    if base_bad:
        print(f"SELFTEST FAIL: a well-formed row read as unmeasurable: {base_bad}", file=sys.stderr)
        return 1

    # A premise's scope narrows. THM-0001's OWN claim moved; THM-0002 moved only through
    # its dependency closure and is exactly the class the old reach never saw.
    after_doc = {"theorem": [thm("THM-0001", scope="narrower"), thm("THM-0002", depends=["THM-0001"])]}
    after_components, _ = claim_components(after_doc)
    cascade = moved_claims(base_components, after_components)
    if [t for t, _ in cascade] != ["THM-0001", "THM-0002"]:
        print(f"SELFTEST FAIL: the cascade measured {cascade!r}", file=sys.stderr)
        return 1
    if dict(cascade)["THM-0001"] != ["theorem_claim"]:
        print(f"SELFTEST FAIL: the source moved on {dict(cascade)['THM-0001']!r}", file=sys.stderr)
        return 1
    if dict(cascade)["THM-0002"] != ["theorem_dependencies"]:
        print(f"SELFTEST FAIL: the dependent moved on {dict(cascade)['THM-0002']!r}", file=sys.stderr)
        return 1

    stale = {t: ("STALE_CLAIM", "changed since review") for t in ("THM-0001", "THM-0002")}
    both = {"THM-0001", "THM-0002"}
    # 1. moved, reviewed once, nothing carries it -> BOTH are defects, not just the source.
    defects = movement_defects(cascade, stale, {}, both)
    if len(defects) != 2 or not any("THM-0002" in d for d in defects):
        print(f"SELFTEST FAIL: the dependency-only movement was not enforced: {defects}", file=sys.stderr)
        return 1
    # 2. re-reviewed at the new claim -> silent.
    if movement_defects(cascade, {t: (REVIEWED, "reviewed") for t in both}, {}, both):
        print("SELFTEST FAIL: a re-reviewed moved claim still failed", file=sys.stderr)
        return 1
    # 3. carried by a recorded correction -> silent.
    if movement_defects(cascade, stale, {t: (True, "carried") for t in both}, both):
        print("SELFTEST FAIL: a recorded correction did not carry a moved claim", file=sys.stderr)
        return 1
    # 4. never reviewed -> silent. There is no approval to invalidate, and inventing one
    #    would make this gate an establishment control, which it is not.
    if movement_defects(cascade, stale, {}, set()):
        print("SELFTEST FAIL: an unreviewed theorem was held to a review it never had", file=sys.stderr)
        return 1
    # 5. nothing moved -> silent, and that must come from EQUALITY rather than from an
    #    empty read: `compared` is asserted non-zero by the caller's note.
    if moved_claims(base_components, base_components):
        print("SELFTEST FAIL: an identical registry reported movement", file=sys.stderr)
        return 1
    # 6. a row this code cannot fingerprint is UNMEASURABLE, never equal.
    broken, broken_ids = claim_components({"theorem": [{"id": "THM-0003", "statement": "s"}]})
    if broken or broken_ids != ["THM-0003"]:
        print(f"SELFTEST FAIL: a malformed row read as {broken!r}/{broken_ids!r}", file=sys.stderr)
        return 1
    if not movement_defects([], {}, {}, set(), unmeasurable=["THM-0003"]):
        print("SELFTEST FAIL: an unmeasurable claim read as an unchanged one", file=sys.stderr)
        return 1
    # 7. an ADDED or DELETED theorem is outside this half, deliberately.
    grown, _ = claim_components({"theorem": [thm("THM-0001"), thm("THM-0009")]})
    if moved_claims(base_components, grown):
        print("SELFTEST FAIL: an added/deleted theorem entered the movement set", file=sys.stderr)
        return 1

    print("claim_surface_gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    try:
        doc = load_verification()
        theorems = load_theorems(
            {unit["id"] for unit in doc.get("unit", [])},
            [e for e in doc.get("edge", []) if e.get("kind") == "PROOF_DEPENDENCY"],
        )
    except ManifestError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    roots = list(theorems.get("root_theorems", []))
    if not roots:
        # An empty root set is the emptiest registry reading as the greenest, one level up.
        print(
            "FAIL: `root_theorems` is empty. A repository that declares no system promise "
            "has no claim surface to be consistent with, and this gate must not report "
            "that as agreement.",
            file=sys.stderr,
        )
        return 1

    fingerprints = {
        row["id"]: fingerprint_theorem(row, theorems) for row in theorems.get("theorem", [])
    }
    reviews = load_reviews(review_root(REPO))
    review_states = {
        theorem: derive_review_state(fingerprints[theorem], reviews.get(("specification", theorem)))
        for theorem in fingerprints
    }

    try:
        corrections = load_corrections(corrections_root(REPO), REPO)
    except CorrectionError as exc:
        # UNPARSABLE IS A FAILURE. A dropped record would make the staleness defect below
        # report a reason that is not the real one.
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    reviewed_at = {
        theorem: (reviews.get(("specification", theorem)) or {}).get("reviewed_fingerprint")
        for theorem in fingerprints
    }
    corrected = {
        theorem: chain(
            corrections.get(theorem, []),
            reviewed_at.get(theorem),
            fingerprints[theorem]["fingerprint"],
        )
        for theorem in fingerprints
    }
    # A DEAD RECORD IS REFUSED WHEREVER IT SITS. The §2 check below only consults
    # `corrected` for theorems the boundary publishes, so a record for any other theorem —
    # or one whose chain stopped closing — would sit unread. The honest exception is a
    # correction the owner has since REVIEWED at the new fingerprint: the chain then no
    # longer closes because its `from` is the superseded review, and the record is history
    # rather than authority. Deleting it to satisfy a gate would destroy the audit trail
    # this register exists to keep.
    dead = sorted(
        subject
        for subject in corrections
        if subject in fingerprints
        and not corrected[subject][0]
        and review_states[subject][0] != REVIEWED
    )
    if dead:
        for subject in dead:
            print(
                f"FAIL: claim-correction record(s) for {subject} authorize no live "
                f"transition and the claim is not reviewed as it stands: "
                f"{corrected[subject][1]}. A record that carries nothing is a row nothing "
                f"can retire.",
                file=sys.stderr,
            )
        return 1

    # A record for a theorem the registry does not declare authorizes a transition of
    # nothing, and would sit unread forever.
    orphaned = sorted(set(corrections) - set(fingerprints))
    if orphaned:
        print(
            f"FAIL: claim-correction record(s) name {orphaned}, which the registry does not "
            f"declare. A correction to a theorem that does not exist is a row nothing can "
            f"ever retire.",
            file=sys.stderr,
        )
        return 1

    claims, gaps, settled, unknown = read_surfaces()
    if not claims:
        print(
            "FAIL: §2 of the security boundary parsed to no claim rows. An unreadable "
            "claim surface must not report as an agreeing one.",
            file=sys.stderr,
        )
        return 1

    found = mapping_defects(roots, claims, gaps, review_states, settled, unknown, corrected)

    # THE DERIVED HALF. Everything above ranges over the twelve published roots; this ranges
    # over what this branch actually moved, which is the population SF-009 measured the gate
    # missing by eight theorems out of nine.
    reviewed_subjects = {
        theorem for theorem in fingerprints
        if reviews.get(("specification", theorem)) is not None
    }
    base = merge_base()
    baseline_doc = theorems_at(base) if base else None
    if baseline_doc is None:
        # PRINTED, never inferred from silence. A comparison that no-ops when it cannot find
        # its baseline is this platform's own "green that measured nothing", and the one edit
        # that disables it must not be the one edit nothing reports.
        movement_note = (
            f"claim-movement half SKIPPED: no readable `verification/policy/theorems.toml` "
            f"at the merge base with {MOVEMENT_REF}"
            + (f" ({base[:12]})" if base else " (no merge base)")
            + ". Claim movement was NOT measured on this run."
        )
        moved: list[tuple[str, list[str]]] = []
        compared = 0
    else:
        before, unmeasurable_before = claim_components(baseline_doc)
        after, unmeasurable_after = claim_components({"theorem": theorems.get("theorem", [])})
        moved = moved_claims(before, after)
        compared = len(set(before) & set(after))
        found += movement_defects(
            moved,
            review_states,
            corrected,
            reviewed_subjects,
            sorted(set(unmeasurable_before) | set(unmeasurable_after)),
        )
        movement_note = (
            f"{compared} theorem(s) compared against the merge base with {MOVEMENT_REF} "
            f"({base[:12]}), {len(moved)} moved"
        )

    if found:
        print(f"claim-surface gate: {movement_note}", file=sys.stderr)
        print("claim-surface gate: FAIL", file=sys.stderr)
        for defect in found:
            print(f"  - {defect}", file=sys.stderr)
        return 1
    print(f"claim-surface gate: {movement_note}")
    print(
        f"claim-surface gate: OK — {len(roots)} declared root(s), {len(claims)} published "
        f"claim(s), {len(gaps)} open §4 area(s), {len(settled)} settled, every claimed root "
        f"reviewed at its current fingerprint"
        + (
            f" or carried there by a recorded Phase-1 correction "
            f"({sum(1 for t in roots if corrected.get(t, (False, ''))[0] and review_states[t][0] != REVIEWED)} of them)."
            if any(
                corrected.get(t, (False, ""))[0] and review_states[t][0] != REVIEWED
                for t in roots
            )
            else "."
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
