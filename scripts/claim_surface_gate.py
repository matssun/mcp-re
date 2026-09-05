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
  * NOT STALE   every claimed root's specification review covers its CURRENT fingerprint.
                A published claim whose statement has moved since the owner read it is a
                claim nobody has approved in its present form.
  * §4 SHAPE    the open-gap table names no declared root, and no area twice. A root that
                is a system promise is not simultaneously an unclosed gap, and a duplicated
                area row gives a reader a different answer depending which one they reach.

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
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BOUNDARY = REPO / "docs" / "spec" / "security-boundary.md"

sys.path.insert(0, str(REPO / "tools" / "verification"))

from _fingerprint import fingerprint_theorem  # noqa: E402
from _manifest import ManifestError, load_verification  # noqa: E402
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
        if state != REVIEWED:
            defects.append(
                f"§2 claims {theorem}, whose specification review is {state}: {reason}. A "
                f"published claim must be one the owner reviewed in its present form; a "
                f"statement that moved since the record was written has been approved in "
                f"no form that is now on the tree."
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

    claims, gaps, settled, unknown = read_surfaces()
    if not claims:
        print(
            "FAIL: §2 of the security boundary parsed to no claim rows. An unreadable "
            "claim surface must not report as an agreeing one.",
            file=sys.stderr,
        )
        return 1

    found = mapping_defects(roots, claims, gaps, review_states, settled, unknown)
    if found:
        print("claim-surface gate: FAIL", file=sys.stderr)
        for defect in found:
            print(f"  - {defect}", file=sys.stderr)
        return 1
    print(
        f"claim-surface gate: OK — {len(roots)} declared root(s), {len(claims)} published "
        f"claim(s), {len(gaps)} open §4 area(s), {len(settled)} settled, every claimed root "
        f"reviewed at its current fingerprint."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
