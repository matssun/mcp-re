#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Conformance-claims gate — an advertised category has a corpus AND a harness.

WHAT THIS PROVES, exactly: every row of the category table in
`docs/conformance-guide.md` names (a) a corpus directory that exists and carries a
`manifest.json`, and (b) at least one Bazel test target that a `BUILD.bazel`
declares as an `nt_rust_test` AND whose declaration reaches that corpus through
`data`. It also proves the reverse containment — every top-level corpus under
`mcp-re-conformance/tests/vectors/` appears as a row — and that any corpus whose
manifest publishes a `corpus_digest` has some reaching harness that recomputes it.

WHAT IT DOES NOT PROVE: that the harness makes good use of the corpus, that the
vectors specify the right behaviour, or that a passing run means the profile is
correctly implemented. It proves the two edges exist, not their quality.

WHY IT MATTERS. Conformance is executable evidence, not documentation. A category
advertised with no harness underneath it is a claim with no witness, and it reads
to an operator — or an auditor — exactly like a category that is proven. The
failure mode is silent in both directions and neither is self-announcing:

  - a corpus with no harness is never executed, so nothing goes red when the
    behaviour it specifies regresses or is removed entirely;
  - a documented category whose corpus, generator, and harness were all deleted
    keeps advertising coverage that no longer exists anywhere in the tree.

A published `corpus_digest` that no test recomputes is the same failure one level
down: as `corpus_pinning_test` puts it, a manifest carrying hashes nobody checks
is worse than no hashes, because it reads as a guarantee.

Run:  python3 scripts/conformance_claims_gate.py
      python3 scripts/conformance_claims_gate.py --selftest
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

GUIDE = "docs/conformance-guide.md"
VECTORS_ROOT = "mcp-re-conformance/tests/vectors"

# The table is delimited so prose may name a corpus or a target freely; only rows
# between the markers are claims this gate reads.
BEGIN = "<!-- conformance-categories:begin -->"
END = "<!-- conformance-categories:end -->"

# `| HTTP profile | `a/b/` | `//pkg:t`, `//pkg:u` |`
ROW = re.compile(r"^\|(?P<cells>.+)\|\s*$")
BACKTICKED = re.compile(r"`([^`]+)`")

# `nt_rust_test(\n    name = "x",\n    ...\n)` — declarations are top-level, so the
# block ends at the first `)` in column 0.
TEST_BLOCK = re.compile(r"nt_rust_test\((?P<body>.*?)\n\)", re.S)
TARGET_NAME = re.compile(r'name = "([^"]+)"')
SRCS_ENTRY = re.compile(r'"([^"]+\.rs)"')


def reaches(body: str, corpus_name: str) -> bool:
    """`true` iff a declaration's text names this corpus as a path.

    Matching the bare directory name would also match the target's own `name`
    field, which is how a harness that never sees the corpus would pass.
    """
    return re.search(rf"vectors/{re.escape(corpus_name)}\b", body) is not None


def recomputes_digest(package: Path, body: str) -> bool:
    """`true` iff a declaration's own sources mention `corpus_digest`.

    Which harness carries the pin is not fixed: two corpora are pinned by the
    shared `corpus_pinning_test`, a third by its own vector runner. What matters
    is that some test reaching the corpus recomputes the published digest.
    """
    for src in SRCS_ENTRY.findall(body):
        path = package / src
        if path.is_file() and "corpus_digest" in path.read_text(encoding="utf-8"):
            return True
    return False


def parse_rows(guide_text: str) -> tuple[list[tuple[str, str, list[str]]], list[str]]:
    """Return (rows, failures). A row is (category, corpus, [targets])."""
    if guide_text.count(BEGIN) != 1 or guide_text.count(END) != 1:
        return [], [
            f"{GUIDE}: expected exactly one {BEGIN} / {END} pair delimiting the "
            "category table"
        ]
    body = guide_text.split(BEGIN, 1)[1].split(END, 1)[0]
    rows: list[tuple[str, str, list[str]]] = []
    for line in body.splitlines():
        match = ROW.match(line.strip())
        if not match:
            continue
        cells = [c.strip() for c in match.group("cells").split("|")]
        if len(cells) != 3 or set(cells[0]) <= {"-", " ", ":"}:
            continue  # header separator, or a shape this gate does not read
        category, corpus_cell, harness_cell = cells
        if category.lower().startswith("category"):
            continue  # header row
        corpus = BACKTICKED.findall(corpus_cell)
        targets = BACKTICKED.findall(harness_cell)
        if len(corpus) != 1:
            return rows, [
                f"{GUIDE}: row {category!r} must name exactly one backticked corpus "
                f"path, found {corpus}"
            ]
        rows.append((category, corpus[0].rstrip("/"), targets))
    if not rows:
        return [], [f"{GUIDE}: the category table has no rows — refusing to pass"]
    return rows, []


def declared_tests(root: Path) -> dict[str, tuple[Path, str]]:
    """Map `//pkg:target` to (package directory, declaration text)."""
    found: dict[str, tuple[Path, str]] = {}
    for build in sorted(root.glob("*/BUILD.bazel")):
        package = build.parent
        for block in TEST_BLOCK.finditer(build.read_text(encoding="utf-8")):
            body = block.group("body")
            name = TARGET_NAME.search(body)
            if name:
                found[f"//{package.name}:{name.group(1)}"] = (package, body)
    return found


def check(root: Path) -> list[str]:
    guide = root / GUIDE
    if not guide.is_file():
        return [f"{GUIDE}: not found"]
    rows, failures = parse_rows(guide.read_text(encoding="utf-8"))
    if failures:
        return failures

    tests = declared_tests(root)
    advertised: set[str] = set()

    for category, corpus, targets in rows:
        corpus_dir = root / corpus
        manifest = corpus_dir / "manifest.json"
        if not corpus_dir.is_dir():
            failures.append(f"{category!r}: corpus directory '{corpus}' does not exist")
            continue
        if not manifest.is_file():
            failures.append(f"{category!r}: corpus '{corpus}' has no manifest.json")
            continue
        advertised.add(corpus_dir.name)

        if not targets:
            failures.append(f"{category!r}: names no harness target")
            continue

        reaching = []
        for target in targets:
            declaration = tests.get(target)
            if declaration is None:
                failures.append(
                    f"{category!r}: harness {target} is not declared as an "
                    "nt_rust_test in any BUILD.bazel"
                )
                continue
            if reaches(declaration[1], corpus_dir.name):
                reaching.append(target)
        if not reaching:
            failures.append(
                f"{category!r}: no declared harness reaches '{corpus}' through data — "
                "a target that never sees the corpus does not execute it"
            )

        digest = json.loads(manifest.read_text(encoding="utf-8")).get("corpus_digest")
        if digest is not None and not any(
            recomputes_digest(*tests[t]) for t in reaching
        ):
            failures.append(
                f"{category!r}: manifest.json publishes a corpus_digest that no "
                "harness reaching this corpus recomputes — a hash nobody checks "
                "reads as a guarantee"
            )

    vectors_root = root / VECTORS_ROOT
    if vectors_root.is_dir():
        for child in sorted(vectors_root.iterdir()):
            if not (child / "manifest.json").is_file():
                continue
            if child.name not in advertised:
                failures.append(
                    f"{VECTORS_ROOT}/{child.name}: a corpus with a manifest that the "
                    "guide's category table does not advertise — add a row, or remove "
                    "the corpus if nothing claims it"
                )
    return failures


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _guide(rows: str) -> str:
    return f"prose\n\n{BEGIN}\n\n| Category | Corpus | Harness targets |\n| --- | --- | --- |\n{rows}\n{END}\n"


def _build(*blocks: str) -> str:
    return "\n".join(f"nt_rust_test(\n{b}\n)" for b in blocks)


def selftest() -> int:
    failed = False
    cases: list[tuple[str, str, str, str, str]] = [
        (
            "a category with a corpus and a reaching harness passes",
            _guide("| Alpha | `mcp-re-conformance/tests/vectors/alpha/` | `//mcp-re-conformance:alpha_test` |"),
            _build('    name = "alpha_test",\n    data = glob(["tests/vectors/alpha/**"]),'),
            '{"fixtures": []}',
            "",
        ),
        (
            "a category whose corpus does not exist",
            _guide("| Alpha | `mcp-re-conformance/tests/vectors/ghost/` | `//mcp-re-conformance:alpha_test` |"),
            _build('    name = "alpha_test",\n    data = glob(["tests/vectors/alpha/**"]),'),
            '{"fixtures": []}',
            "does not exist",
        ),
        (
            "a category whose harness is not a declared target",
            _guide("| Alpha | `mcp-re-conformance/tests/vectors/alpha/` | `//mcp-re-conformance:ghost_test` |"),
            _build('    name = "alpha_test",\n    data = glob(["tests/vectors/alpha/**"]),'),
            '{"fixtures": []}',
            "is not declared",
        ),
        (
            "a declared harness that never reaches the corpus",
            _guide("| Alpha | `mcp-re-conformance/tests/vectors/alpha/` | `//mcp-re-conformance:alpha_test` |"),
            _build('    name = "alpha_test",\n    data = glob(["tests/vectors/other/**"]),'),
            '{"fixtures": []}',
            "does not execute it",
        ),
        (
            "a published corpus_digest no reaching harness recomputes",
            _guide("| Alpha | `mcp-re-conformance/tests/vectors/alpha/` | `//mcp-re-conformance:alpha_test` |"),
            _build(
                '    name = "alpha_test",\n    srcs = ["tests/alpha_test.rs"],\n'
                '    data = glob(["tests/vectors/alpha/**"]),'
            ),
            '{"fixtures": [], "corpus_digest": "deadbeef"}',
            "reads as a guarantee",
        ),
        (
            "a published corpus_digest a reaching harness does recompute",
            _guide("| Alpha | `mcp-re-conformance/tests/vectors/alpha/` | `//mcp-re-conformance:alpha_test` |"),
            _build(
                '    name = "alpha_test",\n    srcs = ["tests/pinning_test.rs"],\n'
                '    data = glob(["tests/vectors/alpha/**"]),'
            ),
            '{"fixtures": [], "corpus_digest": "deadbeef"}',
            "",
        ),
        (
            "a corpus the table does not advertise",
            _guide("| Alpha | `mcp-re-conformance/tests/vectors/alpha/` | `//mcp-re-conformance:alpha_test` |"),
            _build('    name = "alpha_test",\n    data = glob(["tests/vectors/alpha/**"]),'),
            '{"fixtures": []}',
            "does not advertise",
        ),
        (
            "an empty table is refused rather than passed",
            f"prose\n\n{BEGIN}\n\n{END}\n",
            _build('    name = "alpha_test",\n    data = glob(["tests/vectors/alpha/**"]),'),
            '{"fixtures": []}',
            "no rows",
        ),
    ]

    for label, guide, build, manifest, expected in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, GUIDE, guide)
            _write(root, "mcp-re-conformance/BUILD.bazel", build)
            _write(root, f"{VECTORS_ROOT}/alpha/manifest.json", manifest)
            _write(root, "mcp-re-conformance/tests/alpha_test.rs", "fn t() {}\n")
            _write(
                root,
                "mcp-re-conformance/tests/pinning_test.rs",
                'assert_eq!(corpus_digest(&m.fixtures), m.corpus_digest);\n',
            )
            if "does not advertise" in expected:
                _write(root, f"{VECTORS_ROOT}/unlisted/manifest.json", '{"fixtures": []}')
            failures = check(root)
            ok = not failures if not expected else any(expected in f for f in failures)
            print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
            if not ok:
                failed = True
                print(f"        got {failures}")

    if failed:
        print("conformance-claims gate: SELFTEST FAILED")
        return 1
    print("conformance-claims gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    failures = check(REPO)
    if failures:
        print("conformance-claims gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    rows, _ = parse_rows((REPO / GUIDE).read_text(encoding="utf-8"))
    print(
        f"conformance-claims gate: OK — {len(rows)} advertised categories, each with a "
        "corpus and a harness that reaches it"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
