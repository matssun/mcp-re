#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The audit scalar's format-control table is exactly Unicode General_Category `Cf`.

`mcp-re-proxy/src/audit_record/scalar.rs::is_render_hazard` refuses every format control
(THM-0130: "no bidi or format control"), and the set it refuses is the `FORMAT_CONTROLS` range
table in that file. A table typed by hand is a list that can fall behind the standard or be
narrowed by an edit, and a narrowed table leaves every test green that does not name the
dropped codepoint. This gate regenerates the ranges from the interpreter's `unicodedata` and
fails when the Rust table differs, in either direction.

The table states the Unicode version it was generated for. An interpreter that ships another
version cannot say whether the table is right, so that is a failure rather than a pass:
regenerate under the interpreter the repository pins (`python-version` in ci.yml).

    python3 scripts/format_control_table_gate.py
    python3 scripts/format_control_table_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCALAR = REPO / "mcp-re-proxy" / "src" / "audit_record" / "scalar.rs"

_VERSION = re.compile(r"Unicode (\d+\.\d+\.\d+) General_Category `Cf`")
_TABLE = re.compile(
    r"const FORMAT_CONTROLS: &\[\(u32, u32\)\] = &\[\n(?P<rows>.*?)\n\];", re.DOTALL
)
_ROW = re.compile(r"^\s*\(0x([0-9A-Fa-f]+), 0x([0-9A-Fa-f]+)\),$")


def generated_ranges() -> list[tuple[int, int]]:
    """Maximal inclusive runs of `Cf` codepoints, from this interpreter's `unicodedata`."""
    ranges: list[tuple[int, int]] = []
    start: int | None = None
    for code in range(0x110000):
        is_cf = unicodedata.category(chr(code)) == "Cf"
        if is_cf and start is None:
            start = code
        elif not is_cf and start is not None:
            ranges.append((start, code - 1))
            start = None
    if start is not None:
        ranges.append((start, 0x10FFFF))
    return ranges


def check(source: str) -> list[str]:
    """Every way `source` (the text of scalar.rs) disagrees with the generated table."""
    version = _VERSION.search(source)
    if version is None:
        return ["scalar.rs does not state the Unicode version of FORMAT_CONTROLS"]
    table = _TABLE.search(source)
    if table is None:
        return ["scalar.rs has no `const FORMAT_CONTROLS: &[(u32, u32)]` table"]
    declared: list[tuple[int, int]] = []
    for line in table.group("rows").splitlines():
        row = _ROW.match(line)
        if row is None:
            return [f"unreadable FORMAT_CONTROLS row: {line!r}"]
        declared.append((int(row.group(1), 16), int(row.group(2), 16)))
    problems: list[str] = []
    if unicodedata.unidata_version != version.group(1):
        problems.append(
            f"the table is for Unicode {version.group(1)} and this interpreter ships "
            f"{unicodedata.unidata_version}: run the gate under the pinned interpreter or "
            f"regenerate the table"
        )
        return problems
    expected = generated_ranges()
    if declared != expected:
        missing = sorted(set(expected) - set(declared))
        extra = sorted(set(declared) - set(expected))
        problems.append(
            "FORMAT_CONTROLS is not Unicode "
            f"{unicodedata.unidata_version} Cf: missing ranges {missing}, extra ranges {extra}"
        )
    return problems


def selftest() -> int:
    """The gate must catch a narrowed table, an extra range and a missing version."""
    source = SCALAR.read_text()
    if check(source):
        print("selftest: the committed table must pass before it can be mutated")
        return 1
    table = _TABLE.search(source)
    assert table is not None
    rows = table.group("rows").splitlines()
    mutations = {
        "a deleted range": source.replace(rows[1] + "\n", "", 1),
        "a narrowed range": source.replace(rows[0], "    (0x00AD, 0x00AC),", 1),
        "an extra range": source.replace(rows[0], rows[0] + "\n    (0x0041, 0x0041),", 1),
        "no version": _VERSION.sub("General_Category `Cf`", source),
    }
    failed = 0
    for name, text in mutations.items():
        if text == source or not check(text):
            print(f"selftest FAIL: {name} was not detected")
            failed += 1
    with tempfile.TemporaryDirectory() as scratch:
        (Path(scratch) / "scalar.rs").write_text(mutations["a deleted range"])
        if not check((Path(scratch) / "scalar.rs").read_text()):
            print("selftest FAIL: the mutated scratch copy passed")
            failed += 1
    if failed:
        return 1
    print("format-control table gate selftest: OK (4 mutations detected)")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    problems = check(SCALAR.read_text())
    if problems:
        for problem in problems:
            print(f"format-control table gate: FAIL — {problem}")
        return 1
    print(
        f"format-control table gate: OK — FORMAT_CONTROLS equals Unicode "
        f"{unicodedata.unidata_version} Cf ({len(generated_ranges())} ranges)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
