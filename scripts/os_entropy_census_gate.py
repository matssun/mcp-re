#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""OS-entropy census gate — `boundary.os_entropy` names exactly the direct acquisition sites.

WHAT THIS PROVES, exactly: the set of production Rust files that name the `getrandom` crate
in code equals the set of files `verification/policy/trust-boundaries.toml` registers under
`boundary.os_entropy`. It fails on either difference:

  1. UNREGISTERED — a production file acquires OS entropy through `getrandom` and the
     boundary does not name it;
  2. GONE — the boundary names a file that no longer acquires.

ASM-0068 states how many acquisition sites the boundary names and requires owner review for
any new one. That count was kept by hand, and a fifth site went into the tree with the
assumption still saying four.

"Production" is the definition `scripts/module_size_gate.py` owns: no `tests/`, `benches/`,
`examples/` or `build.rs`, and no line inside a `#[cfg(test)]`-family region. "In code" is
the definition `scripts/bazel_srcs_gate.py` owns: comments, string literals and character
literals are blanked first, so a doc comment naming `getrandom` is not a site.

WHAT IT DOES NOT PROVE: anything about the quality of the bytes, or about randomness that
reaches the code indirectly — through `SystemNonceSource` or any other wrapper, or through
another crate's dependency on `getrandom`. The boundary's authority is the act of asking the
OS, and its callers through a seam hold none.

Run:  python3 scripts/os_entropy_census_gate.py
      python3 scripts/os_entropy_census_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from bazel_srcs_gate import strip_noncode  # noqa: E402
from module_size_gate import production_source, rust_sources  # noqa: E402

BOUNDARIES = Path("verification") / "policy" / "trust-boundaries.toml"
BOUNDARY_ID = "boundary.os_entropy"
ACQUISITION = re.compile(r"\bgetrandom\b")


def acquisition_sites(root: Path) -> set[str]:
    """Every production Rust file under `root` that names `getrandom` in code."""
    sites: set[str] = set()
    for path in rust_sources(root):
        production = "\n".join(production_source(path.read_text(encoding="utf-8")))
        if ACQUISITION.search(strip_noncode(production)):
            sites.add(path.relative_to(root).as_posix())
    return sites


def registered_sites(root: Path) -> set[str]:
    """The paths `boundary.os_entropy` registers. A missing boundary is an error, not an
    empty registration: an empty set would make every site an UNREGISTERED finding and
    hide the real cause."""
    data = tomllib.loads((root / BOUNDARIES).read_text(encoding="utf-8"))
    for boundary in data.get("boundary", []):
        if boundary.get("id") == BOUNDARY_ID:
            return set(boundary.get("paths", []))
    raise SystemExit(f"os-entropy census gate: {BOUNDARIES} declares no {BOUNDARY_ID}")


def check(root: Path) -> list[str]:
    present, registered = acquisition_sites(root), registered_sites(root)
    if not present:
        return ["no production acquisition site found at all — the scan measured nothing"]
    return ([f"UNREGISTERED: {p} acquires OS entropy and {BOUNDARY_ID} does not name it "
             "(ASM-0068 requires owner review of a new production site)"
             for p in sorted(present - registered)]
            + [f"GONE: {BOUNDARY_ID} names {p}, which no longer acquires OS entropy"
               for p in sorted(registered - present)])


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------

_SITE = "pub fn draw() -> [u8; 4] {\n    let mut b = [0; 4];\n    getrandom::fill(&mut b).ok();\n    b\n}\n"
_TEST_ONLY = "pub fn f() {}\n#[cfg(test)]\nmod tests {\n    fn t() { getrandom::fill(&mut [0]).ok(); }\n}\n"
_COMMENT_ONLY = "//! Draws from the OS through `getrandom`.\npub fn f() -> &'static str { \"getrandom::fill\" }\n"


def _tree(files: dict[str, str], registered: list[str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="os-entropy-census-"))
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    paths = ", ".join(f'"{p}"' for p in registered)
    (root / BOUNDARIES).parent.mkdir(parents=True, exist_ok=True)
    (root / BOUNDARIES).write_text(f'[[boundary]]\nid = "{BOUNDARY_ID}"\npaths = [{paths}]\n',
                                   encoding="utf-8")
    return root


def selftest() -> int:
    base = {"a/src/one.rs": _SITE, "a/src/test_only.rs": _TEST_ONLY,
            "a/src/comment_only.rs": _COMMENT_ONLY, "a/tests/it.rs": _SITE}
    cases = [
        ("the registered set equals the sites: green", base, ["a/src/one.rs"], []),
        ("a new production site the boundary does not name: red",
         {**base, "a/src/two.rs": _SITE}, ["a/src/one.rs"], ["UNREGISTERED: a/src/two.rs"]),
        ("a registered site that no longer acquires: red",
         {**base, "a/src/two.rs": "pub fn f() {}\n"}, ["a/src/one.rs", "a/src/two.rs"],
         ["GONE: boundary.os_entropy names a/src/two.rs"]),
        ("a registered path that is not in the tree at all: red",
         base, ["a/src/one.rs", "a/src/moved.rs"], ["GONE: boundary.os_entropy names a/src/moved.rs"]),
        ("no site anywhere is not a pass", {"a/src/x.rs": "pub fn f() {}\n"}, [],
         ["no production acquisition site found"]),
    ]
    failed = 0
    for name, files, registered, expect in cases:
        got = check(_tree(files, registered))
        ok = (not got) if not expect else (len(got) == len(expect)
                                           and all(any(e in g for g in got) for e in expect))
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else f" — got {got}"))
        failed += not ok
    if failed:
        print(f"os-entropy census gate selftest: FAIL ({failed} case(s))")
        return 1
    print("os-entropy census gate selftest: PASS (test regions, comments, strings and tests/ "
          "are not sites; an unregistered site and a gone registration each go red)")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    problems = check(REPO)
    for p in problems:
        print(p)
    if problems:
        print(f"os-entropy census gate: FAIL ({len(problems)})")
        return 1
    print(f"os-entropy census gate: PASS — {BOUNDARY_ID} names exactly the "
          f"{len(registered_sites(REPO))} production acquisition sites")
    return 0


if __name__ == "__main__":
    sys.exit(main())
