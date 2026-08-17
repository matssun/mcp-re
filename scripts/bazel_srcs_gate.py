#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bazel srcs gate — a hand-listed `srcs` must match the crate's module tree.

Every crate but one lets Bazel `glob(["src/**/*.rs"])`, which cannot drift from what
cargo compiles. `mcp-re-proxy` hand-lists its sources (`_PROXY_LIB_SRCS`) because
three library flavors share the list, and a hand-list drifts: `src/audit_sink.rs`
landed with the ADR-MCPS-035 audit surface and was never added, so cargo built a
module Bazel could not find and every Bazel target downstream of the proxy library
failed with E0583.

The existing semantic-drift gate compares TARGETS, not sources, so it passed. The
only thing that caught this was a full `bazel test //...` — 30+ minutes, and per its
own commit message it "had never once completed during this audit", which is exactly
how the miss survived several rounds of review.

This is that check at one second. For every crate whose library sources are hand
listed, it walks the module tree from `lib.rs` and requires that each declared
module's declaration file appears in the list, and that each listed file exists.

Three properties are load-bearing, because each one had a silent-blindness failure
mode:

- **Only a glob over `src/` exempts a crate.** A crate is exempt when its library
  sources cannot drift, not when the word `glob` occurs somewhere in its BUILD file.
  `mcp-re-proxy` globs its integration-test sources while hand-listing its library.
- **Both module forms are walked.** `mod cli;` resolves to `src/cli.rs` OR to
  `src/cli/mod.rs`, and in either form the modules IT declares live under `src/cli/`.
  A walk that stops at a resolved file observes nothing after the first
  file-to-directory split, which is precisely when a hand-list starts to drift.
- **Declarations are read from code only.** A `mod` written inside a comment or a
  string literal compiles nothing and needs no `srcs` entry.

Run:  python3 scripts/bazel_srcs_gate.py
      python3 scripts/bazel_srcs_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

MOD_DECL = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+([a-z0-9_]+)[ \t]*;", re.M)
SRC_ENTRY = re.compile(r'"(src/[A-Za-z0-9_/]+\.rs)"')
# A glob that reaches into `src/` — the only construct that makes a library's source
# list undriftable. A glob over `tests/` says nothing about `src/`.
SRC_GLOB = re.compile(r'glob\(\s*\[[^]]*"src/')

IDENT = re.compile(r"[A-Za-z0-9_]")


def strip_noncode(text: str) -> str:
    """`text` with comments, string literals and char literals blanked out.

    Line structure is preserved, so a finding still names the line it came from.
    The gate's claim is about what rustc compiles, and rustc compiles neither the
    `mod` in a doc comment nor the one inside a fixture string — counting either
    would demand a `srcs` entry for a file that nothing needs.
    """
    out: list[str] = []
    i, n = 0, len(text)

    def blank(upto: int) -> None:
        nonlocal i
        out.extend("\n" if ch == "\n" else " " for ch in text[i:upto])
        i = upto

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            blank(n if j < 0 else j)
        elif c == "/" and nxt == "*":
            # Rust block comments nest.
            depth, j = 0, i
            while j < n:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    j += 1
            blank(j)
        elif c == '"' or (c == "r" and _raw_string_here(text, i)):
            blank(_string_end(text, i))
        elif c == "'":
            blank(_char_literal_end(text, i))
        else:
            out.append(c)
            i += 1

    return "".join(out)


def _raw_string_here(text: str, i: int) -> bool:
    """True when the `r` at `i` opens a raw string rather than ending an identifier."""
    if i and IDENT.match(text[i - 1]) and not (text[i - 1] == "b" and (i < 2 or not IDENT.match(text[i - 2]))):
        return False
    j = i + 1
    while j < len(text) and text[j] == "#":
        j += 1
    return j < len(text) and text[j] == '"'


def _string_end(text: str, i: int) -> int:
    """Index one past the string literal starting at `i`."""
    n = len(text)
    if text[i] == "r":
        j = i + 1
        hashes = 0
        while j < n and text[j] == "#":
            hashes += 1
            j += 1
        close = '"' + "#" * hashes
        end = text.find(close, j + 1)
        return n if end < 0 else end + len(close)
    j = i + 1
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == '"':
            return j + 1
        j += 1
    return n


def _char_literal_end(text: str, i: int) -> int:
    """Index one past a char literal at `i`; `i + 1` when it is a lifetime.

    Only a char literal can hide a quote (`'"'`), which is the whole reason this
    distinction is drawn.
    """
    if text.startswith("'\\", i):
        j = text.find("'", i + 2)
        return i + 1 if j < 0 else j + 1
    if i + 2 < len(text) and text[i + 2] == "'":
        return i + 3
    return i + 1


def declared_mods(file: Path) -> list[str]:
    """The module names a Rust file declares in code, deduplicated and sorted."""
    return sorted(set(MOD_DECL.findall(strip_noncode(file.read_text(errors="replace")))))


def check_module_tree(
    crate: Path, rel_dir: str, decl_rel: str, listed: set[str], seen: set[str]
) -> list[str]:
    """Findings for every module `decl_rel` declares, recursively.

    RECURSIVE because a hand-list is flat but a module tree is not. `mod
    config_state;` resolves to a directory whose submodules are hand-listed one by
    one, so a new `src/config_state/foo.rs` is exactly as invisible to Bazel as a
    new `src/foo.rs`.

    A module is resolved the way rustc resolves it — `src/<rel>.rs` first, then
    `src/<rel>/mod.rs` — and the walk continues into whichever file won, with the
    children looked for under `src/<rel>/`. Both forms therefore behave the same
    here, which is what keeps the gate observing a module across the split that
    turns one file into a directory.
    """
    findings: list[str] = []

    for mod in declared_mods(crate / decl_rel):
        rel = f"{rel_dir}/{mod}" if rel_dir else mod
        if rel in seen:
            continue
        seen.add(rel)

        file_form, dir_form = f"src/{rel}.rs", f"src/{rel}/mod.rs"
        if (crate / file_form).is_file():
            child = file_form
        elif (crate / dir_form).is_file():
            child = dir_form
        else:
            findings.append(
                f"{crate.name}: `mod {mod};` in {decl_rel} resolves to neither "
                f"{file_form} nor {dir_form} — cargo cannot compile it either"
            )
            continue

        if child not in listed:
            findings.append(
                f"{crate.name}/BUILD.bazel: `mod {mod};` in {decl_rel} needs {child} "
                f"in the hand-listed srcs — cargo compiles it, Bazel cannot find it "
                f"(E0583)"
            )

        # Descend even when the parent is unlisted: one run should name every
        # missing entry, not one per re-run.
        findings.extend(check_module_tree(crate, rel, child, listed, seen))

    return findings


def check_crate(crate: Path) -> list[str]:
    """Findings for one crate. Empty when the library globs or the list is complete."""
    build, lib = crate / "BUILD.bazel", crate / "src" / "lib.rs"
    if not build.is_file() or not lib.is_file():
        return []
    build_text = build.read_text(errors="replace")
    if SRC_GLOB.search(build_text):
        return []  # cannot drift

    listed = set(SRC_ENTRY.findall(build_text))
    if not listed:
        return []  # nothing hand-listed to check

    findings: list[str] = []
    if "src/lib.rs" not in listed:
        findings.append(
            f"{crate.name}/BUILD.bazel: hand-lists sources without src/lib.rs — "
            f"the crate root itself is missing"
        )
    findings.extend(check_module_tree(crate, "", "src/lib.rs", listed, set()))

    for entry in sorted(listed):
        if not (crate / entry).is_file():
            findings.append(
                f"{crate.name}/BUILD.bazel: lists {entry}, which does not exist"
            )
    return findings


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for crate in sorted(root.glob("mcp-re-*")):
        if crate.is_dir():
            findings.extend(check_crate(crate))
    return findings


def checked_crates(root: Path) -> list[str]:
    """The crates this gate actually examines — what a green run measured."""
    names = []
    for crate in sorted(root.glob("mcp-re-*")):
        build, lib = crate / "BUILD.bazel", crate / "src" / "lib.rs"
        if not crate.is_dir() or not build.is_file() or not lib.is_file():
            continue
        text = build.read_text(errors="replace")
        if SRC_GLOB.search(text) or not SRC_ENTRY.search(text):
            continue
        names.append(crate.name)
    return names


def selftest() -> int:  # noqa: C901 — a control per property, each one named
    def case(name: str, build: str, files: dict[str, str], expect: str | None) -> bool:
        """Build a crate, scan it, and compare against one expected finding.

        `expect` is a substring the single finding must contain, or None for
        "this tree is correct and must produce nothing".
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate = root / "mcp-re-thing"
            (crate / "src").mkdir(parents=True)
            for rel, content in files.items():
                path = crate / "src" / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            (crate / "BUILD.bazel").write_text(build)
            found = scan(root)
        if expect is None:
            if found:
                print(f"SELFTEST FAILED [{name}]: expected nothing, got {found}")
                return False
            return True
        if len(found) != 1 or expect not in found[0]:
            print(f"SELFTEST FAILED [{name}]: expected one finding containing "
                  f"{expect!r}, got {found}")
            return False
        return True

    LIB = "pub mod alpha;\npub mod beta;\n"
    ok = True

    # --- file modules -----------------------------------------------------------
    ok &= case(
        "file module, complete",
        'srcs = ["src/lib.rs", "src/alpha.rs", "src/beta.rs"]\n',
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        None,
    )
    ok &= case(
        "file module, one missing — the defect that shipped",
        'srcs = ["src/lib.rs", "src/alpha.rs"]\n',
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )

    # --- directory modules, mod.rs form -----------------------------------------
    MODRS = {"lib.rs": LIB, "alpha/mod.rs": "pub mod deep;\n", "alpha/deep.rs": "",
             "beta.rs": ""}
    ok &= case(
        "directory module (mod.rs), complete",
        'srcs = ["src/lib.rs", "src/alpha/mod.rs", "src/alpha/deep.rs", '
        '"src/beta.rs"]\n',
        MODRS,
        None,
    )
    ok &= case(
        "directory module (mod.rs), child unlisted",
        'srcs = ["src/lib.rs", "src/alpha/mod.rs", "src/beta.rs"]\n',
        MODRS,
        "mod deep",
    )
    ok &= case(
        "directory module (mod.rs), the mod.rs itself unlisted",
        'srcs = ["src/lib.rs", "src/alpha/deep.rs", "src/beta.rs"]\n',
        MODRS,
        "needs src/alpha/mod.rs",
    )

    # --- directory modules, the form a file-to-directory split actually takes ----
    # `src/alpha.rs` stays put and gains `src/alpha/`. A walk that treats a resolved
    # file as a leaf sees nothing under it, so this is the shape that would go blind
    # the moment cli.rs starts to split.
    SPLIT = {"lib.rs": LIB, "alpha.rs": "pub mod deep;\n", "alpha/deep.rs": "",
             "beta.rs": ""}
    ok &= case(
        "directory module (2018 form), complete",
        'srcs = ["src/lib.rs", "src/alpha.rs", "src/alpha/deep.rs", "src/beta.rs"]\n',
        SPLIT,
        None,
    )
    ok &= case(
        "directory module (2018 form), child unlisted",
        'srcs = ["src/lib.rs", "src/alpha.rs", "src/beta.rs"]\n',
        SPLIT,
        "mod deep",
    )
    ok &= case(
        "directory module (2018 form), grandchild unlisted",
        'srcs = ["src/lib.rs", "src/alpha.rs", "src/alpha/deep.rs", "src/beta.rs"]\n',
        {**SPLIT, "alpha/deep.rs": "pub mod deeper;\n", "alpha/deep/deeper.rs": ""},
        "mod deeper",
    )

    # --- what counts as a declaration -------------------------------------------
    ok &= case(
        "a mod inside a line comment declares nothing",
        'srcs = ["src/lib.rs", "src/alpha.rs", "src/beta.rs"]\n',
        {"lib.rs": LIB + "// mod ghost;\n", "alpha.rs": "", "beta.rs": ""},
        None,
    )
    ok &= case(
        "a mod inside a nested block comment declares nothing",
        'srcs = ["src/lib.rs", "src/alpha.rs", "src/beta.rs"]\n',
        {"lib.rs": LIB + "/* outer /* inner */\nmod ghost;\n*/\n", "alpha.rs": "",
         "beta.rs": ""},
        None,
    )
    ok &= case(
        "a mod inside a raw string declares nothing",
        'srcs = ["src/lib.rs", "src/alpha.rs", "src/beta.rs"]\n',
        {"lib.rs": LIB + 'const F: &str = r#"\nmod ghost;\n"#;\n', "alpha.rs": "",
         "beta.rs": ""},
        None,
    )
    ok &= case(
        "a quote inside a char literal does not swallow the file",
        'srcs = ["src/lib.rs", "src/alpha.rs"]\n',
        {"lib.rs": "pub mod alpha;\nconst Q: char = '\"';\npub mod beta;\n",
         "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )

    # --- exemption and staleness ------------------------------------------------
    ok &= case(
        "a glob over src/ is exempt",
        'srcs = glob(["src/**/*.rs"]),\n',
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        None,
    )
    ok &= case(
        "a glob over tests/ does NOT exempt a hand-listed library",
        'srcs = ["src/lib.rs", "src/alpha.rs"]\n'
        'test_srcs = glob(["tests/integration/*.rs"]) + ["src/lib.rs"]\n',
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "mod beta",
    )
    ok &= case(
        "a listed file that does not exist",
        'srcs = ["src/lib.rs", "src/alpha.rs", "src/beta.rs", "src/gone.rs"]\n',
        {"lib.rs": LIB, "alpha.rs": "", "beta.rs": ""},
        "does not exist",
    )
    ok &= case(
        "a mod that resolves to no file at all",
        'srcs = ["src/lib.rs", "src/alpha.rs"]\n',
        {"lib.rs": "pub mod alpha;\npub mod nowhere;\n", "alpha.rs": ""},
        "resolves to neither",
    )

    if not ok:
        return 1
    print("bazel srcs gate selftest: PASS")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    crates = checked_crates(REPO)
    findings = scan(REPO)
    if findings:
        print("bazel srcs gate: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nA hand-listed srcs drifts silently: cargo globs the directory, Bazel "
            "does not. Add the file to the list.",
            file=sys.stderr,
        )
        return 1
    if not crates:
        print(
            "bazel srcs gate: FAIL — no crate hand-lists its library sources, so this "
            "gate checked nothing. Either the hand-list moved or the exemption rule "
            "is wrong; a pass here would be vacuous.",
            file=sys.stderr,
        )
        return 1
    print(
        f"bazel srcs gate: OK — module tree matches the hand-listed srcs in "
        f"{', '.join(crates)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
