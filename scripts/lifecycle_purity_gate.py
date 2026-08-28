#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lifecycle-purity gate — the state machines that are values depend on no production module.

WHAT THIS PROVES, exactly: in the production half of each module named in `TARGETS`
(every line outside a `#[cfg(test)]`-family region — NOT everything above the first one,
which discards production items below a test module), every path root and every `use` target
resolves either inside the module itself or to an explicitly allowed standard-library
path. It computes the module's external dependency set and asserts it is empty of
production modules.

WHAT IT DOES NOT PROVE: that the lifecycle is semantically pure. A future edit could take
a closure argument, read a `static`, or call a function handed in from outside, and none
of those would be seen here. Keeping the contract narrow is deliberate — overstating a
gate is worse than not having one, because the overstatement is what stops people looking.

## The property, and the two syntactic proxies it is not

The first version of this gate asserted "contains no `use` declaration". That is a
syntactic correlate of the property, not the property, and it was wrong twice within an
hour:

  * `use RuntimeEvent as E;` renames a type the file itself declares, so the transition
    match can fit the 110-pair table on a screen. It names nothing outside. The gate
    rejected it.
  * `impl std::fmt::Display for InvalidTransition` uses no `use` at all, so a `use`-based
    check saw nothing — while the module does in fact reach for the standard library.

Both directions wrong, from the same mistake: measuring the spelling instead of the
proposition. So this gate computes the dependency SET and reports what is in it.

## Why `std::fmt` is allowed and the rest of `std` is not

Formatting traits cannot introduce state, behaviour, or a decision. `std::sync::Mutex`
could. The allowlist is therefore per-path and short, and extending it is a deliberate
edit here with a reason attached — not something a new import does silently.

## WHY the property matters

ADR-MCPRE-059 Phase 2 considered extracting this module into its own pure crate so Verus
could verify it at crate granularity, and rejected it: the crate would have ~212
production lines and three consumers, all sibling modules in `mcp-re-proxy`, modelling
states that describe that same program. Reasoning in
`verification/baseline/phase2-pilot-boundary-decision.md`.

But the extraction was reaching for something real, and this gate is that something
without the crate:

    The lifecycle relation is a value. It depends on no production module, so it cannot
    acquire behaviour, and "is this transition legal?" cannot answer differently on two
    calls with the same arguments.

That is what `FleetDrained` and the terminal latches mean. A lifecycle able to consult the
outside world would be able to answer the same question two ways.

Run:  python3 scripts/lifecycle_purity_gate.py
      python3 scripts/lifecycle_purity_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The state machines that are values. Each depends on no production module, so "is this
#: transition legal?" cannot answer differently on two calls with the same arguments.
TARGETS = (
    REPO_ROOT / "mcp-re-proxy" / "src" / "runtime_state.rs",
    REPO_ROOT / "mcp-re-proxy" / "src" / "exchange_state.rs",
)

#: Opens a test region. Tests legitimately `use super::*`.
#:
#: Both `#[cfg(test)]` and `#[cfg(all(test, ...))]` open one, and a region CLOSES with the
#: item its attribute introduces — the same definition `scripts/module_size_gate.py` uses.
#: Truncating at the first marker instead would state "test code begins here and never
#: ends", which Rust does not say: an inline `#[cfg(test)]` helper may sit far above the
#: test module, and production items may follow it.
TEST_ATTR = re.compile(r"^#\[cfg\((all\()?test\b")

#: Standard-library paths the relation may depend on, each with the reason it cannot
#: introduce behaviour. Adding an entry is a deliberate edit, which is the point.
ALLOWED_STD_PATHS = {
    # Rendering `InvalidTransition` for an error message. Formatting traits carry no
    # state and make no decision.
    "std::fmt",
}

#: A `use` declaration anywhere on a line, including `pub use` and one inside a body.
USE_DECL = re.compile(r"(?:^\s*|[{;]\s*)(?:pub(?:\s*\([^)]*\))?\s+)?use\s+(?P<path>[^;]+);")

#: A name this file declares. Types and enum variants both matter: the transition match
#: writes `RuntimeState::Configured`, so `RuntimeState` must count as local.
LOCAL_DECL = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:enum|struct|type|trait)\s+(?P<name>\w+)"
)

#: The root segment of any `::`-qualified path.
PATH_ROOT = re.compile(r"(?<![:\w])(?P<root>\w+)::")


def production_half(text: str) -> list[tuple[int, str]]:
    """Every line outside a test region, 1-indexed, comments and blanks dropped.

    Comments are dropped because the module's doc comments reference `crate::app` in prose
    and rustdoc links. The gate is about code.

    A test region runs from its `#[cfg(test)]`-family attribute to the end of the item that
    attribute introduces, tracked by brace depth, and counting RESUMES afterwards. A file
    may contain several. This is the definition, not "lines before the first test module":
    that rule reports a clean pass over every production item written below the tests.
    """
    raw = text.splitlines()
    lines: list[tuple[int, str]] = []
    i = 0
    while i < len(raw):
        if TEST_ATTR.match(raw[i].lstrip()):
            i = _end_of_test_region(raw, i)
            continue
        number, line = i + 1, raw[i]
        i += 1
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        code = line.split("//", 1)[0]
        if code.strip():
            lines.append((number, code))
    return lines


def _end_of_test_region(lines: list[str], start: int) -> int:
    """The index just past the region opened at `start`.

    A braced item ends at its matching close; an attributed `;`-terminated item — the
    `#[cfg(test)] use super::*;` form — ends at that semicolon.
    """
    depth, opened, i = 0, False, start
    while i < len(lines):
        code = re.sub(r"//.*", "", re.sub(r'"(?:\\.|[^"\\])*"', '""', lines[i]))
        depth += code.count("{") - code.count("}")
        if "{" in code:
            opened = True
        i += 1
        if opened and depth <= 0:
            return i
        if not opened and code.rstrip().endswith(";"):
            return i
    return i


def local_names(text: str, body: list[tuple[int, str]]) -> set[str]:
    """Names that resolve inside this module: declared types, plus self-alias targets.

    `use RuntimeEvent as E;` makes `E` local, because `RuntimeEvent` is local. An alias of
    something non-local is not: it is an import wearing a short name, which is exactly the
    case a spelling-based check would wave through.
    """
    names = {
        match.group("name")
        for line in text.splitlines()
        if (match := LOCAL_DECL.match(line))
    }
    # Fixed point: an alias chain (A as B, B as C) stays local only if it starts local.
    changed = True
    while changed:
        changed = False
        for _, code in body:
            for match in USE_DECL.finditer(code):
                path = match.group("path").strip()
                if " as " not in path:
                    continue
                source, alias = (part.strip() for part in path.split(" as ", 1))
                if "::" not in source and source in names and alias not in names:
                    names.add(alias)
                    changed = True
    return names


def external_dependencies(text: str) -> list[str]:
    """Every module-external name the production half depends on, as `line: what`.

    Empty list means the relation depends on nothing outside itself but the allowed
    standard-library paths.
    """
    body = production_half(text)
    local = local_names(text, body)
    found: list[str] = []

    for number, code in body:
        for match in USE_DECL.finditer(code):
            path = match.group("path").strip()
            head = path.split(" as ")[0].strip()
            root = head.split("::", 1)[0]
            if "::" not in head and head in local:
                continue  # self-alias
            if root in local:
                continue  # `use RuntimeState::*` over its own variants
            allowed = any(
                head == allow or head.startswith(f"{allow}::")
                for allow in ALLOWED_STD_PATHS
            )
            if allowed:
                continue
            found.append(f"{number}: imports `{path}`")

        for match in PATH_ROOT.finditer(code):
            root = match.group("root")
            if root in local or root in {"Self", "self"}:
                continue
            # A qualified path whose root is std: allowed only if the two-segment prefix
            # is on the list. `std::fmt::Formatter` yes; `std::sync::Mutex` no.
            segments = code[match.start() :].split("::")
            prefix = "::".join(segment.strip() for segment in segments[:2])
            if any(prefix.startswith(allow) for allow in ALLOWED_STD_PATHS):
                continue
            found.append(f"{number}: path into `{root}`")

    # One line can produce the same finding twice (a `use` and its path root); keep the
    # report readable without hiding distinct findings on the same line.
    return sorted(set(found), key=lambda entry: (int(entry.split(":", 1)[0]), entry))


def selftest() -> int:
    """Prove the gate can fail, in both directions it previously got wrong."""
    cases = [
        ("use std::sync::Arc;\npub enum S { A }\n", True, "a std import outside the allowlist"),
        ("use tokio::runtime::Runtime;\n", True, "an external-crate import"),
        ("pub use crate::app::Thing;\n", True, "a pub use of a production module"),
        ("fn f() { crate::app::helper(); }\n", True, "a crate:: path with no use"),
        (
            "pub struct E;\nimpl std::fmt::Display for E { }\n",
            False,
            "an std::fmt impl, which needs no use and is allowlisted",
        ),
        (
            "pub struct E;\nfn f() { let _: std::sync::Mutex<u8>; }\n",
            True,
            "a std path OUTSIDE the allowlist, reached with no use",
        ),
        (
            "pub enum RuntimeEvent { A }\nuse RuntimeEvent as E;\nfn f() { let _ = E::A; }\n",
            False,
            "a self-alias of a type this file declares",
        ),
        (
            # The shape the real file uses, and the one an earlier regex missed: a `use`
            # indented on its own line inside a function body. It was reported as an
            # external dependency on `E`, because the alias was never recognised as local.
            "pub enum RuntimeEvent { A }\nfn f() {\n    use RuntimeEvent as E;\n    let _ = E::A;\n}\n",
            False,
            "an indented self-alias on its own line inside a body",
        ),
        (
            "pub enum S { A }\nfn f() {\n    use tokio::sync::Mutex;\n}\n",
            True,
            "an indented external import on its own line inside a body",
        ),
        (
            "pub enum RuntimeEvent { A }\nuse tokio as E;\nfn f() { let _ = E::A; }\n",
            True,
            "an import wearing a short alias",
        ),
        (
            "pub enum S { A }\nuse S::*;\nfn f() { let _ = A; }\n",
            False,
            "a glob over the file's own enum",
        ),
        (
            "//! Docs mentioning crate::app are fine.\n"
            "// use std::sync::Arc; in a comment is fine\n"
            "pub enum S { A }\n",
            False,
            "prose and commented-out code",
        ),
        (
            "pub enum S { A }\n#[cfg(test)]\nmod tests { use super::*; use tokio; }\n",
            False,
            "the test module, which is out of scope",
        ),
        (
            # The control the truncating form could not pass. Rust puts no constraint on
            # where a test module sits, so a scan that stopped at the first `#[cfg(test)]`
            # reported a clean pass over every line below it.
            "pub enum S { A }\n#[cfg(test)]\nmod tests { use super::*; }\n"
            "fn later() { let _: tokio::sync::Mutex<u8>; }\n",
            True,
            "an external dependency BELOW the test module",
        ),
        (
            # And the shape that made truncation worst in practice: the attribute the scan
            # stopped at was an inline helper, not the test module at all.
            "pub enum S { A }\n#[cfg(test)]\nfn helper() {}\n"
            "fn later() { let _: tokio::sync::Mutex<u8>; }\n",
            True,
            "an external dependency below an INLINE #[cfg(test)] helper",
        ),
        (
            "pub enum S { A }\n#[cfg(all(test, unix))]\nmod tests { use tokio; }\n"
            "pub enum T { B }\n",
            False,
            "the wide #[cfg(all(test, ...))] attribute also opens a region",
        ),
        (
            "pub enum S { A }\n#[cfg(test)]\nuse tokio::sync::Mutex;\npub enum T { B }\n",
            False,
            "an attributed `use ...;` is a one-line region",
        ),
    ]
    failures = 0
    for source, should_fail, label in cases:
        got = bool(external_dependencies(source))
        if got != should_fail:
            failures += 1
            print(
                f"SELFTEST FAIL: {label} — expected "
                f"{'rejection' if should_fail else 'acceptance'}, got the opposite"
            )
        else:
            print(f"ok   {label}")
    if failures:
        print(f"\n{failures} selftest failure(s)")
        return 1
    print("\nlifecycle_purity_gate selftest: PASS")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    failed = False
    for target in TARGETS:
        rel = target.relative_to(REPO_ROOT)
        if not target.exists():
            print(
                f"FAIL: {rel} is missing. If the machine moved, move this gate with it — "
                f"a gate whose target vanished silently stops proving anything.",
                file=sys.stderr,
            )
            failed = True
            continue
        found = external_dependencies(target.read_text(encoding="utf-8"))
        if found:
            print(f"FAIL: {rel} has acquired external dependencies:", file=sys.stderr)
            for entry in found:
                print(f"  {entry}", file=sys.stderr)
            failed = True
            continue
        print(f"lifecycle_purity_gate: PASS — {rel} depends on no production module")
    if failed:
        print(
            "\nA state machine here is a value: it depends on no production module, so it "
            "cannot\nacquire behaviour. If one genuinely needs a dependency, that is an "
            "architecture\nchange — see verification/baseline/phase2-pilot-boundary-decision.md.",
            file=sys.stderr,
        )
        return 1
    allowed = ", ".join(sorted(ALLOWED_STD_PATHS))
    print(f"lifecycle_purity_gate: PASS — {len(TARGETS)} machines (allowed std: {allowed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
