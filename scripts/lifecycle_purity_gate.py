#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lifecycle-purity gate — the runtime lifecycle relation imports nothing.

WHAT THIS PROVES, exactly: the production half of `mcp-re-proxy/src/runtime_state.rs`
(everything above its `#[cfg(test)]` module) contains no `use` declaration naming anything
outside the module, and no `crate::` / `super::` / `::`-qualified path. That is a
syntactic check on one file, and the claim stops there.

A `use` that renames a type the file itself declares — `use RuntimeEvent as E;`, which the
transition match uses so the 110-pair table fits on a screen — is permitted. It names
nothing outside, and deleting it would change only how the match reads.

WHAT IT DOES NOT PROVE: that the lifecycle is semantically pure. A future edit could take
a closure argument, read a `static`, or call a function passed in from outside and none of
those would be seen here. Keeping the contract narrow is deliberate — overstating a gate
is worse than not having one, because the overstatement is what stops people looking.

WHY. ADR-MCPRE-059 Phase 2 considered extracting this module into its own pure crate so
Verus could verify it at crate granularity, and rejected it: the crate would have ~212
production lines and three consumers, all sibling modules in `mcp-re-proxy`, modelling
states that describe that same program. A crate implies reuse and independent versioning,
and neither applies. The full reasoning is in
`verification/baseline/phase2-pilot-boundary-decision.md`.

But the extraction was reaching for something real. `runtime_state.rs` today imports
nothing from outside itself — no external crate, no `std`, no `crate::` path — and that
purity is held by discipline alone. Nothing stops a later edit adding `use tokio::...` or reaching into
`crate::app`, and the moment one does, the module stops being a value and becomes a
component; quietly, in a diff that reads like a convenience. `mcp-re-core` does not rely
on discipline for the equivalent property — its Cargo manifest enforces it
(ADR-MCPS-011/012). This gate is the same enforcement without a crate boundary, and it
states the invariant more precisely than a crate would:

    The lifecycle relation is a value. It imports nothing, so it cannot acquire behaviour.

That matters beyond tidiness. The relation is what `FleetDrained` and the terminal latches
mean; a lifecycle that could consult the outside world would be able to answer
"is this transition legal?" differently on two calls with the same arguments.

Run:  python3 scripts/lifecycle_purity_gate.py
      python3 scripts/lifecycle_purity_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = REPO_ROOT / "mcp-re-proxy" / "src" / "runtime_state.rs"

#: Where the production half ends. Tests legitimately `use super::*`.
TEST_MARKER = "#[cfg(test)]"

#: A `use` declaration at any indentation, including `pub use`.
USE_DECL = re.compile(r"(?:^|[{;]\s*)(?:pub(?:\s*\([^)]*\))?\s+)?use\s+(?P<path>[^;]+);")

#: A type declared in this file. Used to tell a self-alias from an import: the module
#: shortens its own `RuntimeEvent`/`RuntimeState` to `E`/`S` inside the transition match,
#: which is a readability choice about names already in scope and reaches nothing outside.
LOCAL_TYPE = re.compile(
    r"^\s*(pub(\s*\([^)]*\))?\s+)?(enum|struct|type|trait)\s+(?P<name>\w+)"
)

#: A path reaching outside this module. `crate::` and `super::` are the in-tree spellings;
#: a leading `::` or `<crate>::` is how an external crate is named without a `use`.
OUTSIDE_PATH = re.compile(r"\b(crate|super)::|(?<![:\w])::\w")


def production_half(text: str) -> list[tuple[int, str]]:
    """Lines above the test module, 1-indexed, comments and blanks removed.

    Comments are dropped because the module's doc comments legitimately reference
    `crate::app` in prose and rustdoc links; the gate is about code.
    """
    lines: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if TEST_MARKER in line:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        lines.append((number, line))
    return lines


def local_types(text: str) -> set[str]:
    return {
        match.group("name")
        for line in text.splitlines()
        if (match := LOCAL_TYPE.match(line))
    }


def violations(text: str) -> list[str]:
    declared = local_types(text)
    found: list[str] = []
    for number, line in production_half(text):
        code = line.split("//", 1)[0]
        if match := USE_DECL.search(code):
            path = match.group("path").strip()
            # `use RuntimeEvent as E;` renames a type this file declares. It is not an
            # import: nothing outside the module is named, and deleting the line would
            # change only how the transition match reads. A path with `::`, or a
            # single-segment name this file does not declare (`use tokio;`), IS an import.
            head = path.split(" as ")[0].strip()
            if "::" not in head and head in declared:
                continue
            found.append(f"{number}: import declaration — {line.strip()}")
        elif OUTSIDE_PATH.search(code):
            found.append(f"{number}: path outside the module — {line.strip()}")
    return found


def selftest() -> int:
    """Prove the gate can fail. A gate never observed rejecting anything is decoration."""
    cases = [
        ("use std::sync::Arc;\npub enum S { A }\n", True, "a std import"),
        ("use tokio::runtime::Runtime;\n", True, "an external-crate import"),
        ("pub use crate::app::Thing;\n", True, "a pub use"),
        ("fn f() { crate::app::helper(); }\n", True, "a crate:: path in a body"),
        ("fn f() { ::std::mem::drop(1); }\n", True, "a leading :: path"),
        (
            "//! Docs mentioning crate::app are fine.\n"
            "// use std::sync::Arc; in a comment is fine\n"
            "pub enum S { A }\nimpl S { fn f(&self) -> u8 { 1 } }\n",
            False,
            "prose and commented-out code",
        ),
        (
            "pub enum S { A }\n#[cfg(test)]\nmod tests { use super::*; }\n",
            False,
            "the test module's own use",
        ),
        (
            "pub enum RuntimeEvent { A }\nfn f() { use RuntimeEvent as E; let _ = E::A; }\n",
            False,
            "a self-alias of a type this file declares",
        ),
        (
            "pub enum RuntimeEvent { A }\nfn f() { use tokio; }\n",
            True,
            "a single-segment import of a crate this file does not declare",
        ),
    ]
    failures = 0
    for source, should_fail, label in cases:
        got = bool(violations(source))
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
    if not TARGET.exists():
        print(
            f"FAIL: {TARGET.relative_to(REPO_ROOT)} is missing. If the lifecycle moved, "
            f"move this gate with it — a gate whose target vanished silently stops "
            f"proving anything.",
            file=sys.stderr,
        )
        return 1
    found = violations(TARGET.read_text(encoding="utf-8"))
    rel = TARGET.relative_to(REPO_ROOT)
    if found:
        print(f"FAIL: {rel} is no longer import-free:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        print(
            "\nThe lifecycle relation is a value: it imports nothing, so it cannot "
            "acquire\nbehaviour, and 'is this transition legal?' cannot answer differently "
            "on two\ncalls with the same arguments. If the module genuinely needs a "
            "dependency, that\nis an architecture change — see "
            "verification/baseline/phase2-pilot-boundary-decision.md.",
            file=sys.stderr,
        )
        return 1
    print(f"lifecycle_purity_gate: PASS — {rel} imports nothing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
