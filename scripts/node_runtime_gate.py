#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The Node support claim may not exceed the Node evidence — issue #747.

The sibling of `python_runtime_gate.py`, and the same rule in the other ecosystem's
vocabulary: `sdk/typescript/package.json` `engines.node` declares which runtimes the shipped
SDK supports, `verification/policy/toolchains.lock.toml` `[typescript].interpreters` names
the exact ones its battery is measured on, and the two are different facts in two files.

They had drifted further than the Python pair: `engines` was ABSENT, which is not a narrow
claim but an unreadable one — an unstated support range can be neither satisfied nor
exceeded, and every published package is then implicitly claimed to run everywhere. So an
absent `engines.node` is a failure here rather than a pass.

WHY MAJOR LINES AND NOT A RANGE. Node's support lines are majors, and the odd ones are never
LTS. `>=20 <27` would claim 21, 23 and 25 — lines nothing measures and nothing ships — so the
claim is expressed as an explicit disjunction of caret majors, exactly as vitest and the
upstream MCP SDK express theirs, and this gate reads that form and no other. A form it cannot
read is refused rather than waved through: silently accepting an unrecognised specifier is
the "configured but enforces nothing" shape this repository exists to refuse.

Run: python3 scripts/node_runtime_gate.py [--selftest]
"""
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_JSON = REPO_ROOT / "sdk" / "typescript" / "package.json"
LOCK = REPO_ROOT / "verification" / "policy" / "toolchains.lock.toml"

#: One clause of the supported form: `^20.0.0`, or `^20` — a caret over a major line.
CLAUSE = re.compile(r"^\^(\d+)(?:\.0(?:\.0)?)?$")


def fail(message: str) -> int:
    print(f"node-runtime gate: FAIL — {message}", file=sys.stderr)
    return 1


def supported_majors(specifier: str | None) -> tuple[list[int], str | None]:
    """The major lines `engines.node` admits, or why the specifier cannot be read."""
    if not specifier:
        return [], (
            "sdk/typescript/package.json declares no engines.node. An unstated support range "
            "claims every runtime that will ever exist, and nothing can measure that"
        )
    majors: list[int] = []
    for raw in specifier.split("||"):
        clause = raw.strip()
        match = CLAUSE.match(clause)
        if match is None:
            return [], (
                f"cannot read the clause {clause!r} of engines.node {specifier!r}. Express "
                f"the claim as `^20.0.0 || ^22.0.0`, one caret per supported major line, so "
                f"a reader and this gate agree on which lines are claimed"
            )
        major = int(match.group(1))
        if major in majors:
            return [], f"engines.node {specifier!r} names major {major} twice"
        majors.append(major)
    if not majors:
        return [], f"engines.node {specifier!r} names no major line"
    return sorted(majors), None


def check(specifier: str | None, entry) -> tuple[str | None, str]:
    """(refusal, summary) for one support claim measured against one runtime pin.

    Pure, and separate from `main` so `--selftest` can feed it the divergences this gate
    exists to catch. A gate whose logic can only be exercised by editing the real registry is
    a gate nobody proves is alive.
    """
    claimed, unreadable = supported_majors(specifier)
    if unreadable is not None:
        return unreadable, ""

    if not isinstance(entry, dict):
        return "toolchains.lock.toml has no [typescript] runtime pin", ""
    if entry.get("state") != "resolved":
        return "[typescript] is unresolved, so no runtime identity backs the claim", ""

    pinned: dict[int, str] = {}
    for version in entry.get("interpreters", []):
        parts = str(version).split(".")
        if len(parts) != 3 or not all(part.isdigit() for part in parts):
            return (
                f"[typescript].interpreters entry {version!r} is not an exact "
                f"major.minor.patch version. A major alone lets two different builds record "
                f"one identity"
            ), ""
        major = int(parts[0])
        if major in pinned:
            return (
                f"[typescript].interpreters names major {major} twice ({pinned[major]}, "
                f"{version}); one support line is measured on one runtime"
            ), ""
        pinned[major] = str(version)

    missing = [str(major) for major in claimed if major not in pinned]
    extra = [f"{major} ({pinned[major]})" for major in sorted(pinned) if major not in claimed]
    if missing:
        return (
            f"engines.node {specifier} claims Node {', '.join(missing)}, which no pinned "
            f"runtime measures. A support claim wider than its evidence reads one runtime's "
            f"green as proof about the rest"
        ), ""
    if extra:
        return (
            f"[typescript].interpreters pins Node {', '.join(extra)}, outside the supported "
            f"set {specifier}. Either support it or stop measuring it"
        ), ""

    covered = ", ".join(pinned[major] for major in sorted(pinned))
    return None, (
        f"engines.node {specifier} claims {len(claimed)} major line(s), each measured on "
        f"exactly one pinned runtime ({covered})"
    )


#: Every way the two facts can diverge, each paired with the positive case it must not
#: reject. A gate that refuses everything measures as little as one that refuses nothing.
SELFTEST_CASES = (
    ("no engines.node at all", None, {"state": "resolved", "interpreters": ["20.20.2"]}, True),
    (
        "a range form this gate cannot read",
        ">=20 <27",
        {"state": "resolved", "interpreters": ["20.20.2"]},
        True,
    ),
    (
        "a claimed line nothing measures",
        "^20.0.0 || ^22.0.0",
        {"state": "resolved", "interpreters": ["20.20.2"]},
        True,
    ),
    (
        "a runtime measured outside the claim",
        "^20.0.0",
        {"state": "resolved", "interpreters": ["20.20.2", "22.23.2"]},
        True,
    ),
    (
        "a major pinned without a patch version",
        "^20.0.0",
        {"state": "resolved", "interpreters": ["20.20"]},
        True,
    ),
    (
        "one major pinned twice",
        "^20.0.0",
        {"state": "resolved", "interpreters": ["20.20.2", "20.19.0"]},
        True,
    ),
    ("an unresolved runtime pin", "^20.0.0", {"state": "unresolved"}, True),
    ("no runtime pin at all", "^20.0.0", None, True),
    (
        "the claim and the pin agreeing exactly",
        "^20.0.0 || ^22.0.0",
        {"state": "resolved", "interpreters": ["20.20.2", "22.23.2"]},
        False,
    ),
)


def selftest() -> int:
    failures = 0
    for name, specifier, entry, must_refuse in SELFTEST_CASES:
        refusal, _ = check(specifier, entry)
        refused = refusal is not None
        if refused != must_refuse:
            verb = "was accepted" if must_refuse else "was refused"
            print(f"  SELFTEST FAIL: {name} {verb}", file=sys.stderr)
            failures += 1
        else:
            print(f"  ok   {name}: {'refused' if refused else 'accepted'}")
    if failures:
        print(f"node-runtime gate: SELFTEST FAIL — {failures} case(s)", file=sys.stderr)
        return 1
    print(f"node-runtime gate: SELFTEST OK — {len(SELFTEST_CASES)} case(s)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    package = json.loads(PACKAGE_JSON.read_text())
    entry = tomllib.load(LOCK.open("rb")).get("typescript")
    refusal, summary = check(package.get("engines", {}).get("node"), entry)
    if refusal is not None:
        return fail(refusal)
    print(f"node-runtime gate: OK — {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
