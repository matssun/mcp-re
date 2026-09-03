#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The Python support claim may not exceed the Python evidence — issue #746.

`sdk/python/pyproject.toml` declares which interpreters the shipped SDK supports.
`verification/policy/toolchains.lock.toml` `[python].interpreters` names the exact ones the
authoritative battery is measured on. Those are two different facts written in two places,
and before this gate existed they had drifted: the package claimed `>=3.10` — an unbounded
claim over every future runtime — while one unpinned CPython ran the battery.

So the rule is a mutual one, and both directions are failures:

  * a supported minor with no pinned interpreter is a claim with no evidence;
  * a pinned interpreter outside the supported range is evidence for something the package
    says it does not support, which is measurement effort spent outside the claim.

`requires-python` is parsed rather than pattern-matched for a lower and upper bound, because
a range this gate cannot read is a range it cannot check, and silently passing an
unrecognised specifier is exactly the "configured but enforces nothing" shape the repository
refuses. An unbounded upper end therefore FAILS: it claims every future minor.

Run: python3 scripts/python_runtime_gate.py
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "sdk" / "python" / "pyproject.toml"
LOCK = REPO_ROOT / "verification" / "policy" / "toolchains.lock.toml"

#: One clause of a `requires-python` specifier: an operator and a dotted version.
CLAUSE = re.compile(r"^(>=|>|<=|<|==|!=|~=)\s*(\d+)\.(\d+)(?:\.\d+)?$")


def fail(message: str) -> int:
    print(f"python-runtime gate: FAIL — {message}", file=sys.stderr)
    return 1


def supported_minors(specifier: str) -> tuple[list[tuple[int, int]], str | None]:
    """The (major, minor) pairs a `requires-python` specifier admits, or why it cannot be read."""
    floor: tuple[int, int] | None = None
    ceiling: tuple[int, int] | None = None
    ceiling_inclusive = False
    for raw in specifier.split(","):
        clause = raw.strip()
        match = CLAUSE.match(clause)
        if match is None:
            return [], f"cannot read the clause {clause!r} of requires-python {specifier!r}"
        operator, major, minor = match.group(1), int(match.group(2)), int(match.group(3))
        if operator == ">=":
            floor = (major, minor)
        elif operator == "<":
            ceiling, ceiling_inclusive = (major, minor), False
        elif operator == "<=":
            ceiling, ceiling_inclusive = (major, minor), True
        else:
            return [], (
                f"the clause {clause!r} is not a bound this gate reads. Express the support "
                f"claim as `>=X.Y,<A.B`, so a reader and this gate agree on it"
            )
    if floor is None:
        return [], f"requires-python {specifier!r} states no lower bound"
    if ceiling is None:
        return [], (
            f"requires-python {specifier!r} has no upper bound, so it claims support for "
            f"every future Python minor — including ones no battery has ever run on"
        )
    if floor[0] != ceiling[0]:
        return [], f"requires-python {specifier!r} spans two major versions; not supported here"
    last = ceiling[1] if ceiling_inclusive else ceiling[1] - 1
    return [(floor[0], minor) for minor in range(floor[1], last + 1)], None


def check(specifier: str | None, entry) -> tuple[str | None, str]:
    """(refusal, summary) for one support claim measured against one runtime pin.

    Pure, and separate from `main` for one reason: `--selftest` has to be able to feed it
    the divergences this gate exists to catch. A gate whose logic can only be exercised by
    editing the real registry is a gate nobody proves is alive.
    """
    if not specifier:
        return "sdk/python/pyproject.toml declares no requires-python", ""
    claimed, unreadable = supported_minors(specifier)
    if unreadable is not None:
        return unreadable, ""

    if not isinstance(entry, dict):
        return "toolchains.lock.toml has no [python] runtime pin", ""
    if entry.get("state") != "resolved":
        return "[python] is unresolved, so no interpreter identity backs the claim", ""
    pinned: dict[tuple[int, int], str] = {}
    for version in entry.get("interpreters", []):
        parts = str(version).split(".")
        if len(parts) != 3 or not all(part.isdigit() for part in parts):
            return (
                f"[python].interpreters entry {version!r} is not an exact major.minor.patch "
                f"version. A minor alone lets two different patches record one identity"
            ), ""
        key = (int(parts[0]), int(parts[1]))
        if key in pinned:
            return (
                f"[python].interpreters names {key[0]}.{key[1]} twice ({pinned[key]}, "
                f"{version}); one minor is measured on one interpreter"
            ), ""
        pinned[key] = str(version)

    missing = [f"{major}.{minor}" for major, minor in claimed if (major, minor) not in pinned]
    extra = [
        f"{major}.{minor} ({pinned[(major, minor)]})"
        for (major, minor) in sorted(pinned)
        if (major, minor) not in claimed
    ]
    if missing:
        return (
            f"requires-python {specifier} claims {', '.join(missing)}, which no pinned "
            f"interpreter measures. A support claim wider than its evidence reads one "
            f"runtime's green as proof about the rest"
        ), ""
    if extra:
        return (
            f"[python].interpreters pins {', '.join(extra)}, outside the supported range "
            f"{specifier}. Either support it or stop measuring it"
        ), ""

    covered = ", ".join(pinned[key] for key in sorted(pinned))
    return None, (
        f"requires-python {specifier} claims {len(claimed)} minor(s), each measured on "
        f"exactly one pinned interpreter ({covered})"
    )


#: Every way the two facts can diverge, each paired with the positive case it must not
#: reject. A gate that refuses everything measures as little as one that refuses nothing.
SELFTEST_CASES = (
    (
        "an unbounded support claim",
        ">=3.10",
        {"state": "resolved", "interpreters": ["3.10.20"]},
        True,
    ),
    (
        "a supported minor nothing measures",
        ">=3.10,<3.13",
        {"state": "resolved", "interpreters": ["3.10.20", "3.11.15"]},
        True,
    ),
    (
        "an interpreter measured outside the claim",
        ">=3.10,<3.12",
        {"state": "resolved", "interpreters": ["3.10.20", "3.11.15", "3.12.13"]},
        True,
    ),
    (
        "a minor pinned without a patch version",
        ">=3.10,<3.12",
        {"state": "resolved", "interpreters": ["3.10.20", "3.11"]},
        True,
    ),
    (
        "one minor pinned twice",
        ">=3.10,<3.12",
        {"state": "resolved", "interpreters": ["3.10.20", "3.11.15", "3.11.9"]},
        True,
    ),
    (
        "an unresolved runtime pin",
        ">=3.10,<3.12",
        {"state": "unresolved"},
        True,
    ),
    (
        "no runtime pin at all",
        ">=3.10,<3.12",
        None,
        True,
    ),
    (
        "the claim and the pin agreeing exactly",
        ">=3.10,<3.12",
        {"state": "resolved", "interpreters": ["3.10.20", "3.11.15"]},
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
        print(f"python-runtime gate: SELFTEST FAIL — {failures} case(s)", file=sys.stderr)
        return 1
    print(f"python-runtime gate: SELFTEST OK — {len(SELFTEST_CASES)} case(s)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    project = tomllib.load(PYPROJECT.open("rb"))["project"]
    entry = tomllib.load(LOCK.open("rb")).get("python")
    refusal, summary = check(project.get("requires-python"), entry)
    if refusal is not None:
        return fail(refusal)
    print(f"python-runtime gate: OK — {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
