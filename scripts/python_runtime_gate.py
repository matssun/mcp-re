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

THE THIRD FACT is the one that broke on the v0.17 candidate: a **deploy image that
installs the shipped wheel** carries an interpreter too, and nothing related it to either
of the two above. `deploy/docker/Dockerfile.loadgen` sat on `python:3.12-slim` — correct
while the package claimed `>=3.10`, and unbuildable the moment the support claim was
narrowed to `>=3.14.5`. It failed at `docker build`, in stage 5, after a three-replica
fleet rollout, with `ERROR: Package 'mcp-re-sdk' requires a different Python` — a support
decision surfacing as a deploy failure two lanes away from where it was taken.

So a Dockerfile stage that pip-installs the MCP-RE wheel must name a base image that is
EXACTLY one of the pinned interpreters. Exactly, not merely inside the range: a floating
`python:3.14-slim` is a different artefact on every rebuild, which is the reason
`Dockerfile.inner` already gives for pinning `mcp` to an exact version, and "inside the
range at build time" is not a property of the file. A stage that does NOT install the
wheel is not bound by this — `Dockerfile.inner` runs the upstream MCP SDK and nothing of
ours, and its interpreter is its own business.

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
DOCKER_DIR = REPO_ROOT / "deploy" / "docker"

#: `FROM <image> AS <stage>` — the stage name is optional, because an unnamed final stage
#: is still a stage that can install the wheel.
FROM_LINE = re.compile(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE)

#: A `python:` base image, with the version as the tag's leading component.
PYTHON_BASE = re.compile(r"^python:([0-9][^-\s]*)(?:-\S+)?$")

#: What makes a stage one that runs OUR wheel. Matched on the install command rather than
#: on the stage name: a stage renamed from `loadgen` to anything else installs the same
#: wheel, and a rule keyed on the name would stop applying without anything changing.
INSTALLS_SDK = re.compile(r"pip3?\s+install[^\n]*(?:/wheels/|sdk/python)")

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


def wheel_stages(text: str) -> list[tuple[str, str | None]]:
    """`(base image, stage name)` for every stage in one Dockerfile that installs OUR wheel.

    A forward pass over the file rather than a regex over the whole text: the install
    command must be attributed to the stage it is IN, and the two `FROM` lines in
    `Dockerfile.loadgen` are two different interpreters. Attributing an install to the
    wrong stage would check the builder's Python and pass while the runtime's is wrong —
    which is the defect, inverted.
    """
    found: list[tuple[str, str | None]] = []
    base: str | None = None
    stage: str | None = None
    claimed = False
    for line in text.splitlines():
        opening = FROM_LINE.match(line.strip())
        if opening is not None:
            base, stage, claimed = opening.group(1), opening.group(2), False
            continue
        if base is None or claimed:
            continue
        if INSTALLS_SDK.search(line):
            found.append((base, stage))
            claimed = True
    return found


def check_images(dockerfiles: dict[str, str], pinned: dict[tuple[int, int], str]) -> str | None:
    """The third fact: a stage that installs the wheel runs a PINNED interpreter.

    `dockerfiles` is `{path: text}` so `--selftest` can feed it files that do not exist;
    a gate whose only input is the real tree is one nobody proves is alive.
    """
    allowed = set(pinned.values())
    for path in sorted(dockerfiles):
        for base, stage in wheel_stages(dockerfiles[path]):
            where = f"{path} stage {stage!r}" if stage else path
            match = PYTHON_BASE.match(base)
            if match is None:
                return (
                    f"{where} installs the MCP-RE wheel on base image {base!r}, which names "
                    f"no Python version this gate can read. The interpreter that runs the "
                    f"shipped wheel is part of the support claim and must be stated"
                )
            version = match.group(1)
            if version not in allowed:
                inside = tuple(int(part) for part in version.split(".") if part.isdigit())
                hint = (
                    "it is not an exact major.minor.patch, so what it resolves to is a "
                    "property of the day it is built"
                    if len(inside) != 3
                    else "that interpreter is not one the battery is measured on"
                )
                return (
                    f"{where} installs the MCP-RE wheel on python:{version}, and "
                    f"[python].interpreters pins {', '.join(sorted(allowed))} — {hint}. "
                    f"A deploy image outside the supported range cannot install the wheel "
                    f"at all, and it fails at `docker build` inside a fleet proof rather "
                    f"than where the support decision was taken"
                )
    return None


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


#: The wheel-installing base image, against the pinned set. Same shape and same rule as
#: `SELFTEST_CASES`: every refusal paired with the acceptance it must not swallow.
IMAGE_SELFTEST_CASES = (
    (
        "the stale base image the v0.17 candidate actually carried",
        {"Dockerfile.loadgen": "FROM rust:1 AS wheel\nRUN cd sdk/python && maturin build\n"
                               "FROM python:3.12-slim AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        True,
    ),
    (
        "a floating minor tag inside the supported range",
        {"Dockerfile.loadgen": "FROM python:3.14-slim AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        True,
    ),
    (
        "a base image naming no readable version",
        {"Dockerfile.loadgen": "FROM ghcr.io/example/python AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        True,
    ),
    (
        "the install attributed to the BUILDER stage rather than the runtime one",
        {"Dockerfile.loadgen": "FROM python:3.12-slim AS wheel\n"
                               "RUN pip3 install --no-cache-dir maturin\n"
                               "FROM python:3.14.7-slim AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        False,
    ),
    (
        "a stage that installs something else entirely",
        {"Dockerfile.inner": "FROM python:3.12-slim AS inner\n"
                             "RUN pip install --no-cache-dir \"mcp==2.0.0\"\n"},
        False,
    ),
    (
        "the pinned interpreter, exactly",
        {"Dockerfile.loadgen": "FROM python:3.14.7-slim AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        False,
    ),
)

#: The pin the image cases are measured against — one interpreter, as the tree declares.
IMAGE_SELFTEST_PIN = {(3, 14): "3.14.7"}


def selftest() -> int:
    failures = 0
    for name, files, must_refuse in IMAGE_SELFTEST_CASES:
        refused = check_images(files, IMAGE_SELFTEST_PIN) is not None
        if refused != must_refuse:
            verb = "was accepted" if must_refuse else "was refused"
            print(f"  SELFTEST FAIL: {name} {verb}", file=sys.stderr)
            failures += 1
        else:
            print(f"  ok   {name}: {'refused' if refused else 'accepted'}")
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
    total = len(SELFTEST_CASES) + len(IMAGE_SELFTEST_CASES)
    print(f"python-runtime gate: SELFTEST OK — {total} case(s)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    project = tomllib.load(PYPROJECT.open("rb"))["project"]
    entry = tomllib.load(LOCK.open("rb")).get("python")
    refusal, summary = check(project.get("requires-python"), entry)
    if refusal is not None:
        return fail(refusal)

    # Only reached once the claim and the pin agree, so `pinned` below is the checked set
    # rather than a second reading of the registry.
    pinned = {}
    for version in entry["interpreters"]:
        major, minor, _ = str(version).split(".")
        pinned[(int(major), int(minor))] = str(version)
    dockerfiles = {
        path.relative_to(REPO_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(DOCKER_DIR.glob("Dockerfile*"))
        if path.is_file()
    }
    if not dockerfiles:
        return fail(
            f"no Dockerfile under {DOCKER_DIR.relative_to(REPO_ROOT)} — the image half of "
            f"this gate would measure nothing, which is not the same as finding nothing"
        )
    image_refusal = check_images(dockerfiles, pinned)
    if image_refusal is not None:
        return fail(image_refusal)

    print(
        f"python-runtime gate: OK — {summary}; {len(dockerfiles)} deploy Dockerfile(s) "
        f"examined, every stage installing the MCP-RE wheel on a pinned interpreter"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
