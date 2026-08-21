#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verification-trigger gate — the lane runs on everything its fingerprint reads.

WHAT THIS PROVES, exactly: every file that participates in an ADR-MCPRE-059
`ReviewFingerprint` is matched by `.github/workflows/verification.yml`'s
`paths:` filters, on both the `pull_request` and `push` triggers.

WHAT IT DOES NOT PROVE: that the lane passes, that the trigger fires for a given
change, or that the fingerprint's component set is the right one. It proves only
that the trigger set is not NARROWER than the fingerprint set.

WHY IT MATTERS. A path-filtered workflow and a content-addressed fingerprint are
two independent lists of "what this evidence depends on", and they drift apart
silently — in the direction that produces a false green.

`Cargo.lock` is in `_fingerprint.WORKSPACE_BUILD_INPUTS`, so a dependency bump
dirties every declared unit. It was NOT in the workflow's trigger set, so
Dependabot PR #532 (nine patch bumps across three lockfiles) would have merged
with every unit silently `DIRTY_SELF` and nothing re-running to notice. The
attestations on `main` would have kept reading FRESH over a dependency graph no
lane had measured.

`.github/workflows/mcp-re-supply-chain.yml` already states the rule this gate
enforces: "A dependency change lands in a Cargo.lock, so that is the file that
has to re-trigger the gate."

Run:  python3 scripts/verification_trigger_gate.py
      python3 scripts/verification_trigger_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "verification.yml"
MANIFEST = REPO / "verification" / "policy" / "verification.toml"

sys.path.insert(0, str(REPO / "tools" / "verification"))
from _fingerprint import (  # noqa: E402
    MUTATION_LANE_INPUTS,
    TEST_LANE_INPUTS,
    WORKSPACE_BUILD_INPUTS,
    test_source_patterns,
)


def glob_matches(pattern: str, path: str) -> bool:
    """GitHub Actions path matching, restricted to the forms this repository uses.

    `**` crosses directory separators, `*` does not. Implemented directly rather
    than with `fnmatch`, whose `*` crosses `/` — that difference would make the
    gate accept a narrower filter than GitHub actually applies.
    """
    out = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.fullmatch("".join(out), path) is not None


def trigger_paths(text: str) -> dict[str, list[str]]:
    """The `paths:` list under each top-level trigger in the workflow.

    Keyed by trigger name, because a filter present on `pull_request` and absent
    on `push` still leaves `main` unmeasured after the merge.
    """
    found: dict[str, list[str]] = {}
    trigger = ""
    collecting = False
    for line in text.splitlines():
        stripped = line.strip()
        header = re.fullmatch(r"(pull_request|push|schedule|workflow_dispatch):", stripped)
        if header:
            trigger = header.group(1)
            collecting = False
            found.setdefault(trigger, [])
            continue
        if stripped == "paths:" and trigger:
            collecting = True
            continue
        if collecting:
            # A comment or a blank line inside the list does not end it. Treating
            # either as a terminator silently truncates the filter set, and the
            # gate would then report a gap that the workflow does not have —
            # which is how this parser first read its own fix as still broken.
            if not stripped or stripped.startswith("#"):
                continue
            item = re.fullmatch(r'-\s+"?([^"]+)"?', stripped)
            if item:
                found[trigger].append(item.group(1))
            else:
                collecting = False
    return found


def fingerprint_inputs(manifest: Path) -> list[str]:
    """Every repo-relative file a unit fingerprint reads, from the manifest itself.

    Derived, never restated: a unit whose paths move must move this set with them,
    or the gate is checking a list that no longer describes the evidence.
    """
    required = list(WORKSPACE_BUILD_INPUTS)
    if not manifest.is_file():
        return required
    doc = tomllib.load(manifest.open("rb"))
    for unit in doc.get("unit", []):
        for path in unit.get("paths", []):
            required.append(str(path))
            head = str(path).split("/", 1)[0]
            # `_build_configuration` digests each unit crate's own manifest.
            required.append(f"{head}/Cargo.toml")
        # Encoding v4: the integration-test SOURCES a unit's selectors run, and the lane
        # code that decides what a selector means, are both fingerprint inputs. A trigger
        # set blind to them would leave a rewritten control, or a changed selector
        # mechanism, un-re-measured.
        for pattern in test_source_patterns(unit):
            required.append(pattern.replace("/**/*.rs", "/x.rs"))
        required.extend(TEST_LANE_INPUTS)
        # Encoding v5: a unit declaring `mutation://` fingerprints the probe entries and
        # the lane that applies them. Both are already inside `verification/**` and
        # `tools/verification/**`, and both are listed here anyway — the gate's job is to
        # DERIVE the requirement from the fingerprint, not to be right by coincidence about
        # a filter someone could narrow later.
        if any(str(e).startswith("mutation://") for e in unit.get("evidence", [])):
            required.append("verification/policy/mutation-probes.toml")
            required.extend(MUTATION_LANE_INPUTS)
    return sorted(set(required))


def check(workflow_text: str, required: list[str]) -> list[str]:
    triggers = trigger_paths(workflow_text)
    failures: list[str] = []
    for trigger in ("pull_request", "push"):
        patterns = triggers.get(trigger)
        if patterns is None:
            failures.append(f"the workflow declares no `{trigger}` trigger")
            continue
        if not patterns:
            continue  # no `paths:` filter at all means every change triggers it
        for path in required:
            if not any(glob_matches(p, path) for p in patterns):
                failures.append(
                    f"{trigger}: no path filter matches {path!r}, which participates in "
                    "the ReviewFingerprint — a change to it dirties units the lane would "
                    "then not re-measure"
                )
    return failures


def selftest() -> int:
    failed = False
    required = ["Cargo.lock", "mcp-re-core/src/time.rs"]
    cases = [
        ("both triggers cover every input", "on:\n  pull_request:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n  push:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n", ""),
        ("a fingerprint input missing from the filter", "on:\n  pull_request:\n    paths:\n      - \"mcp-re-core/src/**\"\n  push:\n    paths:\n      - \"mcp-re-core/src/**\"\n", "Cargo.lock"),
        ("covered on pull_request but not on push", "on:\n  pull_request:\n    paths:\n      - \"Cargo.lock\"\n      - \"mcp-re-core/src/**\"\n  push:\n    paths:\n      - \"mcp-re-core/src/**\"\n", "push: no path filter matches 'Cargo.lock'"),
        ("no paths filter means everything triggers", "on:\n  pull_request:\n  push:\n", ""),
        ("a single star must not cross a separator", "on:\n  pull_request:\n    paths:\n      - \"mcp-re-core/*\"\n      - \"Cargo.lock\"\n  push:\n    paths:\n      - \"mcp-re-core/*\"\n      - \"Cargo.lock\"\n", "mcp-re-core/src/time.rs"),
        # The parser's own false positive: a comment between two entries used to
        # end the list, so the gate reported a gap the workflow did not have.
        ("a comment inside the list does not truncate it", "on:\n  pull_request:\n    paths:\n      - \"mcp-re-core/src/**\"\n      # why the next one is here\n      - \"Cargo.lock\"\n  push:\n    paths:\n      - \"mcp-re-core/src/**\"\n\n      - \"Cargo.lock\"\n", ""),
    ]
    for label, text, expected in cases:
        failures = check(text, required)
        ok = not failures if not expected else any(expected in f for f in failures)
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failed = True
            print(f"        got {failures}")

    if failed:
        print("verification-trigger gate: SELFTEST FAILED")
        return 1
    print("verification-trigger gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    required = fingerprint_inputs(MANIFEST)
    failures = check(WORKFLOW.read_text(encoding="utf-8"), required)
    if failures:
        print("verification-trigger gate: FAILED")
        for failure in sorted(set(failures)):
            print(f"  - {failure}")
        return 1
    # The examined scope is printed, not just the verdict: a run that derived an
    # empty required-set would otherwise report OK for having checked nothing.
    print(
        f"verification-trigger gate: OK — {len(required)} fingerprint input(s) all "
        "matched by the pull_request and push filters"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
