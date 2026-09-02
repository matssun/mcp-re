#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verification-trigger gate — the lane runs on everything its fingerprint reads.

WHAT THIS PROVES, exactly: two things about the trigger set.

  1. COVERAGE — every file that participates in an ADR-MCPRE-059 `ReviewFingerprint`
     is matched by `.github/workflows/verification.yml`'s `paths:` filters, on both
     the `pull_request` and `push` triggers.
  2. LIVENESS — no wildcard-free filter names a file that is neither in the tree nor a
     required fingerprint input.

The second clause of (2) is not slack. `test_source_patterns` deliberately emits BOTH
layouts a cargo test target can have — `tests/<name>.rs` and `tests/<name>/**/*.rs` — so a
filter may name a file that does not exist TODAY because collapsing the suite back to one
file must still re-run the lane. That is a live trigger for a shape the tree may take. A
filter naming a path nothing depends on and nothing occupies is the different thing: dead.

The second is not implied by the first, and MCPRE-175 is why it is here. When a file
becomes an owner subtree, the filter that named it keeps parsing, keeps matching
nothing, and fails nothing: `mcp-re-proxy/src/tls_plane.rs` sat in two workflows after
the file became `tls_plane/`. Coverage alone caught that only because the manifest also
named the moved paths — a split under a directory filter such as
`mcp-re-http-profile/src/**` would have left the dead entry invisible. A filter that
matches nothing is not a trigger; it is a claim about what re-runs the lane that stopped
being true.

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
from _ecosystems import build_configuration_patterns  # noqa: E402
from _fingerprint import _tracked_files  # noqa: E402
from _fingerprint import (  # noqa: E402
    MUTATION_LANE_INPUTS,
    TEST_LANE_INPUTS,
    WORKSPACE_BUILD_INPUTS,
    test_source_patterns,
)

#: The boundary catalogue, read by `_fingerprint._governing_boundaries`.
TRUST_BOUNDARIES = "verification/policy/trust-boundaries.toml"


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
        # The dependency and configuration inputs, from the ONE function the fingerprint
        # uses. This used to restate the Cargo answer — `{first-segment}/Cargo.toml` — which
        # is the "one dependency set stated twice" shape this gate exists to prevent, and
        # #745 made it wrong: a Python unit's inputs are its `pyproject.toml` and lockfile,
        # and a project can live at `sdk/python` rather than at a top-level directory.
        # Only the ones the fingerprint actually digests, which is the TRACKED ones — the
        # same rule, from the same function. A lockfile alternative a project does not use
        # contributes nothing, and neither does one that exists on a developer's disk and
        # not in the tree; demanding a trigger for either is the mirror of the defect this
        # gate exists for, and the workflow refuses a wildcard-free filter that names
        # nothing, so the two rules would contradict each other.
        tracked = _tracked_files()
        required.extend(
            pattern
            for pattern in build_configuration_patterns(unit)
            if pattern in tracked
        )
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
    # Encoding v6: `governing_boundaries`. A unit's fingerprint reads
    # `trust-boundaries.toml`, and it is the one input the derivation above cannot see —
    # the component holds digests of boundary ENTRIES rather than file paths, so nothing in
    # a unit's `paths` names it. Listed explicitly for that reason, with the reason: a
    # fingerprint input the trigger set is blind to is a lane that stops asking rather than
    # going red, which is the failure this whole gate exists for.
    required.append(TRUST_BOUNDARIES)
    return sorted(set(required))


# A filter entry with no wildcard names exactly one path, so whether that path exists is
# decidable. Anything with `*` is a pattern over files that may legitimately not exist yet.
LITERAL_FILTER = re.compile(r'^\s*-\s*"([^"*?\[]+)"\s*$', re.M)


def stale_filters(workflow_text: str, repo: Path, required: list[str]) -> list[str]:
    """Wildcard-free `paths:` entries that name neither a file in the tree nor a required
    fingerprint input.

    Scoped to entries inside a `paths:` list, so an unrelated quoted scalar elsewhere in
    the workflow is not read as a filter. A path that IS a fingerprint input is live
    whether or not the tree holds it today — see the module docstring.
    """
    wanted = set(required)
    stale: list[str] = []
    for patterns in trigger_paths(workflow_text).values():
        for pattern in patterns:
            if any(ch in pattern for ch in "*?["):
                continue
            if pattern in wanted:
                continue
            if not (repo / pattern).exists():
                stale.append(pattern)
    return sorted(set(stale))


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

    # LIVENESS. A filter that matches nothing fails nothing, which is why it needs its
    # own control: coverage cannot see it.
    live = REPO
    liveness_cases = [
        (
            "a wildcard-free filter naming a file that exists is live",
            'on:\n  pull_request:\n    paths:\n      - "Cargo.lock"\n',
            [],
            [],
        ),
        (
            "a wildcard-free filter naming a moved file is STALE",
            'on:\n  pull_request:\n    paths:\n      - "mcp-re-proxy/src/tls_plane.rs"\n',
            [],
            ["mcp-re-proxy/src/tls_plane.rs"],
        ),
        (
            "the subtree pattern that replaced it is not read as a literal",
            'on:\n  pull_request:\n    paths:\n      - "mcp-re-proxy/src/tls_plane/**"\n',
            [],
            [],
        ),
        (
            "an absent path that IS a fingerprint input is live, not stale",
            'on:\n  pull_request:\n    paths:\n      - "mcp-re-proxy/tests/integration.rs"\n',
            ["mcp-re-proxy/tests/integration.rs"],
            [],
        ),
    ]
    for label, text, wanted, expected in liveness_cases:
        got = stale_filters(text, live, wanted)
        ok = got == expected
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failed = True
            print(f"        got {got}, expected {expected}")

    if failed:
        print("verification-trigger gate: SELFTEST FAILED")
        return 1
    print("verification-trigger gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    required = fingerprint_inputs(MANIFEST)
    text = WORKFLOW.read_text(encoding="utf-8")
    failures = check(text, required)
    failures += [
        f"path filter {p!r} names nothing in the tree — a filter that matches nothing is "
        "not a trigger, and a file that became an owner subtree leaves exactly this behind"
        for p in stale_filters(text, REPO, required)
    ]
    if failures:
        print("verification-trigger gate: FAILED")
        for failure in sorted(set(failures)):
            print(f"  - {failure}")
        return 1
    # The examined scope is printed, not just the verdict: a run that derived an
    # empty required-set would otherwise report OK for having checked nothing.
    print(
        f"verification-trigger gate: OK — {len(required)} fingerprint input(s) all "
        "matched by the pull_request and push filters, and every wildcard-free filter "
        "names something the tree holds or the fingerprint reads"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
