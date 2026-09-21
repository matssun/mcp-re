#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A test-only cargo feature may be enabled only by a dev-dependency.

WHY THIS IS NOT `fixture_boundary.rs`'S JOB. That module owns three controls over the same
boundary and all three read `mcp-re-host/Cargo.toml` through `include_str!`. That is the
right instrument for the two halves it names — the `#[cfg]` on each item, and the feature not
being defaulted — because both are facts about the crate's own files.

It cannot see the third mechanism, and the third mechanism is the one that fired:

    mcp-re-demo/Cargo.toml
        mcp-re-host = { path = "../mcp-re-host", features = ["test-fixtures"] }

`mcp-re-demo` is a default workspace member, the workspace is `resolver = "2"`, and cargo
unifies features across NORMAL dependencies within one invocation. So every workspace build
compiled one `mcp-re-host` with `test-fixtures` on, and that is the rlib `mcp-re-client`
links. Measured on the production closure at the time this gate was written:

    cargo tree -e features,no-dev --workspace | grep -c 'test-fixtures'   ->  1

A control that reads only its own crate's manifest is structurally incapable of reporting
that: the offending line is in a sibling's file. `the_fixture_feature_is_enabled_only_as_a_dev_dependency`
was not weak, it was scoped — it tests the SELF dependency, and the self dependency was
correct the whole time. Three doors of four.

WHAT THIS GATE RANGES OVER. Every `Cargo.toml` in the workspace, including the root. A
dependency line enabling a feature named in `TEST_ONLY_FEATURES` is refused unless it sits in
a dev-dependency table — `[dev-dependencies]`, `[target.'cfg(...)'.dev-dependencies]`, or a
`[dev-dependencies.<name>]` block. Dev-dependency features do not unify into a normal build,
which is exactly why that placement is the sanctioned one.

The registry is deliberately a small literal list rather than a discovered set. A feature is
test-only because someone decided it is; discovering the property from the name would make
the gate agree with whatever it found.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Features that must never be enabled by a normal or build dependency, as `crate/feature`.
#: Adding one here is a decision; the gate does not infer membership from the name.
TEST_ONLY_FEATURES: dict[str, str] = {
    "mcp-re-host": "test-fixtures",
    # ADR-MCPRE-052: the pre-052 direct-root response emitters. Same class, same door —
    # a normal-dependency edge would put a removed signing mode back into every build in
    # the graph, which is exactly the property the relocation was for.
    "mcp-re-http-profile": "pre_052_fixtures",
}

#: Tables whose feature edges do NOT unify into a normal build.
_DEV_TABLE = re.compile(r"^\s*\[(?:target\.[^\]]+\.)?dev-dependencies(?:\.[A-Za-z0-9_-]+)?\]")
#: Any other table header ends a dev-dependency region.
_ANY_TABLE = re.compile(r"^\s*\[")


def _dev_regions(text: str) -> list[range]:
    """Line ranges (0-based) that live under a dev-dependency table."""
    regions: list[range] = []
    start: int | None = None
    for index, line in enumerate(text.splitlines()):
        if _DEV_TABLE.match(line):
            if start is None:
                start = index
        elif _ANY_TABLE.match(line):
            if start is not None:
                regions.append(range(start, index))
                start = None
    if start is not None:
        regions.append(range(start, len(text.splitlines())))
    return regions


def offences(text: str, where: str) -> list[str]:
    """Every line enabling a test-only feature outside a dev-dependency table."""
    dev = _dev_regions(text)
    found: list[str] = []
    for index, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if stripped.startswith("#") or "features" not in stripped:
            continue
        for crate, feature in TEST_ONLY_FEATURES.items():
            if crate not in stripped or f'"{feature}"' not in stripped:
                continue
            if any(index in region for region in dev):
                continue
            found.append(
                f"{where}:{index + 1}: enables `{crate}/{feature}` outside a dev-dependency "
                f"table. Cargo unifies features across normal dependencies, so this puts the "
                f"feature on every build whose graph contains this crate — including the "
                f"library a production consumer links.\n      {stripped}"
            )
    return found


def _manifests() -> list[Path]:
    root = REPO / "Cargo.toml"
    members: list[Path] = [root]
    data = tomllib.loads(root.read_text(encoding="utf-8"))
    for name in data.get("workspace", {}).get("members", []):
        manifest = REPO / name / "Cargo.toml"
        if manifest.is_file():
            members.append(manifest)
    return members


def selftest() -> int:
    """Prove the gate goes RED on the exact shape that shipped, and GREEN on the fix.

    The same bytes in the two placements, so the only thing the verdicts can be reading is
    which table the line is under.
    """
    line = 'mcp-re-host = { path = "../mcp-re-host", features = ["test-fixtures"] }'
    red = f"[package]\nname = \"x\"\n\n[dependencies]\n{line}\n"
    green = f"[package]\nname = \"x\"\n\n[dependencies]\n\n[dev-dependencies]\n{line}\n"

    if not offences(red, "probe"):
        print("fixture-feature gate selftest: FAIL — a normal-dependency edge was not refused")
        return 1
    if offences(green, "probe"):
        print("fixture-feature gate selftest: FAIL — a dev-dependency edge was refused")
        return 1

    # The regions scanner must end a dev region at the next table, or a normal-dependency
    # table written AFTER the dev one would be silently exempt.
    trailing = f"[dev-dependencies]\n\n[dependencies]\n{line}\n"
    if not offences(trailing, "probe"):
        print("fixture-feature gate selftest: FAIL — a dev region swallowed the table after it")
        return 1

    # And a commented-out edge is not an edge.
    if offences(f"[dependencies]\n# {line}\n", "probe"):
        print("fixture-feature gate selftest: FAIL — a commented line was read as an edge")
        return 1

    print("fixture-feature gate selftest: PASS")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    manifests = _manifests()
    problems: list[str] = []
    for manifest in manifests:
        where = manifest.relative_to(REPO).as_posix()
        problems.extend(offences(manifest.read_text(encoding="utf-8"), where))

    if problems:
        print(f"fixture-feature gate: FAIL — {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    registry = ", ".join(f"{c}/{f}" for c, f in sorted(TEST_ONLY_FEATURES.items()))
    print(
        f"fixture-feature gate: OK — {len(manifests)} workspace manifest(s) read; "
        f"no normal or build dependency enables {registry}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
