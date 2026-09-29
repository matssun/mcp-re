#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A test-only crate feature is compiled only into test-only targets.

A test-only feature — `mcp-re-host`'s `test-fixtures`, `mcp-re-http-profile`'s
`pre_052_fixtures` — puts something on a crate's surface that no deployment may be given: a
nonce source with no entropy and a frozen clock, or a removed direct-root response signer.
Bazel compiles a crate's features per TARGET, so the feature reaches a build exactly through
a target that names it in `crate_features` and whatever depends on that target.

`testonly = True` closes the second half: Bazel refuses, at analysis, any target depending on
a test-only one that is not test-only itself. So the whole boundary is one fact per target:
every target compiling a registered crate with its test-only feature on is test-only. That is
what this gate checks, over `verification/generated/rust-targets.json` — the build graph's
own table, whose freshness `tools/verification/rust-targets --check` holds.

`fixture_boundary.rs` states the same boundary from inside `mcp-re-host`, for its own
BUILD file. This gate ranges over every target in the graph: a flavor compiling the crate's
sources from ANOTHER package is found by its crate root, not by where it is declared.

The registry is deliberately a small literal list rather than a discovered set. A feature is
test-only because someone decided it is; discovering the property from the name would make
the gate agree with whatever it found.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))

import _rust_targets  # noqa: E402

#: Features no production target may compile, keyed by the Bazel package of the crate that
#: declares them. Adding one here is a decision; the gate does not infer membership.
TEST_ONLY_FEATURES: dict[str, str] = {
    "mcp-re-host": "test-fixtures",
    # ADR-MCPRE-052: the pre-052 direct-root response emitters. A production target
    # compiling them would put a removed signing mode back into the build.
    "mcp-re-http-profile": "pre_052_fixtures",
}


def problems(rows: dict[str, dict]) -> list[str]:
    """Every target compiling a test-only feature without being test-only, and every
    registered feature with no production library or no flavor to measure."""
    found: list[str] = []
    for package, feature in sorted(TEST_ONLY_FEATURES.items()):
        compiled = {
            label: row
            for label, row in rows.items()
            if row["root"].startswith(f"{package}/") and row["kind"] != "charon_llbc"
        }
        flavors = {label: row for label, row in compiled.items() if feature in row["features"]}
        production = [
            label
            for label, row in compiled.items()
            if row["kind"] == "rust_library" and feature not in row["features"]
        ]
        if not production:
            found.append(
                f"{package}: no rust_library compiles it without `{feature}`, so there is no "
                "production library whose surface this boundary protects"
            )
        if not flavors:
            found.append(
                f"{package}/{feature}: no target compiles the feature. A registered boundary "
                "with nothing on its test side measures nothing; retire the registry entry "
                "with the feature."
            )
        for label, row in sorted(flavors.items()):
            if not row["testonly"]:
                found.append(
                    f"{label} compiles {package} with `{feature}` and is not testonly, so "
                    "a production target may depend on it and ship the feature."
                )
    return found


def _row(root: str, kind: str, features: list[str], testonly: bool) -> dict:
    return {"root": root, "kind": kind, "features": features, "testonly": testonly}


def selftest() -> int:
    """RED on each way the boundary opens, GREEN on the shape the tree has."""
    lib = _row("mcp-re-host/src/lib.rs", "rust_library", [], False)
    flavor = _row("mcp-re-host/src/lib.rs", "rust_library", ["test-fixtures"], True)
    pre = _row("mcp-re-http-profile/src/lib.rs", "rust_library", [], False)
    pre_flavor = _row("mcp-re-http-profile/src/lib.rs", "rust_library", ["pre_052_fixtures"], True)
    green = {"//h:lib": lib, "//h:fx": flavor, "//p:lib": pre, "//p:fx": pre_flavor}
    cases = {
        "a flavor that is not testonly": {**green, "//h:fx": {**flavor, "testonly": False}},
        "the production library carrying the feature": {
            **green, "//h:lib": {**lib, "features": ["test-fixtures"]},
        },
        "a registered feature no target compiles": {k: v for k, v in green.items() if k != "//p:fx"},
        "a flavor declared in another package": {
            **green, "//elsewhere:fx": _row("mcp-re-host/src/lib.rs", "rust_library", ["test-fixtures"], False),
        },
    }
    if problems(green):
        print(f"fixture-feature gate selftest: FAIL — the green shape was refused: {problems(green)}")
        return 1
    for name, rows in cases.items():
        if not problems(rows):
            print(f"fixture-feature gate selftest: FAIL — {name} was not refused")
            return 1
    print(f"fixture-feature gate selftest: PASS ({len(cases) + 1} cases)")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    rows = _rust_targets.table()
    found = problems(rows)
    if found:
        print(f"fixture-feature gate: FAIL — {len(found)} problem(s)")
        for problem in found:
            print(f"  - {problem}")
        return 1

    registry = ", ".join(f"{p}/{f}" for p, f in sorted(TEST_ONLY_FEATURES.items()))
    flavors = sum(
        1
        for package, feature in TEST_ONLY_FEATURES.items()
        for row in rows.values()
        if row["root"].startswith(f"{package}/") and feature in row["features"]
    )
    print(
        f"fixture-feature gate: OK — {flavors} target(s) compile {registry}, every one testonly."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
