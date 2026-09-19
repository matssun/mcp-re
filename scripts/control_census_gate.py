#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ADR-MCPRE-069's ratchet: the undispositioned population may only shrink.

    python3 scripts/control_census_gate.py            # the verdict
    python3 scripts/control_census_gate.py --selftest # prove the verdict can be FAIL
    python3 scripts/control_census_gate.py --rebaseline > config/control-census-debt.toml

ADR-069's closure criterion is *unclaimed and undispositioned = 0*. That is a campaign, not
a commit, and a gate that simply failed on the residue would block every merge until the
campaign ended — which is the pressure that produces exactly the bulk registration ADR-069
D2 forbids. So the shape here is the one this repository already uses for its other debts:

  * a file carrying undispositioned controls is registered with the count it carries;
  * that count may not GROW — whatever the reason, and whatever else changed;
  * a file not in the registry may carry NONE, so a new control is claimed or
    dispositioned in the commit that introduces it;
  * a file that reaches zero must have its entry REMOVED, so the registry cannot keep
    describing debt that has been paid.

Every one of those preserves or improves what is known, and none of them can be satisfied by
adding a symbol to whichever battery happens to be nearest: registration discharges only by
the census agreeing that some unit's declared evidence SELECTS the control.

# Why the registry is per FILE and not per control

Per control, the registry would hold 2,458 rows of pure bookkeeping, every one of which
would have to be deleted by the disposition that resolves it — a second registry of the
same facts, kept in step by hand. Per file, the registry says *this file holds N controls
nobody has dispositioned yet*, which is the fact a campaign actually works against, and the
count falls as the dispositions land.

The debt register is NOT an exception mechanism. There is no permanent entry and no
`reviewed-exception` state: a disposition is how a control leaves, and `not-evidence` is a
disposition, so nothing needs to be exempted from the measurement in order to stay.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools" / "verification"))

REGISTRY = REPO_ROOT / "config" / "control-census-debt.toml"


def residue_by_file(report) -> dict[str, int]:
    counts: dict[str, int] = {}
    for control in report.residue:
        counts[control.carrier] = counts.get(control.carrier, 0) + 1
    return counts


def load_registry(text: str | None = None) -> dict[str, int]:
    if text is None:
        if not REGISTRY.is_file():
            return {}
        text = REGISTRY.read_text()
    raw = tomllib.loads(text)
    return {entry["path"]: entry["baseline"] for entry in raw.get("file", [])}


def verdict(measured: dict[str, int], registered: dict[str, int]) -> list[str]:
    """Every way this tree is worse than its baseline, in the registry's own terms."""
    problems: list[str] = []
    for path in sorted(set(measured) | set(registered)):
        now = measured.get(path, 0)
        baseline = registered.get(path)
        if baseline is None:
            problems.append(
                f"{path}: {now} undispositioned control(s) and no registry entry — "
                "claim it, disposition it, or register the debt"
            )
        elif now > baseline:
            problems.append(f"{path}: grew {baseline} -> {now} undispositioned control(s)")
        elif now == 0:
            problems.append(f"{path}: registered debt is paid; remove the entry")
    return problems


def rebaseline(measured: dict[str, int]) -> str:
    lines = [
        "# SPDX-License-Identifier: Apache-2.0",
        "#",
        "# ADR-MCPRE-069's debt register: files holding controls that no proposition claims",
        "# and no disposition covers. Held at a baseline by scripts/control_census_gate.py —",
        "# a registered file may not grow, an unregistered file may carry none, and an entry",
        "# whose count reaches zero is removed. It is a debt register, not an exception",
        "# mechanism: a control leaves by being claimed or dispositioned, never by being",
        "# excused from the measurement.",
        "",
        "schema_version = 1",
        "",
    ]
    for path, count in sorted(measured.items(), key=lambda kv: (-kv[1], kv[0])):
        lines += ["[[file]]", f'path = "{path}"', f"baseline = {count}", ""]
    return "\n".join(lines)


def selftest() -> int:
    """Prove the verdict can be FAIL — one case per way the ratchet is supposed to bite."""
    cases: list[tuple[str, dict[str, int], dict[str, int], bool]] = [
        ("a registered file at its baseline passes", {"a.rs": 3}, {"a.rs": 3}, True),
        ("a registered file that shrank passes", {"a.rs": 1}, {"a.rs": 3}, True),
        ("a registered file that grew FAILS", {"a.rs": 4}, {"a.rs": 3}, False),
        ("an unregistered file with debt FAILS", {"b.rs": 1}, {}, False),
        ("a paid entry left behind FAILS", {}, {"a.rs": 3}, False),
        ("a clean tree with an empty registry passes", {}, {}, True),
    ]
    failures = 0
    for name, measured, registered, expected_pass in cases:
        problems = verdict(measured, registered)
        if bool(problems) is expected_pass:
            failures += 1
            print(f"FAIL {name}: problems={problems}")
        else:
            print(f"ok   {name}")

    # The live registry must describe the live tree, and a gate whose registry has drifted
    # into naming nothing would pass on an empty measurement. Asserted non-empty for the
    # reason an empty join reads as a clean tree.
    registered = load_registry()
    if not registered:
        failures += 1
        print("FAIL the live registry is empty; a gate over nothing states nothing")
    else:
        print(f"ok   the live registry names {len(registered)} file(s)")
    print(f"control-census ratchet selftest: {'PASS' if not failures else f'FAIL ({failures})'}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--rebaseline", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()

    from _census import census  # noqa: PLC0415 — the tool path is set up above

    measured = residue_by_file(census())
    if args.rebaseline:
        print(rebaseline(measured))
        return 0
    problems = verdict(measured, load_registry())
    for problem in problems[:40]:
        print(f"  {problem}")
    if len(problems) > 40:
        print(f"  … and {len(problems) - 40} more")
    total = sum(measured.values())
    print(
        f"control-census ratchet: {'PASS' if not problems else f'FAIL ({len(problems)})'} — "
        f"{total} undispositioned control(s) across {len(measured)} file(s)"
    )
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
