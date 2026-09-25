# SPDX-License-Identifier: Apache-2.0
"""`--unit` for the formal lanes: one semantics, shared, so no lane can drift from it.

`verify-tests` has carried `--unit` since the test lane landed, and its rules are the ones
every lane now follows:

  * an id no unit declares is FAIL — a subset flag that selects nothing must never read as
    a clean lane;
  * a declared unit that owes THIS lane nothing is FAIL too — measuring an empty selection
    and reporting green is the same false pass one step removed;
  * the selection basis is PRINTED, so a reader who has only the log can see what was
    measured without reconstructing it from the command line.

Scoped pull-request runs (`verify --units-file`) hand each lane only the selected units
the manifest requires of that lane, so a well-formed scoped run never trips the second
rule; a hand-typed one that does is told so.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Iterable


def add_unit_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--unit",
        action="append",
        default=[],
        metavar="ID",
        help="measure only this unit; repeatable. An id no unit declares, or one that "
        "owes this lane nothing, is an error: a subset flag that selects nothing must "
        "never read as a clean lane.",
    )


def refuse(lane: str, message: str) -> int:
    """Print the refusal and the FAIL verdict every lane declares; return the exit code."""
    print(f"FAIL: {lane}: {message}", file=sys.stderr)
    print("VERDICT: FAIL")
    return 1


def selection_error(
    wanted: Iterable[str],
    declared: set[str],
    applicable: set[str],
    what: str,
) -> str | None:
    """Why `wanted` is not a valid selection for this lane, or None when it is.

    `declared` is every unit id in the manifest; `applicable` the ids this lane measures
    (units claiming its evidence, or units with a registered probe). `what` names the
    lane's evidence in the message.
    """
    wanted = list(dict.fromkeys(wanted))
    unknown = sorted(uid for uid in wanted if uid not in declared)
    if unknown:
        return f"--unit names no declared unit: {', '.join(unknown)}"
    silent = sorted(uid for uid in wanted if uid not in applicable)
    if silent:
        return (
            f"--unit names {len(silent)} unit(s) owing no {what}: {', '.join(silent)}. "
            f"Measuring a selection this lane has nothing to say about would report a "
            f"green lane over an empty selection."
        )
    return None


def filter_by_unit(
    items: list[dict], wanted: list[str], unit_of: Callable[[dict], str]
) -> list[dict]:
    """The items belonging to the wanted units, in their original order."""
    keep = set(wanted)
    return [item for item in items if unit_of(item) in keep]


def basis(wanted: list[str], selected: int, total: int, everything: str) -> str:
    """The one-line statement of what this run measured."""
    if not wanted:
        return everything
    return f"--unit ({len(dict.fromkeys(wanted))} unit(s); {selected} of {total} selected)"
