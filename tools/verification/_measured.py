# SPDX-License-Identifier: Apache-2.0
"""The `measured://` registry and its apparatus adjudication — ADR-MCPRE-068 §4.1, §12.2.

A MEASURED proposition is existential and scoped — *over THIS corpus, on THIS hardware
class, the observed value was X* — where a tested one is universal. The difference decides
the falsifier, and it is why owner Ruling 4 exists:

    Deleting a production property does not make a measurement FALSE. It makes it a
    measurement of a different tree.

So `measured` takes no mutation probe. What it owes instead is an APPARATUS CONTROL: the
demonstration that the measurement can still MOVE. A number that cannot move is not a
measurement, whatever it is printed beside — the repository's own words for it, from the
commit that built `evidence-class-census`.

THE FOUR ELEMENTS, AS THE RATIFICATION NAMES THEM
-------------------------------------------------

> `measured://`: a measurement protocol, scope/environment/corpus identity, a result
> artifact, and a reproducibility or sensitivity control.

`protocol` is an argv, not prose: a protocol nobody can execute is a description of a
measurement rather than one. `scope` is prose, because corpus identity is a claim about
meaning that no argv can carry. `artifact` is the result the lane preserves and digests.
`control` is one of exactly two mechanical shapes:

  * `reproducibility` — the protocol is run TWICE and the two artifacts must be identical.
    A measurement that cannot reproduce is not one, and this catches an apparatus that
    reads the clock, the environment, or a directory listing it did not mean to.
  * `sensitivity` — a separate argv perturbs the apparatus and must report how many
    observations MOVED, as `APPARATUS-MOVED: <n>`, with n >= 1. Nothing else counts: an
    exit status of 0 from a control that ran nothing is exactly the false green this class
    of lane exists to prevent, so the lane parses the count rather than the status.

WHY THE COUNT AND NOT THE EXIT STATUS
-------------------------------------

`-- --ignored` selecting zero tests exits 0. A control that skipped its whole perturbation
set exits 0. A control whose harness crashed after printing a banner may exit 0. The only
statement that distinguishes a live apparatus from a dead one is one the control has to
compute, which is why the contract is a number it must print and this module refuses its
absence separately from refusing a zero.

Stdlib only, like the rest of this layer.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from _manifest import ManifestError

#: The two mechanical control shapes — ADR-MCPRE-068 §4.1, owner Ruling 4.
CONTROL_KINDS = ("reproducibility", "sensitivity")

#: What a sensitivity control must print. A line, not an exit status.
MOVED = re.compile(r"^APPARATUS-MOVED:\s*(\d+)\s*$", re.MULTILINE)

_KEYS = {
    "id",
    "unit",
    "protocol",
    "scope",
    "artifact",
    "artifact_pattern",
    "control_kind",
    "control",
    "note",
}
_OPTIONAL = {"note", "control"}


def load_measurements(registry: Path) -> list[dict]:
    """The registry, validated strictly — an unknown key is a failure, not an ignored field."""
    if not registry.is_file():
        return []
    with registry.open("rb") as handle:
        doc = tomllib.load(handle)
    measurements = doc.get("measurement", [])
    seen: set[str] = set()
    for index, measurement in enumerate(measurements):
        _validate(f"{registry.name} [[measurement]] #{index + 1}", measurement, seen)
    return measurements


def _validate(where: str, measurement: dict, seen: set[str]) -> None:
    unknown = set(measurement) - _KEYS
    if unknown:
        raise ManifestError(f"{where}: unknown key(s) {sorted(unknown)}")
    missing = _KEYS - _OPTIONAL - set(measurement)
    if missing:
        raise ManifestError(f"{where}: missing required key(s) {sorted(missing)}")
    if measurement["id"] in seen:
        raise ManifestError(f"{where}: duplicate measurement id {measurement['id']!r}")
    seen.add(measurement["id"])
    if not measurement["protocol"]:
        raise ManifestError(
            f"{where}: `protocol` is empty. The protocol is an argv the lane executes; a "
            f"measurement nobody can run is a description of one."
        )
    if not str(measurement["scope"]).strip():
        raise ManifestError(
            f"{where}: `scope` is empty. A number whose corpus and environment are unstated "
            f"is a number the reader has to guess the meaning of, and it cannot be compared "
            f"against the next one."
        )
    kind = measurement.get("control_kind")
    if kind not in CONTROL_KINDS:
        raise ManifestError(
            f"{where}: `control_kind` is {kind!r}, not one of {list(CONTROL_KINDS)}."
        )
    if kind == "sensitivity" and not measurement.get("control"):
        raise ManifestError(
            f"{where}: `control_kind = 'sensitivity'` requires a `control` argv that "
            f"perturbs the apparatus and reports `APPARATUS-MOVED: <n>`."
        )
    if kind == "reproducibility" and measurement.get("control"):
        raise ManifestError(
            f"{where}: `control_kind = 'reproducibility'` takes no `control` argv — the "
            f"control IS the second run of the protocol, and a third command here would be "
            f"an apparatus check nothing adjudicates."
        )
    try:
        re.compile(str(measurement["artifact_pattern"]))
    except re.error as exc:
        raise ManifestError(f"{where}: `artifact_pattern` is not a regex: {exc}") from exc


def extract(pattern: str, output: str) -> list[str]:
    """The protocol output lines that constitute the result.

    A filter, because a protocol's raw output carries timings, progress and paths that
    differ between two identical measurements — and a reproducibility control comparing
    those would fail over the clock rather than over the apparatus. The pattern is the
    measurement's own statement of which of its lines ARE the result.
    """
    matcher = re.compile(pattern)
    return [line for line in output.splitlines() if matcher.search(line)]


def moved(output: str) -> int | None:
    """How many observations the sensitivity control reports moved, or None if it said nothing.

    None and 0 are different findings and are reported differently: 0 is a DEAD APPARATUS —
    the control perturbed the input and nothing changed — while None is a control that did
    not state a result at all, which is a measurement failure about the control itself.
    """
    hits = MOVED.findall(output)
    if not hits:
        return None
    return min(int(hit) for hit in hits)


def apparatus_problem(measurement: dict, first: list[str], second: list[str] | None, control_output: str | None) -> str | None:
    """Why this run does not demonstrate a live apparatus, or None.

    The order matters: an EMPTY result is refused before either control is consulted,
    because a protocol that produced nothing has already failed to measure, and a control
    over nothing would be adjudicating an absence.
    """
    if not first:
        return (
            f"the protocol produced NO result line matching "
            f"{measurement['artifact_pattern']!r}. A measurement that observed nothing is "
            f"not a weak measurement; it is an apparatus that did not run."
        )
    if measurement["control_kind"] == "reproducibility":
        if second is None:
            return "the reproducibility control did not run the protocol a second time"
        if first != second:
            return (
                "two runs of the same protocol over the same tree produced DIFFERENT "
                "results, so the apparatus is reading something the scope does not name — "
                "a clock, an environment variable, or a directory order. The measurement "
                "cannot be compared against any other."
            )
        return None
    count = moved(control_output or "")
    if count is None:
        return (
            "the sensitivity control printed no `APPARATUS-MOVED: <n>` line, so the lane "
            "cannot say the perturbation moved anything. An exit status of 0 from a control "
            "that selected nothing is the false green this contract exists to refuse."
        )
    if count < 1:
        return (
            "the sensitivity control reports APPARATUS-MOVED: 0 — the perturbation changed "
            "no observation, so the apparatus is DEAD and its number cannot move. A figure "
            "that cannot move is not a measurement."
        )
    return None
