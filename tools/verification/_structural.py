# SPDX-License-Identifier: Apache-2.0
"""The `structural://` probe registry and its adjudication — ADR-MCPRE-068 §12.1.

A STRUCTURAL proposition says *the representation admits no illegal inhabitant; possession
is the proof*. Its falsifier is therefore not a test that goes red — it is a **compilation
that must be refused**. This module owns what such a probe must declare and how its
compiler output is judged; `verify-structural` owns running it.

WHAT THE RATIFICATION MADE MECHANICAL HERE
------------------------------------------

> A sealed owner is structurally established only for the exact invariant for which its
> construction boundary is closed. Private fields alone are insufficient. The structural
> witness must account for every producer path relevant to the claimed invariant, including
> module-tree visibility, alternate constructors, generated/deserialization routes where
> applicable, and test-only construction. The compile-refusal probe attacks that exact
> boundary.

So a probe declares an `invariant` — the exact thing the boundary closes, not the type it
closes it on — and a `producer_paths` table that must answer for EVERY category in
`PRODUCER_PATHS`. A category that does not apply is answered explicitly ("this type derives
no `Deserialize`"), because the failure this rule exists to catch is a witness that attacks
one route while another stands open, and an unanswered category is indistinguishable from
an unconsidered one. That is the same rule the severity field follows: absent may not mean
none.

WHY THE EXPECTED REFUSAL IS AN ERROR CODE AND A SPAN
----------------------------------------------------

"Does not compile" is satisfied by a typo, a missing import, or a fixture that stopped
building for reasons unrelated to the boundary. A probe that accepts it measures the
health of the scratch copy. So a probe names the rustc error code it expects and the marker
line it expects the primary span on, and the toolchain is pinned, which is what makes code
matching stable across runs.

TWO KINDS, ONE MECHANISM
------------------------

The class is one thing — the compiler refusing an illegal inhabitant — and the kinds differ
only in WHERE the hostile construction has to live:

  * `crate-boundary-compile-fail` — outside the owner's crate. The construction is injected
    as an integration test file, which cargo compiles as a SEPARATE crate linking the
    library, so it sees exactly what a downstream consumer sees.
  * `in-crate-source-injection` — inside it, as a sibling module in the owner's own crate.
    `docs/dev/sealed-owners.md` is right that no such file can exist in the tree, because
    it would not build; the scratch copy is the only place it can.

Both then run one mechanism: inject, `cargo check --message-format=json`, adjudicate the
diagnostics. **Deliberately not rustdoc.** The repository's existing ```compile_fail
doctests witness the boundary case, and rustdoc can annotate one with an expected error
code — but that annotation is checked only on nightly, so on the pinned stable toolchain it
is inert. A probe whose declared error code nothing compares is the configured-but-enforcing-
nothing shape this record exists to remove, so the code is compared here, by this lane,
against diagnostics it read itself. The doctests stay; a boundary probe names the one it
corresponds to in `doc_item`, so the documented case and the measured one are relatable.

Stdlib only, like the rest of this layer.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from _manifest import ManifestError

#: The two probe kinds — ADR-MCPRE-068 §12.1.
KINDS = ("crate-boundary-compile-fail", "in-crate-source-injection")

#: Every producer path a structural witness must answer for, from the ratification.
#:
#: The list is CLOSED and every probe answers all of it. A shorter list per probe would
#: make "not mentioned" and "does not apply" the same declaration, and only one of those is
#: a witness.
PRODUCER_PATHS = (
    "module-tree-visibility",
    "alternate-constructors",
    "generated-or-deserialization",
    "test-only-construction",
)

_COMMON_KEYS = {
    "id",
    "unit",
    "kind",
    "invariant",
    "producer_paths",
    "package",
    "insertion_path",
    "construction",
    "marker",
    "error_code",
    "features",
    "note",
}
#: What a boundary probe adds: the documented case it corresponds to. Provenance, not
#: execution — the lane compiles `construction`, and `doc_item` says which ```compile_fail
#: doctest states the same refusal in the source a reader will find first.
_BOUNDARY_KEYS = {"doc_path", "doc_item"}
#: What an in-crate probe adds: how the injected module is reached. A file dropped into
#: `src/` that no `mod` declaration names is not compiled at all, and a lane that did not
#: notice would report "no error" — the finding that means the boundary is OPEN — about a
#: file the compiler never read.
_INCRATE_KEYS = {"insertion_parent", "insertion_declaration"}
_OPTIONAL = {"note", "features"}


def _keys_for(kind: str) -> set[str]:
    return _COMMON_KEYS | (_BOUNDARY_KEYS if kind == KINDS[0] else _INCRATE_KEYS)


def load_probes(registry: Path) -> list[dict]:
    """The registry, validated strictly — an unknown key is a failure, not an ignored field.

    The same rule as every other manifest here: a mistyped security declaration must not
    read as an absent one. A missing registry file is an empty list rather than an error,
    because "no probe is registered" is a state the lane reports (`NOT_REQUIRED`) and a
    state the orphan check judges against the units, not a malformed declaration.
    """
    if not registry.is_file():
        return []
    with registry.open("rb") as handle:
        doc = tomllib.load(handle)
    probes = doc.get("probe", [])
    seen: set[str] = set()
    for index, probe in enumerate(probes):
        where = f"{registry.name} [[probe]] #{index + 1}"
        _validate(where, probe, seen)
    return probes


def _validate(where: str, probe: dict, seen: set[str]) -> None:
    kind = probe.get("kind")
    if kind not in KINDS:
        raise ManifestError(
            f"{where}: `kind` is {kind!r}, not one of {list(KINDS)}. The class is one thing "
            f"— the compiler refusing an illegal inhabitant — and the kind says only where "
            f"the hostile construction has to live."
        )
    allowed = _keys_for(kind)
    unknown = set(probe) - allowed
    if unknown:
        raise ManifestError(f"{where}: unknown key(s) {sorted(unknown)} for kind {kind!r}")
    missing = allowed - _OPTIONAL - set(probe)
    if missing:
        raise ManifestError(f"{where}: missing required key(s) {sorted(missing)}")
    if probe["id"] in seen:
        raise ManifestError(f"{where}: duplicate probe id {probe['id']!r}")
    seen.add(probe["id"])
    if not str(probe["invariant"]).strip():
        raise ManifestError(
            f"{where}: `invariant` is empty. A structural claim is established only for the "
            f"exact invariant whose construction boundary is closed, so a probe that does "
            f"not state one cannot be said to attack the right boundary."
        )
    _validate_producer_paths(where, probe)
    if not str(probe["error_code"]).startswith("E"):
        raise ManifestError(
            f"{where}: `error_code` is {probe['error_code']!r}. The expected refusal is a "
            f"specific rustc error code, not merely 'does not compile' — the weak form is "
            f"satisfied by a typo, a missing import or a broken fixture."
        )
    _validate_marker(where, probe)
    _validate_site(where, probe)


#: Where each kind's construction must be injected, and what that placement MEANS.
#:
#: Cargo compiles `tests/*.rs` as separate crates linking the library, so a construction
#: there sees exactly what a downstream consumer sees; a construction under `src/` is a
#: sibling module inside the owner's own crate. The two witness different propositions, and
#: a probe injected into the wrong one would answer a question it did not ask — a boundary
#: probe in `src/` would claim the in-crate seal it never attacked.
_SITE = {
    "crate-boundary-compile-fail": "tests/",
    "in-crate-source-injection": "src/",
}


def _validate_site(where: str, probe: dict) -> None:
    parts = Path(str(probe["insertion_path"])).parts
    wanted = _SITE[probe["kind"]]
    if len(parts) < 2 or f"{parts[1]}/" != wanted:
        raise ManifestError(
            f"{where}: kind {probe['kind']!r} must inject under `<crate>/{wanted}`, but "
            f"`insertion_path` is {probe['insertion_path']!r}. Cargo compiles `tests/` as a "
            f"SEPARATE crate and `src/` as part of the owner's own, so the placement is "
            f"what decides which proposition the probe attacks."
        )


def _validate_producer_paths(where: str, probe: dict) -> None:
    table = probe["producer_paths"]
    if not isinstance(table, dict):
        raise ManifestError(
            f"{where}: `producer_paths` must be a table mapping each of "
            f"{list(PRODUCER_PATHS)} to what closes it."
        )
    unknown = set(table) - set(PRODUCER_PATHS)
    if unknown:
        raise ManifestError(f"{where}: `producer_paths` has unknown route(s) {sorted(unknown)}")
    missing = [route for route in PRODUCER_PATHS if not str(table.get(route, "")).strip()]
    if missing:
        raise ManifestError(
            f"{where}: `producer_paths` does not answer for {missing}. Every route is "
            f"answered, including the ones that do not apply — a witness that attacks one "
            f"route while another stands open establishes nothing, and an unanswered route "
            f"is indistinguishable from an unconsidered one."
        )


def _validate_marker(where: str, probe: dict) -> None:
    if marker_line(probe) is None:
        raise ManifestError(
            f"{where}: `marker` {probe['marker']!r} appears "
            f"{str(probe['construction']).count(str(probe['marker']))} times in "
            f"`construction`, expected exactly 1. The marker is what the expected error "
            f"span is compared against; an ambiguous one cannot say which line was refused."
        )


def marker_line(probe: dict) -> int | None:
    """The 1-based line of `marker` within `construction`, or None if it is not unique."""
    lines = str(probe["construction"]).splitlines()
    hits = [number for number, line in enumerate(lines, 1) if str(probe["marker"]) in line]
    return hits[0] if len(hits) == 1 else None


def adjudicate(probe: dict, diagnostics: list[dict], relative_path: str) -> str | None:
    """Why this compiler output does not refuse the hostile construction, or None.

    THREE OUTCOMES, AND ONLY ONE IS EVIDENCE.

    * The construction COMPILED — no error at all. That is the finding the lane exists to
      produce: the boundary is open, and the structural claim above it is false. It is not
      a lane malfunction and must never be reported as one.
    * It failed with a DIFFERENT error, or at a different line. The lane could not say the
      boundary refused anything; it watched something else break. A measurement failure.
    * It failed with the declared code, on the marker line. Evidence.
    """
    errors = [d for d in diagnostics if d.get("level") == "error"]
    if not errors:
        return (
            f"the hostile construction COMPILED. {probe['invariant']} is NOT closed by the "
            f"representation: the compiler admits the illegal inhabitant, so possession of "
            f"the value is not proof of the invariant."
        )
    wanted = str(probe["error_code"])
    line = marker_line(probe)
    for diagnostic in errors:
        code = (diagnostic.get("code") or {}).get("code")
        if code != wanted:
            continue
        for span in diagnostic.get("spans", []):
            if not span.get("is_primary"):
                continue
            if span.get("file_name", "").endswith(relative_path) and span.get("line_start") == line:
                return None
    codes = sorted({(d.get("code") or {}).get("code") or "<none>" for d in errors})
    return (
        f"the construction was refused, but not by the boundary this probe attacks: "
        f"expected {wanted} with its primary span on line {line} of {relative_path}, saw "
        f"{codes}. A refusal the probe cannot attribute is not evidence about the "
        f"invariant — re-adjudicate the probe against the current implementation."
    )


def provenance_problem(probe: dict, unit: dict, repo_root: Path) -> str | None:
    """Why a boundary probe's declared documented case is not there, or None.

    A `doc_item` that names nothing, or a `doc_path` holding no ```compile_fail fence, is a
    probe whose provenance has drifted: the lane would still compile its own construction
    and still report a refusal, while the source a reader reaches for first no longer says
    the same thing. Checked rather than trusted, because the drift is silent in exactly the
    direction that makes the registry look better than the tree.

    NOT compared against the unit's `tested_symbols`, and the reason is this phase: once a
    unit reclassifies to `structural` its `test://` URI and its battery are GONE, so a check
    written against that field would refuse exactly the units the class exists for. What is
    checked instead is that the documented case is findable where the record says it is.

    Not applicable to an in-crate probe, which HAS no documented case — that is the whole
    reason its kind exists.
    """
    if probe["kind"] != "crate-boundary-compile-fail":
        return None
    source = repo_root / str(probe["doc_path"])
    if not source.is_file():
        return f"`doc_path` {probe['doc_path']} does not exist"
    text = source.read_text(encoding="utf-8")
    if "```compile_fail" not in text:
        return (
            f"`doc_path` {probe['doc_path']} holds no ```compile_fail doctest. The probe "
            f"claims to correspond to a documented refusal that is no longer there."
        )
    item = str(probe["doc_item"]).rsplit("::", 1)[-1]
    if not re.search(rf"\b(?:struct|enum|trait|fn|type)\s+{re.escape(item)}\b", text):
        return (
            f"`doc_item` {probe['doc_item']!r} names {item!r}, which {probe['doc_path']} "
            f"does not declare. The documented case a probe cites must be findable in the "
            f"source a reader reaches for first."
        )
    return None
