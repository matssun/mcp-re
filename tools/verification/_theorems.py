# SPDX-License-Identifier: Apache-2.0
"""The security theorem registry — ADR-MCPRE-059 §6.3, Phase T1.

Loads and validates `verification/policy/theorems.toml`, strictly in the same sense as
`_manifest.py`: an unknown key is a validation FAILURE, not a field that is ignored.

The registry holds the human claim and two edges — `supported_by` (`unit://`) and
`depends_on` (`THM-NNNN`). Everything below the claim has an existing authority, so a key
that would restate a `[[unit]]` fact is rejected by name rather than merely as unknown.

Two things this module refuses to do, both deliberate:

  * It stores no review or approval field. An approval is evidence about a fingerprint
    (§14.7), and a stored status string cannot say which proposition was approved.
  * It derives no reverse edge (§8.2). `established_theorems` reads the declared direction
    only.

The limit of the ID-permanence rule, stated rather than implied: this loader sees the tree
as it stands, so it can enforce uniqueness and format but cannot see that an ID was
deleted and later reused. Deprecation keeps the record present, which is what makes the
rule checkable at review time; deletion is what a reviewer must catch.

Stdlib only, like the rest of `tools/verification/`.
"""

from __future__ import annotations

import re
import tomllib

from _manifest import POLICY_DIR, SCHEMA_VERSION, ManifestError, _reject_unknown, _require

THEOREMS_TOML = POLICY_DIR / "theorems.toml"

#: `THM-NNNN`, matching the established `ASM-NNNN` convention.
_ID_RE = re.compile(r"^THM-\d{4}$")

_TOP_KEYS = {"schema_version", "theorem"}

_THEOREM_KEYS = {
    "id",
    "title",
    "statement",
    "security_consequence",
    "scope",
    "owner",
    "review_requirement",
    "supported_by",
    "depends_on",
    "replaced_by",
}
#: Everything but the deprecation link. A claim with no consequence or no scope is not a
#: reviewable proposition, so none of these is optional.
_REQUIRED_KEYS = _THEOREM_KEYS - {"replaced_by"}

#: Fields whose facts already have an owner. They are rejected by name because the generic
#: unknown-key message would send a reader looking for a typo when the real answer is
#: "that fact is declared elsewhere, and declaring it twice is how the two disagree".
_DUPLICATED_AUTHORITY = {
    "paths": "verification.toml [[unit]].paths",
    "features": "verification.toml [[unit]].features",
    "evidence": "verification.toml [[unit]].evidence",
    "proved_symbols": "verification.toml [[unit]].proved_symbols",
    "tested_symbols": "verification.toml [[unit]].tested_symbols",
    "exported_contracts": "verification.toml [[unit]].exported_contracts",
    "consumed_contracts": "verification.toml [[unit]].consumed_contracts",
    "assumptions": "verification.toml [[unit]].assumptions, scoped in assumptions.toml",
    "required_evidence": "verification.toml [[unit]].evidence, as target-qualified URIs",
    "review": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "review_status": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "reviewed": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "approved": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "status": "the review attestation, keyed by reviewed_fingerprint (§14.7)",
    "consumed_by": "derived — a reverse edge is never stored (§8.2)",
    "dependents": "derived — a reverse edge is never stored (§8.2)",
    "guarantees": "derived from supported_by — a reverse edge is never stored (§8.2)",
}

_TEXT_KEYS = (
    "title",
    "statement",
    "security_consequence",
    "scope",
    "owner",
    "review_requirement",
)


def _reject_duplicated_authority(where: str, entry: dict) -> None:
    for key, owner in _DUPLICATED_AUTHORITY.items():
        if key in entry:
            raise ManifestError(
                f"{where}: key {key!r} duplicates a fact owned by {owner}. One fact has "
                f"one authority; a theorem resolves downward through `unit://` rather "
                f"than restating what the unit already declares."
            )


def _check_text(where: str, entry: dict) -> None:
    for key in _TEXT_KEYS:
        value = entry[key]
        if not isinstance(value, str) or not value.strip():
            raise ManifestError(
                f"{where}: {key} must be a non-empty string. An empty claim reads as a "
                f"registered theorem while stating nothing."
            )


def _check_list(where: str, entry: dict, key: str) -> list[str]:
    value = entry[key]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ManifestError(f"{where}: {key} must be a list of strings")
    return value


def _check_ids(doc: dict) -> list[str]:
    """Every declared id, in declaration order, after format and uniqueness checks."""
    ids: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(doc.get("theorem", [])):
        where = f"theorems.toml [[theorem]] #{index}"
        _reject_duplicated_authority(where, entry)
        _reject_unknown(where, entry, _THEOREM_KEYS)
        _require(where, entry, _REQUIRED_KEYS)
        theorem_id = entry["id"]
        if not isinstance(theorem_id, str) or not _ID_RE.match(theorem_id):
            raise ManifestError(
                f"{where}: id {theorem_id!r} is not of the form THM-NNNN. An identifier "
                f"the tooling cannot resolve names no claim while reading as one."
            )
        if theorem_id in seen:
            raise ManifestError(
                f"{where}: duplicate theorem id {theorem_id!r}. Ids are never reused — a "
                f"reused id makes two different security claims indistinguishable in the "
                f"review history."
            )
        seen.add(theorem_id)
        ids.append(theorem_id)
    return ids


def _check_edges(doc: dict, ids: list[str], unit_ids: set[str]) -> None:
    declared = set(ids)
    deprecated = {
        entry["id"] for entry in doc.get("theorem", []) if entry.get("replaced_by")
    }
    for index, entry in enumerate(doc.get("theorem", [])):
        where = f"theorems.toml [[theorem]] #{index} ({entry['id']})"
        _check_text(where, entry)
        if entry["owner"] not in unit_ids:
            raise ManifestError(
                f"{where}: owner {entry['owner']!r} is not a [[unit]] declared in "
                f"verification.toml. `owner` names the review unit that is the semantic "
                f"authority for the claim, so an owner nothing resolves leaves the claim "
                f"unowned while reading as governed."
            )
        for target in _check_list(where, entry, "supported_by"):
            # Fail closed. A dangling support edge would otherwise contribute nothing to
            # the closure, and a closure with nothing in it is satisfied vacuously — the
            # theorem would read as supported by evidence that does not exist.
            if not target.startswith("unit://") or target[7:] not in unit_ids:
                raise ManifestError(
                    f"{where}: supported_by {target!r} does not resolve to a [[unit]] "
                    f"declared in verification.toml. An unresolvable support edge derives "
                    f"an empty closure, which is satisfied vacuously — so it fails here "
                    f"rather than passing there."
                )
        for target in _check_list(where, entry, "depends_on"):
            if target == entry["id"]:
                raise ManifestError(f"{where}: depends_on names itself")
            if target not in declared:
                raise ManifestError(
                    f"{where}: depends_on {target!r} is not a declared theorem"
                )
            if target in deprecated and entry["id"] not in deprecated:
                raise ManifestError(
                    f"{where}: depends_on {target!r}, which is deprecated. A live claim "
                    f"may not rest on a withdrawn one; depend on its replacement."
                )
        replacement = entry.get("replaced_by")
        if replacement is None:
            continue
        if replacement == entry["id"] or replacement not in declared:
            raise ManifestError(
                f"{where}: replaced_by {replacement!r} is not another declared theorem. A "
                f"deprecated theorem stays resolvable and links what replaced it."
            )
        if replacement in deprecated:
            raise ManifestError(
                f"{where}: replaced_by {replacement!r}, which is itself deprecated. The "
                f"link must reach a live claim, or the reader follows it to nothing."
            )


def _check_acyclic(doc: dict) -> None:
    """Reject a cycle in `depends_on`.

    The gate covers registry-declared edges only. It does not claim to see a cycle formed
    below the registry, through units or contracts — those have their own owners.
    """
    edges = {
        entry["id"]: list(entry.get("depends_on", []))
        for entry in doc.get("theorem", [])
    }
    state: dict[str, int] = {}

    def walk(node: str, stack: list[str]) -> None:
        if state.get(node) == 2:
            return
        if state.get(node) == 1:
            cycle = " -> ".join(stack[stack.index(node) :] + [node])
            raise ManifestError(
                f"theorems.toml: cycle in depends_on: {cycle}. A claim that transitively "
                f"depends on itself is established by nothing."
            )
        state[node] = 1
        for nxt in edges.get(node, []):
            walk(nxt, stack + [node])
        state[node] = 2

    for node in edges:
        walk(node, [])


def validate_theorems(doc: dict, unit_ids: set[str]) -> dict:
    """Validate a parsed theorem registry against the declared review units."""
    where = "theorems.toml"
    _reject_unknown(where, doc, _TOP_KEYS)
    _require(where, doc, {"schema_version"})
    if doc["schema_version"] != SCHEMA_VERSION:
        raise ManifestError(
            f"{where}: schema_version {doc['schema_version']} but this tooling implements "
            f"{SCHEMA_VERSION}. A schema change alters what a claim means, so it must be "
            f"handled, not tolerated."
        )
    ids = _check_ids(doc)
    _check_edges(doc, ids, unit_ids)
    _check_acyclic(doc)
    return doc


def established_theorems(doc: dict) -> set[str]:
    """The theorems this registry establishes, by the declared edges alone.

    A theorem is established only if some review unit supports it AND every theorem it
    depends on is established. A theorem with no supporting unit is therefore NOT
    established — it is a stated claim awaiting evidence, and the difference is the whole
    reason the layer exists. A deprecated theorem establishes nothing: it is retained so
    historical evidence stays resolvable, not so it can carry a live closure.

    Support here means a resolvable declaration, not a measured one. Whether the unit's
    evidence actually ran is the attestation layer's question, and it is answered lower
    down — this function may never be read as "proved".
    """
    entries = {entry["id"]: entry for entry in doc.get("theorem", [])}
    established = {
        tid
        for tid, entry in entries.items()
        if entry.get("supported_by") and not entry.get("replaced_by")
    }
    changed = True
    while changed:
        changed = False
        for tid in sorted(established):
            deps = entries[tid].get("depends_on", [])
            if any(dep not in established for dep in deps):
                established.discard(tid)
                changed = True
    return established


def unestablished_theorems(doc: dict) -> list[str]:
    """Declared, live theorems that nothing establishes."""
    established = established_theorems(doc)
    return sorted(
        entry["id"]
        for entry in doc.get("theorem", [])
        if entry["id"] not in established and not entry.get("replaced_by")
    )


def load_theorems(unit_ids: set[str]) -> dict:
    """Load and validate `verification/policy/theorems.toml`."""
    if not THEOREMS_TOML.exists():
        raise ManifestError("verification/policy/theorems.toml: missing")
    try:
        with THEOREMS_TOML.open("rb") as handle:
            doc = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"theorems.toml: unparsable: {exc}") from exc
    return validate_theorems(doc, unit_ids)
