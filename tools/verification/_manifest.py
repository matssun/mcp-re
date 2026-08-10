# SPDX-License-Identifier: Apache-2.0
"""Shared loading and validation for the ADR-MCPRE-059 verification manifests.

Strict by construction: an unknown key is a validation FAILURE, not a field that is
silently ignored (ADR-MCPRE-059, "Authoritative manifest"). A typo in a security
declaration must not read as an absent declaration.

Stdlib only. This is analysis tooling, not production code, and it must run before any
verification toolchain exists.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "verification" / "policy"

VERIFICATION_TOML = POLICY_DIR / "verification.toml"
ASSUMPTIONS_TOML = POLICY_DIR / "assumptions.toml"
TRUST_BOUNDARIES_TOML = POLICY_DIR / "trust-boundaries.toml"
TOOLCHAINS_LOCK_TOML = POLICY_DIR / "toolchains.lock.toml"

SCHEMA_VERSION = 1

#: Verification classes, ADR-MCPRE-059 §9.
CLASSES = {"V0", "V1", "V2", "V3"}

#: Typed edge kinds, ADR-MCPRE-059 §4. Collapsing these into one "depends on" relation is
#: forbidden once invalidation is enforced, so the set is closed here.
EDGE_KINDS = {
    "COMPILE_DEPENDENCY",
    "CONTRACT_CONSUMES",
    "PROOF_DEPENDENCY",
    "TEST_EVIDENCE",
    "TRUSTS_ASSUMPTION",
    "GENERATED_FROM",
    "REVIEW_CONTEXT",
}

#: Freshness states, ADR-MCPRE-059 §5.
STATES = {
    "FRESH",
    "DIRTY_SELF",
    "DIRTY_CONTRACT",
    "DIRTY_DEPENDENCY",
    "DIRTY_ASSUMPTION",
    "DIRTY_POLICY",
    "DIRTY_TOOLCHAIN",
    "DIRTY_EVIDENCE",
    "UNKNOWN",
    "BLOCKED",
}

_VERIFICATION_TOP = {
    "schema_version",
    "policy_revision",
    "unknown_is_dirty",
    "formal_model_revision",
    "threat_model_revision",
    "unit",
    "edge",
}
_UNIT_KEYS = {
    "id",
    "class",
    "description",
    "paths",
    "exported_contracts",
    "consumed_contracts",
    "evidence",
    "assumptions",
    "features",
    "pilot",
}
_EDGE_KEYS = {"kind", "from", "to", "contract", "sealed", "sealed_by", "rationale"}

_ASSUMPTION_KEYS = {
    "id",
    "description",
    "justification",
    "scope",
    "owner",
    "introduced_by",
    "review_requirement",
    "affected_contracts",
    "tool_specific_mechanism",
}
_ASSUMPTION_REQUIRED = set(_ASSUMPTION_KEYS)

_BOUNDARY_KEYS = {
    "id",
    "description",
    "kind",
    "paths",
    "beyond",
    "max_class_without_assumption",
}


class ManifestError(Exception):
    """A manifest is malformed. Always fatal — unknown provenance is never freshness."""


def _load(path: Path) -> dict:
    if not path.exists():
        raise ManifestError(f"{path.relative_to(REPO_ROOT)}: missing")
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{path.relative_to(REPO_ROOT)}: unparsable: {exc}") from exc


def _reject_unknown(where: str, got, allowed: set[str]) -> None:
    unknown = sorted(set(got) - allowed)
    if unknown:
        raise ManifestError(
            f"{where}: unknown key(s) {unknown}. "
            f"Unknown keys fail validation rather than being ignored — a mistyped "
            f"security declaration must not read as an absent one."
        )


def _require(where: str, got: dict, required: set[str]) -> None:
    missing = sorted(required - set(got))
    if missing:
        raise ManifestError(f"{where}: missing required key(s) {missing}")


def load_verification() -> dict:
    """Load and validate `verification/policy/verification.toml`."""
    doc = _load(VERIFICATION_TOML)
    where = "verification.toml"
    _reject_unknown(where, doc, _VERIFICATION_TOP)
    _require(
        where,
        doc,
        {"schema_version", "policy_revision", "unknown_is_dirty"},
    )
    if doc["schema_version"] != SCHEMA_VERSION:
        raise ManifestError(
            f"{where}: schema_version {doc['schema_version']} but this tooling "
            f"implements {SCHEMA_VERSION}. A schema change alters what a fingerprint "
            f"means, so it invalidates every attestation and must be handled, not "
            f"tolerated."
        )
    if doc["unknown_is_dirty"] is not True:
        raise ManifestError(
            f"{where}: unknown_is_dirty must be true. Turning it off is a policy change "
            f"that removes the fail-closed property the whole graph rests on; it cannot "
            f"be done by editing this field alone."
        )

    seen_ids: set[str] = set()
    contracts: set[str] = set()
    for index, unit in enumerate(doc.get("unit", [])):
        uwhere = f"{where} [[unit]] #{index}"
        _reject_unknown(uwhere, unit, _UNIT_KEYS)
        _require(uwhere, unit, {"id", "class", "paths"})
        if unit["class"] not in CLASSES:
            raise ManifestError(
                f"{uwhere}: class {unit['class']!r} not one of {sorted(CLASSES)}"
            )
        if unit["id"] in seen_ids:
            raise ManifestError(f"{uwhere}: duplicate unit id {unit['id']!r}")
        seen_ids.add(unit["id"])
        for declared in unit["paths"]:
            if not list(REPO_ROOT.glob(declared)):
                raise ManifestError(
                    f"{uwhere}: path {declared!r} matches nothing. A unit whose source "
                    f"cannot be located has unknown provenance, which is dirty, not empty."
                )
        contracts.update(unit.get("exported_contracts", []))

    for index, edge in enumerate(doc.get("edge", [])):
        ewhere = f"{where} [[edge]] #{index}"
        _reject_unknown(ewhere, edge, _EDGE_KEYS)
        _require(ewhere, edge, {"kind", "from", "to"})
        if edge["kind"] not in EDGE_KINDS:
            raise ManifestError(
                f"{ewhere}: kind {edge['kind']!r} not one of {sorted(EDGE_KINDS)}"
            )
        for endpoint in ("from", "to"):
            if edge[endpoint] not in seen_ids:
                raise ManifestError(
                    f"{ewhere}: {endpoint} {edge[endpoint]!r} is not a declared unit"
                )
        if edge.get("sealed"):
            if edge["kind"] != "CONTRACT_CONSUMES":
                raise ManifestError(
                    f"{ewhere}: only a CONTRACT_CONSUMES edge may be sealed. Sealing "
                    f"means source-only dirtiness stops at a proved unchanged contract, "
                    f"which is meaningless without a contract."
                )
            _require(ewhere, edge, {"contract", "sealed_by", "rationale"})
            if edge["contract"] not in contracts:
                raise ManifestError(
                    f"{ewhere}: sealed on contract {edge['contract']!r}, which no unit "
                    f"exports"
                )
    return doc


def load_assumptions() -> dict:
    """Load and validate the trusted-assumption registry."""
    doc = _load(ASSUMPTIONS_TOML)
    where = "assumptions.toml"
    _reject_unknown(where, doc, {"schema_version", "assumption"})
    _require(where, doc, {"schema_version"})
    seen: set[str] = set()
    for index, entry in enumerate(doc.get("assumption", [])):
        awhere = f"{where} [[assumption]] #{index}"
        _reject_unknown(awhere, entry, _ASSUMPTION_KEYS)
        _require(awhere, entry, _ASSUMPTION_REQUIRED)
        if entry["id"] in seen:
            raise ManifestError(
                f"{awhere}: duplicate assumption id {entry['id']!r}. Ids are never reused "
                f"— a reused id makes two different trusted claims indistinguishable in "
                f"the review history."
            )
        seen.add(entry["id"])
    return doc


def load_trust_boundaries() -> dict:
    """Load and validate the declared trust boundaries."""
    doc = _load(TRUST_BOUNDARIES_TOML)
    where = "trust-boundaries.toml"
    _reject_unknown(where, doc, {"schema_version", "boundary"})
    _require(where, doc, {"schema_version"})
    for index, entry in enumerate(doc.get("boundary", [])):
        bwhere = f"{where} [[boundary]] #{index}"
        _reject_unknown(bwhere, entry, _BOUNDARY_KEYS)
        _require(bwhere, entry, {"id", "description", "kind", "paths", "beyond"})
        cls = entry.get("max_class_without_assumption")
        if cls is not None and cls not in CLASSES:
            raise ManifestError(f"{bwhere}: max_class_without_assumption {cls!r} invalid")
    return doc


def load_toolchains() -> dict:
    """Load and validate the toolchain lock."""
    doc = _load(TOOLCHAINS_LOCK_TOML)
    where = "toolchains.lock.toml"
    _require(where, doc, {"schema_version"})
    for name, entry in doc.items():
        if name == "schema_version":
            continue
        if not isinstance(entry, dict):
            raise ManifestError(f"{where}: [{name}] must be a table")
        state = entry.get("state")
        if state not in {"resolved", "unresolved"}:
            raise ManifestError(
                f"{where}: [{name}] state must be 'resolved' or 'unresolved', got "
                f"{state!r}. A tool with no state is a tool of unknown identity."
            )
        for sub_name, sub in entry.items():
            if isinstance(sub, dict) and sub.get("state") not in {
                "resolved",
                "unresolved",
            }:
                raise ManifestError(
                    f"{where}: [{name}.{sub_name}] state must be 'resolved' or "
                    f"'unresolved'"
                )
    return doc


def unresolved_pins(toolchains: dict) -> list[str]:
    """Every toolchain identity that is not pinned, as dotted names.

    An unresolved pin means the tool's identity is unknown, and unknown is dirty. The
    lanes that depend on it refuse to run rather than running against whatever is on
    PATH — a proof checked by an unknown prover is not evidence.
    """
    out: list[str] = []
    for name, entry in toolchains.items():
        if name == "schema_version" or not isinstance(entry, dict):
            continue
        if entry.get("state") == "unresolved":
            out.append(name)
        for sub_name, sub in entry.items():
            if isinstance(sub, dict) and sub.get("state") == "unresolved":
                out.append(f"{name}.{sub_name}")
    return sorted(out)


def fail(message: str) -> None:
    """Print a fatal manifest/lane error and exit non-zero."""
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)
